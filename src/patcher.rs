use std::io::Cursor;

use aes::{
    Aes256,
    cipher::{
        BlockDecrypt as _, BlockDecryptMut as _, KeyInit as _, KeyIvInit as _,
        block_padding::Pkcs7, generic_array::GenericArray,
    },
};
use anyhow::Result;
use binrw::{BinRead, BinReaderExt as _};
use pelite::{
    pattern,
    pe::{Pe, PeView},
};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

const APP_ID: u32 = 897610;

#[derive(Debug, BinRead)]
#[br(little, magic = 0xC0DEC0DFu32)]
struct SteamHeader {
    image_base: u64,
    _address_of_entry_point: u64,
    _bind_section_offset: u32,
    _bind_code_size: u32,
    _original_entry_point: u64,
    _string_table_offset: u32,
    _string_table_size: u32,
    _drmpdll_offset: u32,
    _drmpdll_size: u32,
    app_id: u32,
    flags: u32,
    _bind_section_virtual_size: u32,
    _some_hash: u32,
    code_section_virtual_address: u64,
    code_section_raw_size: u64,
    aes_key: [u8; 0x20],
    aes_iv: [u8; 0x10],
    code_section_stolen_data: [u8; 0x10],
    _encryption_keys: [u32; 4],
    _unused: [u32; 2],
    _get_module_handle_a_rva: u64,
    _get_module_handle_w_rva: u64,
    _load_library_a_rva: u64,
    _load_library_w_rva: u64,
    _get_proc_address_rva: u64,
    _padding: [u64; 3],
}

fn steam_xor(data: &[u32]) -> Vec<u8> {
    let mut ret = vec![];
    let mut key = data[0];
    for w in &data[1..] {
        ret.extend((w ^ key).to_le_bytes());
        key = *w;
    }
    ret
}

fn aes_decrypt(header: &SteamHeader, data: &mut Vec<u8>) -> Result<()> {
    let key = GenericArray::from(header.aes_key);
    println!(
        "Header AES Key: [{}]",
        key.iter().map(|v| format!("{:02x}", v)).collect::<String>()
    );
    let mut iv = GenericArray::from(header.aes_iv);
    println!(
        "Header AES IV: [{}]",
        iv.iter().map(|v| format!("{:02x}", v)).collect::<String>()
    );
    let cipher = Aes256::new(&key);
    cipher.decrypt_block(&mut iv);
    println!(
        "Decrypted Header AES IV: [{}]",
        iv.iter().map(|v| format!("{:02x}", v)).collect::<String>()
    );
    let cipher = cbc::Decryptor::<Aes256>::new(&key, &iv);
    let data_len = cipher.decrypt_padded_mut::<Pkcs7>(data).unwrap().len();
    data.truncate(data_len);
    Ok(())
}

fn get_patches(pe: &PeView) -> Result<(SteamHeader, Vec<u8>)> {
    let entry_point = pe.optional_header().AddressOfEntryPoint;
    println!("Entry Point: [0x{:x}]", entry_point);
    if pe.derva_slice::<u8>(entry_point, 1)?[0] != 0xe8 {
        anyhow::bail!("invalid entry point stub opcode");
    }

    let header_bytes = pe.derva_slice::<u32>(entry_point - 0xf0, 0xf0)?;
    println!("Header XOR Key: 0x{:x}", header_bytes[0]);
    let header: SteamHeader = Cursor::new(steam_xor(header_bytes)).read_le()?;

    if header.app_id != APP_ID {
        anyhow::bail!(
            "unexpected App ID in decrypted header (got {}, expected {})",
            header.app_id,
            APP_ID
        );
    }
    println!("AppID: {} OK", APP_ID);

    let code_section = pe.derva_slice::<u8>(
        header.code_section_virtual_address as u32,
        header.code_section_raw_size as usize,
    )?;
    let mut code_section = code_section.to_vec();

    let load_delta = (pe.optional_header().ImageBase as i32).wrapping_sub(header.image_base as i32);
    if load_delta != 0 {
        let code_rva = header.code_section_virtual_address as usize;
        let code_end = code_rva
            .checked_add(code_section.len())
            .ok_or_else(|| anyhow::anyhow!("code section range overflow"))?;

        let mut undone = 0usize;
        pe.base_relocs()?.for_each(|rva, ty| {
            use pelite::image::IMAGE_REL_BASED_HIGHLOW;
            if ty != IMAGE_REL_BASED_HIGHLOW {
                return;
            }
            let rva = rva as usize;
            if !(code_rva..code_end).contains(&rva) || rva + 4 > code_end {
                return;
            }
            let off = rva - code_rva;
            let mut raw = [0u8; 4];
            raw.copy_from_slice(&code_section[off..off + 4]);
            let val = u32::from_le_bytes(raw);
            let fixed = val.wrapping_sub(load_delta as u32);
            code_section[off..off + 4].copy_from_slice(&fixed.to_le_bytes());
            undone += 1;
        });
        println!(
            "Undid {undone} runtime relocations in encrypted text with delta {load_delta:08x}"
        );
    }

    let mut text_data: Vec<u8> = header
        .code_section_stolen_data
        .iter()
        .chain(code_section.iter())
        .copied()
        .collect();

    if header.flags & 0x4 != 0x4 {
        aes_decrypt(&header, &mut text_data)?;
    }
    if text_data.len() != code_section.len() {
        anyhow::bail!(
            "decrypted code has incorrect length (expected {}, got {})",
            code_section.len(),
            text_data.len()
        );
    }

    println!("Decrypted code size: [0x{:x}]", text_data.len());
    Ok((header, text_data))
}

unsafe fn patch_in_place(
    pe: &PeView,
    module_base: *mut u8,
    header: &SteamHeader,
    code: &[u8],
) -> Result<usize> {
    let image_size = pe.optional_header().SizeOfImage as usize;

    let code_rva = header.code_section_virtual_address as usize;
    let code_end = code_rva
        .checked_add(code.len())
        .ok_or_else(|| anyhow::anyhow!("code range overflow"))?;
    if code_end > image_size {
        anyhow::bail!("decrypted code range out of mapped image bounds")
    }
    let _handle = region::protect_with_handle(
        module_base,
        image_size,
        region::Protection::READ_WRITE_EXECUTE,
    )?;

    std::ptr::copy_nonoverlapping(code.as_ptr(), module_base.add(code_rva), code.len());

    let delta = (module_base.addr() as i32).wrapping_sub(header.image_base as i32);
    let mut text_relocs = 0usize;
    pe.base_relocs()?.for_each(|rva, ty| {
        use pelite::image::{IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHLOW};
        if ty != IMAGE_REL_BASED_HIGHLOW && ty != IMAGE_REL_BASED_ABSOLUTE {
            return;
        }
        let rva = rva as usize;
        if !(code_rva..code_end).contains(&rva) {
            return;
        }
        if ty == IMAGE_REL_BASED_ABSOLUTE || rva + 4 > image_size {
            return;
        }
        let ptr = module_base.add(rva).cast::<u32>();
        let val = ptr.read_unaligned();
        ptr.write_unaligned(val.wrapping_add(delta as u32));
        text_relocs += 1;
    });
    println!("Applied {text_relocs} text relocations with delta {delta:08x}");
    let pe_slice = std::slice::from_raw_parts_mut(module_base, image_size);
    let (_, nt, _, _) = pelite::pe32::headers_mut(pe_slice);
    nt.OptionalHeader.AddressOfEntryPoint = header._original_entry_point as u32;

    let entry = module_base.addr() + header._original_entry_point as usize;
    println!(
        "Patched in place: code_rva=0x{code_rva:x}, code_size=0x{:x}, OEP={entry:#08x}",
        code.len()
    );
    let scan = pe.scanner();
    let pat = pattern::parse("c6 05 * {' 01 00 00 00} 00 eb ? 80 3d * {' 01 00 00 00} 00")?;
    let mut result = [0u32; 3];
    if !scan.finds_code(&pat, &mut result) || result[1] != result[2] {
        panic!("Failed to locate Steam validation check");
    };
    let check = unsafe { module_base.add(result[1] as usize).cast::<u32>() };
    if unsafe { check.read() == 1 } {
        unsafe { check.write(0) };
    }
    Ok(entry)
}

#[allow(dead_code)]
pub(crate) fn is_steam_stub(pe: &PeView) -> Result<bool> {
    let entry = pe.optional_header().AddressOfEntryPoint;
    if ((entry - 0xf0) % 0x10) != 0 {
        return Ok(false);
    }
    let header_bytes = steam_xor(pe.derva_slice::<u32>(entry - 0xf0, 0xf0)?);
    if !header_bytes.starts_with(b"\xdf\xc0\xde\xc0") {
        return Ok(false);
    }
    let header: SteamHeader = Cursor::new(header_bytes).read_le()?;
    Ok(header.app_id == APP_ID)
}

pub(crate) fn patch() -> Result<Option<usize>> {
    use pelite::pe32::PeView;

    let hmod = unsafe { GetModuleHandleA(None) }?.0.cast::<u8>();
    let pe = unsafe { PeView::module(hmod) };
    let (header, code) = get_patches(&pe)?;
    println!(
        "HMOD: {:#08x}, PE: {:#08x}, Steam: {:#08x}",
        hmod.addr(),
        pe.optional_header().ImageBase,
        header.image_base
    );
    Ok(Some(unsafe { patch_in_place(&pe, hmod, &header, &code) }?))
}
