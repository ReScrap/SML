use std::ffi::{CString, c_char};

use sml_types::ScrapModLoaderFFI;
use tracing::{debug, trace};
use windows::Win32::System::ProcessStatus::GetModuleBaseNameA;

pub(crate) unsafe extern "C" fn cprint(c: u32, s: *const c_char) {
    let s = CStr::from_ptr(s);
    hooks::cprint(c, &s.to_string_lossy());
}

pub(crate) unsafe extern "C" fn log(level: *const c_char, message: *const c_char) {
    use tracing::Level;
    let level = CStr::from_ptr(level)
        .to_string_lossy()
        .to_string()
        .to_lowercase();
    let level = match tracing::Level::from_str(&level) {
        Ok(lvl) => lvl,
        Err(err) => {
            warn!("Invalid log level: {err}, defaulting to INFO");
            tracing::Level::INFO
        }
    };

    let mut module = "<unknown>".to_owned();
    let message = CStr::from_ptr(message).to_string_lossy().to_string();
    bt_rs::trace(|frame| {
        if let Some(addr) = frame.module_base_address() {
            let mut handle: HMODULE = std::mem::zeroed();
            let mut name = [0u8; 1024];
            if GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                PCWSTR(addr as _),
                &mut handle,
            )
            .is_ok()
            {
                GetModuleBaseNameA(GetCurrentProcess(), handle, &mut name);
                let name = CStr::from_bytes_until_nul(&name)
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if name.ends_with(".slm") {
                    module = name;
                    return false;
                }
            };
            module = format!("<unknown @ {addr:p}>");
            return false;
        };
        true
    });
    match level {
        Level::ERROR => {
            error!(module = module, "[{message}]");
        }
        Level::WARN => {
            warn!(module = module, "[{message}]");
        }
        Level::INFO => {
            info!(module = module, "[{message}]");
        }
        Level::DEBUG => {
            debug!(module = module, "[{message}]");
        }
        Level::TRACE => {
            trace!(module = module, "[{message}]");
        }
    }
}

use super::*;

#[instrument(err)]
pub(crate) fn handle_command(cmd: &str) -> Result<()> {
    let (_, cmd) = cmd.split_at(1);
    let (module_name, command) = cmd.split_once('.').unwrap_or(("", cmd));
    let (command, args) = command
        .split_once(|c: char| c.is_ascii_whitespace())
        .unwrap_or((command, ""));
    let plugins = PLUGINS.read();
    info!(plugins=?plugins);
    if let Some(module) = plugins.get(module_name) {
        let command = format!("cmd_{command}");
        let func = unsafe {
            module.get::<unsafe extern "C" fn(*const ScrapModLoaderFFI, *const c_char) -> bool>(
                &command,
            )?
        };
        let c_args = CString::new(args)?;
        let sml = get_sml();
        unsafe { func(&sml, c_args.as_ptr()) };
        info!(
            cmd = cmd,
            module = module_name,
            command = command,
            args = args
        );
    } else {
        unsafe { cprint(0x000000, c"Command not found!\n".as_ptr()) };
    }
    Ok(())
}

// exported commands

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn cmd_plugins(_sml: *const ScrapModLoaderFFI, _cmd: *mut c_char) -> bool {
    true
}

#[repr(C)]
#[derive(Debug)]
struct ServerEntry {
    magic: u16,
    version: u16,
    port: u16,
    max_players: u16,
    num_players: u16,
    flags: u8,
    name: [u8; 32],
    mode: [u8; 16],
    map: [u8; 32],
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn cmd_nethack(_sml: *const ScrapModLoaderFFI, _cmd: *mut c_char) -> bool {
    type OnNetBrowseCallback =
        unsafe extern "C" fn(addr: *const u8, port: u32, entry: *const ServerEntry, ping: u32);
    let func: OnNetBrowseCallback = std::mem::transmute(rva::<()>(0x18e460));
    const NAME: [u8; 32] = *b"Test Server :)\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    const MODE: [u8; 16] = *b"et\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    const MAP: [u8; 32] = *b"TEST\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for n in 0..1024 {
        const ADDR: &[u8] = b"STEAM:1234\0";
        let test = ServerEntry {
            magic: 0xceba,
            version: 0x101,
            port: 31337,
            max_players: 0xffff,
            num_players: 0xffff,
            flags: 0xff,
            name: NAME,
            mode: MODE,
            map: MAP,
        };
        func(ADDR.as_ptr(), test.port as u32, &test, n);
    }

    true
}
