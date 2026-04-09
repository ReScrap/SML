use super::*;
use rhexdump::rhexdump;
use sml_types::CStrDisp;
use std::ffi::{CStr, CString, c_char};
use tracing::info;
use windows::{Win32::Foundation::HWND, core::imp::HANDLE};

// TODO: clean up hooks

pub(crate) fn cprint(col: u32, s: &str) {
    let col = col.swap_bytes() >> 8;
    let func = unsafe {
        std::mem::transmute::<*const (), unsafe extern "C" fn(u32, *const i8, u8)>(rva::<()>(
            0xbcaa0,
        ))
    };
    let Ok(s) = CString::new(s) else {
        error!("Can't print {s:?}");
        return;
    };
    unsafe { func(col, s.as_ptr(), 0) };
}

pub(crate) fn python(code: &str) {
    dbg!(code);
    let Ok(code) = CString::new(code) else {
        error!("{code:?} contains nul bytes");
        return;
    };
    let code = code.as_c_str().as_ptr().into();
    unsafe { py_run_simple_string(code) };
}

pub(crate) fn render(command: &str) {
    let func = unsafe {
        std::mem::transmute::<*const (), unsafe extern "C" fn(*const c_char)>(rva::<()>(0x2302f0))
    };
    let Ok(command) = CString::new(command) else {
        error!("{command:?} contains nul bytes");
        return;
    };
    let command = command.as_c_str().as_ptr();
    unsafe { (func)(command) };
}

pub(crate) fn cmd(command: &str) {
    let Ok(command) = CString::new(command) else {
        error!("{command:?} contains nul bytes");
        return;
    };
    let command = command.as_c_str().as_ptr();
    unsafe { console_handler(command) };
}

#[instrument(err)]
pub(crate) fn initialize_hooks() -> Result<()> {
    for install in HOOK_INSTALLERS {
        (install)()?;
    }
    Ok(())
}

#[sml_hook(0x20c130, C)]
#[instrument]
unsafe fn console_handler(cmd: *const c_char) {
    crate::command::cprint(0x0, c"> ".as_ptr());
    crate::command::cprint(0x0, cmd);
    crate::command::cprint(0x0, c"\n".as_ptr());
    if let Ok(cmd) = CStr::from_ptr(cmd).to_str()
        && cmd.starts_with(',')
    {
        info!(cmd_res=?command::handle_command(cmd));
        return;
    }
    original(cmd)
}

#[sml_hook(0x2edda0, C, false)]
#[instrument(ret)]
unsafe fn py_run_simple_string(code: CStrDisp) -> usize {
    original(code)
}

fn print_logo() {
    const LOGO: [[&str; 3]; 5] = [
        [" SSSSS ", "MM    MM", "LL"],
        ["SS     ", "MMM  MMM", "LL"],
        [" SSSSS ", "MM MM MM", "LL"],
        ["     SS", "MM    MM", "LL"],
        [" SSSSS ", "MM    MM", "LLLLLLL"],
    ];
    cprint(0x000000, "\n");
    for [s, m, l] in LOGO {
        cprint(0xf00000, s);
        cprint(0x00f000, m);
        cprint(0x0000f0, l);
        cprint(0x000000, "\n");
    }
    for (key, library) in crate::PLUGINS.read().iter() {
        let name = match key.as_str() {
            "" => "<SML>",
            other => other,
        };
        let msg = format!("{name} -> {library:?}\n");
        cprint(0x0, &msg);
    }
}

#[sml_hook(0x18c9f0, thiscall, false)]
#[instrument]
unsafe fn process_packet(
    this: *const (),
    param1: i32,
    in_buffer: *mut u8,
    param4: i32,
    pkt_buffer: *mut u8,
    pkt_size: *mut usize,
    usr_buffer: *mut u8,
    usr_size: *mut usize,
) -> usize {
    let ret = original(
        this, param1, in_buffer, param4, pkt_buffer, pkt_size, usr_buffer, usr_size,
    );
    let pkt = unsafe { std::slice::from_raw_parts(pkt_buffer as *const u8, pkt_size.read()) };
    let usr = unsafe { std::slice::from_raw_parts(usr_buffer as *const u8, usr_size.read()) };
    rhexdump!(pkt);
    rhexdump!(usr);
    ret
}

// #[sml_hook(0x12e2b0, thiscall)]
// unsafe fn write(this: *const (), src: *mut u8, size: usize) -> usize {
//      original(this,src,size)
// }

#[sml_hook(0x12e1f0, thiscall, false)]
#[instrument]
unsafe fn read(this: *const (), dest: *mut u8, size: usize) -> usize {
    original(this, dest, size)
}

#[sml_hook(0x2ee3f0, C)]
#[instrument]
unsafe fn py_initialize() {
    original();
    info!("Py_Initialize called!");
    let boot = include_str!("boot.py");
    let cstr = CString::new(boot).unwrap();
    let cmd = CStrDisp::from(cstr.as_ptr());
    info!(cmd=%cmd);
    py_run_simple_string(cmd);
    print_logo();
    for (name, plugin) in PLUGINS.read().iter() {
        let ret = plugin.get::<unsafe extern "C" fn(*const ScrapModLoaderFFI)>("py_init");
        info!("PyInit for {name}: {ret:?}");
        if let Ok(py_init) = ret {
            let sml = get_sml();
            (py_init)(&sml)
        }
    }
}

#[sml_hook(0x130a00, C, false)]
#[instrument(ret)]
unsafe fn load_packed(file: CStrDisp, path: CStrDisp, buf_size: usize) -> bool {
    original(file, path, buf_size)
}

#[sml_hook(0x1307f0, thiscall, false)]
#[instrument(ret)]
unsafe fn pak_open(this: *const (), path: CStrDisp, mode: i32) -> usize {
    let ret = original(this, path, mode);
    let mut cur_file = CURRENT_FILE.lock();
    *cur_file = path.to_string();
    return ret;
}

#[sml_hook(0x12f940, thiscall, false)]
#[instrument(ret)]
unsafe fn pak_close(this: *const ()) -> u32 {
    let ret = original(this);
    let mut cur_file = CURRENT_FILE.lock();
    *cur_file = "".to_owned();
    ret
}

#[sml_hook(0x20f0a0, C)]
unsafe fn parse_command_line(_p1: c_char, hwnd: HWND, _p2: c_char) {
    original(0, hwnd, 0);
    // Debug
    write_rva::<u32>(0x445d74, 10).unwrap();
    // EngineDebug
    write_rva::<u32>(0x4abcc4, 10).unwrap();
    // Alwaysflushlog
    write_rva::<u32>(0x446190, 1).unwrap();
    // Enable scenegraph console
    write_rva::<u32>(0x4abca8, 1).unwrap();
    // r_materiallog
    write_rva::<u32>(0x4adfa0, 1).unwrap();
    // py run parameter
    write_rva::<u32>(0x2ede08, 0x101).unwrap();
}

#[sml_hook(0x1312b0, thiscall, false)]
#[instrument]
unsafe fn file_read(this: *const (), buffer: *mut u8, size: usize) -> usize {
    let ret = original(this, buffer, size);
    let path = CURRENT_FILE.lock();
    if path.ends_with("py") || path.ends_with("pyc") {
        info!(r#return = ret);
    }
    // let buffer = std::slice::from_raw_parts(buffer as *const u8, ret);
    // rhexdump::rhexdump!(&buffer[..0x80.min(size)]);
    ret
}

#[sml_hook(0x12fb30, thiscall, false)]
#[instrument(ret)]
unsafe fn file_exists(this: *const (), path: CStrDisp) -> usize {
    original(this, path)
}

#[sml_hook(0x1313a0, thiscall, false)]
unsafe fn file_get_size(this: *const ()) -> usize {
    original(this)
}

#[sml_hook(0x2099a0, system, false)]
#[instrument(ret)]
unsafe fn create_entity(name: CStrDisp, x: f32, y: f32, z: f32, ty: CStrDisp) -> Entity {
    original(name, x, y, z, ty)
}

#[sml_hook(0x1917c0, C, false)]
#[instrument(ret)]
unsafe fn ent_getattr(ent: PyEntity, attr: CStrDisp) -> *const () {
    original(ent, attr)
}

#[sml_hook(0x136b20, C)]
unsafe fn get_version() -> *const c_char {
    c"SML".as_ptr()
}
