use super::*;
use anyhow::anyhow;
use encoding::{DecoderTrap, EncoderTrap, Encoding, all::WINDOWS_1252};
use rhexdump::rhexdump;
use sml_types::{CStrDisp, python::PyObject};
use std::{
    ffi::{CStr, CString, c_char, c_int},
    ptr::NonNull,
};
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

#[sml_hook(0x2edda0, C, false)]
unsafe fn py_run_simple_string(code: CStrDisp) -> usize {
    original(code)
}

pub(crate) fn python(code: &str) {
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

#[sml_hook(0x192e10, stdcall)]
fn py_loaded() {
    original();
    let quick_console = read_file("Scripts/QuickConsole.py")
        .unwrap()
        .replace('\r', "");
    make_module("QuickConsole", &quick_console, "Scripts/QuickConsole.py");
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

#[sml_hook(0x136b20, C)]
unsafe fn get_version() -> *const c_char {
    c"SML".as_ptr()
}

// ========================

#[derive(Debug)]
#[repr(C)]
struct cFilePackVtbl {
    /// +0x00  0x005307F0  returns 1 on success
    pub open:
        unsafe extern "thiscall" fn(this: *mut cFilePack, name: *const c_char, mode: u32) -> c_int,
    /// +0x04  0x0052FB30
    pub file_exists:
        unsafe extern "thiscall" fn(this: *mut cFilePack, name: *const c_char) -> c_int,
    /// +0x08  0x0052F940
    pub close: unsafe extern "thiscall" fn(this: *mut cFilePack) -> c_int,
    /// +0x0C  0x005312B0  bytes read
    pub read:
        unsafe extern "thiscall" fn(this: *mut cFilePack, dst: *mut c_void, len: usize) -> usize,
    /// +0x10  0x005313B0  bytes written
    pub write:
        unsafe extern "thiscall" fn(this: *mut cFilePack, src: *const c_void, len: usize) -> usize,
    /// +0x14  0x00531340  new absolute position, or -1
    pub seek: unsafe extern "thiscall" fn(this: *mut cFilePack, offset: i32) -> i32,
    /// +0x18  0x005302B0  current absolute position
    pub tell: unsafe extern "thiscall" fn(this: *mut cFilePack) -> i32,
    /// +0x1C  0x005313A0
    pub get_size: unsafe extern "thiscall" fn(this: *mut cFilePack) -> i32,
    /// +0x20  0x0052E6E0  scalar deleting destructor (deletes when flags & 1)
    pub destructor: unsafe extern "thiscall" fn(this: *mut cFilePack, flags: u8) -> *mut cFilePack,
}

#[derive(Debug)]
#[repr(C)]
struct cAbstractFile<'a> {
    vmt: &'a cFilePackVtbl,
    name: CStrDisp,
    mode: u32,
}

impl<'a> std::ops::Deref for cAbstractFile<'a> {
    type Target = &'a cFilePackVtbl;

    fn deref(&self) -> &Self::Target {
        &self.vmt
    }
}

impl<'a> Default for cAbstractFile<'a> {
    fn default() -> Self {
        Self {
            vmt: unsafe { rva::<cFilePackVtbl>(0x3ba924).as_ref().unwrap() },
            name: CStrDisp::null(),
            mode: 0,
        }
    }
}

#[derive(Debug, Default)]
#[repr(C)]
struct cFile<'a> {
    parent: cAbstractFile<'a>,
    file: *const (),
}

impl<'a> std::ops::Deref for cFile<'a> {
    type Target = cAbstractFile<'a>;

    fn deref(&self) -> &Self::Target {
        &self.parent
    }
}

#[derive(Debug, Default)]
#[repr(C)]
struct cFilePack<'a> {
    parent: cFile<'a>,
    start: i32,
    size: i32,
    index: i32,
}

impl<'a> std::ops::Deref for cFilePack<'a> {
    type Target = cFile<'a>;

    fn deref(&self) -> &Self::Target {
        &self.parent
    }
}

/*

Py_CompileString
PyImport_ExecCodeModuleEx
Py_DECREF

*/

fn make_module(name: &str, code: &str, file: &str) -> Option<NonNull<PyObject>> {
    unsafe {
        let py_err_print = rva_copy::<extern "C" fn()>(0x2ed310);
        let py_compile_string = rva_copy::<
            unsafe extern "C" fn(*const c_char, *const c_char, i32) -> *const PyObject,
        >(0x2ee160);
        let py_import_exec_code_module_ex = rva_copy::<
            unsafe extern "C" fn(*const c_char, *const PyObject, *const c_char) -> *const PyObject,
        >(0x2e3710);
        let c_name = CString::new(name).ok()?;
        let mut code = code.replace('\r', "").trim_end().to_owned();
        code.push('\n');
    
        let mut code = s2b(&code).ok()?;
        if let Some(pos) = code.iter().position(|&b| b == 0) {
            let line = 1 + code[..pos].iter().filter(|&&b| b == b'\n').count();
            error!("{file:?}: embedded NUL at byte {pos} (line {line})");
            return None;
        }
        code.push(0);
        let file = CString::new(file).ok()?;

        let Some(co) = py_compile_string(code.as_ptr().cast(), file.as_ptr(), 0x101)
            .cast_mut()
            .as_mut()
        else {
            error!("Failed to compile python code");
            rhexdump!(&code);
            py_err_print();
            return None;
        };
        let Some(module) = py_import_exec_code_module_ex(c_name.as_ptr(), co, file.as_ptr())
            .cast_mut()
            .as_mut()
        else {
            error!("Failed to execute python module");
            py_err_print();
            return None;
        };
        co.ob_refcnt -= 1;
        if co.ob_refcnt == 0
            && let Some(destructor) = co.ob_type.as_mut().unwrap().tp_dealloc
        {
            (destructor)(co);
        };
        Some(module.into())
    }
}

fn b2s(b: &[u8]) -> Result<String> {
    WINDOWS_1252
        .decode(b, DecoderTrap::Strict)
        .map_err(|e| anyhow!("Failed to decode: {e}"))
}
fn s2b(s: &str) -> Result<Vec<u8>> {
    WINDOWS_1252
        .encode(s, EncoderTrap::Strict)
        .map_err(|e| anyhow!("Failed to encode: {e}"))
}

fn read_file(path: &str) -> Result<String> {
    unsafe {
        let c_path = CString::new(path.to_string().replace(".pyc", ".py"))?;
        let mut fh = cFilePack::default();
        (fh.open)(&mut fh, c_path.as_ptr(), 1);
        let size = (fh.get_size)(&mut fh);
        let mut buffer = vec![0u8; usize::try_from(size)? + 1];
        let n_read = (fh.read)(&mut fh, buffer.as_mut_ptr().cast(), buffer.len() - 1);
        (fh.close)(&mut fh);
        buffer.truncate(n_read);
        b2s(&buffer).inspect_err(|e| error!("{e}"))
    }
}

#[sml_hook(0x192f90, C)]
fn preload_library(name: CStrDisp, path: CStrDisp) {
    println!("[PRELOAD] {name} {path}");
    if let Ok(code) = read_file(&path.to_string()) {
        let name = name.to_string();
        let path = path.to_string().replace(".pyc", ".py");
        let res = match crate::lua::patch_file(&name, &path, &code) {
            Ok(new_code) => make_module(&name, &new_code, &path),
            Err(err) => {
                error!("{err}");
                None
            }
        };
        if res.is_some() {
            return;
        }
        warn!("{path} failed to patch!");
    } else {
        warn!("{path} python source not found!");
    }
    return original(name, path);

    // if path.to_string().ends_with(".py") {
    //     let path = path.to_string();
    //     if let Ok(code) = read_file(&path) {
    //         let name = name.to_string();
    //         if make_module(&name, &code, &path).is_none() {
    //             py_err_print();
    //         };

    //         return;
    //     };
    // }

    // let ptr = rva::<*const c_char>(0x44ae6c).cast_const();
    // let p = if !ptr.is_null() {
    //     CStrDisp::from_ptr(ptr.read()).to_string()
    // } else {
    //     Default::default()
    // };
    // println!("Preload {p}{path}");
    // let c_path = CString::new(path.to_string().replace(".pyc", ".py")).unwrap();
    // let mut fh = cFilePack::default();
    // dbg!((fh.open)(&mut fh, c_path.as_ptr(), 1));
    // let size = (fh.get_size)(&mut fh);
    // let mut buffer = vec![0u8; usize::try_from(size).unwrap() + 1];
    // let n_read = (fh.read)(&mut fh, buffer.as_mut_ptr().cast(), buffer.len() - 1);
    // dbg!((fh.close)(&mut fh));
    // let b = &buffer[..n_read + 1];

    // rhexdump!(&b[b.len() - 0x10..]);

    // if let Ok(code) = CStr::from_bytes_until_nul(b)
    //     && let Ok(code) = code.to_str()
    // {
    //     println!(
    //         "{p}{path}: {} chars, {} lines",
    //         code.chars().count(),
    //         code.lines().count()
    //     );
    // }

    // return original(name, path);
}
