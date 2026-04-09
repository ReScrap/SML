#![allow(clippy::missing_safety_doc, unsafe_op_in_unsafe_fn)]
use anyhow::{Context, Result, bail};
use pelite::{
    pattern::{Atom, save_len},
    pe::Pe,
    pe32::PeView,
};
use retour::RawDetour;
use sml_hook_macros::hook as sml_hook;
use std::{
    backtrace,
    collections::HashMap,
    ffi::c_char,
    mem,
    str::FromStr,
    sync::{Mutex, OnceLock},
};
use windows::{
    Win32::{
        Foundation::HMODULE,
        System::{
            Console::{AllocConsole, SetConsoleTitleA},
            LibraryLoader::{
                DisableThreadLibraryCalls, GetModuleHandleW, GetProcAddress, LoadLibraryA,
            },
            ProcessStatus::{GetModuleInformation, MODULEINFO},
            SystemInformation::GetSystemDirectoryA,
            Threading::GetCurrentProcess,
        },
    },
    core::{PCSTR, s},
};
// mod patcher;
mod patcher;

static REAL_CREATE: OnceLock<usize> = OnceLock::new();
static mut HMOD: HMODULE = unsafe { std::mem::zeroed() };
static HOOK_TABLE: OnceLock<HookTable> = OnceLock::new();

pub(crate) type HookInstallFn = fn(usize) -> Result<()>;

#[linkme::distributed_slice]
pub(crate) static HOOK_INSTALLERS: [HookInstallFn];

fn setup_panic_handler() {
    std::panic::set_hook(Box::new(|info| {
        let bt = backtrace::Backtrace::capture();
        let msg = format!("{bt}\n{info}");
        win_msgbox::error::<win_msgbox::Okay>(msg.trim())
            .title("ScrapModLoader")
            .show()
            .ok();
        std::process::exit(1);
    }));
}

#[allow(dead_code)]
pub(crate) struct Pattern {
    pat: Vec<Atom>,
    name: String,
}

impl FromStr for Pattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.replace('\n', "");
        Ok(Self {
            name: s.to_owned(),
            pat: pelite::pattern::parse(&s)?,
        })
    }
}

#[allow(dead_code)]
pub(crate) fn scan(pat: &[Atom], pe: &PeView) -> Result<Vec<Vec<u32>>> {
    let mut ret = vec![];
    let scan = pe.scanner();
    let mut m = scan.matches(pat, 0..u32::MAX);
    let mut save = vec![0u32; save_len(pat)];
    while m.next(&mut save) {
        ret.push(
            save.iter()
                .map(|rva| pe.rva_to_va(*rva).map_err(|e| e.into()))
                .collect::<Result<Vec<u32>>>()?,
        );
    }
    Ok(ret)
}

#[allow(dead_code)]
pub(crate) fn scan_code(pat: &[Atom], pe: &PeView) -> Result<Vec<Vec<u32>>> {
    let mut ret = vec![];
    let scan = pe.scanner();
    let mut m = scan.matches_code(pat);
    let mut save = vec![0u32; save_len(pat)];
    while m.next(&mut save) {
        ret.push(
            save.iter()
                .map(|rva| pe.rva_to_va(*rva).map_err(|e| e.into()))
                .collect::<Result<Vec<u32>>>()?,
        );
    }
    Ok(ret)
}

impl Pattern {
    #[allow(dead_code)]
    pub(crate) fn set_name(&mut self, name: String) {
        self.name = name;
    }

    #[allow(dead_code)]
    pub(crate) fn scan(&self, pe: &PeView) -> Result<Vec<u32>> {
        let scanner = pe.scanner();
        let mut save = vec![0u32; save_len(&self.pat)];
        if !scanner.finds(&self.pat, 0..u32::MAX, &mut save) {
            let matches = scan(&self.pat, pe)?;
            if matches.is_empty() {
                bail!("Pattern {:?} not found", self.name);
            }
            bail!(
                "Pattern {:?} not unique, matches: {matches:08x?}",
                self.name
            );
        }
        let res = save
            .into_iter()
            .map(|r| pe.rva_to_va(r).map_err(|e| e.into()))
            .collect::<Result<Vec<_>>>()?;
        Ok(res)
    }

    #[allow(dead_code)]
    pub(crate) fn scan_code(&self, pe: &PeView) -> Result<Vec<u32>> {
        let scanner = pe.scanner();
        let mut save = vec![0u32; save_len(&self.pat)];
        if !scanner.finds(&self.pat, 0..u32::MAX, &mut save) {
            let matches = scan_code(&self.pat, pe)?;
            if matches.is_empty() {
                bail!("Pattern {:?} not found", self.name);
            }
            bail!(
                "Pattern {:?} not unique, matches: {matches:08x?}",
                self.name
            );
        }
        let res = save
            .into_iter()
            .map(|r| pe.rva_to_va(r).map_err(|e| e.into()))
            .collect::<Result<Vec<_>>>()?;
        Ok(res)
    }
}

#[derive(Debug)]
struct HookTable {
    base: usize,
    table: Mutex<HashMap<usize, RawDetour>>,
}

pub(crate) trait Hookable {
    const RVA: usize;
    type Func: Copy;
    const HOOK: *const ();

    fn hook(base_addr: usize) -> Result<()> {
        let table = HOOK_TABLE.get_or_init(|| HookTable {
            base: base_addr,
            table: Mutex::new(HashMap::new()),
        });
        assert_eq!(
            table.base, base_addr,
            "hook table base address changed unexpectedly"
        );

        let target = (base_addr + Self::RVA) as *const ();
        println!("[HOOK] {target:p} -> {:p}", Self::HOOK);
        let hook = unsafe { RawDetour::new(target, Self::HOOK)? };
        unsafe { hook.enable()? };
        table.table.lock().unwrap().insert(Self::RVA, hook);
        Ok(())
    }

    #[allow(dead_code)]
    fn enable() -> Result<()> {
        let table = HOOK_TABLE
            .get()
            .expect("enable called before hooks initialization");
        let hooks = table.table.lock().unwrap();
        let hook = hooks
            .get(&Self::RVA)
            .expect("hook not installed for enable");
        unsafe { hook.enable()? };
        Ok(())
    }

    #[allow(dead_code)]
    fn disable() -> Result<()> {
        let table = HOOK_TABLE
            .get()
            .expect("disable called before hooks initialization");
        let hooks = table.table.lock().unwrap();
        let hook = hooks
            .get(&Self::RVA)
            .expect("hook not installed for disable");
        unsafe { hook.disable()? };
        Ok(())
    }

    fn get() -> Self::Func {
        let table = HOOK_TABLE
            .get()
            .expect("trampoline lookup before hooks initialization");
        let hooks = table.table.lock().unwrap();
        let trampoline = hooks
            .get(&Self::RVA)
            .expect("hook trampoline not available")
            .trampoline();
        debug_assert_eq!(mem::size_of::<Self::Func>(), mem::size_of::<*const ()>());
        unsafe { mem::transmute_copy(&trampoline) }
    }
}

static DLL_BASE: OnceLock<usize> = OnceLock::new();
static CURRENT_FILE: Mutex<String> = Mutex::new(String::new());

fn rva<T>(addr: usize) -> *mut T {
    unsafe { GetModuleHandleW(None).unwrap().0.cast::<T>().byte_add(addr) }
}

mod hooks {
    use super::*;
    use std::ffi::CStr;
    pub(super) fn initialize_hooks() -> Result<()> {
        let base_addr = unsafe { GetModuleHandleW(None) }?.0.addr();
        for install in HOOK_INSTALLERS {
            install(base_addr)?;
        }
        Ok(())
    }

    #[sml_hook(0x20c130, C)]
    unsafe fn console_handler(cmd: *const c_char) {
        if let Ok(cmd) = CStr::from_ptr(cmd).to_str()
            && cmd.starts_with('$')
        {
            println!("[CMD]: {cmd}");
            return;
        }
        original(cmd)
    }

    #[sml_hook(0x2edda0, C)]
    unsafe fn py_run_simple_string(code: *const c_char) -> usize {
        original(code)
    }

    #[sml_hook(0x2ee3f0, C)]
    unsafe fn py_initialize() {
        original();
        println!("PY_INIT!");
        let cmd = b"import Scrap; Scrap.ConsoleOut(\"ScrapHacks Loaded :)\\n\")\0";
        py_run_simple_string(cmd.as_ptr().cast());
    }

    #[sml_hook(0x1307f0, thiscall)]
    unsafe fn pak_open(this: *const (), path: *const c_char, mode: i32) -> *const () {
        let ret = original(this, path, mode);
        let title = PCSTR::from_raw(path.cast());
        let _ = SetConsoleTitleA(title);
        if let Ok(path) = CStr::from_ptr(path).to_str() {
            let mut cur_file = CURRENT_FILE.lock().unwrap();
            *cur_file = path.to_string();
            println!("[PAK:{this:p}:OPEN]: {path} {mode} -> {ret:p}");
        }
        ret
    }

    #[sml_hook(0x12f940, thiscall)]
    unsafe fn pak_close(this: *const ()) -> u32 {
        let ret = original(this);
        let mut cur_file = CURRENT_FILE.lock().unwrap();
        *cur_file = "".to_owned();
        println!("[PAK:{this:p}:CLOSE]: {ret}");
        ret
    }

    #[sml_hook(0x239560, C)]
    unsafe fn init_scenegraph_console(hwnd: *const ()) {
        // Enable scenegraph console
        rva::<u32>(0x4abca8).write(1);
        original(hwnd)
    }

    #[sml_hook(0x1312b0, thiscall)]
    unsafe fn file_read(this: *const (), buffer: *mut u8, size: usize) -> usize {
        let ret = original(this, buffer, size);
        // if size > 4 {
        //     println!("[PAK:{this:p}:READ]: {size} -> {buffer:p} = {ret}");
        //     let buffer = std::slice::from_raw_parts(buffer as *const u8, ret);
        //     rhexdump::rhexdump!(&buffer[..0x80.min(size)]);
        // }
        ret
    }

    #[sml_hook(0x1313a0, thiscall)]
    unsafe fn file_get_size(this: *const ()) -> usize {
        let ret = original(this);
        // println!("[PAK:{this:p}:SIZE]: {ret}");
        ret
    }

    #[sml_hook(0x136b20, C)]
    unsafe fn get_version() -> *const c_char {
        c"SML".as_ptr()
    }
}

static ENTRY_DETOUR: Mutex<Option<RawDetour>> = Mutex::new(None);

unsafe extern "system" fn entry_point() -> usize {
    let dt = ENTRY_DETOUR.lock().unwrap().take().unwrap();
    dt.disable().unwrap();
    let dt_tramp = (dt.trampoline() as *const ()).addr();
    let original_ep = patcher::patch().unwrap().unwrap_or(dt_tramp);
    let ep: fn() -> usize = std::mem::transmute(original_ep);
    hooks::initialize_hooks().unwrap();
    println!("Entrypoint: {ep:p}");
    (ep)()
}

unsafe fn setup() -> Result<()> {
    AllocConsole().context("AllocConsole")?;
    SetConsoleTitleA(s!("SML Console")).context("SetConsoleTitle")?;
    let mut sys = [0u8; 260];
    let n = GetSystemDirectoryA(Some(&mut sys)) as usize;
    let path = format!("{}\\d3d8.dll\0", std::str::from_utf8(&sys[..n]).unwrap());
    let h_orig_mod = LoadLibraryA(PCSTR(path.as_ptr())).context("LoadLibraryA")?;
    let fp = GetProcAddress(h_orig_mod, s!("Direct3DCreate8"))
        .ok_or_else(windows::core::Error::from_thread)
        .context("GetProcAddress")?;
    REAL_CREATE.set(fp as usize).ok();
    let mut info: MODULEINFO = mem::zeroed();
    GetModuleInformation(
        GetCurrentProcess(),
        GetModuleHandleW(None).context("GetModuleHandle")?,
        &mut info,
        mem::size_of::<MODULEINFO>() as u32,
    )
    .context("GetModuleInformation")?;
    let ep = info.EntryPoint;
    println!("EP: {ep:p}");
    println!("Base: {base:p}", base = info.lpBaseOfDll);
    println!(
        "RVA: {rva:p}",
        rva = info.EntryPoint.sub(info.lpBaseOfDll as usize)
    );
    let entry = RawDetour::new(info.EntryPoint as *const (), entry_point as *const ())?;
    entry.enable()?;
    let _ = ENTRY_DETOUR.lock().unwrap().insert(entry);
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(hmod: HMODULE, reason: u32, _: *mut ()) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    unsafe {
        HMOD = hmod;
    }
    if reason == DLL_PROCESS_ATTACH {
        DisableThreadLibraryCalls(hmod).unwrap();
        setup_panic_handler();
        DLL_BASE.set(hmod.0 as usize).unwrap();
        setup().unwrap();
    }
    1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Direct3DCreate8(ver: u32) -> *const () {
    type Direct3DCreate8 = unsafe extern "system" fn(u32) -> *const ();
    let res = unsafe {
        (mem::transmute::<usize, Direct3DCreate8>(REAL_CREATE.get().copied().unwrap()))(ver)
    };
    println!("Direct3DCreate8({ver}) => {res:p}");
    res
}
