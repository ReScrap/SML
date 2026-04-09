#![allow(clippy::missing_safety_doc, unsafe_op_in_unsafe_fn)]
use anyhow::{Context, Result, bail};
use parking_lot::{Mutex, RwLock};
use pelite::{
    pattern::{Atom, save_len},
    pe::Pe,
    pe32::PeView,
};
use region::Protection;
use retour::RawDetour;
use sml_hook_macros::hook as sml_hook;
use sml_types::ScrapModLoaderFFI;
use std::{
    arch::naked_asm,
    backtrace,
    collections::HashMap,
    env::current_dir,
    ffi::{CStr, CString, OsStr, c_char},
    fmt, mem,
    os::raw::c_void,
    str::FromStr,
    sync::{LazyLock, OnceLock},
    time::Duration,
};
use tracing::instrument;
use tracing::{error, info, warn};
use windows::{
    Win32::{
        Foundation::{
            DBG_PRINTEXCEPTION_C, DBG_PRINTEXCEPTION_WIDE_C, EXCEPTION_ACCESS_VIOLATION,
            FreeLibrary, HANDLE, HMODULE,
        },
        System::{
            Console::{AllocConsole, SetConsoleTitleA},
            Diagnostics::Debug::{
                AddVectoredExceptionHandler, EXCEPTION_CONTINUE_EXECUTION,
                EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, IsDebuggerPresent,
                RemoveVectoredExceptionHandler,
            },
            LibraryLoader::{
                DisableThreadLibraryCalls, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, GetModuleHandleExW, GetModuleHandleW,
                GetProcAddress, LoadLibraryA,
            },
            ProcessStatus::{GetModuleBaseNameA, GetModuleInformation, MODULEINFO},
            SystemInformation::GetSystemDirectoryA,
            Threading::{GetCurrentProcess, GetProcessId, PEB},
        },
    },
    core::{PCSTR, PCWSTR, s, w},
};

use crate::lua::S_LUA;

mod command;
mod gui;
mod hooks;
mod lua;

// TODO: MLua
// TODO: Steamworks callbacks

#[derive(Debug)]
struct ScrapModLoader {}

static INSTANCE: OnceLock<ScrapModLoader> = OnceLock::new();

#[repr(transparent)]
#[derive(Copy, Clone)]
struct Entity(*const ());

impl std::fmt::Debug for Entity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let ent_bytes = self.0 as *const u8;
            let mut name = "(null)".to_owned();
            let key_ptr = *(ent_bytes.add(4) as *const *const std::os::raw::c_char);
            if !key_ptr.is_null() && *key_ptr != 0 {
                name = CStr::from_ptr(key_ptr).to_string_lossy().into_owned()
            }
            f.debug_tuple("Entity").field(&name).field(&self.0).finish()
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct PyEntity(*const ());

impl std::fmt::Debug for PyEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe {
            let ent_bytes = self.0 as *const u8;
            let mut name = "(null)".to_owned();
            let name_struct_ptr = *(ent_bytes.add(8) as *const *const u8);
            if !name_struct_ptr.is_null() {
                let key_ptr = name_struct_ptr.add(0x10) as *const std::os::raw::c_char;
                if *key_ptr != 0 {
                    name = CStr::from_ptr(key_ptr).to_string_lossy().into_owned()
                }
            }
            f.debug_tuple("PyEntity")
                .field(&name)
                .field(&self.0)
                .finish()
        }
    }
}

static REAL_CREATE: OnceLock<usize> = OnceLock::new();
static mut HMOD: HMODULE = unsafe { std::mem::zeroed() };
static HOOK_TABLE: OnceLock<Mutex<HashMap<usize, RawDetour>>> = OnceLock::new();

type HookInstaller = fn() -> Result<()>;

#[linkme::distributed_slice]
pub(crate) static HOOK_INSTALLERS: [HookInstaller];

fn setup_panic_handler_and_logging() {
    std::panic::set_hook(Box::new(|info| {
        let bt = backtrace::Backtrace::capture();
        let msg = format!("{bt}\n{info}");
        win_msgbox::error::<win_msgbox::Okay>(msg.trim())
            .title("ScrapModLoader")
            .show()
            .ok();
        std::process::exit(1);
    }));
    tracing_subscriber::fmt().try_init().unwrap();
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

pub(crate) trait Hookable {
    const RVA: usize;
    type Func: Copy;
    const HOOK: *const ();
    const NAME: &'static str;

    fn ptr() -> *const () {
        rva::<()>(Self::RVA)
    }

    fn hook() -> Result<()> {
        let table = HOOK_TABLE.get_or_init(|| Mutex::new(HashMap::new()));
        let target = Self::ptr();
        let msg = format!(
            "[{}] {:p} (RVA: {:#x}) -> {:p}",
            Self::NAME,
            target,
            Self::RVA,
            Self::HOOK
        );
        info!(target: "hook", "{msg}");
        let hook =
            unsafe { RawDetour::new(target, Self::HOOK) }.context(format!("Hooking {msg}"))?;
        table.lock().insert(target.addr(), hook);
        Ok(())
    }

    #[allow(dead_code)]
    fn enable() -> Result<()> {
        let table = HOOK_TABLE
            .get()
            .expect("enable called before hooks initialization");
        let hooks = table.lock();
        let hook = hooks
            .get(&Self::ptr().addr())
            .expect("hook not installed for enable");
        unsafe { hook.enable()? };
        Ok(())
    }

    #[allow(dead_code)]
    fn disable() -> Result<()> {
        let table = HOOK_TABLE
            .get()
            .expect("disable called before hooks initialization");
        let hooks = table.lock();
        let hook = hooks
            .get(&Self::ptr().addr())
            .expect("hook not installed for disable");
        unsafe { hook.disable()? };
        Ok(())
    }

    fn get() -> Self::Func {
        let table = HOOK_TABLE
            .get()
            .expect("trampoline lookup before hooks initialization");
        let hooks = table.lock();
        let trampoline = hooks
            .get(&Self::ptr().addr())
            .expect("hook trampoline not available")
            .trampoline();
        debug_assert_eq!(mem::size_of::<Self::Func>(), mem::size_of::<*const ()>());
        unsafe { mem::transmute_copy(&trampoline) }
    }
}

static DLL_BASE: OnceLock<usize> = OnceLock::new();
static CURRENT_FILE: Mutex<String> = Mutex::new(String::new());

fn rva<T>(addr: usize) -> *mut T {
    unsafe {
        let hmod: HMODULE = GetModuleHandleW(None).expect("GetModuleHandleW in rva");
        let ptr = hmod.0 as *mut T;
        return ptr.byte_add(addr);
    }
}

pub(crate) fn write_rva<T>(addr: usize, val: T) -> Result<()> {
    let p = rva::<T>(addr);
    unsafe {
        let _handle = region::protect_with_handle(
            p.cast::<()>(),
            std::mem::size_of::<T>(),
            Protection::READ_WRITE_EXECUTE,
        )?;
        p.write(val);
        drop(_handle);
    }
    Ok(())
}

static ENTRY_DETOUR: Mutex<Option<RawDetour>> = Mutex::new(None);
static PLUGINS: LazyLock<RwLock<HashMap<String, libloading::Library>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

fn handle_to_self() -> Result<HMODULE> {
    unsafe {
        let mut handle: HMODULE = std::mem::zeroed();
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            PCWSTR(handle_to_self as _),
            &mut handle,
        )?;
        Ok(handle)
    }
}

unsafe extern "system" fn handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    // VEH hanlder to catch access violation when steamstub tried to execute entrypoint of decrypted .text section
    let info = info.as_mut_unchecked();
    let rec = info.ExceptionRecord.as_ref_unchecked();
    if [DBG_PRINTEXCEPTION_C, DBG_PRINTEXCEPTION_WIDE_C].contains(&rec.ExceptionCode) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    info!("[EXCEPTION] {code:08x}", code = rec.ExceptionCode.0);
    if rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION
        && rec.ExceptionInformation[0] == 8
        && !OEP_FIRED
    {
        OEP_FIRED = true;
        let oep = rec.ExceptionInformation[1] as *const ();
        info!("[EXCEPTION] VEH fired OEP @ {oep:p}!");
        let hmodule = GetModuleHandleW(None).unwrap();
        let base = hmodule.0 as *const u8;
        let pe = PeView::module(base);
        let hdr = pe.section_headers();
        let text = hdr.by_name(b".text").unwrap();
        let text_base = base.byte_add(text.VirtualAddress as usize);
        unsafe {
            region::protect(
                text_base,
                text.VirtualSize as usize,
                Protection::READ_EXECUTE,
            )
        }
        .unwrap();
        let mut hook = ENTRY_DETOUR.lock();
        if let Some(oeh) = hook.take() {
            info!("Found existing entry point hook, unhooking!");
            oeh.disable().unwrap();
        }
        let _ = hook.insert({
            let ep_hook = RawDetour::new(oep, entry_point as *const ()).unwrap();
            ep_hook.enable().unwrap();
            info!(
                "Enty point hook set: {:p} -> {:p}",
                oep, entry_point as *const ()
            );
            ep_hook
        });
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if rec.ExceptionCode.0 > 0 {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    info!(
        "[EXCEPTION] code={code:08x} addr={addr:p}",
        code = rec.ExceptionCode.0,
        addr = rec.ExceptionAddress as *const (),
    );

    let mut frames: Vec<String> = Vec::new();

    bt_rs::trace(|f| {
        let ip = f.ip();
        let sym = f.symbol_address();

        // Resolve the module this frame belongs to.
        let (module, base) = match f.module_base_address() {
            Some(m) => {
                let base = m.addr();
                let mut name = [0u8; 1024];
                let n = unsafe {
                    GetModuleBaseNameA(GetCurrentProcess(), HMODULE(base as isize), &mut name)
                } as usize;
                let name = if n == 0 || n > name.len() {
                    "<unknown>".to_owned()
                } else {
                    String::from_utf8_lossy(&name[..n]).into_owned()
                };
                (name, base)
            }
            None => ("<unknown>".to_owned(), 0),
        };

        // Drop the exception-dispatch machinery — it's just noise.
        let lower = module.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "ntdll.dll" | "kernelbase.dll" | "kernel32.dll"
        ) {
            return true;
        }

        // Resolve name + offset within the symbol.
        let mut symbol = format!("{sym:p}");
        if !sym.is_null() {
            bt_rs::resolve(sym, |s| {
                let addr = s.addr().unwrap_or(std::ptr::null_mut());
                let name = s
                    .name()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| format!("{sym:p}"));
                let offset = ip.offset_from(addr);
                symbol = if offset == 0 {
                    name
                } else {
                    format!("{name}{offset:+#x}")
                };
            });
        }

        let line = if base != 0 {
            let offset = ip.offset_from(base as *const _);
            format!("  {ip:p}  {module}+{offset:+#x}  {symbol}")
        } else {
            format!("  {ip:p}  {symbol}")
        };
        frames.push(line);

        // Cap the trace so a runaway recursion doesn't flood the console.
        frames.len() < 64
    });

    if frames.is_empty() {
        info!("[EXCEPTION] backtrace: <no user frames>");
    } else {
        info!(
            "[EXCEPTION] backtrace ({} frames):\n{}",
            frames.len(),
            frames.join("\n")
        );
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static mut OEP_FIRED: bool = false;

#[instrument(err)]
unsafe fn veh_setup(base: *const ()) -> Result<()> {
    // Register VEH and remove execute permission from .text section
    let pe = PeView::module(base as *const _);
    let hdr = pe.section_headers();
    let text = hdr.by_name(b".text").unwrap();
    AddVectoredExceptionHandler(1, Some(handler));
    let text_base = base.byte_add(text.VirtualAddress as usize);
    unsafe { region::protect(text_base, text.VirtualSize as usize, Protection::READ) }.unwrap();
    Ok(())
}

unsafe extern "system" fn entry_point(_peb: *const PEB) -> usize {
    info!("Entry point hook hit!");
    let ep = ENTRY_DETOUR.lock().take().unwrap();
    ep.disable().unwrap();
    let ep: fn() -> usize = std::mem::transmute(ep.trampoline());
    let mut plugin_map = LazyLock::force(&PLUGINS).write();
    match current_dir().unwrap().join("plugins").read_dir() {
        Ok(plugins) => {
            for plugin in plugins {
                let plugin = match plugin {
                    Ok(plugin) => plugin,
                    Err(err) => {
                        error!("Error loading plugin: {err}");
                        continue;
                    }
                };
                let plugin = plugin.path();
                if plugin.as_path().extension().and_then(OsStr::to_str) != Some("slm") {
                    continue;
                }
                info!("Found plugin: {plugin}", plugin = plugin.display());
                let plugin_key = plugin
                    .file_stem()
                    .unwrap_or_default()
                    .to_str()
                    .unwrap_or_default()
                    .to_owned();
                match libloading::Library::new(&plugin) {
                    Ok(lib) => {
                        if let Ok(init) =
                            lib.get::<unsafe extern "C" fn(*const ScrapModLoaderFFI)>("init")
                        {
                            unsafe { (init)(&get_sml()) };
                        };
                        plugin_map.insert(plugin_key, lib)
                    }
                    Err(err) => {
                        let err = anyhow::anyhow!(err);
                        error!("Error loading {plugin_key}: {err:#}");
                        continue;
                    }
                };
            }
        }
        Err(err) => {
            error!("Error loading plugin directory: {err}");
        }
    }
    let lib_self = libloading::os::windows::Library::from_raw(handle_to_self().unwrap().0).into();
    plugin_map.insert("".to_owned(), lib_self);
    // unlock before calling entry point!
    drop(plugin_map);
    info!("Setting up Hooks...");
    hooks::initialize_hooks().unwrap();
    pre_oep();
    info!("Setup done, calling entrypoint @ {ep:p}");
    (ep)()
}

fn pre_oep() {
    let lua = S_LUA.read();
    lua.run_file("init.lua").unwrap();
    gui::spawn();
}

extern "C" fn on_overlay_activated(param: *mut c_void) {
    use steamworks::*;
    if param.is_null() {
        return;
    }
    let event = unsafe { &*(param as *const GameOverlayActivated_t) };
    println!("Overlay active: {}", event.m_bActive != 0);
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn cmd_steam(_sml: *const ScrapModLoaderFFI, _cmd: *mut c_char) -> bool {
    let res: Result<()> = (|| unsafe {
        use steamworks::*;
        let lib = libloading::os::windows::Library::open_already_loaded("steam_api.dll")?;
        let api = SteamApi::from_library(lib)?;
        let client = api.SteamInternal_CreateInterface(c"SteamClient017".as_ptr().cast()) as isize;
        let user = api.SteamAPI_GetHSteamUser();
        let pipe = api.SteamAPI_GetHSteamPipe();
        let mm = api.SteamAPI_ISteamClient_GetISteamMatchmaking(
            client,
            user,
            pipe,
            c"SteamMatchMaking009".as_ptr(),
        );
        let utils =
            api.SteamAPI_ISteamClient_GetISteamUtils(client, pipe, c"SteamUtils009".as_ptr());
        let net = api.SteamAPI_ISteamClient_GetISteamNetworking(
            client,
            user,
            pipe,
            c"SteamNetworking005".as_ptr(),
        );
        let net_new = api.SteamAPI_ISteamClient_GetISteamNetworking(
            client,
            user,
            pipe,
            c"SteamNetworkingMessages002".as_ptr(),
        );
        dbg!(client, user, pipe, mm, utils, net, net_new);
        // let callback = rust_callback_create(
        //     size_of::<GameOverlayActivated_t>() as i32,
        //     false,
        //     Some(on_overlay_activated),
        // );
        // if callback.is_null() {
        //     error!("Failed to allocate callback")
        // }
        // api.SteamAPI_RegisterCallback(callback, GameOverlayActivated_t_k_iCallback.0);

        Ok(())
    })();
    return res.is_ok();
}

#[unsafe(no_mangle)]
unsafe extern "C" fn init() {
    /* No init procedure for the modloader as we have the entry point hook */
}

fn get_sml() -> ScrapModLoaderFFI {
    ScrapModLoaderFFI {
        base: rva(0),
        cprint: command::cprint,
        log: command::log,
    }
}

unsafe extern "C" {
    fn __acrt_iob_func(index: u32) -> *mut core::ffi::c_void;
    fn _wfreopen_s(
        p_file: *mut *mut core::ffi::c_void,
        file_name: *const u16,
        mode: *const u16,
        old_stream: *mut core::ffi::c_void,
    ) -> i32;
}

#[instrument(err)]
unsafe fn setup(enabled: bool) -> Result<()> {
    let mut sys = [0u8; 260];
    let n = GetSystemDirectoryA(Some(&mut sys)) as usize;
    let path = format!("{}\\d3d8.dll\0", std::str::from_utf8(&sys[..n]).unwrap());
    let h_orig_mod = LoadLibraryA(PCSTR(path.as_ptr())).context("LoadLibraryA")?;
    let fp = GetProcAddress(h_orig_mod, s!("Direct3DCreate8")).context("GetProcAddress")?;
    REAL_CREATE.set(fp as usize).ok();
    if !enabled {
        return Ok(());
    }
    AllocConsole().context("AllocConsole")?;
    let mut dummy: *mut core::ffi::c_void = std::ptr::null_mut();
    _wfreopen_s(&mut dummy, w!("CONOUT$").0, w!("w").0, __acrt_iob_func(1));
    _wfreopen_s(&mut dummy, w!("CONOUT$").0, w!("w").0, __acrt_iob_func(2));

    SetConsoleTitleA(s!("SML Console")).context("SetConsoleTitle")?;
    let mut info: MODULEINFO = mem::zeroed();
    GetModuleInformation(
        GetCurrentProcess(),
        GetModuleHandleW(None).context("GetModuleHandle")?,
        &mut info,
        mem::size_of::<MODULEINFO>() as u32,
    )
    .context("GetModuleInformation")?;
    let mut hook = ENTRY_DETOUR.lock();
    let hdr_ptr = info.EntryPoint as *const u32;
    let magic = hdr_ptr.offset(-0x3c).read_unaligned() ^ hdr_ptr.offset(-0x3b).read_unaligned();
    if magic == 0xc0dec0df {
        info!("Steamstub detected, setting up VEH hook");
        return veh_setup(info.lpBaseOfDll as *const ());
    };
    let _ = hook.insert({
        let ep_hook =
            RawDetour::new(info.EntryPoint as *const (), entry_point as *const ()).unwrap();
        ep_hook.enable().unwrap();
        ep_hook
    });
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(hmod: HMODULE, reason: u32, _: *mut ()) -> i32 {
    const DLL_PROCESS_ATTACH: u32 = 1;
    unsafe {
        HMOD = hmod;
    }
    if reason == DLL_PROCESS_ATTACH {
        let this_exe = std::env::current_exe()
            .unwrap_or_default()
            .file_name()
            .unwrap_or_default()
            .display()
            .to_string();
        if this_exe.contains("Dedicated.exe") {
            return 1;
        }
        DisableThreadLibraryCalls(hmod).unwrap();
        setup_panic_handler_and_logging();
        DLL_BASE.set(hmod.0 as usize).unwrap();
        setup(!std::env::args().any(|a| a == "-sml:disable")).unwrap();
    }
    1
}

#[unsafe(no_mangle)]
#[instrument(ret)]
pub unsafe extern "system" fn Direct3DCreate8(ver: u32) -> *const () {
    unsafe {
        (mem::transmute::<usize, unsafe extern "system" fn(u32) -> *const ()>(
            REAL_CREATE.get().copied().unwrap(),
        ))(ver)
    }
}
