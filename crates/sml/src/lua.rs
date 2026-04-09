use crate::{hooks, rva};
use anyhow::{Result, anyhow};
use mlua::prelude::*;
use parking_lot::RwLock;
use pelite::{
    pattern::{Atom, save_len},
    pe::Pe,
    pe32::PeView,
};
use retour::RawDetour;
use sml_types::{CStrDisp, ScrapModLoaderFFI};
use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char},
    sync::{Arc, LazyLock, Weak},
    time::{Duration, Instant},
};
use tracing::*;

const SAFE_MODULES: &[&str] = &[
    "string",
    "table",
    "math",
    "bit",
    "os.time",
    "os.date",
    "os.difftime",
    "os.clock",
    "_VERSION",
    "pairs",
    "ipairs",
    "error",
    "tostring",
];

#[derive(Debug)]
struct Detour {
    original_addr: usize,
    target_addr: usize,
    detour: RawDetour,
    signature: String,
    table: LuaTable,
}

// TODO: pelite based memory scanner

impl Detour {
    fn get_handle(&self) -> DetourHandle {
        DetourHandle {
            original_addr: self.original_addr,
            target_addr: self.target_addr,
            signature: self.signature.clone(),
        }
    }
}

#[derive(Default, Debug)]
struct LuaHooks(HashMap<usize, Vec<Detour>>);

impl std::ops::DerefMut for LuaHooks {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Deref for LuaHooks {
    type Target = HashMap<usize, Vec<Detour>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
struct DetourHandle {
    original_addr: usize,
    target_addr: usize,
    signature: String,
}

impl LuaUserData for DetourHandle {
    fn add_methods<M: LuaUserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(
            LuaMetaMethod::ToString,
            |_: &Lua, this: &Self, (): ()| -> LuaResult<String> {
                Ok(format!(
                    "Hook[{:08x} -> {:08x}|{}]",
                    this.original_addr, this.target_addr, this.signature
                ))
            },
        );
        methods.add_function(
            "get",
            |l: &Lua, (addr, target): (usize, usize)| -> LuaResult<Option<Self>> {
                let mut hooks = l
                    .app_data_mut::<LuaHooks>()
                    .ok_or_else(|| LuaError::runtime("LuaHooks not initialized!"))?;
                let chain = hooks
                    .get_mut(&addr)
                    .ok_or_else(|| LuaError::runtime("Hook not found!!"))?;
                let res = chain
                    .iter()
                    .find(|d| d.target_addr == target)
                    .map(|d| d.get_handle());
                Ok(res)
            },
        );

        methods.add_method_once("unhook", |l: &Lua, this: Self, _: ()| -> LuaResult<bool> {
            let mut hooks = l
                .app_data_mut::<LuaHooks>()
                .ok_or_else(|| LuaError::runtime("LuaHooks not initialized!"))?;

            let (removed, became_empty) = {
                let chain = hooks
                    .get_mut(&this.original_addr)
                    .ok_or_else(|| LuaError::runtime("Hook not found!"))?;

                for h in chain.iter_mut().rev() {
                    let _ = unsafe { h.detour.disable() };
                }

                let removed: Vec<Detour> = chain
                    .extract_if(.., |d| d.target_addr == this.target_addr)
                    .collect();
                for hit in &removed {
                    if let Ok(cb) = hit.table.get::<LuaAnyUserData>("detour")
                        && let Err(e) = cb.call_method::<()>("free", ())
                    {
                        tracing::error!("unhook: failed to free FFI callback: {e}");
                    }
                    let _ = hit.table.set("detour", LuaValue::Nil);
                    let _ = hit.table.set("original", LuaValue::Nil);
                    let _ = hit.table.set("callback", LuaValue::Nil);
                }

                for h in chain.iter_mut() {
                    let _ = unsafe { h.detour.enable() };
                }

                (removed, chain.is_empty())
            };
            if became_empty {
                hooks.remove(&this.original_addr);
            }
            drop(removed);

            Ok(true)
        });
    }
}

struct EnvStore(mlua::Table);

pub(crate) struct LuaState {
    lua: mlua::Lua,
    env: mlua::Table,
}

impl LuaState {
    fn new() -> Result<Self> {
        let lua = unsafe { Lua::unsafe_new_with(LuaStdLib::ALL, LuaOptions::new()) };
        lua.load("jit.off()").exec()?;
        lua.set_app_data(LuaHooks::default());
        lua.set_memory_limit(1024 * 1024 * 32)?;
        let env = lua.create_table()?;
        let hook_env = env.clone();
        let g = lua.globals();
        let ffi_str = g.get_path::<LuaFunction>("ffi.string")?;
        env.set("cstr", ffi_str)?;
        for &m in SAFE_MODULES {
            env.set(m, g.get_path::<LuaValue>(m)?)?;
        }
        env.set("_G", env.clone())?;
        env.set("print", lua.create_function(Self::lua_print)?)?;
        env.set(
            "hook",
            lua.create_function(move |lua, args: (usize, String, LuaFunction)| {
                Self::lua_hook_raw(lua, &hook_env, args)
            })?,
        )?;
        env.set(
            "rva",
            lua.create_function(|_, v: usize| Ok(rva::<()>(v).addr()))?,
        )?;
        env.set("scan", lua.create_function(Self::lua_scan)?)?;
        lua.set_app_data(EnvStore(env.clone())); // <-- store sandbox env
        Ok(LuaState { lua, env })
    }

    fn lua_scan(lua: &Lua, pat: String) -> LuaResult<Vec<Vec<u32>>> {
        // TODO: test
        let pat = pelite::pattern::parse(&pat).map_err(|e| anyhow!(e))?;
        let pe = unsafe { PeView::module(rva::<u8>(0).cast_const()) };
        let mut ret = vec![];
        let scan = pe.scanner();
        let mut m = scan.matches_code(&pat);
        let mut save = vec![0u32; save_len(&pat)];
        while m.next(&mut save) {
            ret.push(save.to_vec());
        }
        Ok(ret)
    }

    fn lua_hook_raw(
        lua: &Lua,
        env: &LuaTable,
        (addr, signature, hook): (usize, String, LuaFunction),
    ) -> LuaResult<DetourHandle> {
        // The user callback runs with cstr, scan, rva, etc.
        if !hook.set_environment(env.clone())? {
            return Err(LuaError::runtime("hook callback must be a Lua function"));
        }

        // The FFI setup runs with lua.globals().
        let state = lua
            .load(
                r#"
                local uintptr = ffi.typeof("uintptr_t")
                local signature, callback = ...
                local self = { signature = signature, callback = callback }

                self.detour = ffi.cast(signature, function(...)
                    local ok, ret = pcall(self.callback, self.original, ...)
                    if not ok then
                        error("hook error: " .. tostring(ret))
                    end
                    return ret
                end)

                self.addr = tonumber(ffi.cast(uintptr, self.detour))
                self.set_original = function(p)
                    self.original = ffi.cast(signature, p)
                end

                return self
                "#,
            )
            .set_environment(lua.globals())
            .call::<LuaTable>((signature.clone(), hook))?;

        let detour_addr: usize = state.get("addr")?;

        let raw = unsafe { RawDetour::new(addr as _, detour_addr as _) }
            .map_err(|e| LuaError::runtime(format!("RawDetour::new: {e}")))?;

        let tramp = (raw.trampoline() as *const ()).addr();
        info!(target=?addr as *const (), detour=?detour_addr as *const (), tramp=?tramp as *const (), "hook");
        state
            .get::<LuaFunction>("set_original")?
            .call::<()>(tramp)?;
        state.set("set_original", LuaValue::Nil)?;

        dbg!(&state);

        unsafe { raw.enable() }
            .map_err(|e| LuaError::runtime(format!("RawDetour::enable: {e}")))?;

        let detour = Detour {
            original_addr: addr,
            target_addr: detour_addr,
            detour: raw,
            signature,
            table: state,
        };
        let handle = detour.get_handle();

        lua.app_data_mut::<LuaHooks>()
            .ok_or_else(|| LuaError::runtime("LuaHooks not initialized!"))?
            .entry(addr)
            .or_default()
            .push(detour);

        Ok(handle)
    }
    fn lua_print(_: &Lua, vals: LuaMultiValue) -> LuaResult<()> {
        let message = vals
            .iter()
            .map(|v| v.to_string().unwrap())
            .collect::<Vec<_>>()
            .join("\t");
        hooks::cprint(0x0000ff, &format!("[Lua] {message}\n"));
        Ok(())
    }

    pub fn lua<F, T>(&self, lua_fn: F) -> LuaResult<T>
    where
        F: Fn(&Lua) -> LuaResult<T>,
    {
        let t_start = Instant::now();
        const TIMEOUT: Duration = Duration::from_secs(1);
        self.lua.set_hook(
            LuaHookTriggers::new().every_nth_instruction(1000),
            move |lua, debug| {
                if t_start.elapsed() > TIMEOUT {
                    // 1. Grab function metadata
                    let info = debug.function().info();
                    let func_name = info.name.as_deref().unwrap_or("<anonymous>");
                    let source = info.short_src.unwrap_or_else(|| "<unknown>".to_owned());
                    let line = debug
                        .current_line()
                        .map(|l| l.to_string())
                        .unwrap_or_else(|| "?".to_owned());

                    // 2. Format a descriptive message
                    let msg = format!(
                        "Lua execution timed out after {:.2}s — function '{}' at {}:{}",
                        t_start.elapsed().as_secs_f64(),
                        func_name,
                        source,
                        line
                    );
                    return Err(mlua::Error::runtime(msg));
                }
                Ok(mlua::VmState::Continue)
            },
        )?;
        let ret = (lua_fn)(&self.lua);
        self.lua.remove_hook();
        ret
    }

    pub fn run_file(&self, path: &str) -> LuaResult<()> {
        self.lua(|lua| -> LuaResult<()> {
            lua.load(fs_err::read(path)?)
                .set_name(path)
                .set_environment(self.env.clone())
                .exec()
        })
    }

    pub fn run(&self, code: &str) -> LuaResult<LuaValue> {
        self.lua(|lua| -> LuaResult<LuaValue> {
            lua.load(code)
                .set_name("ScrapLua")
                .set_environment(self.env.clone())
                .eval::<LuaValue>()
        })
    }
}

pub(crate) static S_LUA: LazyLock<RwLock<LuaState>> =
    LazyLock::new(|| RwLock::new(LuaState::new().unwrap()));

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn cmd_lua(_sml: *const ScrapModLoaderFFI, cmd: *mut c_char) -> bool {
    let Ok(cmd) = CStr::from_ptr(cmd).to_str().inspect_err(|e| error!("{e}")) else {
        return false;
    };
    if cmd == "reset" {
        let mut state = S_LUA.write();
        if let Some(mut hooks) = state.lua.app_data_mut::<LuaHooks>() {
            for (_, chunk) in hooks.0.drain() {
                for hook in chunk.into_iter().rev() {
                    drop(hook);
                }
            }
        }
        match LuaState::new() {
            Ok(new_state) => {
                *state = new_state;
            }
            Err(err) => {
                error!("Failed to reset Lua state: {err}");
            }
        }
        return true;
    }
    let state = S_LUA.read();
    match state.run(cmd).and_then(|r| r.to_string()) {
        Ok(res) => hooks::cprint(0x0000ff, &format!("[Lua] {res}\n")),
        Err(err) => hooks::cprint(0xff0000, &format!("[Lua] {err}\n")),
    }
    // state.gc();
    true
}
