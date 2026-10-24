# Scrap Mod Loader (SML)

A mod loader for **Scrapland** (Steam App ID `897610`, Build `7863744`).

SML installs as a `d3d8.dll` proxy, hooks the game's entry point (works around Steamstub), and adds a Lua scripting sandbox, Lua-driven Python script patching, a native Python 1.5.2 module, an egui console, and a `.slm` plugin loader.

---

## Requirements

| Component | Version |
|---|---|
| Rust | **nightly** (workspace uses `#![feature(...)]`) |
| Target | `i686-pc-windows-msvc` (32-bit) |
| MSVC | VS Build Tools with C++ workload |
| Game | Scrapland build `7863744` |

---

## Building

```powershell
# Debug build of loader + default plugins
cargo xtask build

# Release build, install into your Scrapland install, then launch
cargo xtask build --release --install --run
```

`xtask` uses `steamlocate` to find the game and copies artifacts into:

- `<scrapland>/Bin/d3d8.dll` - the loader (from `sml_loader.dll`)
- `<scrapland>/plugins/util.slm` - default plugin
- `<scrapland>/init.lua` - Lua bootstrap

Only packages that declare `[package.metadata] mod_loader = true` or a `[package.metadata.rescrap]` block are installed. The loader's `target_file = "d3d8"` metadata drives the DLL name.

### Manual install

```powershell
cargo build -r
Copy-Item target/i686-pc-windows-msvc/release/sml_loader.dll <scrapland>\Bin\d3d8.dll
Copy-Item target/i686-pc-windows-msvc/release/util.dll       <scrapland>\plugins\util.slm
Copy-Item init.lua                                            <scrapland>\
```

Launch with `-sml:disable` to skip all modloader behaviour (loads the real `d3d8.dll` and exits).

---

## Repository layout

```
crates/
├── sml/                 → Bin/d3d8.dll  (the modloader)
│   ├── lib.rs           DllMain, entry hook, VEH, plugin loader
│   ├── hooks.rs         Engine detours (Py_Initialize, PreloadLibrary, …)
│   ├── command.rs       Console dispatcher, FFI exports
│   ├── gui.rs           egui console + log bridges
│   ├── lua.rs           Sandboxed LuaJIT runtime + script patcher
│   └── boot.py          Python injected at Py_Initialize
├── sml_hook_macros/     #[hook(rva, abi, enable)] proc-macro
├── sml_types/           Engine types: HashTable/PackedIndex, Py* FFI
├── steamworks/          Bindgen flat API + CCallbackBase shim
└── util_plugin/         → plugins/util.slm  (installs SML Python module)

xtask/                   cargo xtask build [--release] [--install] [--run]
init.lua                 Lua bootstrap, installed next to the game executable
```

---

## Usage

### In‑game console

Any console input starting with `,` is intercepted: `,<module>.<command> <args>`.

```
,util.dump              # list packed-file index
,util.dump scripts      # filter by substring
,lua print("hi")        # evaluate Lua in the sandbox
,lua reset              # tear down Lua state and all Lua detours
,nethack                # fake LAN server (builtin)
,steam                  # dump Steam interface pointers (builtin)
,plugins                # no-op; plugins are printed to the log at startup
```

Omitting the module (`nethack`) targets SML itself.

### GUI console

The **Scrapland Console** window opens on startup:

- **Editor** - Lua/Python scratchpad with syntax highlighting. Run with `Ctrl+Enter`. Lua uses the sandbox; Python calls `PyRun_SimpleString`.
- **Console** - mirrors the engine log with colors, plus a **Render Console** mode that replays the engine's `rcon` buffer.

### Lua

```lua
-- Sandbox API:
--   hook(rva, signature, callback)    -> DetourHandle
--   rva(offset)                       -> usize
--   scan(pattern)                     -> {{rva, …}, …}
--   patch_python(matcher, callback)   -> nil
--   cstr(ptr)                         -> string
--   print(...)                        -> engine console

_G.create_entity_hook = hook(
    rva(0x2099A0),
    "void* (__stdcall *)(char*, float, float, float, char*)",
    function(func, name, x, y, z, kind)
        print("spawn", cstr(name), cstr(kind), x, y, z)
        return func(name, 0, 0, 0, kind)  -- trampoline
    end
)
```

Hooks are refcounted per address; call `handle:unhook()` to remove one. The sandbox exposes `string`, `table`, `math`, `bit`, the clock functions of `os`, and a few globals — no `io`, no `os.execute`, no `ffi`. Lua is capped at 32 MB and a 1 s per‑call watchdog.

### Python script patching

`patch_python` registers a Lua callback that rewrites the source of a game Python module as it is loaded from the pack. The matcher uses Lua patterns against the module name and/or path; the callback receives `(name, path, code)` and returns the replacement source:

```lua
patch_python({name = "^[Mm]enu"}, function(name, path, code)
    -- Lua patterns treat ( ) as captures, so escape them with %( )
    local new_code, n = code:gsub(
        "def DrawBackMainMenu%(id%):",
        "def DrawBackMainMenu(id):\n\treturn\n"
    )
    print(string.format("[patch] %s (%s): %d replacement(s)", name, path, n))
    return new_code
end)
```

- `name` and `path` are optional, but at least one is required; both are Lua patterns.
- Callbacks run in registration order and **every** match is applied.
- The result is compiled in memory by the game's own Python 1.5.2 compiler (`Py_CompileString` → `PyImport_ExecCodeModuleEx`); no temporary files are written.
- If the module cannot be read or the patched source fails to compile, SML logs the error and falls back to the stock `.pyc`.
- Patched source must use **Python 1.5.2** syntax (no `True`/`False`, list comprehensions, `except E as e`, or f-strings).


### Python

`boot.py` is injected at `Py_Initialize` (currently empty), then `py_init` is called on every plugin. `util.slm` installs an `SML` module providing:

| Function | Description |
|---|---|
| `SML.module(name?)` | Wrap a loaded module (or the game itself) as a writable Python buffer. |
| `SML.hax(*objs)` | Print type names of the given objects. |
| `SML.scan()` | Find `PyTypeObject`s in `.data` by heuristics. |
| `SML.mem_scan(path)` | Dump a heap+module memory map to `path`. |

Interpreter is **Python 1.5.2** (pre‑`Py_ssize_t`); see `crates/sml_types/src/python.rs`.

---

## Writing a plugin

A `cdylib` that links `sml_types`, exposing any of:

```rust
#[unsafe(no_mangle)] pub unsafe extern "C" fn init(sml: *const ScrapModLoaderFFI) {}
#[unsafe(no_mangle)] pub unsafe extern "C" fn py_init(sml: *const ScrapModLoaderFFI) -> bool { true }
#[unsafe(no_mangle)] pub unsafe extern "C" fn cmd_dump(sml: *const ScrapModLoaderFFI, args: *mut c_char) -> bool { true }
```

Install metadata so `xtask` copies the artifact:

```toml
[package.metadata.rescrap]     # presence is enough

[lib]
crate-type = ["cdylib"]
name       = "myplug"           # → plugins/myplug.slm
```

`ScrapModLoaderFFI` provides:

```rust
pub struct ScrapModLoaderFFI {
    pub base:   *const (),                                  // game module base
    pub cprint: unsafe extern "C" fn(u32, *const c_char),   // color, msg
    pub log:    unsafe extern "C" fn(*const c_char, *const c_char), // level, msg
}
```

See `crates/util_plugin/` for a minimal example.

---

## How it works

1. **`DllMain`** - installs a panic handler, spawns a console, caches the real `Direct3DCreate8` from `%SystemRoot%\system32\d3d8.dll`.
2. **Entry-point hook** - places a `retour` detour on `AddressOfEntryPoint`. If the PE magic at `[−0x3c] ^ [−0x3b]` equals `0xC0DEC0DF` (Steamstub), `.text` is remapped `RX → R`, a VEH is installed, and the hook is placed on the *unpacked* entry point when the decryptor faults.
3. **`entry_point`** - loads every `plugins/*.slm`, calls `init`, runs `hooks::initialize_hooks()`, executes `init.lua`, spawns the GUI, then calls the original entry point.
4. **`Direct3DCreate8`** - exported stub forwards to the cached pointer.
5. **`Py_Initialize` / `PreloadLibrary`** - script patching registers Lua rules before the first game module loads; `PreloadLibrary` recompiles matched modules from patched source and falls back to the stock `.pyc` on any error.

---

## Notes & limitations

- Most hook RVAs are baked in against build `7863744`; other builds will fail to attach or crash.
- The sandbox does **not** expose `ffi`; only the API listed above plus a curated subset of stdlibs. `cmd_lua("reset")` tears down the state and all detours.
- Script patching callbacks run on the game's startup path, so a slow callback delays loading. A timeout aborts the patch and the stock `.pyc` is used.
- Patched modules are compiled once and cached by `sys.modules`; there is no hot reload.
- The GUI is a standalone `eframe` window on its own thread - it is not rendered inside the game.
- `SML.module` relies on Python 1.5.2's pre-`Py_ssize_t` ABI; porting to modern CPython requires rewriting that call.


