# SML - ScrapModLoader

A mod loader and runtime patcher for the **Scrapland Remastered** game. SML is a Windows DLL that intercepts the game's execution, decrypts the Steam DRM stub, hooks game functions, and provides a console for modding.

## Features

- **Steam DRM Unpacking** — Decrypts and patches the Steam stub in-memory at runtime, restoring the original entry point and applying base relocations.
- **Function Hooking** — Hooks game functions via detours using the `retour` library, with a custom `#[sml_hook]` procedural macro for ergonomic hook definition.
- **Console Access** — Allocates a debug console and enables the built-in scenegraph console for interactive debugging.
- **PAK File Monitoring** — Logs `.pak` archive open/close/read operations for modding insight.
- **Python Integration** — Hooks `Py_Initialize` to inject custom Python code (`ScrapHacks`) into the game's embedded Python runtime.
- **Panic Handler** — Captures backtraces on panic and displays them in a Windows message box for crash diagnostics.

## Architecture

```
SML (sml_loader.dll)
├── patcher.rs        — Steam DRM decryptor & in-place patcher
├── lib.rs            — DLL entry point, hook framework, game hooks
└── sml_hook_macros/  — Procedural macro crate for #[sml_hook]
```

### Hook System

Hooks are defined using the `#[sml_hook(RVA, ABI)]` attribute macro:

```rust
#[sml_hook(0x1307f0, thiscall)]
unsafe fn pak_open(this: *const (), path: *const c_char, mode: i32) -> *const () {
    let ret = original(this, path, mode);
    println!("[PAK:OPEN]: {}", CStr::from_ptr(path).to_str().unwrap());
    ret
}
```

The macro generates a `Hookable` impl that registers the hook at load time via `linkme`'s distributed slice mechanism. Supported ABIs include `C` and `thiscall`.

### Loading Mechanism

SML is loaded as a **proxy DLL** (`d3d8.dll`). When the game loads `d3d8.dll` for Direct3D 8, SML is loaded instead, which then:

1. Allocates a console for debug output.
2. Loads the real `d3d8.dll` and forwards `Direct3DCreate8`.
3. Detours the game's entry point to run the patcher and initialize hooks.
4. Patches the Steam DRM stub in-place, restoring the original code section.
5. Installs all registered function hooks.
6. Transfers control to the original entry point.

## Building

### Prerequisites

- **Rust** nightly toolchain (required by `retour`'s `thiscall-abi` and `nightly` features)
- Windows SDK

### Build

```bash
cargo build --release
```

The output is `target/release/sml_loader.dll`. Rename or copy it to `d3d8.dll` and place it in the game directory.

## Project Structure

| Path               | Description                                                                                    |
| ------------------ | ---------------------------------------------------------------------------------------------- |
| `src/lib.rs`       | DLL entry point (`DllMain`), pattern scanner, hook framework, game hooks, console setup        |
| `src/patcher.rs`   | Steam DRM header parsing, XOR/AES decryption, in-place code patching, relocation fixup         |
| `sml_hook_macros/` | Proc-macro crate implementing `#[sml_hook]`                                                    |
| `Cargo.toml`       | Dependencies: `retour`, `pelite`, `aes`, `cbc`, `linkme`, `facet`, `binrw`, `windows-rs`, etc. |

## Key Dependencies

| Crate         | Purpose                                 |
| ------------- | --------------------------------------- |
| `retour`      | Runtime function detouring/hooking      |
| `pelite`      | PE file parsing and pattern scanning    |
| `aes` + `cbc` | Steam DRM decryption                    |
| `linkme`      | Distributed slice for hook registration |
| `binrw`       | Binary reading for Steam header parsing |
| `facet`       | Reflection for manifest/config parsing  |
| `region`      | Memory protection manipulation          |
| `windows`     | Win32 API bindings                      |

## License

See the root `LICENSE` file if present, or contact the author.
