use std::{env, path::PathBuf};

fn main() {
    let sdk = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("steam_sdk");
    let target = env::var("TARGET").unwrap();
    let compiler =
        cc::windows_registry::find_tool(&target, "cl.exe").expect("MSVC compiler not found");

    let includes = compiler
        .get_envs()
        .find(|(key, _)| key.eq_ignore_ascii_case("INCLUDE"))
        .map(|(_, value)| value.to_owned())
        .or_else(|| std::env::var_os("INCLUDE"))
        .expect("MSVC INCLUDE paths not found");

    let includes: Vec<String> = format!("{}", includes.display())
        .split(';')
        .filter(|p| !p.is_empty())
        .map(|p| format!("-I{p}"))
        .collect();

    println!("cargo:rerun-if-changed=src/steam_callback.cpp");

    cc::Build::new()
        .cpp(true)
        .file("src/steam_callback.cpp")
        .include(sdk.join("public"))
        .define("STEAM_API_NODLL", None)
        .compile("steam_callback");

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=STEAMWORKS_SDK");
    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(includes)
        .clang_args(["-x", "c++", "-std=c++11"])
        .clang_arg(format!("-I{}", sdk.join("public").display()))
        .clang_arg("-DSTEAM_API_NODLL")
        // Types
        .allowlist_type("E[A-Z][A-Za-z0-9_]*")
        .allowlist_type("[A-Za-z0-9_]+_t")
        .allowlist_type("C.*")
        .opaque_type("ISteam.*")
        .opaque_type("HSteam.*")
        // Functions
        .allowlist_function("SteamAPI_.*")
        .allowlist_function("[A-Z].*")
        .allowlist_function("SteamInternal_.*")
        // Constants, if needed
        .allowlist_var("k_.*")
        .allowlist_var("STEAM_.*")
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .derive_default(true)
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .dynamic_library_name("SteamApi")
        .impl_debug(true)
        .generate_cstr(true)
        .array_pointers_in_arguments(true)
        .wrap_unsafe_ops(true)
        .generate_inline_functions(true)
        .generate()
        .unwrap();

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings.write_to_file(out.join("bindings.rs")).unwrap();

    // Copy the DLL next to the build output so `cargo run` works.
    // OUT_DIR is target/<triple>/<profile>/build/<crate>-<hash>/out, so go up 3.
    // let profile_dir = out.ancestors().nth(3).unwrap();
    // let dll = lib_dir.join(format!("{lib_name}.dll"));
    // let _ = fs::copy(&dll, profile_dir.join(format!("{lib_name}.dll")));
}
