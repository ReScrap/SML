use std::ffi::{CStr, c_char};

use sml_types::Addressable;
use sml_types::PackedIndex;
use sml_types::{PackedHandles, ScrapModLoaderFFI};

#[allow(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn py_init(sml: *const ScrapModLoaderFFI) -> bool {
    let sml = unsafe { sml.as_ref().unwrap() };
    unsafe { sml_types::python::PySML::init(sml.base) };
    unsafe { (sml.log)(c"info".as_ptr(), c"PyInit OK!".as_ptr()) };
    true
}

#[unsafe(no_mangle)]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn cmd_dump(sml: *const ScrapModLoaderFFI, cmd: *mut c_char) -> bool {
    let sml = unsafe { sml.as_ref().unwrap() };
    let args = unsafe { CStr::from_ptr(cmd) }.to_string_lossy().to_string();

    let Some(handles) = PackedHandles::get_ref(sml.base) else {
        return false;
    };
    let Some(index) = PackedIndex::get_ref(sml.base) else {
        return false;
    };
    for (key, item) in index.iter() {
        let key = key.to_string();
        if args.is_empty() || key.contains(&args) {
            let handle = &handles.handles[item.packed_idx as usize];
            if handle.mode.fopen() {
                println!(
                    "{key} -> {path} @ {offset}+{size} ({mode:?}, {read} bytes read)",
                    offset = item.offset,
                    size = item.size,
                    mode = handle.mode,
                    path = handle.filename,
                    read = handle.bytes_read,
                );
            }
        }
    }
    true
}
