#[allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unsafe_op_in_unsafe_fn,
    clippy::all
)]

mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

unsafe extern "C" {
    pub fn rust_callback_create(
        size: i32,
        game_server: bool,
        fn_ptr: Option<extern "C" fn(*mut std::ffi::c_void)>,
    ) -> *mut CCallbackBase;

    pub fn rust_callback_destroy(callback: *mut CCallbackBase);
}

pub use bindings::*;
