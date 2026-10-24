#![allow(
    non_camel_case_types,
    non_snake_case,
    clippy::declare_interior_mutable_const,
    non_upper_case_globals,
    clippy::borrow_interior_mutable_const,
    clippy::missing_safety_doc
)]
use byteorder::{LittleEndian, WriteBytesExt};
use facet::Facet;
use pelite::{
    pe::{
        Pe, PeView,
        msvc::{RTTICompleteObjectLocator, TypeDescriptor},
    },
    util::CStr,
};
use petgraph::data::FromElements;
use region::Region;
use rhexdump::{rhexdump, rhexdumps};
use stacked_errors::{Error, Result, StackableErr, anyhow, bail};
use windows::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::EnumerateLoadedModules, LibraryLoader::GetModuleHandleW,
        Memory::HeapUnlock, Threading::GetCurrentProcess,
    },
};

use crate::CStrDisp;

use std::{
    any::TypeId, backtrace, cell::LazyCell, collections::{BTreeMap, HashMap}, ffi::CString, fmt::{Debug, Formatter}, fs::File, io::{BufWriter, Seek, Write}, ops::ControlFlow, os::raw::{c_char, c_int, c_long, c_void}, path::PathBuf, sync::LazyLock, u32,
};

pub const METH_OLDARGS: c_int = 0x0000; // "old-style" - single tuple argument
pub const METH_VARARGS: c_int = 0x0001; // standard tuple argument
pub const METH_KEYWORDS: c_int = 0x0002; // function accepts keyword arguments

trait PyType: Sized + 'static {
    fn py_type() -> PyTypeObject;

    fn new<'a>() -> &'a mut Self {
        let py_types = &*PyTypes;
        let tid = TypeId::of::<Self>();
        let py_ptr_type = py_types.get(&tid).unwrap();
        unsafe {
            PySML::native::Py_NewObject(py_ptr_type)
                .cast::<Self>()
                .as_mut_unchecked()
        }
    }
}

#[repr(transparent)]
pub struct NonNullPtr<T> {
    ptr: *mut T,
}

impl<T> NonNullPtr<T> {
    /// Creates a NonNullPtr from a raw pointer.
    /// # Safety
    /// The pointer must be valid (or null) for the lifetime of the wrapper.
    pub unsafe fn new(ptr: *mut T) -> Self {
        Self { ptr }
    }

    pub unsafe fn null() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
        }
    }
}

impl<T: Debug> Debug for NonNullPtr<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.ptr.is_null() {
            write!(f, "null")
        } else {
            // Safety: caller guarantees non‑null pointers are valid.
            unsafe { (*self.ptr).fmt(f) }
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PyMethodDef {
    name: CStrDisp,
    method: Option<extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject>,
    flags: c_int,
    doc: CStrDisp,
}

// Opaque forward declarations (already defined, but needed for circular references)
#[repr(C)]
#[derive(Debug)]
pub struct PyObject {
    pub ob_refcnt: c_int,
    pub ob_type: *mut PyTypeObject,
}

#[repr(C)]
#[derive(Debug)]
pub struct PyTypeObject {
    pub ob_refcnt: c_int,
    pub ob_type: *const Self,
    pub ob_size: c_int,
    pub tp_name: CStrDisp,
    pub tp_basicsize: c_int,
    pub tp_itemsize: c_int,
    pub tp_dealloc: destructor,
    pub tp_print: printfunc,
    pub tp_getattr: getattrfunc,
    pub tp_setattr: setattrfunc,
    pub tp_compare: cmpfunc,
    pub tp_repr: reprfunc,
    pub tp_as_number: NonNullPtr<PyNumberMethods>,
    pub tp_as_sequence: NonNullPtr<PySequenceMethods>,
    pub tp_as_mapping: NonNullPtr<PyMappingMethods>,
    pub tp_hash: hashfunc,
    pub tp_call: ternaryfunc,
    pub tp_str: reprfunc,
    pub tp_getattro: getattrofunc,
    pub tp_setattro: setattrofunc,
    pub tp_as_buffer: NonNullPtr<PyBufferProcs>,
    pub tp_flags: c_long,
    pub tp_doc: CStrDisp,
    pub tp_xxx5: c_long,
    pub tp_xxx6: c_long,
    pub tp_xxx7: c_long,
    pub tp_xxx8: c_long,
}

#[repr(C)]
#[derive(Debug)]
pub struct PyVarObject {
    pub ob_refcnt: c_int,
    pub ob_type: NonNullPtr<PyTypeObject>,
    pub ob_size: c_int,
}
#[repr(C)]
#[derive(Debug)]
pub struct PyTupleObject {
    pub head: PyVarObject,
    items: [*const PyObject; 0],
}

// Function pointer types (all can be null, hence Option)
pub type destructor = Option<extern "C" fn(*mut PyObject)>;
pub type printfunc = Option<extern "C" fn(*mut PyObject, *mut c_void, c_int) -> c_int>;
pub type getattrfunc = Option<extern "C" fn(*mut PyObject, *mut c_char) -> *mut PyObject>;
pub type setattrfunc = Option<extern "C" fn(*mut PyObject, *mut c_char, *mut PyObject) -> c_int>;
pub type cmpfunc = Option<extern "C" fn(*mut PyObject, *mut PyObject) -> c_int>;
pub type reprfunc = Option<extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type hashfunc = Option<extern "C" fn(*mut PyObject) -> c_long>;
pub type ternaryfunc =
    Option<extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type getattrofunc = Option<extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type setattrofunc = Option<extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> c_int>;
pub type binaryfunc = Option<extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type unaryfunc = Option<extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type inquiry = Option<extern "C" fn(*mut PyObject) -> c_int>;
pub type coercion = Option<extern "C" fn(*mut *mut PyObject, *mut *mut PyObject) -> c_int>;
pub type intargfunc = Option<extern "C" fn(*mut PyObject, c_int) -> *mut PyObject>;
pub type intintargfunc = Option<extern "C" fn(*mut PyObject, c_int, c_int) -> *mut PyObject>;
pub type intobjargproc = Option<extern "C" fn(*mut PyObject, c_int, *mut PyObject) -> c_int>;
pub type intintobjargproc =
    Option<extern "C" fn(*mut PyObject, c_int, c_int, *mut PyObject) -> c_int>;
pub type objobjargproc =
    Option<extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> c_int>;
pub type getreadbufferproc = Option<extern "C" fn(*mut PyObject, c_int, *mut *mut c_void) -> c_int>;
pub type getwritebufferproc =
    Option<extern "C" fn(*mut PyObject, c_int, *mut *mut c_void) -> c_int>;
pub type getsegcountproc = Option<extern "C" fn(*mut PyObject, *mut c_int) -> c_int>;
pub type getcharbufferproc = Option<extern "C" fn(*mut PyObject, c_int, *mut *mut c_char) -> c_int>;

// Protocol structures
#[repr(C)]
#[derive(Debug)]
pub struct PyNumberMethods {
    pub nb_add: binaryfunc,
    pub nb_subtract: binaryfunc,
    pub nb_multiply: binaryfunc,
    pub nb_divide: binaryfunc,
    pub nb_remainder: binaryfunc,
    pub nb_divmod: binaryfunc,
    pub nb_power: ternaryfunc,
    pub nb_negative: unaryfunc,
    pub nb_positive: unaryfunc,
    pub nb_absolute: unaryfunc,
    pub nb_nonzero: inquiry,
    pub nb_invert: unaryfunc,
    pub nb_lshift: binaryfunc,
    pub nb_rshift: binaryfunc,
    pub nb_and: binaryfunc,
    pub nb_xor: binaryfunc,
    pub nb_or: binaryfunc,
    pub nb_coerce: coercion,
    pub nb_int: unaryfunc,
    pub nb_long: unaryfunc,
    pub nb_float: unaryfunc,
    pub nb_oct: unaryfunc,
    pub nb_hex: unaryfunc,
}

#[repr(C)]
#[derive(Debug)]
pub struct PyBufferProcs {
    pub bf_getreadbuffer: getreadbufferproc,
    pub bf_getwritebuffer: getwritebufferproc,
    pub bf_getsegcount: getsegcountproc,
    pub bf_getcharbuffer: getcharbufferproc,
}

#[repr(C)]
#[derive(Debug)]
pub struct PyMappingMethods {
    pub mp_length: inquiry,
    pub mp_subscript: binaryfunc,
    pub mp_ass_subscript: objobjargproc,
}

#[repr(C)]
#[derive(Debug)]
pub struct PySequenceMethods {
    pub sq_length: inquiry,
    pub sq_concat: binaryfunc,
    pub sq_repeat: intargfunc,
    pub sq_item: intargfunc,
    pub sq_slice: intintargfunc,
    pub sq_ass_item: intobjargproc,
    pub sq_ass_slice: intintobjargproc,
}

fn rva<T>(addr: usize) -> *mut T {
    unsafe { GetModuleHandleW(None).unwrap().0.cast::<T>().byte_add(addr) }
}

#[repr(C)]
#[derive(Debug)]
struct PySlice {
    head: PyObject,
    ptr: *const u8,
    size: usize,
}

impl PyType for PySlice {
    fn py_type() -> PyTypeObject {
        unsafe {
            PyTypeObject {
                ob_refcnt: 1,
                ob_type: rva::<PyTypeObject>(0x435f98),
                ob_size: 0,
                tp_name: CStrDisp(c"Slice".as_ptr()),
                tp_basicsize: std::mem::size_of::<PySlice>() as i32,
                tp_itemsize: 0,
                tp_dealloc: None,
                tp_print: None,
                tp_getattr: None,
                tp_setattr: None,
                tp_compare: None,
                tp_repr: Some(py_slice_repr),
                tp_as_number: NonNullPtr::null(),
                tp_as_sequence: NonNullPtr::null(),
                tp_as_mapping: NonNullPtr::null(),
                tp_hash: None,
                tp_call: None,
                tp_str: None,
                tp_getattro: None,
                tp_setattro: None,
                tp_as_buffer: NonNullPtr::null(),
                tp_flags: 0,
                tp_doc: CStrDisp(c"Pointer!".as_ptr()),
                tp_xxx5: 0,
                tp_xxx6: 0,
                tp_xxx7: 0,
                tp_xxx8: 0,
            }
        }
    }
}

fn py_typename(this: *mut PyObject) -> String {
    let name = unsafe { this.as_ref_unchecked().ob_type.as_ref_unchecked().tp_name };
    name.to_string()
}

extern "C" fn py_slice_repr(this: *mut PyObject) -> *mut PyObject {
    let this = this.cast::<PySlice>();
    let this = unsafe { this.as_ref_unchecked() };
    let slice = unsafe { std::slice::from_raw_parts(this.ptr, this.size) };
    let excess = this.size.saturating_sub(0x100);
    let mut repr_str = rhexdumps!(&slice[..0x100], this.ptr as u64);
    if excess > 0 {
        repr_str.push_str(&format!("\n<+0x{excess:x} bytes>"));
    }
    let repr_str = CString::new(repr_str).unwrap();
    unsafe { PySML::native::Py_BuildValue(c"s".as_ptr(), repr_str) }
}

const PyTypes: LazyLock<HashMap<TypeId, PyTypeObject>> = LazyLock::new(|| {
    let mut ret = HashMap::new();
    ret.insert(TypeId::of::<PySlice>(), PySlice::py_type());
    ret
});

fn get_section<'a>(name: &'static [u8; 8]) -> Result<&'a [u8]> {
    use pelite::pe::{Pe, PeView};
    let pe = unsafe { PeView::module(rva::<u8>(0)) };
    let name_str = CStr::from_bytes(name)
        .ok_or_else(|| anyhow!("Invalid section name"))?
        .to_string();
    let data = pe
        .section_headers()
        .iter()
        .find(|hdr| hdr.Name == *name)
        .ok_or_else(|| anyhow!("Section {name_str} not found"))?;
    pe.get_section_bytes(data).map_err(|e| anyhow!(e))
}

#[derive(Debug, Clone)]
enum Class {
    Float(f32),
    Double(f64),
    String(String),
    Pointer(String),
}

#[derive(Debug, facet::Facet, Clone)]
#[repr(u8)]
enum MemType {
    Heap(u32),
    Section(String, String),
    Module(String),
}

impl MemType {
    fn to_bytes<W: std::io::Write>(&self, mut buf: W) {
        match self {
            MemType::Heap(id) => {
                buf.write_u8(0).unwrap();
                buf.write_u32::<LittleEndian>(*id).unwrap();
            }
            MemType::Section(bin, sec) => {
                buf.write_u8(1).unwrap();
                buf.write_u8(bin.as_bytes().len().try_into().unwrap())
                    .unwrap();
                buf.write_all(bin.as_bytes()).unwrap();
                buf.write_u8(sec.as_bytes().len().try_into().unwrap())
                    .unwrap();
                buf.write_all(sec.as_bytes()).unwrap();
            }
            MemType::Module(bin) => {
                buf.write_u8(2).unwrap();
                buf.write_u8(bin.as_bytes().len().try_into().unwrap())
                    .unwrap();
                buf.write_all(bin.as_bytes()).unwrap();
            }
        }
    }
    fn is_section(&self, name: &str) -> bool {
        match self {
            MemType::Heap(_) => false,
            MemType::Section(_, sect) => sect == name,
            MemType::Module(_) => false,
        }
    }
}

unsafe extern "system" fn module_callback(
    modulename: windows::core::PCSTR,
    modulebase: u32,
    modulesize: u32,
    usercontext: *const core::ffi::c_void,
) -> windows::core::BOOL {
    if modulebase != (rva::<()>(0).addr() as u32) {
        return true.into();
    }
    let intervals = unsafe {
        (usercontext.cast_mut() as *mut Vec<(std::range::Range<*const u8>, MemType)>)
            .as_mut_unchecked()
    };
    let module_name = unsafe { modulename.display() }.to_string();
    let addr = modulebase as *const u8;
    let ptr_range = unsafe { addr..addr.byte_add(modulesize as usize) };
    intervals.push((ptr_range.into(), MemType::Module(module_name.clone())));
    let module = unsafe { PeView::module(modulebase as *const u8) };
    for section in module.section_headers().iter() {
        if let Ok(section_name) = str::from_utf8(section.name_bytes()) {
            let section_ptr = (modulebase + section.VirtualAddress) as *const u8;
            let section_range =
                unsafe { section_ptr..section_ptr.byte_add(section.VirtualSize as usize) };
            intervals.push((
                section_range.into(),
                MemType::Section(module_name.clone(), section_name.to_owned()),
            ));
        };
    }
    return true.into();
}

#[inline(never)]
fn typename(obj: *const u8) -> Option<String> {
    if region::query(obj).is_err() {
        return None;
    }
    println!("TY: {obj:p} -> {q:?}", q = region::query(obj));
    let rdata = get_section(b".rdata\0\0").ok()?;
    let vtable_ptr = unsafe { obj.cast::<*const u8>().read() };
    if rdata.as_ptr_range().contains(&vtable_ptr) {
        let object_locator = unsafe { vtable_ptr.cast::<*const u8>().offset(-1).read() };
        if rdata.as_ptr_range().contains(&object_locator) {
            let object_locator = unsafe {
                object_locator
                    .cast::<RTTICompleteObjectLocator>()
                    .as_ref_unchecked()
            };
            if object_locator.signature != 0 {
                return None;
            }
            let type_desc = unsafe {
                (object_locator.type_descriptor.into_raw() as *const TypeDescriptor)
                    .as_ref_unchecked()
            };
            let ty_name = CStrDisp(type_desc.name.as_ptr().cast()).to_string();
            let readable =
                undname::demangle(&ty_name, undname::Flags::NAME_ONLY).unwrap_or(ty_name);
            return Some(readable);
        }
    }
    return None;
}

type MemTree =
    sif_itree::ITree<*const u8, MemType, Vec<((std::ops::Range<*const u8>, MemType), *const u8)>>;

#[derive(Debug)]
struct MemoryMap(
    sif_itree::ITree<*const u8, MemType, Vec<((std::ops::Range<*const u8>, MemType), *const u8)>>,
);

impl std::ops::Deref for MemoryMap {
    type Target = sif_itree::ITree<
        *const u8,
        MemType,
        Vec<((std::ops::Range<*const u8>, MemType), *const u8)>,
    >;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, facet::Facet)]
struct VTable {
    methods: u32,
    addr: u32,
    typename: Option<String>,
}

#[derive(Debug, facet::Facet)]
struct FieldInfo {
    name: String,
    addr: u32,
}

#[derive(Debug, facet::Facet)]
struct HeapNode {
    size: u32,              // Bytes occupied on the heap
    vtable: Option<VTable>, // VTable address (useful for colouring by “class”)
    fields: BTreeMap<u32, FieldInfo>,
}

type HeapDump = BTreeMap<u32, HeapNode>;

impl MemoryMap {
    fn new(items: Vec<(std::ops::Range<*const u8>, MemType)>) -> Self {
        Self(sif_itree::ITree::new(items))
    }

    fn is_heap_base<T>(&self, ptr: *const T) -> bool {
        let mut ret = false;
        let ptr = ptr.cast::<u8>();
        let _ = self.0.query(ptr..=ptr, |(r, t)| {
            if matches!(t, MemType::Heap(_)) && r.start == ptr {
                ret = true;
                return ControlFlow::Break(());
            }
            return ControlFlow::Continue(());
        });
        return ret;
    }

    fn is_heap<T>(&self, ptr: *const T) -> bool {
        let mut ret = false;
        let ptr = ptr.cast::<u8>();
        let _ = self.0.query(ptr..=ptr, |(_, t)| {
            if matches!(t, MemType::Heap(_)) {
                ret |= true;
                return ControlFlow::Break(());
            }
            return ControlFlow::Continue(());
        });
        return ret;
    }

    fn is_code<T>(&self, ptr: *const T) -> bool {
        let mut ret = false;
        let ptr = ptr.cast::<u8>();
        let _ = self.0.query(ptr..=ptr, |(r, t)| {
            match t {
                MemType::Section(_, sec) if sec == ".text" => {
                    ret = true;
                }
                _ => (),
            }
            ControlFlow::<(), ()>::Continue(())
        });

        return ret;
    }

    fn get_vtable_from_addr<T>(&self, addr: *const T) -> Option<VTable> {
        let vtable = addr.cast::<*const ()>();
        let vtable_u8 = vtable.cast::<u8>();
        println!("VMT: {vtable:p} -> {:?}", region::query(vtable));
        // 1. The vtable pointer itself must live in .rdata
        let mut in_rdata = false;
        let _ = self.0.query(vtable_u8..=vtable_u8, |(_, t)| {
            if t.is_section(".rdata") {
                in_rdata = true;
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        });
        if !in_rdata {
            return None;
        }

        // 2. Walk the vtable slot-by-slot.
        //    A slot is valid iff the slot address itself is readable (.rdata)
        //    AND the function pointer stored there lands in .text.
        //    Stop at the first slot that fails either check.
        let mut methods = 0usize;
        loop {
            let slot_addr = unsafe { vtable.add(methods) }.cast::<u8>();

            // Is the slot address still inside .rdata?
            let mut slot_readable = false;
            let _ = self.0.query(slot_addr..=slot_addr, |(_, t)| {
                if t.is_section(".rdata") {
                    slot_readable = true;
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            });
            if !slot_readable {
                break;
            }

            // Does the stored function pointer point into .text?
            let fn_ptr = unsafe { vtable.add(methods).read() }.cast::<u8>();
            if !self.is_code(fn_ptr) {
                break;
            }

            methods += 1;
        }

        // A vtable with no valid .text entries isn't a vtable.
        if methods == 0 {
            return None;
        }

        // 3. Attempt to recover a type name from RTTI.
        //    On MSVC the Complete Object Locator pointer is stored at vtable[-1].
        let typename = (|| -> Option<String> {
            // Read the pointer stored one slot before the vtable.
            let locator_ptr = unsafe { vtable_u8.cast::<*const u8>().offset(-1).read() };

            // That pointer must also be in .rdata to be a real COL.
            let mut locator_in_rdata = false;
            let _ = self.0.query(locator_ptr..=locator_ptr, |(_, t)| {
                if t.is_section(".rdata") {
                    locator_in_rdata = true;
                    return ControlFlow::Break(());
                }
                ControlFlow::Continue(())
            });
            if !locator_in_rdata {
                return None;
            }

            let locator = unsafe {
                locator_ptr
                    .cast::<RTTICompleteObjectLocator>()
                    .as_ref_unchecked()
            };

            // signature == 0 means the old x86 32-bit layout (absolute pointers).
            // signature == 1 is the x64 relative-offset layout; reject anything else.
            if locator.signature != 0 {
                return None;
            }

            let type_desc = unsafe {
                (locator.type_descriptor.into_raw() as *const TypeDescriptor).as_ref_unchecked()
            };

            let mangled = CStrDisp(type_desc.name.as_ptr().cast()).to_string();
            let readable =
                undname::demangle(&mangled, undname::Flags::NAME_ONLY).unwrap_or(mangled);
            Some(readable)
        })();

        Some(VTable {
            methods: methods as u32,
            addr: vtable.addr() as u32,
            typename,
        })
    }
}
fn do_mem_scan(dump_name: &str) -> Result<()> {
    use windows::Win32::{
        Foundation::HANDLE,
        System::{
            Memory::{HeapLock, HeapWalk, PROCESS_HEAP_ENTRY},
            SystemServices::PROCESS_HEAP_ENTRY_BUSY,
        },
    };
    let base = rva::<()>(0).addr();
    let mut intervals = vec![];
    let heap = unsafe { rva::<HANDLE>(0x4eca30).cast_const().read() };
    unsafe { HeapLock(heap) }.stack()?;
    let mut entry: PROCESS_HEAP_ENTRY = unsafe { std::mem::zeroed() };
    while unsafe { HeapWalk(heap, &mut entry).is_ok() } {
        if entry.wFlags as u32 & PROCESS_HEAP_ENTRY_BUSY == 0 || entry.cbData < 4 {
            continue;
        }
        let chunk =
            unsafe { std::slice::from_raw_parts(entry.lpData.cast::<u8>(), entry.cbData as usize) };
        intervals.push((chunk.as_ptr_range(), MemType::Heap(heap.0.addr() as u32)));
    }
    unsafe {
        EnumerateLoadedModules(
            GetCurrentProcess(),
            Some(module_callback),
            Some(&mut intervals as *mut Vec<_> as *mut c_void),
        )
    }
    .unwrap();
    intervals.sort_by_key(|(v, _)| (v.start.addr(), v.end.addr()));
    let tree = MemoryMap::new(intervals);
    let mut dump = BufWriter::new(File::create(dump_name).stack()?);
    for (range, desc) in tree.iter() {
        let size = unsafe { range.end.offset_from_unsigned(range.start) };
        let chunk = unsafe { std::slice::from_raw_parts(range.start, size) };
        if !matches!(desc, MemType::Heap(_)) {
            println!("{range:p} -> {desc:?}");
        }
        let pos = dump.stream_position().unwrap();
        dump.write_u32::<LittleEndian>(range.start.addr() as u32)
            .stack()?;
        dump.write_u32::<LittleEndian>(range.end.addr() as u32)
            .stack()?;
        desc.to_bytes(&mut dump);
        if let Err(e) = dump.write_all(chunk) {
            println!("Write error: {e}");
            dump.seek(std::io::SeekFrom::Start(pos)).unwrap();
            dump.get_mut().set_len(pos).unwrap();
        };
    }
    unsafe { HeapUnlock(heap) }.stack()?;
    return Ok(());
}


pub(crate) const fn func<T: Sized + Copy + 'static, const OFFSET: usize>() -> LazyCell<T> {
    LazyCell::new(|| unsafe { core::mem::transmute_copy::<*mut (), T>(&rva::<()>(OFFSET)) })
}

pub mod PySML {
    use std::{
        cell::LazyCell,
        collections::BTreeSet,
        ffi::{CStr, CString},
    };

    use rhexdump::rhexdump;
    use windows::{
        Win32::{
            Foundation::{ERROR_NO_MORE_ITEMS, HANDLE, HMODULE},
            System::{
                LibraryLoader::GetModuleHandleA,
                Memory::{HeapLock, HeapUnlock, HeapWalk, PROCESS_HEAP_ENTRY},
                ProcessStatus::{GetModuleInformation, MODULEINFO},
                SystemServices::PROCESS_HEAP_ENTRY_BUSY,
                Threading::GetCurrentProcess,
            },
        },
        core::PCSTR,
    };

    use self::native::*;

    use super::*;
    pub(crate) mod native {
        use super::*;

        pub(crate) const PyNoneRVA: usize = 0x435f84;
        pub(crate) const PyArg_ParseTuple: LazyCell<
            unsafe extern "C" fn(args: *mut PyObject, format: *const c_char, ...) -> c_int,
        > = func::<_, 0x2f1b70>();

        pub(crate) const Py_BuildValue: LazyCell<
            unsafe extern "C" fn(format: *const c_char, ...) -> *mut PyObject,
        > = func::<_, 0x2f31a0>();

        pub(crate) const Py_NewObject: LazyCell<
            unsafe extern "C" fn(*const PyTypeObject) -> *mut PyObject,
        > = func::<_, 0x2ed210>();

        pub(crate) const PyBuffer_FromReadWriteMemory: LazyCell<
            unsafe extern "C" fn(*const (), usize) -> *mut PyObject,
        > = func::<_, 0x313230>();

        pub(crate) const PyErr_SetString: LazyCell<
            unsafe extern "C" fn(*const PyObject, *const c_char) -> *mut PyObject,
        > = func::<_, 0x2f1b00>();

        pub(crate) const PyErr_NewException: LazyCell<
            unsafe extern "C" fn(*const c_char, *const PyObject, *const PyObject) -> *mut PyObject,
        > = func::<_, 0x2f1520>();

        pub(crate) const Py_InitModule: LazyCell<
            unsafe extern "C" fn(
                CStrDisp,
                *const PyMethodDef,
                CStrDisp,
                *mut PyObject,
                c_int,
            ) -> *mut PyObject,
        > = func::<_, 0x2f31c0>();

        pub(crate) const PyModule_SetAttr: LazyCell<
            unsafe extern "C" fn(*mut PyObject, *const c_char, *mut PyObject) -> *mut PyObject,
        > = func::<_, 0x2e27a0>();
    }

    // TODO: build pointer type with methods to read, write, dump memory
    // TODO: build byte array wrapper type to hold data
    // TODO: hex str <-> byte array conversion
    // TODO: function hooking?

    extern "C" fn module_impl(this: *mut PyObject, args: *mut PyObject) -> *mut PyObject {
        dbg!(this, py_typename(args));
        let mut modname: *const u8 = std::ptr::null();
        dbg!(modname);
        if unsafe { PyArg_ParseTuple(args, c"|s".as_ptr(), &mut modname) } == 0 {
            let py_none = rva::<PyObject>(PyNoneRVA);
            unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
            return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
        }
        dbg!(modname);
        let module = match unsafe { GetModuleHandleA(PCSTR::from_raw(modname)) } {
            Ok(module) => module,
            Err(err) => unsafe {
                let err_str = CString::new(format!("{err}")).unwrap();
                let exc =
                    PyErr_NewException(c"SML.module".as_ptr(), std::ptr::null(), std::ptr::null());
                PyErr_SetString(exc, err_str.as_ptr());
                return std::ptr::null_mut();
            },
        };
        let mut modinfo = unsafe { std::mem::zeroed() };
        unsafe {
            GetModuleInformation(
                GetCurrentProcess(),
                module,
                &mut modinfo,
                std::mem::size_of::<MODULEINFO>().try_into().unwrap(),
            )
            .unwrap()
        };
        unsafe {
            PyBuffer_FromReadWriteMemory(
                modinfo.lpBaseOfDll as *const (),
                modinfo.SizeOfImage as usize,
            )
            .as_mut_unchecked()
        }
    }

    extern "C" fn scan_impl(this: *mut PyObject, args: *mut PyObject) -> *mut PyObject {
        if unsafe { PyArg_ParseTuple(args, c"".as_ptr(), std::ptr::null_mut::<()>()) } == 0 {
            let py_none = rva::<PyObject>(PyNoneRVA);
            unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
            return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
        }
        let py_none = rva::<PyObject>(PyNoneRVA);
        let Some(data) = get_section(b".data\0\0\0").ok() else {
            unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
            return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
        };
        let Some(text) = get_section(b".text\0\0\0").ok() else {
            unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
            return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
        };
        let Some(rdata) = get_section(b".rdata\0\0").ok() else {
            unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
            return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
        };
        let mut types = BTreeSet::new();
        let mut found_new = true;
        while found_new {
            found_new = false;
            for w in data.windows(std::mem::size_of::<PyTypeObject>()) {
                let py_type_ptr = w.as_ptr().cast::<PyTypeObject>();
                let py_type = unsafe { py_type_ptr.as_ref_unchecked() };
                if py_type.tp_basicsize == 0 || py_type.ob_refcnt <= 0 {
                    continue;
                }
                if !rdata
                    .as_ptr_range()
                    .contains(&py_type.tp_name.0.cast::<u8>())
                {
                    continue;
                }
                let valid_type = py_type.ob_type == py_type_ptr || types.contains(&py_type.ob_type);
                let new_edge = !types.contains(&py_type_ptr);
                let name_valid = data
                    .as_ptr_range()
                    .contains(&py_type.tp_name.0.cast::<u8>())
                    || rdata
                        .as_ptr_range()
                        .contains(&py_type.tp_name.0.cast::<u8>());
                if valid_type && new_edge && name_valid {
                    found_new = true;
                    types.insert(py_type_ptr);
                    let ty_name = py_type.tp_name.to_string();
                    println!("Found PyType: {py_type:p} -> {ty_name}");
                }
            }
        }
        for ty in &types {
            let ty = unsafe { ty.as_ref_unchecked() };
            let name = ty.tp_name.to_string();
            let parent = unsafe { ty.ob_type.as_ref_unchecked() }.tp_name.to_string();
            let size = ty.tp_basicsize;
            println!("{parent} -> {name}: ({size})",);
        }
        unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
        unsafe { Py_BuildValue(c"O".as_ptr(), py_none) }
    }

    // 1. Walk heap to find objets + sizes + vtable pointers
    // 2. Scan .data + .rdata for vtable pointers, to find object base addresses
    // 3. use object sizes and addresses from 1. to scan object for pointers into the heap as well as into .data and .rdata
    // 4. rinse and repeat until we've got a full object graph
    extern "C" fn mem_scan_impl(this: *mut PyObject, args: *mut PyObject) -> *mut PyObject {
        let py_none = rva::<PyObject>(PyNoneRVA);
        let mut dump_name: *const i8 = std::ptr::null();
        dbg!(dump_name);
        if unsafe { PyArg_ParseTuple(args, c"s".as_ptr(), &mut dump_name) } == 0 {
            unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
            return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
        }
        let dump_name = unsafe { CStr::from_ptr(dump_name) }
            .to_string_lossy()
            .into_owned();
        if let Err(e) = do_mem_scan(&dump_name) {
            eprintln!("{e}");
        };
        unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
        return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
    }

    extern "C" fn hax_impl(this: *mut PyObject, args: *mut PyObject) -> *mut PyObject {
        let obj = unsafe { args.cast::<PyTupleObject>().as_ref_unchecked() };
        if obj.head.ob_size <= 0 {
            let py_none = rva::<PyObject>(PyNoneRVA);
            unsafe { py_none.as_mut_unchecked() }.ob_refcnt += 1;
            return unsafe { Py_BuildValue(c"O".as_ptr(), py_none) };
        }
        let items =
            unsafe { std::slice::from_raw_parts(obj.items.as_ptr(), obj.head.ob_size as usize) };
        let types: HashMap<_, _> = items
            .iter()
            .map(|v| unsafe {
                (
                    *v,
                    v.as_ref_unchecked()
                        .ob_type
                        .as_ref_unchecked()
                        .tp_name
                        .to_string(),
                )
            })
            .collect();
        dbg!(types);
        return unsafe { Py_BuildValue(c"O".as_ptr(), obj) };
    }

    // extern "C" fn rtti_impl(this: *mut PyObject, args: *mut PyObject) -> *mut PyObject {
    //     use pelite::pe::{Pe, PeView};
    //     let pe = unsafe { PeView::module(rva::<u8>(0)) };
    //     dbg!(rtti::parse(&pe));
    //     std::ptr::null_mut()
    // }

    const Methods: &[PyMethodDef] = &[
        PyMethodDef {
            name: CStrDisp(c"module".as_ptr()),
            method: Some(module_impl),
            flags: METH_VARARGS,
            doc: CStrDisp(c"test method :)".as_ptr()),
        },
        PyMethodDef {
            name: CStrDisp(c"hax".as_ptr()),
            method: Some(hax_impl),
            flags: METH_VARARGS,
            doc: CStrDisp(c"test hax :)".as_ptr()),
        },
        PyMethodDef {
            name: CStrDisp(c"scan".as_ptr()),
            method: Some(scan_impl),
            flags: METH_VARARGS,
            doc: CStrDisp(std::ptr::null()),
        },
        PyMethodDef {
            name: CStrDisp(c"mem_scan".as_ptr()),
            method: Some(mem_scan_impl),
            flags: METH_VARARGS,
            doc: CStrDisp(std::ptr::null()),
        },
        // PyMethodDef {
        //     name: CStrDisp(c"rtti".as_ptr()),
        //     method: Some(rtti_impl),
        //     flags: METH_VARARGS,
        //     doc: CStrDisp(std::ptr::null()),
        // },
        PyMethodDef {
            name: CStrDisp::null(),
            method: None,
            flags: 0,
            doc: CStrDisp::null(),
        }, // sentinel
    ];

    pub unsafe fn init(_: *const ()) {
        unsafe {
            let pyMod = Py_InitModule(
                CStrDisp(c"SML".as_ptr()),
                Methods.as_ptr(),
                CStrDisp(c"Scrap Mod Loader Python Interface".as_ptr()),
                std::ptr::null_mut(),
                1007,
            );
            // PyModule_SetAttr(pyMod,c"loop".as_ptr(),pyMod);
        };
    }
}
