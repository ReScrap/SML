#![feature(debug_closure_helpers)]
use std::ffi::{CStr, CString, c_char};
use std::fmt::Debug;
use std::ops::Deref;
use std::ptr::NonNull;
use std::str::FromStr;

pub mod python;
pub trait Addressable: Sized {
    const RVA: usize;
    fn get_ref<'a>(base: *const ()) -> Option<&'a Self> {
        unsafe { base.cast::<Self>().byte_add(Self::RVA).as_ref() }
    }
}

pub struct Ptr<T>(Option<NonNull<T>>);

impl<T> Deref for Ptr<T> {
    type Target = Option<NonNull<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Debug> Debug for Ptr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(ptr) => {
                if f.alternate() {
                    writeln!(f, "{ptr:p} -> {:#?} ", unsafe { ptr.as_ref() })
                } else {
                    writeln!(f, "{ptr:p} -> {:?} ", unsafe { ptr.as_ref() })
                }
            }
            None => {
                writeln!(f, "(null)")
            }
        }
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Default)]
pub struct CStrDisp(*const c_char);

impl CStrDisp {
    pub fn get(&self) -> Option<&CStr> {
        unsafe { (!self.0.is_null()).then(|| CStr::from_ptr(self.0)) }
    }
    const fn null() -> Self {
        Self(std::ptr::null())
    }

    pub fn from_ptr(ptr: *const c_char) -> Self {
        ptr.into()
    }
}

impl From<*const c_char> for CStrDisp {
    fn from(value: *const c_char) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for CStrDisp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_null() {
            return write!(f, "(null)");
        }
        write!(f, "{}", unsafe { CStr::from_ptr(self.0) }.to_string_lossy())
    }
}

impl std::fmt::Debug for CStrDisp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_null() {
            return write!(f, "(null)");
        }
        write!(
            f,
            "{:?}",
            unsafe { CStr::from_ptr(self.0) }
                .to_string_lossy()
                .to_string()
        )
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ScrapModLoaderFFI {
    pub base: *const (),
    pub cprint: unsafe extern "C" fn(u32, *const c_char),
    pub log: unsafe extern "C" fn(*const c_char, *const c_char),
}

#[repr(C)]
#[derive(Debug)]
pub struct HashNode<T = *const ()> {
    pub data: T,
    pub key: CStrDisp,
    pub next: Option<NonNull<Self>>,
}

#[repr(C)]
pub struct HashTable<T> {
    pub size: u32,
    pub table: *const Option<NonNull<HashNode<T>>>,
    pub locked: u8,
    pub case_sensitive: u8,
    pub flags: [u8; 2],
}

impl<T> HashTable<T> {
    fn hash(&self, key: &[u8]) -> usize {
        let mut hash: u32 = 0;
        let case_sensitive = self.case_sensitive != 0;

        for &byte in key {
            let mut c = byte;
            if !case_sensitive && c.is_ascii_uppercase() {
                c = c.to_ascii_lowercase()
            }
            hash = hash.wrapping_shl(4).wrapping_add(c as u32);
            if hash & 0xF000_0000 != 0 {
                let high = (hash >> 24) & 0xF0;
                hash ^= high;
                hash &= 0x0FFF_FFFF;
            }
        }
        (hash % self.size) as usize
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        let buckets = unsafe { std::slice::from_raw_parts(self.table, self.size as usize) };
        let mut node = buckets[self.hash(key.as_bytes())]?;
        let key = CString::from_str(key).ok()?;
        loop {
            let node_ref = unsafe { node.as_ref() };
            if node_ref.key.get() == Some(key.as_c_str()) {
                return Some(&node_ref.data);
            }
            node = node_ref.next?;
        }
    }

    pub fn iter(&self) -> HashTableIter<'_, T> {
        let len = self.size as usize;
        let buckets = unsafe { std::slice::from_raw_parts(self.table, len) };
        let current_node = if len == 0 {
            None
        } else {
            buckets.first().copied().flatten()
        };
        HashTableIter {
            buckets,
            current_bucket: 0,
            current_node,
        }
    }
}

impl<T: Debug> Debug for HashTable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashTable")
            .field("size", &self.size)
            .field_with("table", |f| {
                let mut map = f.debug_map();
                map.entries(self.iter());
                map.finish()
            })
            .field("locked", &self.locked)
            .field("case_sensitive", &self.case_sensitive)
            .field("flags", &self.flags)
            .finish()
    }
}

/// Dumps the hash table to a nicely formatted string if `T` implements `Debug`.
pub fn dump_hash_table<T: Debug>(ht: &HashTable<T>) -> String {
    format!("{ht:#?}")
}

pub struct HashTableIter<'a, T: 'a> {
    buckets: &'a [Option<NonNull<HashNode<T>>>],
    current_bucket: usize,
    current_node: Option<NonNull<HashNode<T>>>,
}

impl<'a, T: 'a> Iterator for HashTableIter<'a, T> {
    type Item = (&'a CStrDisp, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        while self.current_bucket < self.buckets.len() {
            if let Some(nn) = self.current_node {
                let node = unsafe { nn.as_ref() };
                self.current_node = node.next;
                return Some((&node.key, &node.data));
            }
            // Chain exhausted → advance to next bucket
            self.current_bucket += 1;
            if self.current_bucket < self.buckets.len() {
                self.current_node = self.buckets[self.current_bucket];
            }
        }
        None
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PackIndexEntry {
    pub offset: u32,
    pub size: u32,
    // index in PackedHandles array
    pub packed_idx: u8,
}

pub type PackedIndex = HashTable<PackIndexEntry>;

impl Addressable for PackedIndex {
    const RVA: usize = 0x428994;
}

#[repr(transparent)]
pub struct Mode(u32);

impl Mode {
    pub fn fopen(&self) -> bool {
        self.0 & 0x8 != 0
    }
}

impl std::fmt::Debug for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = match self.0 & 0x7 {
            1 => "rb".to_owned(),
            2 | 6 => "wb".to_owned(),
            3 => "r+b".to_owned(),
            7 => "w+b".to_owned(),
            other => format!("Unknown({other})"),
        };
        f.debug_struct("Mode")
            .field("mode", &mode)
            .field("fopen", &self.fopen())
            .finish()
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PackedHandle {
    vtable: *const (),
    pub filename: CStrDisp,
    pub mode: Mode,
    file: *const (),
    pub bytes_read: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct PackedHandles {
    pub num_open: u32,
    pub handles: [PackedHandle; 0x80],
}

impl Addressable for PackedHandles {
    const RVA: usize = 0x44aea4;
}
