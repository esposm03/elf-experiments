use std::{collections::HashMap, ffi::CStr};

pub struct Interner<'a> {
    strings: HashMap<&'a CStr, usize>,
    buf: Vec<u8>,
}

impl<'a> Default for Interner<'a> {
    fn default() -> Self {
        Self {
            strings: HashMap::from([(c"", 0)]),
            buf: vec![0],
        }
    }
}

impl<'a> Interner<'a> {
    pub fn insert<'b: 'a>(&mut self, s: &'b CStr) -> &'a CStr {
        if !self.strings.contains_key(s) {
            self.strings.insert(s, self.buf.len());
            self.buf.extend_from_slice(s.to_bytes_with_nul());
        }
        s
    }

    pub fn insert_bytes<'b: 'a>(&mut self, s: &'b [u8]) -> &'a CStr {
        let name = CStr::from_bytes_until_nul(s).unwrap();
        self.insert(name)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn offsetof(&self, s: &'a CStr) -> usize {
        self.strings[s]
    }

    pub fn get(&'a self, off: usize) -> &'a CStr {
        CStr::from_bytes_until_nul(&self.buf[off..]).unwrap()
    }
}
