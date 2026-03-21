use std::{collections::HashSet, ffi::CStr};

#[derive(Default)]
pub struct Interner<'a> {
    strings: HashSet<&'a CStr>,
}

impl<'a> Interner<'a> {
    pub fn insert<'b: 'a>(&mut self, s: &'b CStr) -> &'a CStr {
        self.strings.insert(s);
        s
    }

    pub fn insert_bytes<'b: 'a>(&mut self, s: &'b [u8]) -> &'a CStr {
        let name = CStr::from_bytes_until_nul(s).unwrap();
        self.insert(name)
    }
}
