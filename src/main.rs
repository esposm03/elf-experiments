use std::{env, ffi::CStr, fs};

use indexmap::IndexMap;

use crate::{
    interner::Interner,
    parser::{ElfType, SectionFlags, SectionType},
};

mod interner;
mod parser;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GroupKey<'a> {
    name: &'a CStr,
    typ: SectionType,
    flags: SectionFlags,
}

struct PlainDataSection<'a> {
    #[expect(dead_code)]
    data: &'a [u8],
    #[expect(dead_code)]
    align: u64,
}

fn main() {
    let files: Vec<Vec<u8>> = env::args()
        .skip(1)
        .map(fs::read)
        .map(Result::unwrap)
        .collect();

    let mut state = State::new();
    for file in &files {
        state.group_file_sections(file);
    }
    for (k, v) in state.groups {
        println!("{k:?} = {:?}", v.len());
    }
}

#[derive(Default)]
struct State<'a> {
    strtab: Interner<'a>,
    groups: IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,
}

impl<'a> State<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn group_file_sections(&mut self, file: &'a [u8]) {
        let obj = parser::elf(&file);

        assert_eq!(obj.header.typ, ElfType::Relocatable);
        assert!(obj.segments.is_empty());

        let shstrtab = &obj.sections[obj.header.shstrndx as usize];
        assert_eq!(shstrtab.typ, SectionType::ShtStrtab);
        let shstrtab = &file[shstrtab.offset..][..shstrtab.size];

        for sec in obj.sections {
            let name = self.strtab.insert_bytes(&shstrtab[sec.name..]);
            let typ = sec.typ;
            let flags = sec.flags;

            if typ == SectionType::ShtNull {
                // Don't need to group null sections
            } else if typ == SectionType::ShtStrtab && !flags.contains(SectionFlags::SHF_ALLOC) {
                // If this is a strtab (but is not ALLOC, i.e. is not .dynstr), skip it
            } else {
                // Generic treatment
                let groupkey = GroupKey { name, typ, flags };
                let data = PlainDataSection {
                    data: &file[sec.offset..][..sec.size],
                    align: sec.align,
                };
                self.groups.entry(groupkey).or_default().push(data);
            }
        }
    }
}
