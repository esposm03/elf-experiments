use std::{
    cmp::max,
    env,
    ffi::CStr,
    fs::{self, File},
    io::{Seek, Write},
};

use indexmap::IndexMap;

use crate::{
    elf::{ElfClass, ElfEndian, ElfHeader, ElfType, SectionFlags, SectionHeader, SectionType},
    interner::Interner,
    writer::Writer,
};

mod elf;
mod interner;
mod parser;
mod writer;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GroupKey<'a> {
    name: &'a CStr,
    typ: SectionType,
    flags: SectionFlags,
}

struct PlainDataSection<'a> {
    data: &'a [u8],
    align: u64,
}

fn main() {
    let files: Vec<(String, Vec<u8>)> = env::args()
        .skip(1)
        .map(|p| (p.clone(), fs::read(p).unwrap()))
        .collect();

    let mut state = State::new("target/b.out");
    for (path, file) in &files {
        state.group_file_sections(path, file);
    }
    // for (k, v) in &state.groups {
    //     println!("{k:?} = {:?}", v.len());
    // }
    state.emit();
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ElfIdent {
    class: ElfClass,
    endian: ElfEndian,
    os_abi: u8,
    abiversion: u8,
    machine: u16,
}

struct State<'a> {
    strtab: Interner<'a>,
    groups: IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,
    ident: Option<ElfIdent>,

    out: File,
}

impl<'a> State<'a> {
    pub fn new(out_path: &str) -> Self {
        Self {
            out: File::create(out_path).unwrap(),
            strtab: Default::default(),
            groups: Default::default(),
            ident: Default::default(),
        }
    }

    pub fn group_file_sections(&mut self, path: &str, file: &'a [u8]) {
        let obj = parser::elf(&file);

        assert_eq!(obj.header.typ, ElfType::Relocatable);
        assert!(obj.segments.is_empty());

        // Verify that e_ident is equal between all processed objects
        let ident = ElfIdent {
            class: obj.header.class,
            endian: obj.header.endianness,
            os_abi: obj.header.os_abi,
            abiversion: obj.header.abi_version,
            machine: obj.header.machine,
        };
        if let Some(x) = &self.ident {
            assert_eq!(*x, ident);
        } else {
            self.ident = Some(ident);
        }

        let shstrtab = &obj.sections[obj.header.shstrndx as usize];
        assert_eq!(shstrtab.typ, SectionType::ShtStrtab);
        let shstrtab = &file[shstrtab.offset..][..shstrtab.size];

        for (i, sec) in obj.sections.iter().enumerate() {
            let name = self.strtab.insert_bytes(&shstrtab[sec.name..]);
            let typ = sec.typ;
            let flags = sec.flags;
            assert!(
                sec.align.is_power_of_two() || sec.align == 0,
                "Invalid alignment for section {i} of object {path:?}: {}",
                sec.align
            );

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

    pub fn emit(&mut self) {
        let ident = self.ident.unwrap();
        let mut wr = Writer::new(ident.class, ident.endian);

        let phnum = 0usize;
        let shnum = self.groups.len() + 2;
        let initial_skip = wr.elf_header_size() + wr.shentsize() * shnum + wr.phentsize() * phnum;

        self.out.seek_relative(initial_skip as i64).unwrap();
        let strtab_off = self.out.stream_position().unwrap();
        let strtab_size = self.emit_strtab();

        let shdrs = self
            .groups
            .iter()
            .map(|(k, v)| Self::emit_section(&mut self.out, &self.strtab, k, v))
            .collect::<Vec<_>>();

        self.out.rewind().unwrap();
        wr.write_ehdr(
            &mut self.out,
            &ElfHeader {
                class: ident.class,
                endianness: ident.endian,
                os_abi: ident.os_abi,
                abi_version: ident.abiversion,
                typ: ElfType::Executable,
                machine: ident.machine,
                entry: 0,
                phoff: 0,
                shoff: wr.elf_header_size() + wr.phentsize() * phnum,
                flags: 0,
                header_size: wr.elf_header_size() as u16,
                phentsize: wr.phentsize() as u16,
                phnum: phnum as u16,
                shentsize: wr.shentsize() as u16,
                shnum: shnum as u16,
                shstrndx: 1,
            },
        );

        // TODO: write program headers
        wr.write_shdr(
            &mut self.out,
            &SectionHeader {
                name: 0,
                typ: SectionType::ShtNull,
                flags: SectionFlags::empty(),
                addr: 0,
                offset: 0,
                size: 0,
                link: 0,
                info: 0,
                align: 0,
                entry_size: 0,
            },
        );
        wr.write_shdr(
            &mut self.out,
            &SectionHeader {
                name: self.strtab.offsetof(c".strtab"),
                typ: SectionType::ShtStrtab,
                flags: SectionFlags::empty(),
                addr: 0,
                offset: strtab_off as usize,
                size: strtab_size,
                link: 0,
                info: 0,
                align: 0,
                entry_size: 0,
            },
        );
        for shdr in shdrs {
            wr.write_shdr(&mut self.out, &shdr);
        }
    }

    pub fn emit_strtab(&mut self) -> usize {
        self.out.write_all(self.strtab.bytes()).unwrap();
        self.strtab.bytes().len()
    }

    pub fn emit_section(
        out: &mut File,
        strtab: &Interner,
        key: &GroupKey,
        src_sections: &[PlainDataSection<'a>],
    ) -> SectionHeader {
        let off = out.stream_position().unwrap();
        let padding = align(off, src_sections[0].align) - off;
        for _ in 0..padding {
            out.write_all(b"\xdd").unwrap();
        }

        let start_offset = out.stream_position().unwrap();
        let mut max_align = 1;

        for src in src_sections {
            let off = out.stream_position().unwrap();
            let padding = align(off, src_sections[0].align) - off;
            max_align = max(max_align, src.align);

            for _ in 0..padding {
                out.write_all(b"\xcc").unwrap();
            }

            out.write_all(src.data).unwrap();
        }

        let end_offset = out.stream_position().unwrap();

        SectionHeader {
            name: strtab.offsetof(key.name),
            typ: key.typ,
            flags: key.flags,
            addr: 0,
            offset: start_offset as usize,
            size: (end_offset - start_offset) as usize,
            link: 0,
            info: 0,
            align: max_align,
            entry_size: 0,
        }
    }
}

fn align(v: u64, align: u64) -> u64 {
    v + (align - 1) & !(align - 1)
}
