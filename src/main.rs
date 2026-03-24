use std::{
    cmp::max,
    env,
    ffi::CStr,
    fs::{self, File},
    io::{Seek, Write},
};

use indexmap::IndexMap;

use crate::{
    elf::{
        ElfClass, ElfEndian, ElfHeader, ElfType, SectionFlags as Shf, SectionFlags, SectionHeader,
        SectionType, SegmentFlags as Pf, SegmentHeader, SegmentType,
    },
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

    let dest = files.last().unwrap().0.strip_suffix(".o").unwrap();
    let mut state = State::new(dest);
    for (path, file) in &files {
        state.group_sections(path, file);
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
    ident: Option<ElfIdent>,
    strtab: Interner<'a>,

    progbits_noalloc: IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,
    progbits_rdonly: IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,
    progbits_rw: IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,
    progbits_rx: IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,
    progbits_rwx: IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,

    out: File,
}

impl<'a> State<'a> {
    pub fn new(out_path: &str) -> Self {
        Self {
            strtab: Default::default(),
            ident: Default::default(),

            progbits_noalloc: IndexMap::new(),
            progbits_rdonly: IndexMap::new(),
            progbits_rw: IndexMap::new(),
            progbits_rx: IndexMap::new(),
            progbits_rwx: IndexMap::new(),

            out: File::create(out_path).unwrap(),
        }
    }

    pub fn group_sections(&mut self, path: &str, file: &'a [u8]) {
        let obj = parser::elf(&file);

        assert_eq!(obj.header.typ, ElfType::Relocatable);
        assert!(obj.segments.is_empty());

        // Verify that e_ident is equal between all processed objects
        self.verify_ident(&obj);

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

            match typ {
                SectionType::ShtNull => {}
                SectionType::ShtStrtab => {}
                // Generic treatment. Especially for PROGBITS sections
                _ => {
                    let groupkey = GroupKey { name, typ, flags };
                    let data = PlainDataSection {
                        data: &file[sec.offset..][..sec.size],
                        align: sec.align,
                    };

                    let group = if flags.contains(Shf::Alloc | Shf::Write | Shf::ExecInstr) {
                        &mut self.progbits_rwx
                    } else if flags.contains(Shf::Alloc | Shf::Write) {
                        &mut self.progbits_rw
                    } else if flags.contains(Shf::Alloc | Shf::ExecInstr) {
                        &mut self.progbits_rx
                    } else if flags.contains(Shf::Alloc) {
                        &mut self.progbits_rdonly
                    } else {
                        &mut self.progbits_noalloc
                    };

                    group.entry(groupkey).or_default().push(data);
                }
            };
        }
    }

    fn verify_ident(&mut self, obj: &elf::ElfFile) {
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
    }

    pub fn emit(&mut self) {
        let ident = self.ident.unwrap();
        let mut wr = Writer::new(ident.class, ident.endian);

        let count_ph = |s: &IndexMap<_, _>| {
            if s.is_empty() { 0 } else { 1 }
        };

        let phnum = count_ph(&self.progbits_rwx)
            + count_ph(&self.progbits_rw)
            + count_ph(&self.progbits_rx)
            + count_ph(&self.progbits_rdonly);
        let shnum = self.progbits_rwx.len()
            + self.progbits_rx.len()
            + self.progbits_rw.len()
            + self.progbits_rdonly.len()
            + self.progbits_noalloc.len()
            + 2; // there is also a null section and a strtab
        let initial_skip = wr.elf_header_size() + wr.shentsize() * shnum + wr.phentsize() * phnum;

        let mut shdrs = Vec::with_capacity(shnum);
        let mut phdrs = Vec::with_capacity(phnum);

        // Skip over the headers, and emit the strtab and the sections that are not Alloc
        self.out.seek_relative(initial_skip as i64).unwrap();
        let strtab_off = self.out.stream_position().unwrap();
        let strtab_size = self.emit_strtab();
        self.emit_noalloc_sections(&mut shdrs);

        // Emit sections with respective padding. Also popuplates program headers and section headers in the meantime
        #[rustfmt::skip]
        Self::emit_group(&mut self.out, &self.strtab, &self.progbits_rdonly, Pf::Read, &mut shdrs, &mut phdrs);
        #[rustfmt::skip]
        Self::emit_group(&mut self.out, &self.strtab, &self.progbits_rw, Pf::Read | Pf::Write, &mut shdrs, &mut phdrs);
        #[rustfmt::skip]
        Self::emit_group(&mut self.out, &self.strtab, &self.progbits_rx, Pf::Read | Pf::Exec, &mut shdrs, &mut phdrs);
        #[rustfmt::skip]
        Self::emit_group(&mut self.out, &self.strtab, &self.progbits_rwx, Pf::Read | Pf::Write | Pf::Exec, &mut shdrs, &mut phdrs);

        // Emit the elf header
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
                entry: 0x400000,
                phoff: wr.elf_header_size(),
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

        for ph in phdrs {
            wr.write_phdr(&mut self.out, &ph);
        }

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

    pub fn emit_noalloc_sections(&mut self, res: &mut Vec<SectionHeader>) {
        for (k, v) in &self.progbits_noalloc {
            res.push(Self::emit_section_data(&mut self.out, &self.strtab, k, v))
        }
    }

    pub fn emit_group(
        out: &mut File,
        strtab: &Interner,
        group: &IndexMap<GroupKey<'a>, Vec<PlainDataSection<'a>>>,
        flags: Pf,
        shdrs: &mut Vec<SectionHeader>,
        phdrs: &mut Vec<SegmentHeader>,
    ) {
        if group.is_empty() {
            return;
        }

        let page_size = 0x1000; // TODO: this should be based on architecture

        // Pad to a multiple of page size
        emit_padding(out, page_size);

        // Emit all data, recording offsets
        let start = out.stream_position().unwrap();
        for (k, v) in group {
            shdrs.push(State::emit_section_data(out, &strtab, k, v))
        }
        let end = out.stream_position().unwrap();

        // Create the program header
        assert!(phdrs.is_sorted_by_key(|h| h.virtual_addr));
        let last_phdr = phdrs
            .last()
            .map(|h| (h.virtual_addr, h.mem_size))
            .unwrap_or((0x400000, 0));
        phdrs.push(SegmentHeader {
            segment_type: SegmentType::Load,
            flags,
            offset: start,
            virtual_addr: align(last_phdr.0 + last_phdr.1, page_size),
            physical_addr: 0,
            file_size: end - start,
            mem_size: end - start,
            align: page_size,
        });
    }

    pub fn emit_section_data(
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

fn emit_padding(out: &mut File, alignment: u64) {
    let off = out.stream_position().unwrap();
    for _ in 0..(align(off, alignment) - off) {
        out.write_all(b"\0").unwrap();
    }
}
