use std::{cmp::max, env, ffi::CStr, fs};

use indexmap::IndexMap;

use crate::{
    elf::{
        ElfClass, ElfEndian, ElfHeader, ElfType, SectionFlags as Shf, SectionFlags, SectionHeader,
        SectionType, SegmentFlags as Pf, SegmentHeader, SegmentType, Sym, SymBind, SymType,
    },
    interner::Interner,
    writer::Writer,
};

mod elf;
mod interner;
mod parser;
mod writer;

struct InputSection<'a> {
    data: &'a [u8],
    align: u64,
    syms: Vec<InputSym<'a>>,
}

#[derive(Clone, Copy, Debug)]
struct InputSym<'a> {
    name: &'a CStr,
    bind: SymBind,
    typ: SymType,
    other: u8,
    value: usize,
    size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct OutputSection<'a> {
    name: &'a CStr,
    typ: SectionType,
    flags: SectionFlags,
}

fn main() {
    let files: Vec<(String, Vec<u8>)> = env::args()
        .skip(1)
        .map(|p| (p.clone(), fs::read(p).unwrap()))
        .collect();

    let dest = files.last().unwrap().0.strip_suffix(".o").unwrap();
    let mut state = State::new(dest);
    for (path, file) in &files {
        state.process_input_file(path, file);
    }
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

    progbits_noalloc: IndexMap<OutputSection<'a>, Vec<InputSection<'a>>>,
    progbits_rdonly: IndexMap<OutputSection<'a>, Vec<InputSection<'a>>>,
    progbits_rw: IndexMap<OutputSection<'a>, Vec<InputSection<'a>>>,
    progbits_rx: IndexMap<OutputSection<'a>, Vec<InputSection<'a>>>,
    progbits_rwx: IndexMap<OutputSection<'a>, Vec<InputSection<'a>>>,

    phdrs: Vec<SegmentHeader>,
    shdrs: Vec<SectionHeader>,
    syms: Vec<Sym>,
    entry: Option<usize>,

    out_path: &'a str,
}

impl<'a> State<'a> {
    pub fn new(out_path: &'a str) -> Self {
        Self {
            strtab: Default::default(),
            ident: Default::default(),

            progbits_noalloc: IndexMap::new(),
            progbits_rdonly: IndexMap::new(),
            progbits_rw: IndexMap::new(),
            progbits_rx: IndexMap::new(),
            progbits_rwx: IndexMap::new(),

            phdrs: vec![],
            shdrs: vec![],
            syms: vec![],
            entry: None,

            out_path,
        }
    }

    pub fn process_input_file(&mut self, path: &str, file: &'a [u8]) {
        let obj = parser::elf(&file);

        assert_eq!(obj.header.typ, ElfType::Relocatable);
        assert!(obj.segments.is_empty());

        // Verify that e_ident is equal between all processed objects
        self.verify_ident(&obj);

        let shstrtab = &obj.sections[obj.header.shstrndx as usize];
        assert_eq!(shstrtab.typ, SectionType::ShtStrtab);
        let shstrtab = &file[shstrtab.offset..][..shstrtab.size];

        for (sndx, sec) in obj.sections.iter().enumerate() {
            let name = self.strtab.insert_bytes(&shstrtab[sec.name..]);
            let typ = sec.typ;
            let flags = sec.flags;
            assert!(
                sec.align.is_power_of_two() || sec.align == 0,
                "Invalid alignment for section {sndx} of object {path:?}: {}",
                sec.align
            );

            match typ {
                SectionType::ShtNull => {}
                SectionType::ShtStrtab => {}
                SectionType::ShtSymtab => {}
                // Generic treatment. Especially for PROGBITS sections
                _ => {
                    // Process symbols of this section
                    let syms = process_input_symbols(&mut self.strtab, file, &obj, sndx);

                    let out_sect = OutputSection { name, typ, flags };
                    let data = InputSection {
                        data: &file[sec.offset..][..sec.size],
                        align: sec.align,
                        syms,
                    };

                    let segment = if flags.contains(Shf::Alloc | Shf::Write | Shf::ExecInstr) {
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

                    segment.entry(out_sect).or_default().push(data);
                }
            }
        }
    }

    pub fn emit(mut self) {
        let ident = self.ident.unwrap();
        let mut wr = Writer::new(self.out_path, ident.class, ident.endian);

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
            + 3; // there are also a null section, a strtab, and a symtab
        let initial_skip = wr.elf_header_size() + wr.shentsize() * shnum + wr.phentsize() * phnum;

        // Skip over the headers
        wr.seek(initial_skip as i64);

        // Emit sections with respective padding. Also popuplates `self.phdrs` and `self.shdrs`
        self.emit_noalloc_sections(&mut wr);
        self.emit_alloc_sections(&mut wr, AllocSectionsKind::R);
        self.emit_alloc_sections(&mut wr, AllocSectionsKind::RW);
        self.emit_alloc_sections(&mut wr, AllocSectionsKind::RX);
        self.emit_alloc_sections(&mut wr, AllocSectionsKind::RWX);

        // Emit symbol table. This has to be done after emitting sections, so that we know the offsets.
        let symtab_off = wr.tell();
        for sym in &self.syms {
            wr.write_sym(sym);
        }
        let symtab_size = wr.tell() - symtab_off;
        self.shdrs.push(SectionHeader {
            name: self.strtab.offsetof(c".symtab"),
            typ: SectionType::ShtSymtab,
            flags: Shf::empty(),
            addr: 0,
            offset: symtab_off as usize,
            size: symtab_size as usize,
            link: 1, // The index of the string table
            info: 0,
            align: 1,
            entry_size: wr.symsize() as u64,
        });

        // Go back to the beginning of the file, and emit the headers
        wr.rewind();
        let elf_header = ElfHeader {
            class: ident.class,
            endianness: ident.endian,
            os_abi: ident.os_abi,
            abi_version: ident.abiversion,
            typ: ElfType::Executable,
            machine: ident.machine,
            entry: self.entry.expect("No _start symbol was defined"),
            phoff: wr.elf_header_size(),
            shoff: wr.elf_header_size() + wr.phentsize() * phnum,
            flags: 0,
            header_size: wr.elf_header_size() as u16,
            phentsize: wr.phentsize() as u16,
            phnum: phnum as u16,
            shentsize: wr.shentsize() as u16,
            shnum: shnum as u16,
            shstrndx: 1,
        };
        wr.write_ehdr(elf_header);

        for ph in &self.phdrs {
            wr.write_phdr(ph);
        }

        wr.write_null_section();
        for shdr in &self.shdrs {
            wr.write_shdr(shdr);
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

    fn emit_noalloc_sections(&mut self, wr: &mut Writer) {
        let strtab_off = wr.tell();
        let strtab_size = self.strtab.bytes().len();
        wr.write_bytes(self.strtab.bytes());
        self.shdrs.push(SectionHeader {
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
        });

        for (out_sect, in_sect) in &self.progbits_noalloc {
            wr.align(in_sect[0].align);
            let start_offset = wr.tell();

            let mut max_align = 1;
            for src in in_sect {
                max_align = max(max_align, src.align);

                wr.align(in_sect[0].align);
                wr.write_bytes(src.data);
            }

            let end_offset = wr.tell();

            self.shdrs.push(SectionHeader {
                name: self.strtab.offsetof(out_sect.name),
                typ: out_sect.typ,
                flags: out_sect.flags,
                addr: 0,
                offset: start_offset as usize,
                size: (end_offset - start_offset) as usize,
                link: 0,
                info: 0,
                align: max_align,
                entry_size: 0,
            });
        }
    }

    fn emit_alloc_sections(&mut self, wr: &mut Writer, kind: AllocSectionsKind) {
        let (group, flags) = match kind {
            AllocSectionsKind::R => (&self.progbits_rdonly, Pf::Read),
            AllocSectionsKind::RW => (&self.progbits_rw, Pf::Read | Pf::Write),
            AllocSectionsKind::RX => (&self.progbits_rx, Pf::Read | Pf::Exec),
            AllocSectionsKind::RWX => (&self.progbits_rwx, Pf::Read | Pf::Write | Pf::Exec),
        };

        if group.is_empty() {
            return;
        }

        assert!(self.phdrs.is_sorted_by_key(|h| h.virtual_addr));
        let (last_phdr_addr, last_phdr_size) = self
            .phdrs
            .last()
            .map(|h| (h.virtual_addr, h.mem_size))
            .unwrap_or((0x400000, 0));
        let page_size = 0x1000; // TODO: this should be based on architecture

        // Pad to a multiple of page size
        wr.align(page_size);
        let mut addr = last_phdr_addr as usize;

        // Emit all data, recording offsets
        let start = wr.tell();
        for (k, v) in group {
            addr += wr.align(v[0].align);

            let start_offset = wr.tell();
            let shndx = self.shdrs.len();

            let mut max_align = 1;
            for src in v {
                max_align = max(max_align, src.align);

                addr += wr.align(v[0].align);

                wr.write_bytes(src.data);

                for sym in &src.syms {
                    self.syms.push(Sym {
                        name: self.strtab.offsetof(sym.name) as u32,
                        shndx: shndx as u16,
                        value: addr + sym.value,
                        bind: sym.bind,
                        typ: sym.typ,
                        other: sym.other,
                        size: sym.size,
                    });

                    if sym.name == c"_start" {
                        self.entry = Some(addr + sym.value);
                    }
                }

                addr += src.data.len();
            }

            let end_offset = wr.tell();

            self.shdrs.push(SectionHeader {
                name: self.strtab.offsetof(k.name),
                typ: k.typ,
                flags: k.flags,
                addr: last_phdr_addr,
                offset: start_offset as usize,
                size: (end_offset - start_offset) as usize,
                link: 0,
                info: 0,
                align: max_align,
                entry_size: 0,
            });
        }
        let end = wr.tell();

        // Create the program header
        self.phdrs.push(SegmentHeader {
            segment_type: SegmentType::Load,
            flags,
            offset: start,
            virtual_addr: align(last_phdr_addr + last_phdr_size, page_size),
            physical_addr: 0,
            file_size: end - start,
            mem_size: end - start,
            align: page_size,
        });
    }
}

fn align(v: u64, align: u64) -> u64 {
    v + (align - 1) & !(align - 1)
}

enum AllocSectionsKind {
    R,
    RW,
    RX,
    RWX,
}

fn process_input_symbols<'b>(
    strtab: &mut Interner<'b>,
    file: &'b [u8],
    obj: &elf::ElfFile,
    sndx: usize,
) -> Vec<InputSym<'b>> {
    let syms_strtab = &obj.sections[obj.symtab_strtab];
    let syms_strtab = &file[syms_strtab.offset..][..syms_strtab.size];
    let syms = obj
        .syms
        .iter()
        .filter(|sym| sym.shndx == sndx as u16)
        // .filter(|sym| sym.bind != SymBind::Local)
        .map(|s| InputSym {
            name: strtab.insert_bytes(&syms_strtab[s.name as usize..]),
            bind: s.bind,
            typ: s.typ,
            other: s.other,
            value: s.value,
            size: s.size,
        })
        .collect();
    syms
}
