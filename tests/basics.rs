use std::ffi::CStr;

use elf_experiments::{
    State,
    elf::{
        ElfClass, ElfEndian, ElfFile, ElfHeader, ElfType, SectionFlags, SectionHeader, SectionType,
    },
    interner::Interner,
    parser,
    writer::Writer,
};

struct PendingSection {
    name: &'static CStr,
    flags: SectionFlags,
    size: usize,
    align: u64,

    offset: u64,
}

pub struct ElfBuilder {
    sections: Vec<PendingSection>,
    wr: Writer,
    shstrtab: Interner<'static>,
    path: &'static str,
}

impl ElfBuilder {
    pub fn new(path: &'static str) -> Self {
        let mut wr = Writer::new(ElfClass::Class64, ElfEndian::EndianLittle);
        wr.seek(wr.elf_header_size() as _);

        let mut shstrtab = Interner::default();
        shstrtab.insert(c".strtab");
        Self {
            sections: vec![],
            shstrtab: shstrtab,
            wr,
            path,
        }
    }

    pub fn progbits(mut self, name: &'static CStr, flags: &str, size: usize, align: u64) -> Self {
        assert!(!name.is_empty(), "section name must not be empty");
        self.shstrtab.insert(name);

        assert!(
            align == 0 || align.is_power_of_two(),
            "alignment must be a power of two or zero"
        );
        self.wr.align(align);

        self.sections.push(PendingSection {
            flags: parse_section_flags(flags),
            name,
            size,
            align,
            offset: self.wr.tell(),
        });

        assert!(self.sections.len() < 10);
        let ch = self.sections.len() as u8 + 0x40;
        for _ in 0..size {
            self.wr.write_bytes(&[ch]);
        }

        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        let shstrtab_start = self.wr.tell() as usize;
        self.wr.write_bytes(self.shstrtab.bytes());
        let shstrtab_len = self.wr.tell() as usize - shstrtab_start;

        let sections_start = self.wr.tell();
        self.wr.write_null_section();
        self.wr.write_shdr(&SectionHeader {
            name: self.shstrtab.offsetof(c".strtab"),
            typ: SectionType::ShtStrtab,
            flags: SectionFlags::empty(),
            addr: 0,
            offset: shstrtab_start,
            size: shstrtab_len,
            link: 0,
            info: 0,
            align: 0,
            entry_size: 0,
        });

        for sec in &self.sections {
            self.wr.write_shdr(&SectionHeader {
                name: self.shstrtab.offsetof(sec.name),
                typ: SectionType::ShtProgbits,
                flags: sec.flags,
                addr: 0,
                offset: sec.offset as usize,
                size: sec.size,
                link: 0,
                info: 0,
                align: sec.align,
                entry_size: 0,
            });
        }

        let shnum = self.sections.len() + 2;
        let elf_header_size = self.wr.elf_header_size();
        let phentsize = self.wr.phentsize();
        let shentsize = self.wr.shentsize();

        self.wr.rewind();
        self.wr.write_ehdr(ElfHeader {
            class: ElfClass::Class64,
            endianness: ElfEndian::EndianLittle,
            os_abi: 0,
            abi_version: 0,
            typ: ElfType::Relocatable,
            machine: 0,
            entry: 0,
            phoff: 0,
            shoff: sections_start as usize,
            flags: 0,
            header_size: elf_header_size as u16,
            phentsize: phentsize as u16,
            phnum: 0,
            shentsize: shentsize as u16,
            shnum: shnum as u16,
            shstrndx: 1,
        });

        self.wr.into_inner()
    }

    pub fn link(self) -> Vec<u8> {
        let mut state = State::new();
        state.override_entry(0);

        let path = self.path;
        let finish = self.finish();
        state.process_input_file(path, &finish);

        state.emit()
    }
}

fn parse_section_flags(flags: &str) -> SectionFlags {
    let mut parsed = SectionFlags::empty();

    for flag in flags.chars() {
        match flag {
            'A' | 'a' => parsed |= SectionFlags::Alloc,
            'W' | 'w' => parsed |= SectionFlags::Write,
            'X' | 'x' => parsed |= SectionFlags::ExecInstr,
            _ => panic!("unknown section flag: {flag}"),
        }
    }

    parsed
}

fn assert_null_section(elf: &ElfFile) {
    assert_eq!(
        elf.sections[0],
        SectionHeader {
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
        }
    )
}

fn assert_strtab(elf: &ElfFile, strings: &[u8]) {
    let shdr = &elf.sections[1];
    let data = &elf.data[shdr.offset..][..shdr.size];

    assert_eq!(shdr.typ, SectionType::ShtStrtab);
    assert_eq!(shdr.flags, SectionFlags::empty());
    assert_eq!(data, strings);
}

#[track_caller]
fn assert_data(elf: &ElfFile, section: usize, data: &[u8]) {
    let shdr = &elf.sections[section];
    assert_eq!(&elf.data[shdr.offset..][..shdr.size], data);
}

#[track_caller]
fn assert_name(elf: &ElfFile, section: usize, name: &CStr) {
    let shdr = &elf.sections[section];
    let strtab = &elf.data[elf.sections[1].offset..];
    let namestr = CStr::from_bytes_until_nul(&strtab[shdr.name..]).unwrap();
    assert_eq!(namestr, name);
}

#[test]
fn basics() {
    let data = ElfBuilder::new("input.o")
        .progbits(c".text", "AX", 16, 16)
        .progbits(c".data", "AW", 8, 8)
        .link();
    let elf = parser::elf(&data);

    assert_eq!(elf.header.typ, ElfType::Executable);
    assert_eq!(elf.sections.len(), 4);
    assert_eq!(elf.header.shnum, elf.sections.len() as u16);
    assert_eq!(elf.segments.len(), 2);
    assert_eq!(elf.header.phnum, elf.segments.len() as u16);

    assert_null_section(&elf);
    assert_strtab(&elf, b"\0.strtab\0.text\0.data\0");

    assert_eq!(elf.sections[2].typ, SectionType::ShtProgbits);
    assert_name(&elf, 2, c".data");
    assert_data(&elf, 2, b"BBBBBBBB");
    assert_eq!(elf.sections[2].align % 8, 0);
    assert_eq!(elf.sections[2].addr, 0x400000);

    assert_eq!(elf.sections[3].typ, SectionType::ShtProgbits);
    assert_name(&elf, 3, c".text");
    assert_data(&elf, 3, b"AAAAAAAAAAAAAAAA");
    assert_eq!(elf.sections[3].addr, 0x401000);

    assert_eq!(elf.segments[0].virtual_addr, 0x400000);
    assert_eq!(elf.segments[0].offset, elf.sections[2].offset as u64);
    assert_eq!(elf.segments[0].mem_size, elf.sections[2].size as u64);
    assert_eq!(elf.segments[1].virtual_addr, 0x401000);
    assert_eq!(elf.segments[1].offset, elf.sections[3].offset as u64);
    assert_eq!(elf.segments[1].mem_size, elf.sections[3].size as u64);
}
