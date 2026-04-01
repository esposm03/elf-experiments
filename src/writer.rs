use std::fs::{File, Permissions};
use std::io::{BufWriter, Seek, Write};
use std::os::unix::fs::PermissionsExt;

use crate::elf::ElfClass::{Class32, Class64};
use crate::elf::ElfEndian::{EndianBig, EndianLittle};
use crate::elf::{
    ElfClass, ElfEndian, ElfHeader, SectionFlags, SectionHeader, SectionType, SegmentHeader, Sym,
};

pub struct Writer {
    class: ElfClass,
    endian: ElfEndian,

    wr: BufWriter<File>,
    head: u64,
}

impl Writer {
    pub fn new(path: &str, class: ElfClass, endian: ElfEndian) -> Self {
        let file = File::create(path).unwrap();
        file.set_permissions(Permissions::from_mode(0o755)).unwrap();
        Self {
            class,
            endian,
            wr: BufWriter::new(file),
            head: 0,
        }
    }

    pub fn seek(&mut self, off: i64) {
        self.wr.seek_relative(off).unwrap();
        self.head = self.head.saturating_add_signed(off);
    }

    pub fn tell(&self) -> u64 {
        self.head
    }

    pub fn rewind(&mut self) {
        self.wr.rewind().unwrap();
        self.head = 0;
    }

    fn write_u8(&mut self, v: u8) {
        self.write_bytes(&[v])
    }

    fn write_u16(&mut self, v: u16) {
        self.write_bytes(&match self.endian {
            EndianBig => v.to_be_bytes(),
            EndianLittle => v.to_le_bytes(),
        })
    }

    fn write_u32(&mut self, v: u32) {
        self.write_bytes(&match self.endian {
            EndianBig => v.to_be_bytes(),
            EndianLittle => v.to_le_bytes(),
        })
    }

    fn write_u64(&mut self, v: u64) {
        self.write_bytes(&match self.endian {
            EndianBig => v.to_be_bytes(),
            EndianLittle => v.to_le_bytes(),
        })
    }

    fn write_usize(&mut self, v: usize) {
        match (self.endian, self.class) {
            (EndianLittle, Class32) => self.write_bytes(&(v as u32).to_le_bytes()),
            (EndianLittle, Class64) => self.write_bytes(&(v as u64).to_le_bytes()),
            (EndianBig, Class32) => self.write_bytes(&(v as u32).to_be_bytes()),
            (EndianBig, Class64) => self.write_bytes(&(v as u64).to_be_bytes()),
        }
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.wr.write_all(bytes).unwrap();
        self.head += bytes.len() as u64;
    }

    pub fn write_ehdr(&mut self, ehdr: ElfHeader) {
        assert_eq!(self.class, ehdr.class);
        assert_eq!(self.endian, ehdr.endianness);

        // e_ident
        self.write_u8(b'\x7f');
        self.write_u8(b'E');
        self.write_u8(b'L');
        self.write_u8(b'F');
        self.write_u8(self.class as u8);
        self.write_u8(self.endian as u8);
        self.write_u8(1);
        self.write_u8(ehdr.os_abi);
        self.write_u8(ehdr.abi_version);
        for _ in 0..7 {
            self.write_u8(0);
        }

        self.write_u16(ehdr.typ as u16); // e_type
        self.write_u16(ehdr.machine); // e_machine
        self.write_u32(1); // e_version

        self.write_usize(ehdr.entry as usize); // e_entry
        self.write_usize(ehdr.phoff); // e_phoff
        self.write_usize(ehdr.shoff); // e_shoff

        self.write_u32(ehdr.flags); // e_flags
        self.write_u16(ehdr.header_size); // e_ehsize
        self.write_u16(ehdr.phentsize as u16); // e_phentsize
        self.write_u16(ehdr.phnum as u16); // e_phnum
        self.write_u16(ehdr.shentsize as u16); // e_shentsize
        self.write_u16(ehdr.shnum as u16); // e_shnum
        self.write_u16(ehdr.shstrndx); // e_shstrndx
    }

    pub fn write_shdr(&mut self, shdr: &SectionHeader) {
        self.write_u32(shdr.name as u32);
        self.write_u32(shdr.typ as u32);

        match self.class {
            Class32 => {
                self.write_u32(shdr.flags.bits());
                self.write_usize(shdr.addr as usize);
                self.write_usize(shdr.offset);
                self.write_u32(shdr.size as u32);
                self.write_u32(shdr.link);
                self.write_u32(shdr.info);
                self.write_u32(shdr.align as u32);
                self.write_u32(shdr.entry_size as u32);
            }
            Class64 => {
                self.write_u64(shdr.flags.bits() as u64);
                self.write_usize(shdr.addr as usize);
                self.write_usize(shdr.offset);
                self.write_u64(shdr.size as u64);
                self.write_u32(shdr.link);
                self.write_u32(shdr.info);
                self.write_u64(shdr.align);
                self.write_u64(shdr.entry_size);
            }
        }
    }

    pub fn write_null_section(&mut self) {
        self.write_shdr(&SectionHeader {
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
        });
    }

    pub fn write_phdr(&mut self, phdr: &SegmentHeader) {
        match self.class {
            Class32 => {
                self.write_u32(phdr.segment_type as u32);
                self.write_usize(phdr.offset as usize);
                self.write_usize(phdr.virtual_addr as usize);
                self.write_usize(phdr.physical_addr as usize);
                self.write_u32(phdr.file_size as u32);
                self.write_u32(phdr.mem_size as u32);
                self.write_u32(phdr.flags.bits());
                self.write_u32(phdr.align as u32);
            }
            Class64 => {
                self.write_u32(phdr.segment_type as u32);
                self.write_u32(phdr.flags.bits());
                self.write_usize(phdr.offset as usize);
                self.write_usize(phdr.virtual_addr as usize);
                self.write_usize(phdr.physical_addr as usize);
                self.write_u64(phdr.file_size);
                self.write_u64(phdr.mem_size);
                self.write_u64(phdr.align);
            }
        }
    }

    pub fn write_sym(&mut self, sym: &Sym) {
        match self.class {
            Class32 => {
                self.write_u32(sym.name);
                self.write_usize(sym.value);
                self.write_usize(sym.size);
                self.write_u8(((sym.bind as u8) << 4) + ((sym.typ as u8) & 0xf));
                self.write_u8(sym.other);
                self.write_u16(sym.shndx);
            }
            Class64 => {
                self.write_u32(sym.name);
                self.write_u8(((sym.bind as u8) << 4) + ((sym.typ as u8) & 0xf));
                self.write_u8(sym.other);
                self.write_u16(sym.shndx);
                self.write_usize(sym.value);
                self.write_usize(sym.size);
            }
        }
    }

    pub fn align(&mut self, align: u64) -> usize {
        let aligned = self.head + (align - 1) & !(align - 1);
        let padding = aligned - self.head;
        for _ in 0..padding {
            self.write_bytes(b"\0");
        }
        padding as usize
    }

    pub fn elf_header_size(&mut self) -> usize {
        match self.class {
            Class32 => 52,
            Class64 => 64,
        }
    }

    pub fn shentsize(&mut self) -> usize {
        match self.class {
            Class32 => 40,
            Class64 => 64,
        }
    }

    pub fn phentsize(&mut self) -> usize {
        match self.class {
            Class32 => 32,
            Class64 => 56,
        }
    }

    pub fn symsize(&self) -> usize {
        match self.class {
            Class32 => 16,
            Class64 => 24,
        }
    }
}
