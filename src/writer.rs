use std::io::Write;

use crate::elf::ElfClass::{Class32, Class64};
use crate::elf::ElfEndian::{EndianBig, EndianLittle};
use crate::elf::{ElfClass, ElfEndian, ElfHeader, SectionHeader, SegmentHeader};

pub struct Writer {
    class: ElfClass,
    endian: ElfEndian,
}

impl Writer {
    pub fn new(class: ElfClass, endian: ElfEndian) -> Self {
        Self { class, endian }
    }

    fn write_u8(&self, wr: &mut dyn Write, v: u8) {
        wr.write_all(&[v]).unwrap()
    }

    fn write_u16(&self, wr: &mut dyn Write, v: u16) {
        wr.write_all(&match self.endian {
            EndianBig => v.to_be_bytes(),
            EndianLittle => v.to_le_bytes(),
        })
        .unwrap()
    }

    fn write_u32(&self, wr: &mut dyn Write, v: u32) {
        wr.write_all(&match self.endian {
            EndianBig => v.to_be_bytes(),
            EndianLittle => v.to_le_bytes(),
        })
        .unwrap()
    }

    fn write_u64(&self, wr: &mut dyn Write, v: u64) {
        wr.write_all(&match self.endian {
            EndianBig => v.to_be_bytes(),
            EndianLittle => v.to_le_bytes(),
        })
        .unwrap()
    }

    fn write_usize(&self, wr: &mut dyn Write, v: usize) {
        match (self.endian, self.class) {
            (EndianLittle, Class32) => wr.write_all(&(v as u32).to_le_bytes()),
            (EndianLittle, Class64) => wr.write_all(&(v as u64).to_le_bytes()),
            (EndianBig, Class32) => wr.write_all(&(v as u32).to_be_bytes()),
            (EndianBig, Class64) => wr.write_all(&(v as u64).to_be_bytes()),
        }
        .unwrap();
    }

    pub fn write_ehdr(&mut self, wr: &mut dyn Write, ehdr: &ElfHeader) {
        assert_eq!(self.class, ehdr.class);
        assert_eq!(self.endian, ehdr.endianness);

        // e_ident
        self.write_u8(wr, b'\x7f');
        self.write_u8(wr, b'E');
        self.write_u8(wr, b'L');
        self.write_u8(wr, b'F');
        self.write_u8(wr, self.class as u8);
        self.write_u8(wr, self.endian as u8);
        self.write_u8(wr, 1);
        self.write_u8(wr, ehdr.os_abi);
        self.write_u8(wr, ehdr.abi_version);
        for _ in 0..7 {
            self.write_u8(wr, 0);
        }

        self.write_u16(wr, ehdr.typ as u16); // e_type
        self.write_u16(wr, ehdr.machine); // e_machine
        self.write_u32(wr, 1); // e_version

        self.write_usize(wr, ehdr.entry as usize); // e_entry
        self.write_usize(wr, ehdr.phoff); // e_phoff
        self.write_usize(wr, ehdr.shoff); // e_shoff

        self.write_u32(wr, ehdr.flags); // e_flags
        self.write_u16(wr, ehdr.header_size); // e_ehsize
        self.write_u16(wr, ehdr.phentsize as u16); // e_phentsize
        self.write_u16(wr, ehdr.phnum as u16); // e_phnum
        self.write_u16(wr, ehdr.shentsize as u16); // e_shentsize
        self.write_u16(wr, ehdr.shnum as u16); // e_shnum
        self.write_u16(wr, ehdr.shstrndx); // e_shstrndx
    }

    pub fn write_shdr(&self, wr: &mut dyn Write, shdr: &SectionHeader) {
        self.write_u32(wr, shdr.name as u32);
        self.write_u32(wr, shdr.typ as u32);

        match self.class {
            Class32 => {
                self.write_u32(wr, shdr.flags.bits());
                self.write_usize(wr, shdr.addr as usize);
                self.write_usize(wr, shdr.offset);
                self.write_u32(wr, shdr.size as u32);
                self.write_u32(wr, shdr.link);
                self.write_u32(wr, shdr.info);
                self.write_u32(wr, shdr.align as u32);
                self.write_u32(wr, shdr.entry_size as u32);
            }
            Class64 => {
                self.write_u64(wr, shdr.flags.bits() as u64);
                self.write_usize(wr, shdr.addr as usize);
                self.write_usize(wr, shdr.offset);
                self.write_u64(wr, shdr.size as u64);
                self.write_u32(wr, shdr.link);
                self.write_u32(wr, shdr.info);
                self.write_u64(wr, shdr.align);
                self.write_u64(wr, shdr.entry_size);
            }
        }
    }

    #[expect(dead_code)]
    pub fn write_phdr(&self, wr: &mut dyn Write, phdr: &SegmentHeader) {
        match self.class {
            Class32 => {
                self.write_u32(wr, phdr.segment_type);
                self.write_usize(wr, phdr.offset as usize);
                self.write_usize(wr, phdr.virtual_addr as usize);
                self.write_usize(wr, phdr.physical_addr as usize);
                self.write_u32(wr, phdr.file_size as u32);
                self.write_u32(wr, phdr.mem_size as u32);
                self.write_u32(wr, phdr.flags);
                self.write_u32(wr, phdr.align as u32);
            }
            Class64 => {
                self.write_u32(wr, phdr.segment_type);
                self.write_u32(wr, phdr.flags);
                self.write_usize(wr, phdr.offset as usize);
                self.write_usize(wr, phdr.virtual_addr as usize);
                self.write_usize(wr, phdr.physical_addr as usize);
                self.write_u64(wr, phdr.file_size);
                self.write_u64(wr, phdr.mem_size);
                self.write_u64(wr, phdr.align);
            }
        }
    }

    pub fn elf_header_size(&self) -> usize {
        match self.class {
            Class32 => 52,
            Class64 => 64,
        }
    }

    pub fn shentsize(&self) -> usize {
        match self.class {
            Class32 => 40,
            Class64 => 64,
        }
    }

    pub fn phentsize(&self) -> usize {
        match self.class {
            Class32 => 32,
            Class64 => 56,
        }
    }
}
