use bitflags::bitflags;
use nom::{IResult, Parser, bytes, multi, number::complete as number};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
pub enum ElfClass {
    Class32 = 1,
    Class64 = 2,
}

#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
pub enum ElfEndian {
    EndianLittle = 1,
    EndianBig = 2,
}

#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
pub enum ElfType {
    Relocatable = 1, // ET_REL
    Executable = 2,  // ET_EXEC
    Shared = 3,      // ET_DYN
    Core = 4,        // ET_CORE
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct SectionFlags: u32 {
        const SHF_WRITE	           = 1 << 0;	/* Writable */
        const SHF_ALLOC	           = 1 << 1;	/* Occupies memory during execution */
        const SHF_EXECINSTR	       = 1 << 2;	/* Executable */
        const SHF_MERGE	           = 1 << 4;	/* Might be merged */
        const SHF_STRINGS	       = 1 << 5;	/* Contains nul-terminated strings */
        const SHF_INFO_LINK	       = 1 << 6;	/* `sh_info' contains SHT index */
        const SHF_LINK_ORDER	   = 1 << 7;	/* Preserve order after combining */
        const SHF_OS_NONCONFORMING = 1 << 8;	/* Non-standard OS specific handling */
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq, Hash)]
pub enum SectionType {
    ShtNull = 0,                   /* Section header table entry unused */
    ShtProgbits = 1,               /* Program data */
    ShtSymtab = 2,                 /* Symbol table */
    ShtStrtab = 3,                 /* String table */
    ShtRela = 4,                   /* Relocation entries with addends */
    ShtHash = 5,                   /* Symbol hash table */
    ShtDynamic = 6,                /* Dynamic linking information */
    ShtNote = 7,                   /* Notes */
    ShtNobits = 8,                 /* Program space with no data (bss) */
    ShtRel = 9,                    /* Relocation entries, no addends */
    ShtShlib = 10,                 /* Reserved */
    ShtDynsym = 11,                /* Dynamic linker symbol table */
    ShtInitArray = 14,             /* Array of constructors */
    ShtFiniArray = 15,             /* Array of destructors */
    ShtPreinitArray = 16,          /* Array of pre-constructors */
    ShtGroup = 17,                 /* Section group */
    ShtSymtabShndx = 18,           /* Extended section indices */
    ShtRelr = 19,                  /* RELR relative relocations */
    ShtNum = 20,                   /* Number of defined types.  */
    ShtLoos = 0x60000000,          /* Start OS-specific.  */
    LlvmAddrSig = 0x6fff4c03,      /* LLVM Address Signatures */
    ShtGnuAttributes = 0x6ffffff5, /* Object attributes.  */
    ShtGnuHash = 0x6ffffff6,       /* GNU-style hash table.  */
    ShtGnuLiblist = 0x6ffffff7,    /* Prelink library list */
    ShtChecksum = 0x6ffffff8,      /* Checksum for DSO content.  */
    ShtSunwMove = 0x6ffffffa,
    ShtSunwComdat = 0x6ffffffb,
    ShtSunwSyminfo = 0x6ffffffc,
    ShtGnuVerdef = 0x6ffffffd,  /* Version definition section.  */
    ShtGnuVerneed = 0x6ffffffe, /* Version needs section.  */
    ShtGnuVersym = 0x6fffffff,  /* Version symbol table.  */
    X8664Unwind = 0x70000001,
}

#[derive(Debug)]
pub struct ElfHeader {
    class: ElfClass,
    endianness: ElfEndian,
    #[expect(dead_code)]
    os_abi: u8,
    #[expect(dead_code)]
    abi_version: u8,
    pub typ: ElfType,
    #[expect(dead_code)]
    machine: u16,
    #[expect(dead_code)]
    entry: u64,
    phoff: usize,
    shoff: usize,
    #[expect(dead_code)]
    flags: u32,
    #[expect(dead_code)]
    header_size: u16,
    phentsize: usize,
    phnum: usize,
    shentsize: usize,
    shnum: usize,
    pub shstrndx: u16,
}

#[derive(Debug)]
pub struct SectionHeader {
    pub name: usize,
    pub typ: SectionType,
    pub flags: SectionFlags,
    #[expect(dead_code)]
    addr: u64,
    pub offset: usize,
    pub size: usize,
    #[expect(dead_code)]
    link: u32,
    #[expect(dead_code)]
    info: u32,
    pub align: u64,
    #[expect(dead_code)]
    entry_size: u64,
}

#[derive(Debug)]
pub struct SegmentHeader {
    #[expect(dead_code)]
    segment_type: u32,
    #[expect(dead_code)]
    flags: u32,
    #[expect(dead_code)]
    offset: u64,
    #[expect(dead_code)]
    virtual_addr: u64,
    #[expect(dead_code)]
    physical_addr: u64,
    #[expect(dead_code)]
    file_size: u64,
    #[expect(dead_code)]
    mem_size: u64,
    #[expect(dead_code)]
    align: u64,
}

#[derive(Debug)]
pub struct ElfFile {
    pub header: ElfHeader,
    pub sections: Vec<SectionHeader>,
    pub segments: Vec<SegmentHeader>,
}

fn parse_u16<'a>(i: &'a [u8], endianness: ElfEndian) -> IResult<&'a [u8], u16> {
    match endianness {
        ElfEndian::EndianLittle => number::le_u16(i),
        ElfEndian::EndianBig => number::be_u16(i),
    }
}

fn parse_u32<'a>(i: &'a [u8], endianness: ElfEndian) -> IResult<&'a [u8], u32> {
    match endianness {
        ElfEndian::EndianLittle => number::le_u32(i),
        ElfEndian::EndianBig => number::be_u32(i),
    }
}

fn parse_u64<'a>(i: &'a [u8], endianness: ElfEndian) -> IResult<&'a [u8], u64> {
    match endianness {
        ElfEndian::EndianLittle => number::le_u64(i),
        ElfEndian::EndianBig => number::be_u64(i),
    }
}

fn section_header(
    class: ElfClass,
    endianness: ElfEndian,
) -> impl Fn(&[u8]) -> IResult<&[u8], SectionHeader> {
    move |i: &[u8]| match class {
        ElfClass::Class32 => {
            let (i, name) = parse_u32(i, endianness)?;
            let (i, typ) = parse_u32(i, endianness)?;
            let (i, flags) = parse_u32(i, endianness)?;
            let (i, addr) = parse_u32(i, endianness)?;
            let (i, offset) = parse_u32(i, endianness)?;
            let (i, size) = parse_u32(i, endianness)?;
            let (i, link) = parse_u32(i, endianness)?;
            let (i, info) = parse_u32(i, endianness)?;
            let (i, addr_align) = parse_u32(i, endianness)?;
            let (i, entry_size) = parse_u32(i, endianness)?;

            let section_header = SectionHeader {
                name: name as usize,
                typ: SectionType::from_u32(typ).unwrap(),
                flags: SectionFlags::from_bits_truncate(flags),
                addr: addr as u64,
                offset: offset as usize,
                size: size as usize,
                link,
                info,
                align: addr_align as u64,
                entry_size: entry_size as u64,
            };
            Ok((i, section_header))
        }
        ElfClass::Class64 => {
            let (i, name) = parse_u32(i, endianness)?;
            let (i, typ) = parse_u32(i, endianness)?;
            let (i, flags) = parse_u64(i, endianness)?;
            let (i, addr) = parse_u64(i, endianness)?;
            let (i, offset) = parse_u64(i, endianness)?;
            let (i, size) = parse_u64(i, endianness)?;
            let (i, link) = parse_u32(i, endianness)?;
            let (i, info) = parse_u32(i, endianness)?;
            let (i, addr_align) = parse_u64(i, endianness)?;
            let (i, entry_size) = parse_u64(i, endianness)?;

            let section_header = SectionHeader {
                name: name as usize,
                typ: SectionType::from_u32(typ).unwrap(),
                flags: SectionFlags::from_bits_truncate(flags as u32),
                addr,
                offset: offset as usize,
                size: size as usize,
                link,
                info,
                align: addr_align,
                entry_size,
            };
            Ok((i, section_header))
        }
    }
}

fn segment_header(
    class: ElfClass,
    endianness: ElfEndian,
) -> impl Fn(&[u8]) -> IResult<&[u8], SegmentHeader> {
    move |i: &[u8]| match class {
        ElfClass::Class32 => {
            let (i, segment_type) = parse_u32(i, endianness)?;
            let (i, offset) = parse_u32(i, endianness)?;
            let (i, virtual_addr) = parse_u32(i, endianness)?;
            let (i, physical_addr) = parse_u32(i, endianness)?;
            let (i, file_size) = parse_u32(i, endianness)?;
            let (i, mem_size) = parse_u32(i, endianness)?;
            let (i, flags) = parse_u32(i, endianness)?;
            let (i, align) = parse_u32(i, endianness)?;

            Ok((
                i,
                SegmentHeader {
                    segment_type,
                    flags,
                    offset: offset as u64,
                    virtual_addr: virtual_addr as u64,
                    physical_addr: physical_addr as u64,
                    file_size: file_size as u64,
                    mem_size: mem_size as u64,
                    align: align as u64,
                },
            ))
        }
        ElfClass::Class64 => {
            let (i, segment_type) = parse_u32(i, endianness)?;
            let (i, flags) = parse_u32(i, endianness)?;
            let (i, offset) = parse_u64(i, endianness)?;
            let (i, virtual_addr) = parse_u64(i, endianness)?;
            let (i, physical_addr) = parse_u64(i, endianness)?;
            let (i, file_size) = parse_u64(i, endianness)?;
            let (i, mem_size) = parse_u64(i, endianness)?;
            let (i, align) = parse_u64(i, endianness)?;

            Ok((
                i,
                SegmentHeader {
                    segment_type,
                    flags,
                    offset,
                    virtual_addr,
                    physical_addr,
                    file_size,
                    mem_size,
                    align,
                },
            ))
        }
    }
}

fn elf_header(i: &[u8]) -> IResult<&[u8], ElfHeader> {
    let (i, _) = bytes::tag(&b"\x7fELF"[..]).parse(i)?;
    let (i, class) = number::u8(i)?;
    let (i, endianness) = number::u8(i)?;
    let (i, _elfversion) = number::u8(i)?;
    let (i, os_abi) = number::u8(i)?;
    let (i, abi_version) = number::u8(i)?;
    let (i, _) = bytes::take(7usize).parse(i)?;

    let class = ElfClass::from_u8(class).unwrap();
    let endianness = ElfEndian::from_u8(endianness).unwrap();

    let (i, typ) = parse_u16(i, endianness)?;
    let (i, machine) = parse_u16(i, endianness)?;
    let (i, _version) = parse_u32(i, endianness)?;

    let (i, entry) = match class {
        ElfClass::Class32 => {
            let (i, entry) = parse_u32(i, endianness)?;
            (i, entry as u64)
        }
        ElfClass::Class64 => parse_u64(i, endianness)?,
    };
    let (i, phoff) = match class {
        ElfClass::Class32 => {
            let (i, offset) = parse_u32(i, endianness)?;
            (i, offset as u64)
        }
        ElfClass::Class64 => parse_u64(i, endianness)?,
    };
    let (i, shoff) = match class {
        ElfClass::Class32 => {
            let (i, offset) = parse_u32(i, endianness)?;
            (i, offset as u64)
        }
        ElfClass::Class64 => parse_u64(i, endianness)?,
    };

    let (i, flags) = parse_u32(i, endianness)?;
    let (i, header_size) = parse_u16(i, endianness)?;
    let (i, phentsize) = parse_u16(i, endianness)?;
    let (i, phnum) = parse_u16(i, endianness)?;
    let (i, shentsize) = parse_u16(i, endianness)?;
    let (i, shnum) = parse_u16(i, endianness)?;
    let (i, section_name_table_index) = parse_u16(i, endianness)?;

    let elf_header = ElfHeader {
        class,
        endianness,
        os_abi,
        abi_version,
        typ: ElfType::from_u16(typ).unwrap(),
        machine,
        entry,
        phoff: phoff as usize,
        shoff: shoff as usize,
        flags,
        header_size,
        phentsize: phentsize as usize,
        phnum: phnum as usize,
        shentsize: shentsize as usize,
        shnum: shnum as usize,
        shstrndx: section_name_table_index,
    };

    Ok((i, elf_header))
}

pub fn elf(data: &[u8]) -> ElfFile {
    let ehdr = elf_header(&data).unwrap().1;

    let sections: Vec<SectionHeader> =
        multi::many(ehdr.shnum, section_header(ehdr.class, ehdr.endianness))
            .parse(&data[ehdr.shoff..ehdr.shoff + (ehdr.shnum * ehdr.shentsize)])
            .unwrap()
            .1;
    let segments: Vec<SegmentHeader> =
        multi::many(ehdr.phnum, segment_header(ehdr.class, ehdr.endianness))
            .parse(&data[ehdr.phoff..ehdr.phoff + (ehdr.phnum * ehdr.phentsize)])
            .unwrap()
            .1;

    ElfFile {
        header: ehdr,
        sections,
        segments,
    }
}
