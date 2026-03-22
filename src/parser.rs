use nom::{IResult, Parser, bytes, multi, number::complete as number};
use num_traits::FromPrimitive;

use crate::elf::{
    ElfClass, ElfEndian, ElfFile, ElfHeader, ElfType, SectionFlags, SectionHeader, SectionType,
    SegmentHeader,
};

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
    move |i: &[u8]| -> Result<(&[u8], SectionHeader), nom::Err<nom::error::Error<&[u8]>>> {
        match class {
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
        entry: entry as usize,
        phoff: phoff as usize,
        shoff: shoff as usize,
        flags,
        header_size,
        phentsize: phentsize,
        phnum: phnum,
        shentsize: shentsize,
        shnum: shnum,
        shstrndx: section_name_table_index,
    };

    Ok((i, elf_header))
}

pub fn elf(data: &[u8]) -> ElfFile {
    let ehdr = elf_header(&data).unwrap().1;

    let phnum = ehdr.phnum as usize;
    let phentsize = ehdr.phentsize as usize;
    let shnum = ehdr.shnum as usize;
    let shentsize = ehdr.shentsize as usize;

    let sections: Vec<SectionHeader> =
        multi::many(shnum, section_header(ehdr.class, ehdr.endianness))
            .parse(&data[ehdr.shoff..ehdr.shoff + (shnum * shentsize)])
            .unwrap()
            .1;
    let segments: Vec<SegmentHeader> =
        multi::many(phnum, segment_header(ehdr.class, ehdr.endianness))
            .parse(&data[ehdr.phoff..ehdr.phoff + (phnum * phentsize)])
            .unwrap()
            .1;

    ElfFile {
        header: ehdr,
        sections,
        segments,
    }
}
