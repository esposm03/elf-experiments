use std::{env, fs, num::NonZeroUsize};

use nom::{
    Err, IResult, Parser,
    branch::alt,
    bytes,
    error::{Error, ErrorKind},
    number::complete::{be_u16, be_u32, be_u64, le_u16, le_u32, le_u64},
};

fn main() {
    let path = env::args().nth(1).expect("You didn't provide an argument!");
    let data = fs::read(path).expect("Failed to read input file");
    dbg!(elf_header(&data).unwrap().1);
}

fn tag1(tag: u8) -> impl Fn(&[u8]) -> IResult<&[u8], u8> {
    move |i: &[u8]| match i.get(0) {
        None => Err(Err::Incomplete(nom::Needed::Size(
            NonZeroUsize::new(1).unwrap(),
        ))),
        Some(x) if *x != tag => Err(Err::Error(Error {
            input: i,
            code: ErrorKind::Tag,
        })),
        Some(_) => Ok((&i[1..], tag)),
    }
}

const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const EV_CURRENT: u32 = 1;
const EI_NIDENT: usize = 16;

#[derive(Debug, Clone, Copy)]
pub enum ElfClass {
    Class32,
    Class64,
}

const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

#[derive(Debug, Clone, Copy)]
pub enum ElfEndian {
    EndianLittle,
    EndianBig,
}

#[derive(Debug)]
pub struct ElfHeader {
    #[expect(dead_code)]
    class: ElfClass,
    #[expect(dead_code)]
    endianness: ElfEndian,
    #[expect(dead_code)]
    os_abi: u8,
    #[expect(dead_code)]
    abi_version: u8,
    #[expect(dead_code)]
    elf_type: u16,
    #[expect(dead_code)]
    machine: u16,
    #[expect(dead_code)]
    entry: u64,
    #[expect(dead_code)]
    program_header_offset: u64,
    #[expect(dead_code)]
    section_header_offset: u64,
    #[expect(dead_code)]
    flags: u32,
    #[expect(dead_code)]
    header_size: u16,
    #[expect(dead_code)]
    program_header_entry_size: u16,
    #[expect(dead_code)]
    program_header_entry_count: u16,
    #[expect(dead_code)]
    section_header_entry_size: u16,
    #[expect(dead_code)]
    section_header_entry_count: u16,
    #[expect(dead_code)]
    section_name_table_index: u16,
}

fn parse_u16<'a>(i: &'a [u8], endianness: ElfEndian) -> IResult<&'a [u8], u16> {
    match endianness {
        ElfEndian::EndianLittle => le_u16(i),
        ElfEndian::EndianBig => be_u16(i),
    }
}

fn parse_u32<'a>(i: &'a [u8], endianness: ElfEndian) -> IResult<&'a [u8], u32> {
    match endianness {
        ElfEndian::EndianLittle => le_u32(i),
        ElfEndian::EndianBig => be_u32(i),
    }
}

fn parse_u64<'a>(i: &'a [u8], endianness: ElfEndian) -> IResult<&'a [u8], u64> {
    match endianness {
        ElfEndian::EndianLittle => le_u64(i),
        ElfEndian::EndianBig => be_u64(i),
    }
}

fn elf_header(i: &[u8]) -> IResult<&[u8], ElfHeader> {
    let (i, _) = bytes::tag(&b"\x7fELF"[..]).parse(i)?;
    let (i, class) = alt((
        tag1(ELFCLASS32).map(|_| ElfClass::Class32),
        tag1(ELFCLASS64).map(|_| ElfClass::Class64),
    ))
    .parse(i)?;
    let (i, endianness) = alt((
        tag1(ELFDATA2LSB).map(|_| ElfEndian::EndianLittle),
        tag1(ELFDATA2MSB).map(|_| ElfEndian::EndianBig),
    ))
    .parse(i)?;
    let (i, _elfversion) = tag1(EV_CURRENT as u8)(i)?;
    let (i, os_abi) = nom::number::complete::u8(i)?;
    let (i, abi_version) = nom::number::complete::u8(i)?;
    let (i, _) = bytes::take(EI_NIDENT - 9).parse(i)?;

    let (i, elf_type) = parse_u16(i, endianness)?;
    let (i, machine) = parse_u16(i, endianness)?;
    let (i, version) = parse_u32(i, endianness)?;
    if version != EV_CURRENT {
        return Err(Err::Error(Error {
            input: i,
            code: ErrorKind::Tag,
        }));
    }

    let (i, entry) = match class {
        ElfClass::Class32 => {
            let (i, entry) = parse_u32(i, endianness)?;
            (i, entry as u64)
        }
        ElfClass::Class64 => parse_u64(i, endianness)?,
    };
    let (i, program_header_offset) = match class {
        ElfClass::Class32 => {
            let (i, offset) = parse_u32(i, endianness)?;
            (i, offset as u64)
        }
        ElfClass::Class64 => parse_u64(i, endianness)?,
    };
    let (i, section_header_offset) = match class {
        ElfClass::Class32 => {
            let (i, offset) = parse_u32(i, endianness)?;
            (i, offset as u64)
        }
        ElfClass::Class64 => parse_u64(i, endianness)?,
    };

    let (i, flags) = parse_u32(i, endianness)?;
    let (i, header_size) = parse_u16(i, endianness)?;
    let (i, program_header_entry_size) = parse_u16(i, endianness)?;
    let (i, program_header_entry_count) = parse_u16(i, endianness)?;
    let (i, section_header_entry_size) = parse_u16(i, endianness)?;
    let (i, section_header_entry_count) = parse_u16(i, endianness)?;
    let (i, section_name_table_index) = parse_u16(i, endianness)?;

    let elf_header = ElfHeader {
        class,
        endianness,
        os_abi,
        abi_version,
        elf_type,
        machine,
        entry,
        program_header_offset,
        section_header_offset,
        flags,
        header_size,
        program_header_entry_size,
        program_header_entry_count,
        section_header_entry_size,
        section_header_entry_count,
        section_name_table_index,
    };

    Ok((i, elf_header))
}
