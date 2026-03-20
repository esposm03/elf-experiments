use std::{env, fs, num::NonZeroUsize};

use nom::{
    Err, IResult, Parser,
    branch::alt,
    bytes,
    error::{Error, ErrorKind},
};

fn main() {
    let path = env::args().nth(1).expect("You didn't provide an argument!");
    let data = fs::read(path).expect("Failed to read input file");
    elf_ident(&data).unwrap();
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

#[derive(Debug)]
pub enum ElfClass {
    Class32,
    Class64,
}

const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

#[derive(Debug)]
pub enum ElfEndian {
    EndianLittle,
    EndianBig,
}

#[derive(Debug)]
pub struct ElfHeader {
    class: ElfClass,
    endianness: ElfEndian,
}

fn elf_ident(i: &[u8]) -> IResult<&[u8], ElfHeader> {
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
    let (i, _elfversion) = tag1(1)(i)?;
    let (i, _abi) = tag1(0 /* SYSV */).parse(i)?;
    let (i, _abiversion) = tag1(0).parse(i)?;
    let (i, _) = bytes::take(7usize).parse(i)?;

    Ok((i, ElfHeader { class, endianness }))
}
