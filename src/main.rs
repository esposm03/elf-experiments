use std::{env, fs};

fn main() {
    let path = env::args().nth(1).expect("You didn't provide an argument!");
    let data = fs::read(path).expect("Failed to read input file");
    let obj = parser::elf(&data);

    println!("ELF header:\n{:?}", obj.header);
    println!("Sections:");
    for sec in obj.sections {
        println!("- {sec:?}");
    }
    println!("Segments:");
    for seg in obj.segments {
        println!("- {seg:?}");
    }
}

mod parser {
    use std::num::NonZeroUsize;

    use nom::{
        Err, IResult, Parser,
        branch::alt,
        bytes,
        error::{Error, ErrorKind},
        multi,
        number::complete::{be_u16, be_u32, be_u64, le_u16, le_u32, le_u64},
    };

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
    const ELFDATA2LSB: u8 = 1;
    const ELFDATA2MSB: u8 = 2;

    #[derive(Debug, Clone, Copy)]
    pub enum ElfClass {
        Class32,
        Class64,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum ElfEndian {
        EndianLittle,
        EndianBig,
    }

    #[derive(Debug)]
    pub struct ElfHeader {
        class: ElfClass,
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
        #[expect(dead_code)]
        section_name_table_index: u16,
    }

    #[derive(Debug)]
    pub struct SectionHeader {
        #[expect(dead_code)]
        name: u32,
        #[expect(dead_code)]
        section_type: u32,
        #[expect(dead_code)]
        flags: u64,
        #[expect(dead_code)]
        addr: u64,
        #[expect(dead_code)]
        offset: u64,
        #[expect(dead_code)]
        size: u64,
        #[expect(dead_code)]
        link: u32,
        #[expect(dead_code)]
        info: u32,
        #[expect(dead_code)]
        addr_align: u64,
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

    fn section_header(
        class: ElfClass,
        endianness: ElfEndian,
    ) -> impl Fn(&[u8]) -> IResult<&[u8], SectionHeader> {
        move |i: &[u8]| match class {
            ElfClass::Class32 => {
                let (i, name) = parse_u32(i, endianness)?;
                let (i, section_type) = parse_u32(i, endianness)?;
                let (i, flags) = parse_u32(i, endianness)?;
                let (i, addr) = parse_u32(i, endianness)?;
                let (i, offset) = parse_u32(i, endianness)?;
                let (i, size) = parse_u32(i, endianness)?;
                let (i, link) = parse_u32(i, endianness)?;
                let (i, info) = parse_u32(i, endianness)?;
                let (i, addr_align) = parse_u32(i, endianness)?;
                let (i, entry_size) = parse_u32(i, endianness)?;

                Ok((
                    i,
                    SectionHeader {
                        name,
                        section_type,
                        flags: flags as u64,
                        addr: addr as u64,
                        offset: offset as u64,
                        size: size as u64,
                        link,
                        info,
                        addr_align: addr_align as u64,
                        entry_size: entry_size as u64,
                    },
                ))
            }
            ElfClass::Class64 => {
                let (i, name) = parse_u32(i, endianness)?;
                let (i, section_type) = parse_u32(i, endianness)?;
                let (i, flags) = parse_u64(i, endianness)?;
                let (i, addr) = parse_u64(i, endianness)?;
                let (i, offset) = parse_u64(i, endianness)?;
                let (i, size) = parse_u64(i, endianness)?;
                let (i, link) = parse_u32(i, endianness)?;
                let (i, info) = parse_u32(i, endianness)?;
                let (i, addr_align) = parse_u64(i, endianness)?;
                let (i, entry_size) = parse_u64(i, endianness)?;

                Ok((
                    i,
                    SectionHeader {
                        name,
                        section_type,
                        flags,
                        addr,
                        offset,
                        size,
                        link,
                        info,
                        addr_align,
                        entry_size,
                    },
                ))
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
            elf_type,
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
            section_name_table_index,
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
}
