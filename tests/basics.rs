use std::{io::Read, process::Command};

use elf_experiments::{State, parser};
use insta::assert_yaml_snapshot;
use tempfile::NamedTempFile;

fn compile(src_path: &str) -> Vec<u8> {
    let mut obj_file = NamedTempFile::with_suffix(".o").unwrap();

    let status = Command::new("clang")
        .args(["-target", "x86_64-unknown-linux-gnu", "-c"])
        .arg(src_path)
        .arg("-o")
        .arg(obj_file.path())
        .status()
        .unwrap();
    assert!(status.success(), "Compilation failed");

    let mut obj = vec![];
    obj_file.read_to_end(&mut obj).unwrap();
    obj
}

fn link<I: IntoIterator<Item = &'static str>>(paths: I) -> testtypes::TestElfFile {
    let mut state = State::new();
    state.override_entry(0);

    let files: Vec<_> = paths.into_iter().map(|p| (p, compile(p))).collect();
    for (path, data) in &files {
        state.process_input_file(path, data);
    }

    let data = state.emit().leak();
    parser::elf(data).into()
}

#[test]
fn snapshot() {
    assert_yaml_snapshot!(link(["tests/static.s"]));
}

mod testtypes {
    use std::ffi::CStr;

    use elf_experiments::elf;
    use num_derive::FromPrimitive;
    use num_traits::FromPrimitive;

    pub struct Bytestring(&'static [u8]);

    impl serde::Serialize for Bytestring {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let escaped: Vec<u8> = self.0.escape_ascii().collect();
            let str = String::from_utf8_lossy(&escaped);
            serializer.serialize_str(&str)
        }
    }

    #[derive(serde::Serialize)]
    pub enum TestElfClass {
        Class32 = 1,
        Class64 = 2,
    }

    impl From<elf::ElfClass> for TestElfClass {
        fn from(value: elf::ElfClass) -> Self {
            match value {
                elf::ElfClass::Class32 => Self::Class32,
                elf::ElfClass::Class64 => Self::Class64,
            }
        }
    }

    #[derive(serde::Serialize)]
    pub enum TestElfEndian {
        EndianLittle = 1,
        EndianBig = 2,
    }

    impl From<elf::ElfEndian> for TestElfEndian {
        fn from(value: elf::ElfEndian) -> Self {
            match value {
                elf::ElfEndian::EndianLittle => Self::EndianLittle,
                elf::ElfEndian::EndianBig => Self::EndianBig,
            }
        }
    }

    #[derive(serde::Serialize)]
    pub enum TestElfType {
        Relocatable = 1, // ET_REL
        Executable = 2,  // ET_EXEC
        Shared = 3,      // ET_DYN
        Core = 4,        // ET_CORE
    }

    impl From<elf::ElfType> for TestElfType {
        fn from(value: elf::ElfType) -> Self {
            match value {
                elf::ElfType::Relocatable => Self::Relocatable,
                elf::ElfType::Executable => Self::Executable,
                elf::ElfType::Shared => Self::Shared,
                elf::ElfType::Core => Self::Core,
            }
        }
    }

    #[derive(serde::Serialize)]
    pub struct TestElfHeader {
        pub class: TestElfClass,
        pub endianness: TestElfEndian,
        pub os_abi: u8,
        pub abi_version: u8,
        pub typ: TestElfType,
        pub machine: u16,
        pub entry: usize,
        pub phoff: usize,
        pub shoff: usize,
        pub flags: u32,
        pub header_size: u16,
        pub phentsize: u16,
        pub phnum: u16,
        pub shentsize: u16,
        pub shnum: u16,
        pub shstrndx: u16,
    }

    impl From<&elf::ElfHeader> for TestElfHeader {
        fn from(value: &elf::ElfHeader) -> Self {
            Self {
                class: value.class.into(),
                endianness: value.endianness.into(),
                os_abi: value.os_abi,
                abi_version: value.abi_version,
                typ: value.typ.into(),
                machine: value.machine,
                entry: value.entry,
                phoff: value.phoff,
                shoff: value.shoff,
                flags: value.flags,
                header_size: value.header_size,
                phentsize: value.phentsize,
                phnum: value.phnum,
                shentsize: value.shentsize,
                shnum: value.shnum,
                shstrndx: value.shstrndx,
            }
        }
    }

    bitflags::bitflags! {
        #[derive(serde::Serialize)]
        pub struct TestSectionFlags: u32 {
            const Write	           = 1 << 0;	/* Writable */
            const Alloc	           = 1 << 1;	/* Occupies memory during execution */
            const ExecInstr	       = 1 << 2;	/* Executable */
            const SHF_MERGE	           = 1 << 4;	/* Might be merged */
            const SHF_STRINGS	       = 1 << 5;	/* Contains nul-terminated strings */
            const SHF_INFO_LINK	       = 1 << 6;	/* `sh_info' contains SHT index */
            const SHF_LINK_ORDER	   = 1 << 7;	/* Preserve order after combining */
            const SHF_OS_NONCONFORMING = 1 << 8;	/* Non-standard OS specific handling */
        }
    }

    impl From<elf::SectionFlags> for TestSectionFlags {
        fn from(value: elf::SectionFlags) -> Self {
            // Both are bitflags over `u32`; preserve raw bits.
            Self::from_bits(value.bits()).unwrap()
        }
    }

    #[derive(serde::Serialize, FromPrimitive)]
    pub enum TestSectionType {
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

    impl From<elf::SectionType> for TestSectionType {
        fn from(value: elf::SectionType) -> Self {
            let raw = value as u32;
            TestSectionType::from_u32(raw).unwrap_or_else(|| {
                panic!("unsupported/unknown SectionType value: {raw:#x}");
            })
        }
    }

    #[derive(serde::Serialize)]
    struct TestSection {
        pub name: Bytestring,
        pub typ: TestSectionType,
        pub flags: TestSectionFlags,
        pub addr: u64,
        pub offset: usize,
        pub size: usize,
        pub link: u32,
        pub info: u32,
        pub align: u64,
        pub entry_size: u64,
        pub data: Bytestring,
    }

    impl<'a> From<(&'a elf::ElfFile<'static>, &'a elf::SectionHeader)> for TestSection {
        fn from((elf, shdr): (&'a elf::ElfFile<'static>, &'a elf::SectionHeader)) -> Self {
            let data = &elf.data[shdr.offset..][..shdr.size];
            let strtab = &elf.sections[elf.header.shstrndx as usize];
            let strtab = &elf.data[strtab.offset..][..strtab.size][shdr.name..];
            Self {
                name: Bytestring(CStr::from_bytes_until_nul(strtab).unwrap().to_bytes()),
                typ: shdr.typ.into(),
                flags: shdr.flags.into(),
                addr: shdr.addr,
                offset: shdr.offset,
                size: shdr.size,
                link: shdr.link,
                info: shdr.info,
                align: shdr.align,
                entry_size: shdr.entry_size,
                data: Bytestring(data),
            }
        }
    }

    #[derive(serde::Serialize)]
    pub struct TestSegmentHeader {
        pub segment_type: TestSegmentType,
        pub flags: TestSegmentFlags,
        pub offset: u64,
        pub virtual_addr: u64,
        pub physical_addr: u64,
        pub file_size: u64,
        pub mem_size: u64,
        pub align: u64,
        pub data: Bytestring,
    }

    #[derive(serde::Serialize, FromPrimitive)]
    pub enum TestSegmentType {
        Null = 0,                 /* Program header table entry unused */
        Load = 1,                 /* Loadable program segment */
        Dynamic = 2,              /* Dynamic linking information */
        Interp = 3,               /* Program interpreter */
        Note = 4,                 /* Auxiliary information */
        Shlib = 5,                /* Reserved */
        Phdr = 6,                 /* Entry for header table itself */
        Tls = 7,                  /* Thread-local storage segment */
        Num = 8,                  /* Number of defined types */
        GnuEhFrame = 0x6474e550,  /* GCC .eh_frame_hdr segment */
        GnuStack = 0x6474e551,    /* Indicates stack executability */
        GnuRelro = 0x6474e552,    /* Read-only after relocation */
        GnuProperty = 0x6474e553, /* GNU property */
        GnuSframe = 0x6474e554,   /* SFrame segment.  */
        SunwBss = 0x6ffffffa,     /* Sun Specific segment */
        SunWstack = 0x6ffffffb,   /* Stack segment */
    }

    bitflags::bitflags! {
        #[derive(serde::Serialize)]
        pub struct TestSegmentFlags: u32 {
            const Read             = 1 << 2;
            const Write            = 1 << 1;
            const Exec             = 1 << 0;
        }
    }

    impl From<elf::SegmentFlags> for TestSegmentFlags {
        fn from(value: elf::SegmentFlags) -> Self {
            Self::from_bits(value.bits()).unwrap()
        }
    }

    impl From<elf::SegmentType> for TestSegmentType {
        fn from(value: elf::SegmentType) -> Self {
            let raw = value as u32;
            TestSegmentType::from_u32(raw).unwrap_or_else(|| {
                panic!("unsupported/unknown SegmentType value: {raw:#x}");
            })
        }
    }

    impl From<(&elf::ElfFile<'static>, &elf::SegmentHeader)> for TestSegmentHeader {
        fn from((elf, value): (&elf::ElfFile<'static>, &elf::SegmentHeader)) -> Self {
            let start = value.offset as usize;
            let end = start + (value.file_size as usize);
            let data = &elf.data[start..end];

            Self {
                segment_type: value.segment_type.into(),
                flags: value.flags.into(),
                offset: value.offset,
                virtual_addr: value.virtual_addr,
                physical_addr: value.physical_addr,
                file_size: value.file_size,
                mem_size: value.mem_size,
                align: value.align,
                data: Bytestring(data),
            }
        }
    }

    #[derive(serde::Serialize)]
    pub enum TestSymBind {
        Local = 0,
        Global = 1,
        Weak = 2,
    }

    impl From<elf::SymBind> for TestSymBind {
        fn from(value: elf::SymBind) -> Self {
            match value {
                elf::SymBind::Local => Self::Local,
                elf::SymBind::Global => Self::Global,
                elf::SymBind::Weak => Self::Weak,
            }
        }
    }

    #[derive(serde::Serialize)]
    pub enum TestSymType {
        NoType = 0,
        Object = 1,
        Func = 2,
        Section = 3,
        File = 4,
        Common = 5,
        Tls = 6,
    }

    impl From<elf::SymType> for TestSymType {
        fn from(value: elf::SymType) -> Self {
            match value {
                elf::SymType::NoType => Self::NoType,
                elf::SymType::Object => Self::Object,
                elf::SymType::Func => Self::Func,
                elf::SymType::Section => Self::Section,
                elf::SymType::File => Self::File,
                elf::SymType::Common => Self::Common,
                elf::SymType::Tls => Self::Tls,
            }
        }
    }

    #[derive(serde::Serialize)]
    pub struct TestSym {
        pub name: u32,
        pub bind: TestSymBind,
        pub typ: TestSymType,
        pub other: u8,
        pub shndx: u16,
        pub value: usize,
        pub size: usize,
    }

    impl From<&elf::Sym> for TestSym {
        fn from(value: &elf::Sym) -> Self {
            Self {
                name: value.name,
                bind: value.bind.into(),
                typ: value.typ.into(),
                other: value.other,
                shndx: value.shndx,
                value: value.value,
                size: value.size,
            }
        }
    }

    #[derive(serde::Serialize)]
    pub struct TestElfFile {
        header: TestElfHeader,
        sections: Vec<TestSection>,
        segments: Vec<TestSegmentHeader>,
        syms: Vec<TestSym>,
        /// The index of the strtab to be used for looking up symbol names.
        symtab_strtab: usize,
    }

    impl From<elf::ElfFile<'static>> for TestElfFile {
        fn from(parsed: elf::ElfFile<'static>) -> Self {
            let header = TestElfHeader::from(&parsed.header);

            let sections = parsed
                .sections
                .iter()
                .map(|shdr| TestSection::from((&parsed, shdr)))
                .collect();

            let segments = parsed
                .segments
                .iter()
                .map(|phdr| TestSegmentHeader::from((&parsed, phdr)))
                .collect();

            let syms = parsed.syms.iter().map(TestSym::from).collect();

            TestElfFile {
                header,
                sections,
                segments,
                syms,
                symtab_strtab: parsed.symtab_strtab,
            }
        }
    }
}
