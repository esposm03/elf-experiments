use bitflags::bitflags;
use num_derive::FromPrimitive;

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
    pub class: ElfClass,
    pub endianness: ElfEndian,
    pub os_abi: u8,
    pub abi_version: u8,
    pub typ: ElfType,
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

#[derive(Debug)]
pub struct SectionHeader {
    pub name: usize,
    pub typ: SectionType,
    pub flags: SectionFlags,
    pub addr: u64,
    pub offset: usize,
    pub size: usize,
    pub link: u32,
    pub info: u32,
    pub align: u64,
    pub entry_size: u64,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq, Hash)]
pub enum SegmentType {
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

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct SegmentFlags: u32 {
        const Read             = 1 << 2;
        const Write            = 1 << 1;
        const Exec             = 1 << 0;
    }
}

#[derive(Debug)]
pub struct SegmentHeader {
    pub segment_type: SegmentType,
    pub flags: SegmentFlags,
    pub offset: u64,
    pub virtual_addr: u64,
    pub physical_addr: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub align: u64,
}

#[derive(Debug)]
pub struct ElfFile {
    pub header: ElfHeader,
    pub sections: Vec<SectionHeader>,
    pub segments: Vec<SegmentHeader>,
}
