use crate::elf::{ElfClass, ElfFile, Endianness, ProgramHeader};
use std::io::{self, Read, Seek, SeekFrom};
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_TEXTREL: u64 = 22;
const DT_BIND_NOW: u64 = 24;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6ffffffb;
const DF_TEXTREL: u64 = 4;
const DF_BIND_NOW: u64 = 8;
const DF_1_NOW: u64 = 1;
const DF_1_PIE: u64 = 0x08000000;
const MAX_DYNAMIC_SIZE: u64 = 16 * 1024 * 1024;
const MAX_STRING_TABLE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_NEEDED_COUNT: usize = 4096;
const MAX_TOTAL_STRING_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct DynamicInfo {
    pub needed: Vec<Vec<u8>>,
    pub soname: Option<Vec<u8>>,
    pub rpath: Option<Vec<u8>>,
    pub runpath: Option<Vec<u8>>,
    pub flags: Option<u64>,
    pub flags_1: Option<u64>,
    pub bind_now_tag: bool,
    pub textrel_tag: bool,
}
impl DynamicInfo {
    pub fn bind_now_requested(&self) -> bool {
        self.bind_now_tag
            || self.flags.is_some_and(|flags| flags & DF_BIND_NOW != 0)
            || self.flags_1.is_some_and(|flags| flags & DF_1_NOW != 0)
    }
    pub fn pie_requested(&self) -> bool {
        self.flags_1.is_some_and(|flags| flags & DF_1_PIE != 0)
    }
    pub fn textrel_requested(&self) -> bool {
        self.textrel_tag || self.flags.is_some_and(|flags| flags & DF_TEXTREL != 0)
    }
}
#[derive(Default)]
struct StringOffsets {
    needed: Vec<u64>,
    soname: Option<u64>,
    rpath: Option<u64>,
    runpath: Option<u64>,
}
impl StringOffsets {
    fn is_empty(&self) -> bool {
        self.needed.is_empty()
            && self.soname.is_none()
            && self.rpath.is_none()
            && self.runpath.is_none()
    }
}
fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
fn read_word(reader: &mut impl Read, class: ElfClass, endian: Endianness) -> io::Result<u64> {
    match class {
        ElfClass::Elf32 => {
            let mut bytes = [0_u8; 4];
            reader.read_exact(&mut bytes)?;
            Ok(u64::from(match endian {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }))
        }
        ElfClass::Elf64 => {
            let mut bytes = [0_u8; 8];
            reader.read_exact(&mut bytes)?;
            Ok(match endian {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            })
        }
    }
}
fn validate_range(offset: u64, size: u64, file_size: u64) -> io::Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_data("PT_DYNAMIC: przepełnienie zakresu"))?;
    if end > file_size {
        return Err(invalid_data("PT_DYNAMIC: zakres danych wykracza poza plik"));
    }
    Ok(())
}
fn set_once(target: &mut Option<u64>, value: u64, name: &str) -> io::Result<()> {
    if target.replace(value).is_some() {
        return Err(invalid_data(&format!("Powtórzony wpis {}", name)));
    }
    Ok(())
}
fn virtual_to_file_offset(headers: &[ProgramHeader], address: u64, size: u64) -> io::Result<u64> {
    address
        .checked_add(size)
        .ok_or_else(|| invalid_data("Przepełnienie zakresu adresów tabeli napisów"))?;
    let mut result = None;
    for segment in headers {
        if segment.segment_type != PT_LOAD {
            continue;
        }
        let Some(delta) = address.checked_sub(segment.virtual_address) else {
            continue;
        };
        let Some(end_delta) = delta.checked_add(size) else {
            continue;
        };
        if end_delta > segment.file_size || end_delta > segment.memory_size {
            continue;
        }
        let offset = segment
            .offset
            .checked_add(delta)
            .ok_or_else(|| invalid_data("Przepełnienie offsetu tabeli napisów"))?;
        if result.is_some_and(|previous| previous != offset) {
            return Err(invalid_data(
                "Niejednoznaczne mapowanie adresu tabeli napisów",
            ));
        }
        result = Some(offset);
    }
    result.ok_or_else(|| {
        invalid_data("Tabela DT_STRTAB nie mieści się w części plikowej jednego PT_LOAD")
    })
}
fn copy_string(strings: &[u8], offset: u64, total: &mut usize) -> io::Result<Vec<u8>> {
    let start = usize::try_from(offset)
        .map_err(|_| invalid_data("Offset napisu nie mieści się w usize"))?;
    let tail = strings
        .get(start..)
        .ok_or_else(|| invalid_data("Offset napisu wykracza poza tabelę"))?;
    let end = tail
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| invalid_data("Brak końcowego bajtu zerowego napisu"))?;
    *total = total
        .checked_add(end)
        .ok_or_else(|| invalid_data("Przepełnienie łącznego rozmiaru napisów"))?;
    if *total > MAX_TOTAL_STRING_BYTES {
        return Err(unsupported(
            "Łączna długość odczytanych napisów przekracza 16 MiB",
        ));
    }
    Ok(tail[..end].to_vec())
}
fn optional_string(
    strings: &[u8],
    offset: Option<u64>,
    total: &mut usize,
) -> io::Result<Option<Vec<u8>>> {
    offset
        .map(|offset| copy_string(strings, offset, total))
        .transpose()
}
pub fn read_dynamic(
    reader: &mut (impl Read + Seek),
    elf: &ElfFile,
) -> io::Result<Option<DynamicInfo>> {
    let mut matches = elf
        .program_headers
        .iter()
        .filter(|header| header.segment_type == PT_DYNAMIC);
    let segment = match matches.next() {
        Some(segment) => segment,
        None => return Ok(None),
    };
    if matches.next().is_some() {
        return Err(invalid_data(
            "Więcej niż jeden wpis PT_DYNAMIC nie jest obsługiwany",
        ));
    }
    let class = elf.header.ident.class;
    let endian = elf.header.ident.endianness;
    let entry_size: u64 = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };
    if segment.file_size == 0 || segment.file_size % entry_size != 0 {
        return Err(invalid_data("Nieprawidłowy rozmiar tablicy PT_DYNAMIC"));
    }
    if segment.file_size > MAX_DYNAMIC_SIZE {
        return Err(unsupported("PT_DYNAMIC przekracza limit narzędzia: 16 MiB"));
    }
    let file_size = reader.seek(SeekFrom::End(0))?;
    validate_range(segment.offset, segment.file_size, file_size)?;
    reader.seek(SeekFrom::Start(segment.offset))?;
    let mut offsets = StringOffsets::default();
    let mut string_address = None;
    let mut string_size = None;
    let mut terminated = false;
    let mut info = DynamicInfo::default();
    for _ in 0..segment.file_size / entry_size {
        let tag = read_word(reader, class, endian)?;
        let value = read_word(reader, class, endian)?;
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_NEEDED => {
                if offsets.needed.len() >= MAX_NEEDED_COUNT {
                    return Err(unsupported("Przekroczono limit 4096 wpisów DT_NEEDED"));
                }
                offsets.needed.push(value);
            }
            DT_STRTAB => set_once(&mut string_address, value, "DT_STRTAB")?,
            DT_STRSZ => set_once(&mut string_size, value, "DT_STRSZ")?,
            DT_SONAME => set_once(&mut offsets.soname, value, "DT_SONAME")?,
            DT_RPATH => set_once(&mut offsets.rpath, value, "DT_RPATH")?,
            DT_RUNPATH => set_once(&mut offsets.runpath, value, "DT_RUNPATH")?,
            DT_FLAGS => set_once(&mut info.flags, value, "DT_FLAGS")?,
            DT_FLAGS_1 => set_once(&mut info.flags_1, value, "DT_FLAGS_1")?,
            DT_BIND_NOW => info.bind_now_tag = true,
            DT_TEXTREL => info.textrel_tag = true,
            _ => {}
        }
    }
    if !terminated {
        return Err(invalid_data("Brak DT_NULL w tablicy PT_DYNAMIC"));
    }
    if offsets.is_empty() {
        return Ok(Some(info));
    }
    let address = string_address.ok_or_else(|| invalid_data("Wpisy napisowe bez DT_STRTAB"))?;
    let size = string_size.ok_or_else(|| invalid_data("Wpisy napisowe bez DT_STRSZ"))?;
    if size == 0 {
        return Err(invalid_data(
            "Pusta tabela napisów przy obecnych wpisach napisowych",
        ));
    }
    if size > MAX_STRING_TABLE_SIZE {
        return Err(unsupported(
            "Dynamiczna tabela napisów przekracza limit 16 MiB",
        ));
    }
    let offset = virtual_to_file_offset(&elf.program_headers, address, size)?;
    validate_range(offset, size, file_size)?;
    let size = usize::try_from(size)
        .map_err(|_| invalid_data("Rozmiar tabeli napisów nie mieści się w usize"))?;
    reader.seek(SeekFrom::Start(offset))?;
    let mut strings = vec![0_u8; size];
    reader.read_exact(&mut strings)?;
    if strings.first() != Some(&0) || strings.last() != Some(&0) {
        return Err(invalid_data(
            "Tabela napisów musi zaczynać się i kończyć bajtem zerowym",
        ));
    }
    let mut total = 0;
    for offset in offsets.needed {
        let name = copy_string(&strings, offset, &mut total)?;
        if name.is_empty() {
            return Err(invalid_data("DT_NEEDED wskazuje pustą nazwę biblioteki"));
        }
        info.needed.push(name);
    }
    info.soname = optional_string(&strings, offsets.soname, &mut total)?;
    info.rpath = optional_string(&strings, offsets.rpath, &mut total)?;
    info.runpath = optional_string(&strings, offsets.runpath, &mut total)?;
    Ok(Some(info))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::{ElfHeader, ElfIdent};
    use std::io::Cursor;
    const NAMES: &[u8] = b"\0libexample.so\0example.so\0$ORIGIN/legacy\0$ORIGIN/lib\0";
    fn name_offset(name: &[u8]) -> u64 {
        NAMES
            .windows(name.len())
            .position(|part| part == name)
            .unwrap() as u64
    }
    fn put(bytes: &mut [u8], at: usize, width: usize, value: u64, endian: Endianness) {
        match endian {
            Endianness::Little => {
                bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width])
            }
            Endianness::Big => {
                bytes[at..at + width].copy_from_slice(&value.to_be_bytes()[8 - width..])
            }
        }
    }
    fn fixture(class: ElfClass, endian: Endianness) -> (Vec<u8>, ElfFile) {
        let width = match class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };
        let entries = [
            (DT_NEEDED, name_offset(b"libexample.so")),
            (DT_STRTAB, 0x400180),
            (DT_STRSZ, NAMES.len() as u64),
            (DT_SONAME, name_offset(b"example.so")),
            (DT_RPATH, name_offset(b"$ORIGIN/legacy")),
            (DT_RUNPATH, name_offset(b"$ORIGIN/lib")),
            (DT_FLAGS, 12),
            (DT_FLAGS_1, DF_1_PIE | DF_1_NOW),
            (DT_BIND_NOW, 0),
            (DT_TEXTREL, 0),
            (DT_NULL, 0),
        ];
        let mut bytes = vec![0_u8; 512];
        for (index, (tag, value)) in entries.iter().enumerate() {
            let at = 64 + index * width * 2;
            put(&mut bytes, at, width, *tag, endian);
            put(&mut bytes, at + width, width, *value, endian);
        }
        bytes[384..384 + NAMES.len()].copy_from_slice(NAMES);
        let load = ProgramHeader {
            segment_type: PT_LOAD,
            flags: 4,
            offset: 0,
            virtual_address: 0x400000,
            physical_address: 0,
            file_size: 512,
            memory_size: 512,
            alignment: 1,
        };
        let dynamic = ProgramHeader {
            segment_type: PT_DYNAMIC,
            offset: 64,
            virtual_address: 0x400040,
            file_size: (width * 2 * entries.len()) as u64,
            memory_size: (width * 2 * entries.len()) as u64,
            ..load.clone()
        };
        let header = ElfHeader {
            ident: ElfIdent {
                class,
                endianness: endian,
                version: 1,
                os_abi: 0,
                abi_version: 0,
            },
            file_type: 3,
            machine: 0,
            version: 1,
            entry: 0,
            program_header_offset: 0,
            section_header_offset: 0,
            flags: 0,
            header_size: match class {
                ElfClass::Elf32 => 52,
                ElfClass::Elf64 => 64,
            },
            program_header_entry_size: 0,
            program_header_count: 2,
            section_header_entry_size: 0,
            section_header_count: 0,
            section_names_index: 0,
        };
        (
            bytes,
            ElfFile {
                header,
                program_headers: vec![load, dynamic],
            },
        )
    }
    fn read(bytes: Vec<u8>, elf: &ElfFile) -> io::Result<Option<DynamicInfo>> {
        read_dynamic(&mut Cursor::new(bytes), elf)
    }
    #[test]
    fn reads_both_classes_and_byte_orders() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                let (bytes, elf) = fixture(class, endian);
                let info = read(bytes, &elf).unwrap().unwrap();
                assert_eq!(info.needed, vec![b"libexample.so".to_vec()]);
                assert_eq!(info.soname, Some(b"example.so".to_vec()));
                assert_eq!(info.rpath, Some(b"$ORIGIN/legacy".to_vec()));
                assert_eq!(info.runpath, Some(b"$ORIGIN/lib".to_vec()));
                assert_eq!(info.flags, Some(12));
                assert!(info.bind_now_requested());
                assert!(info.pie_requested());
                assert!(info.textrel_requested());
            }
        }
    }
    #[test]
    fn accepts_absent_dynamic_segment() {
        let (bytes, mut elf) = fixture(ElfClass::Elf64, Endianness::Little);
        elf.program_headers.retain(|h| h.segment_type != PT_DYNAMIC);
        assert!(read(bytes, &elf).unwrap().is_none());
    }
    #[test]
    fn rejects_duplicate_dynamic_segments() {
        let (bytes, mut elf) = fixture(ElfClass::Elf64, Endianness::Little);
        elf.program_headers.push(elf.program_headers[1].clone());
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn rejects_missing_null_terminator() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 224, 8, 0x70000000, Endianness::Little);
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn rejects_name_offset_outside_table() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 72, 8, 999, Endianness::Little);
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn rejects_unmapped_string_table() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 88, 8, 0x500000, Endianness::Little);
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn rejects_unterminated_string_table() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        bytes[384 + NAMES.len() - 1] = b'x';
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn accepts_dynamic_table_without_needed_entries() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 64, 8, 0x70000000, Endianness::Little);
        let info = read(bytes, &elf).unwrap().unwrap();
        assert!(info.needed.is_empty());
        assert!(info.soname.is_some());
    }
    #[test]
    fn rejects_duplicate_soname() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 128, 8, DT_SONAME, Endianness::Little);
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn rejects_runpath_offset_outside_table() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 152, 8, 999, Endianness::Little);
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn preserves_present_but_empty_runpath() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 152, 8, 0, Endianness::Little);
        assert_eq!(
            read(bytes, &elf).unwrap().unwrap().runpath,
            Some(Vec::new())
        );
    }
    #[test]
    fn recognizes_each_now_encoding() {
        for info in [
            DynamicInfo {
                bind_now_tag: true,
                ..DynamicInfo::default()
            },
            DynamicInfo {
                flags: Some(8),
                ..DynamicInfo::default()
            },
            DynamicInfo {
                flags_1: Some(1),
                ..DynamicInfo::default()
            },
        ] {
            assert!(info.bind_now_requested());
        }
    }
    #[test]
    fn pie_marker_does_not_imply_now() {
        let info = DynamicInfo {
            flags_1: Some(DF_1_PIE),
            ..DynamicInfo::default()
        };
        assert!(info.pie_requested());
        assert!(!info.bind_now_requested());
    }
    #[test]
    fn recognizes_both_textrel_encodings() {
        assert!(
            DynamicInfo {
                textrel_tag: true,
                ..DynamicInfo::default()
            }
            .textrel_requested()
        );
        assert!(
            DynamicInfo {
                flags: Some(4),
                ..DynamicInfo::default()
            }
            .textrel_requested()
        );
    }
    #[test]
    fn preserves_flags_when_no_strings_are_requested() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        for index in 0..6 {
            put(
                &mut bytes,
                64 + index * 16,
                8,
                0x70000000,
                Endianness::Little,
            );
        }
        let info = read(bytes, &elf).unwrap().unwrap();
        assert!(info.needed.is_empty());
        assert!(info.soname.is_none());
        assert!(info.bind_now_requested());
        assert!(info.pie_requested());
    }
    #[test]
    fn rejects_duplicate_flags() {
        let (mut bytes, elf) = fixture(ElfClass::Elf64, Endianness::Little);
        put(&mut bytes, 208, 8, DT_FLAGS, Endianness::Little);
        assert!(read(bytes, &elf).is_err());
    }
    #[test]
    fn defaults_do_not_claim_dynamic_declarations() {
        let info = DynamicInfo::default();
        assert!(info.flags.is_none());
        assert!(info.flags_1.is_none());
        assert!(!info.bind_now_requested());
        assert!(!info.pie_requested());
        assert!(!info.textrel_requested());
    }
}
