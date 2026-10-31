use std::io::{self, Read, Seek, SeekFrom};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PN_XNUM: u16 = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfIdent {
    pub class: ElfClass,
    pub endianness: Endianness,
    pub version: u8,
    pub os_abi: u8,
    pub abi_version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeader {
    pub ident: ElfIdent,
    pub file_type: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub section_header_entry_size: u16,
    pub section_header_count: u16,
    pub section_names_index: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramHeader {
    pub segment_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

#[derive(Debug)]
pub struct ElfFile {
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_bytes<const N: usize>(reader: &mut impl Read) -> io::Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_u16(reader: &mut impl Read, endian: Endianness) -> io::Result<u16> {
    let bytes = read_bytes::<2>(reader)?;

    Ok(match endian {
        Endianness::Little => u16::from_le_bytes(bytes),
        Endianness::Big => u16::from_be_bytes(bytes),
    })
}

fn read_u32(reader: &mut impl Read, endian: Endianness) -> io::Result<u32> {
    let bytes = read_bytes::<4>(reader)?;

    Ok(match endian {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    })
}

fn read_u64(reader: &mut impl Read, endian: Endianness) -> io::Result<u64> {
    let bytes = read_bytes::<8>(reader)?;

    Ok(match endian {
        Endianness::Little => u64::from_le_bytes(bytes),
        Endianness::Big => u64::from_be_bytes(bytes),
    })
}

fn read_address(reader: &mut impl Read, class: ElfClass, endian: Endianness) -> io::Result<u64> {
    match class {
        ElfClass::Elf32 => Ok(u64::from(read_u32(reader, endian)?)),
        ElfClass::Elf64 => read_u64(reader, endian),
    }
}

pub fn read_ident(reader: &mut impl Read) -> io::Result<Option<ElfIdent>> {
    let mut magic = [0_u8; 4];

    match reader.read_exact(&mut magic) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }

    if magic != ELF_MAGIC {
        return Ok(None);
    }

    let mut rest = [0_u8; 12];
    reader.read_exact(&mut rest)?;

    let class = match rest[0] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        _ => return Err(invalid_data("Nieprawidłowa klasa ELF")),
    };

    let endianness = match rest[1] {
        1 => Endianness::Little,
        2 => Endianness::Big,
        _ => {
            return Err(invalid_data("Nieprawidłowa kolejność bajtów ELF"));
        }
    };

    let version = rest[2];

    if version != 1 {
        return Err(invalid_data("Nieobsługiwana wersja identyfikatora ELF"));
    }

    Ok(Some(ElfIdent {
        class,
        endianness,
        version,
        os_abi: rest[3],
        abi_version: rest[4],
    }))
}

pub fn read_header(reader: &mut impl Read) -> io::Result<Option<ElfHeader>> {
    let ident = match read_ident(reader)? {
        Some(ident) => ident,
        None => return Ok(None),
    };

    let endian = ident.endianness;
    let class = ident.class;

    let header = ElfHeader {
        ident,
        file_type: read_u16(reader, endian)?,
        machine: read_u16(reader, endian)?,
        version: read_u32(reader, endian)?,
        entry: read_address(reader, class, endian)?,
        program_header_offset: read_address(reader, class, endian)?,
        section_header_offset: read_address(reader, class, endian)?,
        flags: read_u32(reader, endian)?,
        header_size: read_u16(reader, endian)?,
        program_header_entry_size: read_u16(reader, endian)?,
        program_header_count: read_u16(reader, endian)?,
        section_header_entry_size: read_u16(reader, endian)?,
        section_header_count: read_u16(reader, endian)?,
        section_names_index: read_u16(reader, endian)?,
    };

    if header.version != 1 {
        return Err(invalid_data("Nieobsługiwana wersja nagłówka ELF"));
    }

    let expected_size = match class {
        ElfClass::Elf32 => 52,
        ElfClass::Elf64 => 64,
    };

    if header.header_size != expected_size {
        return Err(invalid_data(
            "Rozmiar nagłówka nie odpowiada obsługiwanemu układowi ELF",
        ));
    }

    Ok(Some(header))
}

fn read_program_header(reader: &mut impl Read, ident: ElfIdent) -> io::Result<ProgramHeader> {
    let endian = ident.endianness;
    let class = ident.class;

    let segment_type = read_u32(reader, endian)?;

    let early_flags = match class {
        ElfClass::Elf32 => None,
        ElfClass::Elf64 => Some(read_u32(reader, endian)?),
    };

    let offset = read_address(reader, class, endian)?;
    let virtual_address = read_address(reader, class, endian)?;
    let physical_address = read_address(reader, class, endian)?;
    let file_size = read_address(reader, class, endian)?;
    let memory_size = read_address(reader, class, endian)?;

    let flags = match early_flags {
        Some(flags) => flags,
        None => read_u32(reader, endian)?,
    };

    let alignment = read_address(reader, class, endian)?;

    Ok(ProgramHeader {
        segment_type,
        flags,
        offset,
        virtual_address,
        physical_address,
        file_size,
        memory_size,
        alignment,
    })
}

fn validate_file_range(offset: u64, size: u64, file_size: u64) -> io::Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_data("Przepełnienie zakresu danych w pliku"))?;

    if end > file_size {
        return Err(invalid_data("Zakres danych wykracza poza plik"));
    }

    Ok(())
}

fn validate_program_header(segment: &ProgramHeader, file_size: u64) -> io::Result<()> {
    // Pozostałe pola wpisu PT_NULL nie mają określonego znaczenia.
    if segment.segment_type == PT_NULL {
        return Ok(());
    }

    if segment.file_size != 0 {
        validate_file_range(segment.offset, segment.file_size, file_size)?;
    }

    if segment.segment_type == PT_LOAD {
        if segment.file_size > segment.memory_size {
            return Err(invalid_data(
                "PT_LOAD: rozmiar w pliku przekracza rozmiar w pamięci",
            ));
        }

        let align = segment.alignment;

        if align > 1 {
            if !align.is_power_of_two() {
                return Err(invalid_data("PT_LOAD: wyrównanie nie jest potęgą dwójki"));
            }

            if segment.virtual_address % align != segment.offset % align {
                return Err(invalid_data(
                    "PT_LOAD: adres i offset nie są zgodne z wyrównaniem",
                ));
            }
        }
    }

    Ok(())
}

pub fn read_program_headers(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
) -> io::Result<Vec<ProgramHeader>> {
    let count = header.program_header_count;

    if count == PN_XNUM {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Rozszerzona liczba nagłówków programu nie jest jeszcze obsługiwana",
        ));
    }

    if count == 0 {
        return Ok(Vec::new());
    }

    let expected_entry_size: u16 = match header.ident.class {
        ElfClass::Elf32 => 32,
        ElfClass::Elf64 => 56,
    };

    if header.program_header_entry_size != expected_entry_size {
        return Err(invalid_data("Nieobsługiwany rozmiar nagłówka programu"));
    }

    if header.program_header_offset == 0 {
        return Err(invalid_data(
            "Niezerowa liczba nagłówków programu przy zerowym offsecie tabeli",
        ));
    }

    let file_size = reader.seek(SeekFrom::End(0))?;

    let table_size = u64::from(count)
        .checked_mul(u64::from(header.program_header_entry_size))
        .ok_or_else(|| invalid_data("Przepełnienie rozmiaru tabeli programu"))?;

    validate_file_range(header.program_header_offset, table_size, file_size)?;

    reader.seek(SeekFrom::Start(header.program_header_offset))?;

    let mut segments = Vec::with_capacity(usize::from(count));

    for index in 0..count {
        let segment = read_program_header(reader, header.ident)?;

        validate_program_header(&segment, file_size)
            .map_err(|error| invalid_data(&format!("Nagłówek programu #{}: {}", index, error)))?;

        segments.push(segment);
    }

    Ok(segments)
}

pub fn read_elf(reader: &mut (impl Read + Seek)) -> io::Result<Option<ElfFile>> {
    reader.seek(SeekFrom::Start(0))?;

    let header = match read_header(reader)? {
        Some(header) => header,
        None => return Ok(None),
    };

    let program_headers = read_program_headers(reader, &header)?;

    Ok(Some(ElfFile {
        header,
        program_headers,
    }))
}

pub fn file_type_name(value: u16) -> &'static str {
    match value {
        0 => "NONE",
        1 => "REL — plik relokowalny",
        2 => "EXEC — plik wykonywalny",
        3 => "DYN — obiekt współdzielony lub program PIE",
        4 => "CORE — zrzut pamięci",
        _ => "inny/nieznany",
    }
}

pub fn machine_name(value: u16) -> &'static str {
    match value {
        3 => "Intel 80386",
        40 => "ARM",
        62 => "AMD x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "inna/nieznana",
    }
}

pub fn segment_type_name(value: u32) -> &'static str {
    match value {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474e550 => "GNU_EH_FRAME",
        0x6474e551 => "GNU_STACK",
        0x6474e552 => "GNU_RELRO",
        0x6474e553 => "GNU_PROPERTY",
        _ => "OTHER",
    }
}

pub fn segment_permissions(flags: u32) -> String {
    let read = if flags & 4 != 0 { 'R' } else { '-' };
    let write = if flags & 2 != 0 { 'W' } else { '-' };
    let execute = if flags & 1 != 0 { 'X' } else { '-' };

    format!("{read}{write}{execute}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn valid_ident() -> [u8; 16] {
        [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn reads_elf64_little_endian() {
        let mut input = Cursor::new(valid_ident());

        let ident = read_ident(&mut input).unwrap().unwrap();

        assert_eq!(ident.class, ElfClass::Elf64);
        assert_eq!(ident.endianness, Endianness::Little);
        assert_eq!(ident.version, 1);
        assert_eq!(ident.os_abi, 0);
        assert_eq!(ident.abi_version, 0);
    }

    #[test]
    fn reads_elf32_big_endian() {
        let mut bytes = valid_ident();
        bytes[4] = 1;
        bytes[5] = 2;

        let ident = read_ident(&mut Cursor::new(bytes)).unwrap().unwrap();

        assert_eq!(ident.class, ElfClass::Elf32);
        assert_eq!(ident.endianness, Endianness::Big);
    }

    #[test]
    fn ignores_non_elf() {
        let mut input = Cursor::new(b"ordinary text");

        assert_eq!(read_ident(&mut input).unwrap(), None);
    }

    #[test]
    fn ignores_short_non_elf() {
        let mut input = Cursor::new(b"\x7fEL");

        assert_eq!(read_ident(&mut input).unwrap(), None);
    }

    #[test]
    fn reports_truncated_elf_ident() {
        let mut input = Cursor::new(b"\x7fELF");

        let error = read_ident(&mut input).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_invalid_class() {
        let mut bytes = valid_ident();
        bytes[4] = 0;

        let error = read_ident(&mut Cursor::new(bytes)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_invalid_endianness() {
        let mut bytes = valid_ident();
        bytes[5] = 0;

        let error = read_ident(&mut Cursor::new(bytes)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = valid_ident();
        bytes[6] = 0;

        let error = read_ident(&mut Cursor::new(bytes)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[cfg(test)]
mod header_tests {
    use super::*;
    use std::io::Cursor;

    fn sample_header(class: ElfClass, endian: Endianness) -> Vec<u8> {
        let size = match class {
            ElfClass::Elf32 => 52,
            ElfClass::Elf64 => 64,
        };

        let mut bytes = vec![0_u8; size];
        bytes[..4].copy_from_slice(b"\x7fELF");

        bytes[4] = match class {
            ElfClass::Elf32 => 1,
            ElfClass::Elf64 => 2,
        };

        bytes[5] = match endian {
            Endianness::Little => 1,
            Endianness::Big => 2,
        };

        bytes[6] = 1;

        put(&mut bytes, 16, 2, 2, endian);
        put(&mut bytes, 18, 2, 62, endian);
        put(&mut bytes, 20, 4, 1, endian);

        let (address_size, size_offset) = match class {
            ElfClass::Elf32 => (4, 40),
            ElfClass::Elf64 => (8, 52),
        };

        put(&mut bytes, 24, address_size, 0x12345678, endian);

        put(&mut bytes, size_offset, 2, size as u64, endian);

        bytes
    }

    fn put(bytes: &mut [u8], offset: usize, width: usize, value: u64, endian: Endianness) {
        match endian {
            Endianness::Little => {
                bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
            }
            Endianness::Big => {
                bytes[offset..offset + width].copy_from_slice(&value.to_be_bytes()[8 - width..]);
            }
        }
    }

    #[test]
    fn reads_both_classes_and_byte_orders() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                let bytes = sample_header(class, endian);
                let expected_size = bytes.len() as u16;
                let mut input = Cursor::new(bytes);

                let header = read_header(&mut input).unwrap().unwrap();

                assert_eq!(header.ident.class, class);
                assert_eq!(header.ident.endianness, endian);
                assert_eq!(header.file_type, 2);
                assert_eq!(header.machine, 62);
                assert_eq!(header.entry, 0x12345678);
                assert_eq!(header.header_size, expected_size);
                assert_eq!(input.position(), u64::from(expected_size));
            }
        }
    }

    #[test]
    fn preserves_64_bit_addresses() {
        let mut bytes = sample_header(ElfClass::Elf64, Endianness::Big);

        let entry = 0x123456789abcdef0;

        put(&mut bytes, 24, 8, entry, Endianness::Big);

        let header = read_header(&mut Cursor::new(bytes)).unwrap().unwrap();

        assert_eq!(header.entry, entry);
    }

    #[test]
    fn rejects_truncated_header() {
        let mut bytes = sample_header(ElfClass::Elf64, Endianness::Little);

        bytes.pop();

        let error = read_header(&mut Cursor::new(bytes)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_wrong_header_size() {
        let mut bytes = sample_header(ElfClass::Elf64, Endianness::Little);

        put(&mut bytes, 52, 2, 52, Endianness::Little);

        let error = read_header(&mut Cursor::new(bytes)).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[cfg(test)]
mod program_header_tests {
    use super::*;
    use std::io::Cursor;

    fn ident(class: ElfClass, endian: Endianness) -> ElfIdent {
        ElfIdent {
            class,
            endianness: endian,
            version: 1,
            os_abi: 0,
            abi_version: 0,
        }
    }

    fn sample_segment() -> ProgramHeader {
        ProgramHeader {
            segment_type: PT_LOAD,
            flags: 5,
            offset: 0x1000,
            virtual_address: 0x401000,
            physical_address: 0,
            file_size: 0x200,
            memory_size: 0x300,
            alignment: 0x1000,
        }
    }

    fn push_value(bytes: &mut Vec<u8>, value: u64, width: usize, endian: Endianness) {
        match endian {
            Endianness::Little => {
                bytes.extend_from_slice(&value.to_le_bytes()[..width]);
            }
            Endianness::Big => {
                bytes.extend_from_slice(&value.to_be_bytes()[8 - width..]);
            }
        }
    }

    fn encode_segment(segment: &ProgramHeader, class: ElfClass, endian: Endianness) -> Vec<u8> {
        let mut bytes = Vec::new();

        push_value(&mut bytes, u64::from(segment.segment_type), 4, endian);

        if class == ElfClass::Elf64 {
            push_value(&mut bytes, u64::from(segment.flags), 4, endian);
        }

        let width = match class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };

        for value in [
            segment.offset,
            segment.virtual_address,
            segment.physical_address,
            segment.file_size,
            segment.memory_size,
        ] {
            push_value(&mut bytes, value, width, endian);
        }

        if class == ElfClass::Elf32 {
            push_value(&mut bytes, u64::from(segment.flags), 4, endian);
        }

        push_value(&mut bytes, segment.alignment, width, endian);

        bytes
    }

    #[test]
    fn reads_all_program_header_layouts() {
        let expected = sample_segment();

        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                let bytes = encode_segment(&expected, class, endian);

                let expected_size = match class {
                    ElfClass::Elf32 => 32,
                    ElfClass::Elf64 => 56,
                };

                assert_eq!(bytes.len(), expected_size);

                let parsed =
                    read_program_header(&mut Cursor::new(bytes), ident(class, endian)).unwrap();

                assert_eq!(parsed, expected);
            }
        }
    }

    #[test]
    fn rejects_segment_outside_file() {
        let segment = sample_segment();

        assert!(validate_program_header(&segment, 0x1100).is_err());
    }

    #[test]
    fn rejects_load_larger_on_disk_than_in_memory() {
        let mut segment = sample_segment();
        segment.memory_size = 0x100;

        assert!(validate_program_header(&segment, 0x2000).is_err());
    }

    #[test]
    fn rejects_inconsistent_alignment() {
        let mut segment = sample_segment();
        segment.virtual_address += 1;

        assert!(validate_program_header(&segment, 0x2000).is_err());
    }

    #[test]
    fn ignores_unused_null_entry_fields() {
        let mut segment = sample_segment();
        segment.segment_type = PT_NULL;
        segment.offset = u64::MAX;

        assert!(validate_program_header(&segment, 0).is_ok());
    }

    #[test]
    fn rejects_range_overflow() {
        assert!(validate_file_range(u64::MAX, 1, u64::MAX).is_err());
    }

    #[test]
    fn formats_permissions() {
        assert_eq!(segment_permissions(5), "R-X");
        assert_eq!(segment_permissions(6), "RW-");
        assert_eq!(segment_permissions(0), "---");
    }
}
