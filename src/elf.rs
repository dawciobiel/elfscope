use std::io::{self, Read};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

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

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
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
        _ => return Err(invalid_data("Nieprawidłowa kolejność bajtów ELF")),
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
