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
