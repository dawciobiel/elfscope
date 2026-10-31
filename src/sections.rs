use std::io::{self, Read, Seek, SeekFrom};

use crate::elf::{ElfClass, ElfHeader, Endianness};

const SHT_NULL: u32 = 0;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;
const SHN_LORESERVE: u16 = 0xff00;

// Limit naszego narzędzia, a nie ograniczenie formatu ELF.
const MAX_NAME_TABLE_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    pub name_offset: u32,
    pub section_type: u32,
    pub flags: u64,
    pub address: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub alignment: u64,
    pub entry_size: u64,
}

#[derive(Debug, Default)]
pub struct SectionTable {
    pub headers: Vec<SectionHeader>,
    names: Option<Vec<u8>>,
}

impl SectionTable {
    pub fn name(&self, index: usize) -> Option<&[u8]> {
        let section = self.headers.get(index)?;
        let names = self.names.as_ref()?;
        let start = usize::try_from(section.name_offset).ok()?;
        let tail = names.get(start..)?;
        let end = tail.iter().position(|&byte| byte == 0)?;

        Some(&tail[..end])
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn read_u32(reader: &mut impl Read, endian: Endianness) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;

    Ok(match endian {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    })
}

fn read_u64(reader: &mut impl Read, endian: Endianness) -> io::Result<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;

    Ok(match endian {
        Endianness::Little => u64::from_le_bytes(bytes),
        Endianness::Big => u64::from_be_bytes(bytes),
    })
}

fn read_word(reader: &mut impl Read, class: ElfClass, endian: Endianness) -> io::Result<u64> {
    match class {
        ElfClass::Elf32 => Ok(u64::from(read_u32(reader, endian)?)),
        ElfClass::Elf64 => read_u64(reader, endian),
    }
}

fn read_section_header(
    reader: &mut impl Read,
    class: ElfClass,
    endian: Endianness,
) -> io::Result<SectionHeader> {
    Ok(SectionHeader {
        name_offset: read_u32(reader, endian)?,
        section_type: read_u32(reader, endian)?,
        flags: read_word(reader, class, endian)?,
        address: read_word(reader, class, endian)?,
        offset: read_word(reader, class, endian)?,
        size: read_word(reader, class, endian)?,
        link: read_u32(reader, endian)?,
        info: read_u32(reader, endian)?,
        alignment: read_word(reader, class, endian)?,
        entry_size: read_word(reader, class, endian)?,
    })
}

fn validate_range(offset: u64, size: u64, file_size: u64) -> io::Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_data("Przepełnienie zakresu sekcji"))?;

    if end > file_size {
        return Err(invalid_data("Zakres sekcji wykracza poza plik"));
    }

    Ok(())
}

fn validate_section(section: &SectionHeader, file_size: u64) -> io::Result<()> {
    if section.section_type == SHT_NULL {
        return Ok(());
    }

    if section.section_type != SHT_NOBITS && section.size != 0 {
        validate_range(section.offset, section.size, file_size)?;
    }

    if section.alignment > 1 {
        if !section.alignment.is_power_of_two() {
            return Err(invalid_data("Wyrównanie sekcji nie jest potęgą dwójki"));
        }

        if section.address % section.alignment != 0 {
            return Err(invalid_data("Adres sekcji nie jest zgodny z wyrównaniem"));
        }
    }

    Ok(())
}

pub fn read_sections(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
) -> io::Result<SectionTable> {
    let count = header.section_header_count;
    let names_index = header.section_names_index;

    if header.section_header_offset == 0 {
        if count != 0 || names_index != 0 {
            return Err(invalid_data(
                "Brak tabeli sekcji przy niezerowym liczniku lub indeksie nazw",
            ));
        }

        return Ok(SectionTable::default());
    }

    if count == 0 {
        return Err(unsupported(
            "Rozszerzona liczba sekcji nie jest jeszcze obsługiwana",
        ));
    }

    if count >= SHN_LORESERVE {
        return Err(invalid_data("Zarezerwowana wartość licznika sekcji"));
    }

    if names_index >= SHN_LORESERVE {
        return Err(unsupported(
            "Rozszerzony lub zarezerwowany indeks nazw sekcji nie jest obsługiwany",
        ));
    }

    let expected_entry_size: u16 = match header.ident.class {
        ElfClass::Elf32 => 40,
        ElfClass::Elf64 => 64,
    };

    if header.section_header_entry_size != expected_entry_size {
        return Err(invalid_data("Nieobsługiwany rozmiar nagłówka sekcji"));
    }

    let file_size = reader.seek(SeekFrom::End(0))?;

    let table_size = u64::from(count)
        .checked_mul(u64::from(header.section_header_entry_size))
        .ok_or_else(|| invalid_data("Przepełnienie rozmiaru tabeli sekcji"))?;

    validate_range(header.section_header_offset, table_size, file_size)?;

    reader.seek(SeekFrom::Start(header.section_header_offset))?;

    let mut headers = Vec::with_capacity(usize::from(count));

    for index in 0..count {
        let section = read_section_header(reader, header.ident.class, header.ident.endianness)?;

        validate_section(&section, file_size)
            .map_err(|error| invalid_data(&format!("Sekcja #{}: {}", index, error)))?;

        headers.push(section);
    }

    if headers[0].section_type != SHT_NULL {
        return Err(invalid_data("Zerowy nagłówek sekcji nie ma typu SHT_NULL"));
    }

    // Indeks 0 oznacza brak tabeli nazw sekcji.
    if names_index == 0 {
        return Ok(SectionTable {
            headers,
            names: None,
        });
    }

    let names_header = headers
        .get(usize::from(names_index))
        .ok_or_else(|| invalid_data("Indeks tabeli nazw wykracza poza tabelę sekcji"))?;

    if names_header.section_type != SHT_STRTAB {
        return Err(invalid_data("Sekcja nazw nie ma typu SHT_STRTAB"));
    }

    if names_header.size > MAX_NAME_TABLE_SIZE {
        return Err(unsupported(
            "Tabela nazw przekracza limit narzędzia: 16 MiB",
        ));
    }

    let names_size = usize::try_from(names_header.size)
        .map_err(|_| invalid_data("Rozmiar tabeli nazw nie mieści się w usize"))?;

    reader.seek(SeekFrom::Start(names_header.offset))?;

    let mut names = vec![0_u8; names_size];
    reader.read_exact(&mut names)?;

    if names.first() != Some(&0) || names.last() != Some(&0) {
        return Err(invalid_data(
            "Tabela nazw musi zaczynać się i kończyć bajtem zerowym",
        ));
    }

    let table = SectionTable {
        headers,
        names: Some(names),
    };

    for (index, section) in table.headers.iter().enumerate() {
        if section.section_type != SHT_NULL && table.name(index).is_none() {
            return Err(invalid_data(&format!(
                "Sekcja #{}: nieprawidłowy offset nazwy lub brak końca napisu",
                index
            )));
        }
    }

    Ok(table)
}

pub fn section_type_name(value: u32) -> &'static str {
    match value {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        10 => "SHLIB",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB_SHNDX",
        0x6ffffff6 => "GNU_HASH",
        0x6ffffffd => "GNU_VERDEF",
        0x6ffffffe => "GNU_VERNEED",
        0x6fffffff => "GNU_VERSYM",
        _ => "OTHER",
    }
}

pub fn section_flags(flags: u64) -> String {
    let write = if flags & 1 != 0 { 'W' } else { '-' };
    let alloc = if flags & 2 != 0 { 'A' } else { '-' };
    let execute = if flags & 4 != 0 { 'X' } else { '-' };

    format!("{write}{alloc}{execute}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfIdent;
    use std::io::Cursor;

    fn sample_section() -> SectionHeader {
        SectionHeader {
            name_offset: 1,
            section_type: 1,
            flags: 6,
            address: 0x401000,
            offset: 0x1000,
            size: 0x200,
            link: 3,
            info: 4,
            alignment: 16,
            entry_size: 0,
        }
    }

    fn push(bytes: &mut Vec<u8>, value: u64, width: usize, endian: Endianness) {
        match endian {
            Endianness::Little => {
                bytes.extend_from_slice(&value.to_le_bytes()[..width]);
            }
            Endianness::Big => {
                bytes.extend_from_slice(&value.to_be_bytes()[8 - width..]);
            }
        }
    }

    fn encode(section: &SectionHeader, class: ElfClass, endian: Endianness) -> Vec<u8> {
        let width = match class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };

        let mut bytes = Vec::new();

        push(&mut bytes, u64::from(section.name_offset), 4, endian);
        push(&mut bytes, u64::from(section.section_type), 4, endian);

        for value in [section.flags, section.address, section.offset, section.size] {
            push(&mut bytes, value, width, endian);
        }

        push(&mut bytes, u64::from(section.link), 4, endian);
        push(&mut bytes, u64::from(section.info), 4, endian);
        push(&mut bytes, section.alignment, width, endian);
        push(&mut bytes, section.entry_size, width, endian);

        bytes
    }

    fn sample_header() -> ElfHeader {
        ElfHeader {
            ident: ElfIdent {
                class: ElfClass::Elf64,
                endianness: Endianness::Little,
                version: 1,
                os_abi: 0,
                abi_version: 0,
            },
            file_type: 1,
            machine: 62,
            version: 1,
            entry: 0,
            program_header_offset: 0,
            section_header_offset: 64,
            flags: 0,
            header_size: 64,
            program_header_entry_size: 0,
            program_header_count: 0,
            section_header_entry_size: 64,
            section_header_count: 2,
            section_names_index: 1,
        }
    }

    fn sample_file() -> Vec<u8> {
        let null = SectionHeader {
            name_offset: 0,
            section_type: 0,
            flags: 0,
            address: 0,
            offset: 0,
            size: 0,
            link: 0,
            info: 0,
            alignment: 0,
            entry_size: 0,
        };

        let names = b"\0.shstrtab\0";

        let names_header = SectionHeader {
            name_offset: 1,
            section_type: SHT_STRTAB,
            offset: 192,
            size: names.len() as u64,
            alignment: 1,
            ..null.clone()
        };

        let mut bytes = vec![0_u8; 64];

        bytes.extend(encode(&null, ElfClass::Elf64, Endianness::Little));

        bytes.extend(encode(&names_header, ElfClass::Elf64, Endianness::Little));

        bytes.extend_from_slice(names);

        bytes
    }

    #[test]
    fn reads_both_classes_and_byte_orders() {
        let expected = sample_section();

        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                let bytes = encode(&expected, class, endian);

                let expected_size = match class {
                    ElfClass::Elf32 => 40,
                    ElfClass::Elf64 => 64,
                };

                assert_eq!(bytes.len(), expected_size);

                let parsed = read_section_header(&mut Cursor::new(bytes), class, endian).unwrap();

                assert_eq!(parsed, expected);
            }
        }
    }

    #[test]
    fn reads_table_and_section_names() {
        let table = read_sections(&mut Cursor::new(sample_file()), &sample_header()).unwrap();

        assert_eq!(table.headers.len(), 2);
        assert_eq!(table.name(0), Some(&b""[..]));
        assert_eq!(table.name(1), Some(&b".shstrtab"[..]));
    }

    #[test]
    fn rejects_truncated_section_table() {
        let mut bytes = sample_file();
        bytes.truncate(100);

        assert!(read_sections(&mut Cursor::new(bytes), &sample_header(),).is_err());
    }

    #[test]
    fn nobits_does_not_require_file_contents() {
        let mut section = sample_section();
        section.section_type = SHT_NOBITS;
        section.offset = u64::MAX;
        section.size = 0x1000;

        assert!(validate_section(&section, 0).is_ok());
    }

    #[test]
    fn rejects_bad_name_offset() {
        let mut bytes = sample_file();

        // sh_name drugiego nagłówka sekcji.
        bytes[128..132].copy_from_slice(&999_u32.to_le_bytes());

        assert!(read_sections(&mut Cursor::new(bytes), &sample_header(),).is_err());
    }

    #[test]
    fn rejects_unterminated_name_table() {
        let mut bytes = sample_file();
        *bytes.last_mut().unwrap() = b'x';

        assert!(read_sections(&mut Cursor::new(bytes), &sample_header(),).is_err());
    }

    #[test]
    fn accepts_file_without_section_table() {
        let mut header = sample_header();
        header.section_header_offset = 0;
        header.section_header_count = 0;
        header.section_names_index = 0;

        let table = read_sections(&mut Cursor::new(Vec::<u8>::new()), &header).unwrap();

        assert!(table.headers.is_empty());
    }

    #[test]
    fn formats_basic_section_flags() {
        assert_eq!(section_flags(6), "-AX");
        assert_eq!(section_flags(3), "WA-");
        assert_eq!(section_flags(0), "---");
    }
}
