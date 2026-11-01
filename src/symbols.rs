use std::fmt;
use std::io::{self, BufReader, Read, Seek, SeekFrom};

use crate::elf::{ElfClass, ElfHeader, Endianness};
use crate::sections::SectionHeader;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;
const SHT_SYMTAB_SHNDX: u32 = 18;

const SHN_UNDEF: u16 = 0;
const SHN_LORESERVE: u32 = 0xff00;
const SHN_XINDEX: u16 = 0xffff;

// Limity naszego narzędzia.
const MAX_SYMBOL_COUNT: u64 = 1_000_000;
const MAX_SYMBOL_TABLES: usize = 128;
const MAX_STRING_TABLE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_PREVIEW_SYMBOLS: usize = 20;
const MAX_PREVIEW_NAME_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolSectionIndex {
    Direct(u16),
    Extended(u32),
}

impl fmt::Display for SymbolSectionIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct(index) => write!(formatter, "{}", index),
            Self::Extended(index) => {
                write!(formatter, "{} -> {}", SHN_XINDEX, index)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SymbolPreview {
    pub index: u64,
    pub name: Vec<u8>,
    pub name_truncated: bool,
    pub value: u64,
    pub size: u64,
    pub binding: u8,
    pub symbol_type: u8,
    pub visibility: u8,
    pub section_index: SymbolSectionIndex,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SymbolTableSummary {
    pub section_index: usize,
    pub total: u64,
    pub functions: u64,
    pub objects: u64,
    pub locals: u64,
    pub globals: u64,
    pub weaks: u64,
    pub undefined: u64,
    pub extended_indices: u64,
    pub preview: Vec<SymbolPreview>,
}

struct SymbolRecord {
    name_offset: u32,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    section_index: u16,
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn record_size(class: ElfClass) -> usize {
    match class {
        ElfClass::Elf32 => 16,
        ElfClass::Elf64 => 24,
    }
}

fn u16_at(bytes: &[u8], offset: usize, endian: Endianness) -> u16 {
    let value = [bytes[offset], bytes[offset + 1]];

    match endian {
        Endianness::Little => u16::from_le_bytes(value),
        Endianness::Big => u16::from_be_bytes(value),
    }
}

fn u32_at(bytes: &[u8], offset: usize, endian: Endianness) -> u32 {
    let value = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];

    match endian {
        Endianness::Little => u32::from_le_bytes(value),
        Endianness::Big => u32::from_be_bytes(value),
    }
}

fn u64_at(bytes: &[u8], offset: usize, endian: Endianness) -> u64 {
    let value = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ];

    match endian {
        Endianness::Little => u64::from_le_bytes(value),
        Endianness::Big => u64::from_be_bytes(value),
    }
}

fn decode_record(bytes: &[u8], class: ElfClass, endian: Endianness) -> SymbolRecord {
    match class {
        ElfClass::Elf32 => SymbolRecord {
            name_offset: u32_at(bytes, 0, endian),
            value: u64::from(u32_at(bytes, 4, endian)),
            size: u64::from(u32_at(bytes, 8, endian)),
            info: bytes[12],
            other: bytes[13],
            section_index: u16_at(bytes, 14, endian),
        },
        ElfClass::Elf64 => SymbolRecord {
            name_offset: u32_at(bytes, 0, endian),
            info: bytes[4],
            other: bytes[5],
            section_index: u16_at(bytes, 6, endian),
            value: u64_at(bytes, 8, endian),
            size: u64_at(bytes, 16, endian),
        },
    }
}

fn validate_range(offset: u64, size: u64, file_size: u64) -> io::Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_data("Przepełnienie zakresu danych symboli"))?;

    if end > file_size {
        return Err(invalid_data(
            "Dane symboli lub ich tablic pomocniczych wykraczają poza plik",
        ));
    }

    Ok(())
}

fn load_strings(
    reader: &mut (impl Read + Seek),
    table: &SectionHeader,
    sections: &[SectionHeader],
    file_size: u64,
    symbol_count: u64,
) -> io::Result<Vec<u8>> {
    let index = usize::try_from(table.link)
        .map_err(|_| invalid_data("Indeks tablicy napisów nie mieści się w usize"))?;

    let strings = sections
        .get(index)
        .ok_or_else(|| invalid_data("sh_link tablicy symboli wykracza poza sekcje"))?;

    if strings.section_type != SHT_STRTAB {
        return Err(invalid_data(
            "sh_link tablicy symboli nie wskazuje sekcji STRTAB",
        ));
    }

    if strings.size > MAX_STRING_TABLE_SIZE {
        return Err(unsupported("Tabela nazw symboli przekracza limit 16 MiB"));
    }

    validate_range(strings.offset, strings.size, file_size)?;

    let size = usize::try_from(strings.size)
        .map_err(|_| invalid_data("Rozmiar napisów nie mieści się w usize"))?;

    reader.seek(SeekFrom::Start(strings.offset))?;

    let mut bytes = vec![0_u8; size];
    reader.read_exact(&mut bytes)?;

    if bytes.is_empty() && symbol_count == 0 {
        return Ok(bytes);
    }

    if bytes.first() != Some(&0) || bytes.last() != Some(&0) {
        return Err(invalid_data(
            "Tabela nazw symboli musi zaczynać się i kończyć bajtem zerowym",
        ));
    }

    Ok(bytes)
}

fn load_extended_indices(
    reader: &mut (impl Read + Seek),
    sections: &[SectionHeader],
    symbol_table_index: usize,
    symbol_count: u64,
    file_size: u64,
    endian: Endianness,
) -> io::Result<Option<Vec<u32>>> {
    let mut matches = sections.iter().filter(|section| {
        section.section_type == SHT_SYMTAB_SHNDX
            && usize::try_from(section.link).ok() == Some(symbol_table_index)
    });

    let section = match matches.next() {
        Some(section) => section,
        None => return Ok(None),
    };

    if matches.next().is_some() {
        return Err(invalid_data(
            "Więcej niż jedna tablica SYMTAB_SHNDX dla tej samej tablicy symboli",
        ));
    }

    if section.entry_size != 4 {
        return Err(invalid_data(
            "SYMTAB_SHNDX: rozmiar wpisu musi wynosić 4 bajty",
        ));
    }

    if section.info != 0 {
        return Err(invalid_data("SYMTAB_SHNDX: pole sh_info musi wynosić zero"));
    }

    let expected_size = symbol_count
        .checked_mul(4)
        .ok_or_else(|| invalid_data("Przepełnienie rozmiaru SYMTAB_SHNDX"))?;

    if section.size != expected_size {
        return Err(invalid_data(
            "SYMTAB_SHNDX: liczba wpisów nie odpowiada liczbie symboli",
        ));
    }

    validate_range(section.offset, section.size, file_size)?;

    let count = usize::try_from(symbol_count)
        .map_err(|_| invalid_data("Liczba indeksów nie mieści się w usize"))?;

    reader.seek(SeekFrom::Start(section.offset))?;

    let mut indices = Vec::with_capacity(count);

    for _ in 0..count {
        let mut bytes = [0_u8; 4];
        reader.read_exact(&mut bytes)?;
        indices.push(u32_at(&bytes, 0, endian));
    }

    Ok(Some(indices))
}

fn resolve_section_index(
    raw: u16,
    auxiliary: Option<u32>,
    section_count: usize,
) -> io::Result<SymbolSectionIndex> {
    if raw != SHN_XINDEX {
        if auxiliary.is_some_and(|value| value != 0) {
            return Err(invalid_data(
                "Niezerowy wpis SYMTAB_SHNDX dla symbolu bez SHN_XINDEX",
            ));
        }

        return Ok(SymbolSectionIndex::Direct(raw));
    }

    let actual = auxiliary.ok_or_else(|| {
        invalid_data("Symbol z SHN_XINDEX nie ma powiązanej tablicy SYMTAB_SHNDX")
    })?;

    if actual < SHN_LORESERVE {
        return Err(invalid_data(
            "Rozszerzony indeks symbolu jest mniejszy niż SHN_LORESERVE",
        ));
    }

    let index = usize::try_from(actual)
        .map_err(|_| invalid_data("Rozszerzony indeks nie mieści się w usize"))?;

    if index >= section_count {
        return Err(invalid_data(
            "Rozszerzony indeks symbolu wykracza poza tabelę sekcji",
        ));
    }

    Ok(SymbolSectionIndex::Extended(actual))
}

fn preview_name(tail: &[u8]) -> (Vec<u8>, bool) {
    let inspected = tail.len().min(MAX_PREVIEW_NAME_BYTES + 1);

    if let Some(end) = tail[..inspected].iter().position(|&byte| byte == 0) {
        return (tail[..end].to_vec(), false);
    }

    (tail[..MAX_PREVIEW_NAME_BYTES].to_vec(), true)
}

pub fn read_symbol_summaries(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
    sections: &[SectionHeader],
) -> io::Result<Vec<SymbolTableSummary>> {
    let size = record_size(header.ident.class);

    let mut reader = BufReader::new(reader);
    let file_size = reader.seek(SeekFrom::End(0))?;

    let mut summaries = Vec::new();
    let mut total_symbols = 0_u64;

    for (section_index, section) in sections.iter().enumerate() {
        if !matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM) {
            continue;
        }

        if summaries.len() >= MAX_SYMBOL_TABLES {
            return Err(unsupported("Przekroczono limit 128 tablic symboli"));
        }

        if section.entry_size != size as u64 {
            return Err(invalid_data(&format!(
                "Sekcja #{}: nieobsługiwany rozmiar rekordu symbolu",
                section_index
            )));
        }

        if section.size % section.entry_size != 0 {
            return Err(invalid_data(&format!(
                "Sekcja #{}: rozmiar tablicy nie jest wielokrotnością rekordu",
                section_index
            )));
        }

        let count = section.size / section.entry_size;

        total_symbols = total_symbols
            .checked_add(count)
            .ok_or_else(|| invalid_data("Przepełnienie licznika symboli"))?;

        if total_symbols > MAX_SYMBOL_COUNT {
            return Err(unsupported(
                "Liczba symboli przekracza limit narzędzia: 1000000",
            ));
        }

        validate_range(section.offset, section.size, file_size)?;

        let strings = load_strings(&mut reader, section, sections, file_size, count)?;

        let extended_indices = load_extended_indices(
            &mut reader,
            sections,
            section_index,
            count,
            file_size,
            header.ident.endianness,
        )?;

        reader.seek(SeekFrom::Start(section.offset))?;

        let mut summary = SymbolTableSummary {
            section_index,
            total: count,
            ..SymbolTableSummary::default()
        };

        let mut bytes = [0_u8; 24];

        for index in 0..count {
            reader.read_exact(&mut bytes[..size])?;

            let record = decode_record(&bytes[..size], header.ident.class, header.ident.endianness);

            let auxiliary = match &extended_indices {
                Some(indices) => {
                    let position = usize::try_from(index)
                        .map_err(|_| invalid_data("Indeks symbolu nie mieści się w usize"))?;

                    Some(indices[position])
                }
                None => None,
            };

            let resolved_index =
                resolve_section_index(record.section_index, auxiliary, sections.len())?;

            let binding = record.info >> 4;
            let symbol_type = record.info & 0x0f;

            match symbol_type {
                1 => summary.objects += 1,
                2 => summary.functions += 1,
                _ => {}
            }

            match binding {
                0 => summary.locals += 1,
                1 => summary.globals += 1,
                2 => summary.weaks += 1,
                _ => {}
            }

            if record.section_index == SHN_UNDEF {
                summary.undefined += 1;
            }

            if record.section_index == SHN_XINDEX {
                summary.extended_indices += 1;
            }

            let name_offset = usize::try_from(record.name_offset)
                .map_err(|_| invalid_data("st_name nie mieści się w usize"))?;

            let tail = strings
                .get(name_offset..)
                .filter(|tail| !tail.is_empty())
                .ok_or_else(|| {
                    invalid_data(&format!(
                        "Sekcja #{}, symbol #{}: st_name poza tabelą napisów",
                        section_index, index
                    ))
                })?;

            if record.name_offset == 0 || tail[0] == 0 {
                continue;
            }

            if summary.preview.len() < MAX_PREVIEW_SYMBOLS {
                let (name, name_truncated) = preview_name(tail);

                summary.preview.push(SymbolPreview {
                    index,
                    name,
                    name_truncated,
                    value: record.value,
                    size: record.size,
                    binding,
                    symbol_type,
                    visibility: record.other & 0x03,
                    section_index: resolved_index,
                });
            }
        }

        summaries.push(summary);
    }

    Ok(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfIdent;
    use std::io::Cursor;

    const NAMES: &[u8] = b"\0example_function\0example_object\0";

    fn header(class: ElfClass, endian: Endianness) -> ElfHeader {
        ElfHeader {
            ident: ElfIdent {
                class,
                endianness: endian,
                version: 1,
                os_abi: 0,
                abi_version: 0,
            },
            file_type: 1,
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
            program_header_count: 0,
            section_header_entry_size: 0,
            section_header_count: 0,
            section_names_index: 0,
        }
    }

    fn section(size: usize, count: usize) -> SectionHeader {
        SectionHeader {
            name_offset: 0,
            section_type: SHT_SYMTAB,
            flags: 0,
            address: 0,
            offset: 0,
            size: (size * count) as u64,
            link: 1,
            info: 0,
            alignment: 1,
            entry_size: size as u64,
        }
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

    fn fixture(class: ElfClass, endian: Endianness) -> (Vec<u8>, Vec<SectionHeader>) {
        let size = record_size(class);
        let mut bytes = vec![0_u8; size * 3];

        let (value_offset, size_offset, info_offset, index_offset, width) = match class {
            ElfClass::Elf32 => (4, 8, 12, 14, 4),
            ElfClass::Elf64 => (8, 16, 4, 6, 8),
        };

        put(&mut bytes, size, 4, 1, endian);
        put(&mut bytes, size + value_offset, width, 0x1234, endian);
        put(&mut bytes, size + size_offset, width, 16, endian);
        bytes[size + info_offset] = 0x12;
        put(&mut bytes, size + index_offset, 2, 1, endian);

        let object_name_offset = b"\0example_function\0".len() as u64;

        put(&mut bytes, size * 2, 4, object_name_offset, endian);
        put(&mut bytes, size * 2 + size_offset, width, 8, endian);
        bytes[size * 2 + info_offset] = 0x21;

        let symbols = section(size, 3);

        let strings = SectionHeader {
            section_type: SHT_STRTAB,
            offset: bytes.len() as u64,
            size: NAMES.len() as u64,
            link: 0,
            entry_size: 0,
            ..section(1, 0)
        };

        bytes.extend_from_slice(NAMES);

        (bytes, vec![symbols, strings])
    }

    fn read_default(
        bytes: Vec<u8>,
        sections: &[SectionHeader],
    ) -> io::Result<Vec<SymbolTableSummary>> {
        read_symbol_summaries(
            &mut Cursor::new(bytes),
            &header(ElfClass::Elf64, Endianness::Little),
            sections,
        )
    }

    fn append_indices(
        bytes: &mut Vec<u8>,
        sections: &mut Vec<SectionHeader>,
        values: &[u32],
        endian: Endianness,
    ) {
        let auxiliary = SectionHeader {
            section_type: SHT_SYMTAB_SHNDX,
            offset: bytes.len() as u64,
            size: (values.len() * 4) as u64,
            link: 0,
            info: 0,
            entry_size: 4,
            ..section(1, 0)
        };

        for value in values {
            let encoded = match endian {
                Endianness::Little => value.to_le_bytes(),
                Endianness::Big => value.to_be_bytes(),
            };

            bytes.extend_from_slice(&encoded);
        }

        sections.push(auxiliary);
    }

    #[test]
    fn summarizes_all_record_layouts() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                let (bytes, sections) = fixture(class, endian);

                let result = read_symbol_summaries(
                    &mut Cursor::new(bytes),
                    &header(class, endian),
                    &sections,
                )
                .unwrap();

                let summary = &result[0];

                assert_eq!(summary.total, 3);
                assert_eq!(summary.functions, 1);
                assert_eq!(summary.objects, 1);
                assert_eq!(summary.locals, 1);
                assert_eq!(summary.globals, 1);
                assert_eq!(summary.weaks, 1);
                assert_eq!(summary.undefined, 2);
                assert_eq!(summary.extended_indices, 0);
                assert_eq!(summary.preview.len(), 2);
                assert_eq!(summary.preview[0].name, b"example_function");
                assert_eq!(summary.preview[0].value, 0x1234);
                assert_eq!(summary.preview[0].size, 16);
                assert_eq!(summary.preview[1].name, b"example_object");
                assert_eq!(
                    summary.preview[0].section_index,
                    SymbolSectionIndex::Direct(1)
                );
            }
        }
    }

    #[test]
    fn ignores_non_symbol_sections() {
        let mut section = section(24, 1);
        section.section_type = 1;

        assert!(read_default(Vec::new(), &[section]).unwrap().is_empty());
    }

    #[test]
    fn rejects_wrong_record_size() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        sections[0].entry_size = 16;

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_partial_record() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        sections[0].size -= 1;

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_truncated_table() {
        let (mut bytes, sections) = fixture(ElfClass::Elf64, Endianness::Little);

        bytes.truncate(23);

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn enforces_symbol_limit() {
        let mut section = section(24, 0);
        section.size = 24 * (MAX_SYMBOL_COUNT + 1);

        let error = read_default(Vec::new(), &[section]).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn accepts_empty_table() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        sections[0].size = 0;

        let result = read_default(bytes, &sections).unwrap();

        assert_eq!(result[0].total, 0);
        assert!(result[0].preview.is_empty());
    }

    #[test]
    fn rejects_overflowing_table_range() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        sections[0].offset = u64::MAX;

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_invalid_string_table_link() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        sections[0].link = 999;

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_link_to_non_string_section() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        sections[1].section_type = 1;

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_name_outside_string_table() {
        let (mut bytes, sections) = fixture(ElfClass::Elf64, Endianness::Little);

        put(&mut bytes, 24, 4, 999, Endianness::Little);

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn truncates_long_preview_names() {
        let mut bytes = vec![b'a'; MAX_PREVIEW_NAME_BYTES + 10];
        bytes.push(0);

        let (name, truncated) = preview_name(&bytes);

        assert_eq!(name.len(), MAX_PREVIEW_NAME_BYTES);
        assert!(truncated);
    }

    #[test]
    fn resolves_extended_indices_in_all_layouts() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                let (mut bytes, mut sections) = fixture(class, endian);

                let index_offset = match class {
                    ElfClass::Elf32 => 14,
                    ElfClass::Elf64 => 6,
                };

                put(
                    &mut bytes,
                    record_size(class) + index_offset,
                    2,
                    u64::from(SHN_XINDEX),
                    endian,
                );

                append_indices(&mut bytes, &mut sections, &[0, SHN_LORESERVE, 0], endian);

                let mut unused = section(1, 0);
                unused.section_type = 0;
                unused.link = 0;

                sections.resize(SHN_LORESERVE as usize + 1, unused);
                sections[SHN_LORESERVE as usize].section_type = 1;

                let result = read_symbol_summaries(
                    &mut Cursor::new(bytes),
                    &header(class, endian),
                    &sections,
                )
                .unwrap();

                assert_eq!(result[0].extended_indices, 1);

                assert_eq!(
                    result[0].preview[0].section_index,
                    SymbolSectionIndex::Extended(SHN_LORESERVE)
                );

                assert_eq!(
                    result[0].preview[0].section_index.to_string(),
                    "65535 -> 65280"
                );
            }
        }
    }

    #[test]
    fn rejects_missing_extended_table() {
        assert!(resolve_section_index(SHN_XINDEX, None, 65_536).is_err());
    }

    #[test]
    fn rejects_nonzero_auxiliary_for_direct_index() {
        assert!(resolve_section_index(1, Some(2), 3).is_err());
    }

    #[test]
    fn rejects_extended_index_outside_sections() {
        assert!(resolve_section_index(SHN_XINDEX, Some(65_536), 65_536).is_err());
    }

    #[test]
    fn rejects_too_small_extended_index() {
        assert!(resolve_section_index(SHN_XINDEX, Some(1), 65_536).is_err());
    }

    #[test]
    fn rejects_wrong_auxiliary_table_length() {
        let (mut bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        append_indices(&mut bytes, &mut sections, &[0, 0], Endianness::Little);

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_duplicate_auxiliary_tables() {
        let (mut bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little);

        append_indices(&mut bytes, &mut sections, &[0, 0, 0], Endianness::Little);

        let duplicate = sections.last().unwrap().clone();
        sections.push(duplicate);

        assert!(read_default(bytes, &sections).is_err());
    }
}
