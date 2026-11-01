use std::io::{self, BufReader, Read, Seek, SeekFrom};

use crate::elf::{ElfClass, ElfHeader, Endianness};
use crate::sections::SectionHeader;

const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;

const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;

const MAX_RELOCATION_COUNT: u64 = 1_000_000;
const MAX_RELOCATION_TABLES: usize = 128;
const MAX_PREVIEW_RECORDS: usize = 10;
const MAX_STRING_TABLE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_NAME_BYTES: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub struct RelocationSymbol {
    pub index: u64,
    pub relocation_type: u32,
    pub name: Vec<u8>,
    pub name_truncated: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RelocationPreview {
    pub index: u64,
    pub offset: u64,
    pub info: u64,
    pub addend: Option<i64>,
    pub symbol: Option<RelocationSymbol>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RelocationTableSummary {
    pub section_index: usize,
    pub symbol_table_index: usize,
    pub target_section_index: Option<usize>,
    pub with_addend: bool,
    pub total: u64,
    pub preview: Vec<RelocationPreview>,
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

fn entry_size(class: ElfClass, with_addend: bool) -> u64 {
    match (class, with_addend) {
        (ElfClass::Elf32, false) => 8,
        (ElfClass::Elf32, true) => 12,
        (ElfClass::Elf64, false) => 16,
        (ElfClass::Elf64, true) => 24,
    }
}

fn read_u32(reader: &mut impl Read, endian: Endianness) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;

    Ok(match endian {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    })
}

fn read_word(reader: &mut impl Read, class: ElfClass, endian: Endianness) -> io::Result<u64> {
    match class {
        ElfClass::Elf32 => Ok(u64::from(read_u32(reader, endian)?)),
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

fn read_record(
    reader: &mut impl Read,
    header: &ElfHeader,
    with_addend: bool,
    index: u64,
) -> io::Result<RelocationPreview> {
    let class = header.ident.class;
    let endian = header.ident.endianness;

    let offset = read_word(reader, class, endian)?;
    let info = read_word(reader, class, endian)?;

    let addend = if with_addend {
        let raw = read_word(reader, class, endian)?;

        Some(match class {
            ElfClass::Elf32 => i64::from(raw as u32 as i32),
            ElfClass::Elf64 => raw as i64,
        })
    } else {
        None
    };

    Ok(RelocationPreview {
        index,
        offset,
        info,
        addend,
        symbol: None,
    })
}

fn decode_info(info: u64, header: &ElfHeader) -> Option<(u64, u32)> {
    match (header.ident.class, header.machine) {
        (ElfClass::Elf32, EM_386) => Some((info >> 8, (info & 0xff) as u32)),
        (ElfClass::Elf64, EM_X86_64) => Some((info >> 32, (info & 0xffff_ffff) as u32)),
        _ => None,
    }
}

fn linked_symbol_count(symbols: &SectionHeader, class: ElfClass) -> io::Result<u64> {
    let expected_size = match class {
        ElfClass::Elf32 => 16,
        ElfClass::Elf64 => 24,
    };

    if symbols.entry_size != expected_size {
        return Err(invalid_data(
            "Powiązana tablica symboli ma nieprawidłowy rozmiar rekordu",
        ));
    }

    if symbols.size % expected_size != 0 {
        return Err(invalid_data("Powiązana tablica symboli ma niepełny rekord"));
    }

    Ok(symbols.size / expected_size)
}

fn validate_range(offset: u64, size: u64, file_size: u64) -> io::Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_data("Przepełnienie zakresu danych relokacji"))?;

    if end > file_size {
        return Err(invalid_data(
            "Dane relokacji lub powiązanych tablic wykraczają poza plik",
        ));
    }

    Ok(())
}

fn bounded_name(tail: &[u8]) -> (Vec<u8>, bool) {
    let inspected = tail.len().min(MAX_NAME_BYTES + 1);

    if let Some(end) = tail[..inspected].iter().position(|&byte| byte == 0) {
        return (tail[..end].to_vec(), false);
    }

    (tail[..MAX_NAME_BYTES].to_vec(), true)
}

fn resolve_preview_symbols(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
    sections: &[SectionHeader],
    symbols: &SectionHeader,
    preview: &mut [RelocationPreview],
    file_size: u64,
) -> io::Result<()> {
    if preview.is_empty() || decode_info(0, header).is_none() {
        return Ok(());
    }

    validate_range(symbols.offset, symbols.size, file_size)?;

    let strings_index = usize::try_from(symbols.link)
        .map_err(|_| invalid_data("Indeks napisów symboli nie mieści się w usize"))?;

    let strings_header = sections
        .get(strings_index)
        .ok_or_else(|| invalid_data("sh_link tablicy symboli wykracza poza sekcje"))?;

    if strings_header.section_type != SHT_STRTAB {
        return Err(invalid_data(
            "sh_link tablicy symboli nie wskazuje sekcji STRTAB",
        ));
    }

    if strings_header.size > MAX_STRING_TABLE_SIZE {
        return Err(unsupported(
            "Tabela nazw symboli relokacji przekracza limit 16 MiB",
        ));
    }

    validate_range(strings_header.offset, strings_header.size, file_size)?;

    let strings_size = usize::try_from(strings_header.size)
        .map_err(|_| invalid_data("Rozmiar napisów nie mieści się w usize"))?;

    reader.seek(SeekFrom::Start(strings_header.offset))?;

    let mut strings = vec![0_u8; strings_size];
    reader.read_exact(&mut strings)?;

    if strings.first() != Some(&0) || strings.last() != Some(&0) {
        return Err(invalid_data(
            "Tabela nazw symboli musi zaczynać się i kończyć bajtem zerowym",
        ));
    }

    for record in preview {
        let Some((symbol_index, relocation_type)) = decode_info(record.info, header) else {
            continue;
        };

        if symbol_index == 0 {
            record.symbol = Some(RelocationSymbol {
                index: 0,
                relocation_type,
                name: Vec::new(),
                name_truncated: false,
            });

            continue;
        }

        let displacement = symbol_index
            .checked_mul(symbols.entry_size)
            .ok_or_else(|| invalid_data("Przepełnienie przesunięcia symbolu"))?;

        let symbol_offset = symbols
            .offset
            .checked_add(displacement)
            .ok_or_else(|| invalid_data("Przepełnienie offsetu symbolu"))?;

        reader.seek(SeekFrom::Start(symbol_offset))?;

        // st_name znajduje się na początku rekordu w ELF32 i ELF64.
        let name_offset = usize::try_from(read_u32(reader, header.ident.endianness)?)
            .map_err(|_| invalid_data("st_name nie mieści się w usize"))?;

        let tail = strings
            .get(name_offset..)
            .filter(|tail| !tail.is_empty())
            .ok_or_else(|| invalid_data("Nazwa symbolu relokacji wykracza poza tabelę napisów"))?;

        let (name, name_truncated) = bounded_name(tail);

        record.symbol = Some(RelocationSymbol {
            index: symbol_index,
            relocation_type,
            name,
            name_truncated,
        });
    }

    Ok(())
}

pub fn read_relocation_summaries(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
    sections: &[SectionHeader],
) -> io::Result<Vec<RelocationTableSummary>> {
    let mut reader = BufReader::new(reader);
    let file_size = reader.seek(SeekFrom::End(0))?;

    let mut summaries = Vec::new();
    let mut total_records = 0_u64;

    for (section_index, section) in sections.iter().enumerate() {
        if !matches!(section.section_type, SHT_REL | SHT_RELA) {
            continue;
        }

        if summaries.len() >= MAX_RELOCATION_TABLES {
            return Err(unsupported("Przekroczono limit 128 tablic relokacji"));
        }

        let with_addend = section.section_type == SHT_RELA;
        let expected_size = entry_size(header.ident.class, with_addend);

        if section.entry_size != expected_size {
            return Err(invalid_data(&format!(
                "Sekcja #{}: nieprawidłowy rozmiar rekordu relokacji",
                section_index
            )));
        }

        if section.size % expected_size != 0 {
            return Err(invalid_data(
                "Rozmiar tablicy relokacji nie jest wielokrotnością rekordu",
            ));
        }

        let count = section.size / expected_size;

        total_records = total_records
            .checked_add(count)
            .ok_or_else(|| invalid_data("Przepełnienie licznika relokacji"))?;

        if total_records > MAX_RELOCATION_COUNT {
            return Err(unsupported("Liczba relokacji przekracza limit 1000000"));
        }

        validate_range(section.offset, section.size, file_size)?;

        let symbol_table_index = usize::try_from(section.link)
            .map_err(|_| invalid_data("Indeks tablicy symboli nie mieści się w usize"))?;

        let symbols = sections
            .get(symbol_table_index)
            .ok_or_else(|| invalid_data("sh_link relokacji wykracza poza sekcje"))?;

        if !matches!(symbols.section_type, SHT_SYMTAB | SHT_DYNSYM) {
            return Err(invalid_data(
                "sh_link relokacji nie wskazuje tablicy symboli",
            ));
        }

        let symbol_count = linked_symbol_count(symbols, header.ident.class)?;

        let target_section_index = if section.info == 0 {
            if header.file_type == 1 {
                return Err(invalid_data(
                    "Relokacja w ET_REL nie wskazuje sekcji docelowej",
                ));
            }

            None
        } else {
            let index = usize::try_from(section.info)
                .map_err(|_| invalid_data("Indeks sekcji docelowej nie mieści się w usize"))?;

            if index >= sections.len() {
                return Err(invalid_data("sh_info relokacji wykracza poza sekcje"));
            }

            Some(index)
        };

        reader.seek(SeekFrom::Start(section.offset))?;

        let mut preview = Vec::new();

        for index in 0..count {
            let record = read_record(&mut reader, header, with_addend, index)?;

            if let Some((symbol_index, _)) = decode_info(record.info, header) {
                if symbol_index >= symbol_count {
                    return Err(invalid_data(&format!(
                        "Sekcja #{}, relokacja #{}: indeks symbolu {} poza tablicą #{} (liczba wpisów: {})",
                        section_index, index, symbol_index, symbol_table_index, symbol_count
                    )));
                }
            }

            if preview.len() < MAX_PREVIEW_RECORDS {
                preview.push(record);
            }
        }

        // Nazwy rozwiązujemy po odczytaniu rekordów, aby dodatkowe seek()
        // nie zmieniały pozycji podczas przechodzenia tablicy relokacji.
        resolve_preview_symbols(
            &mut reader,
            header,
            sections,
            symbols,
            &mut preview,
            file_size,
        )?;

        summaries.push(RelocationTableSummary {
            section_index,
            symbol_table_index,
            target_section_index,
            with_addend,
            total: count,
            preview,
        });
    }

    Ok(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ElfIdent;
    use std::io::Cursor;

    fn header(class: ElfClass, endian: Endianness) -> ElfHeader {
        ElfHeader {
            ident: ElfIdent {
                class,
                endianness: endian,
                version: 1,
                os_abi: 0,
                abi_version: 0,
            },
            file_type: 3,
            machine: match class {
                ElfClass::Elf32 => EM_386,
                ElfClass::Elf64 => EM_X86_64,
            },
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

    fn push(bytes: &mut Vec<u8>, value: u64, class: ElfClass, endian: Endianness) {
        let width = match class {
            ElfClass::Elf32 => 4,
            ElfClass::Elf64 => 8,
        };

        match endian {
            Endianness::Little => {
                bytes.extend_from_slice(&value.to_le_bytes()[..width]);
            }
            Endianness::Big => {
                bytes.extend_from_slice(&value.to_be_bytes()[8 - width..]);
            }
        }
    }

    fn encoded_info(class: ElfClass, symbol: u64, kind: u64) -> u64 {
        match class {
            ElfClass::Elf32 => (symbol << 8) | kind,
            ElfClass::Elf64 => (symbol << 32) | kind,
        }
    }

    fn fixture(
        class: ElfClass,
        endian: Endianness,
        with_addend: bool,
    ) -> (Vec<u8>, Vec<SectionHeader>) {
        let size = entry_size(class, with_addend);
        let mut bytes = Vec::new();

        push(&mut bytes, 0x1234, class, endian);
        push(&mut bytes, encoded_info(class, 1, 2), class, endian);

        if with_addend {
            push(&mut bytes, (-7_i64) as u64, class, endian);
        }

        let relocation = SectionHeader {
            name_offset: 0,
            section_type: if with_addend { SHT_RELA } else { SHT_REL },
            flags: 0,
            address: 0,
            offset: 0,
            size,
            link: 1,
            info: 0,
            alignment: 1,
            entry_size: size,
        };

        let symbol_size = match class {
            ElfClass::Elf32 => 16,
            ElfClass::Elf64 => 24,
        };

        let symbols = SectionHeader {
            section_type: SHT_SYMTAB,
            offset: size,
            size: 2 * symbol_size,
            link: 2,
            entry_size: symbol_size,
            ..relocation.clone()
        };

        bytes.resize((size + 2 * symbol_size) as usize, 0);

        let symbol_one_offset = (size + symbol_size) as usize;
        let name_offset = match endian {
            Endianness::Little => 1_u32.to_le_bytes(),
            Endianness::Big => 1_u32.to_be_bytes(),
        };

        bytes[symbol_one_offset..symbol_one_offset + 4].copy_from_slice(&name_offset);

        let names = b"\0example_symbol\0";

        let strings = SectionHeader {
            section_type: SHT_STRTAB,
            offset: bytes.len() as u64,
            size: names.len() as u64,
            link: 0,
            entry_size: 0,
            ..relocation.clone()
        };

        bytes.extend_from_slice(names);

        (bytes, vec![relocation, symbols, strings])
    }

    fn replace_info(bytes: &mut [u8], info: u64) {
        bytes[8..16].copy_from_slice(&info.to_le_bytes());
    }

    fn read_default(
        bytes: Vec<u8>,
        sections: &[SectionHeader],
    ) -> io::Result<Vec<RelocationTableSummary>> {
        read_relocation_summaries(
            &mut Cursor::new(bytes),
            &header(ElfClass::Elf64, Endianness::Little),
            sections,
        )
    }

    #[test]
    fn reads_all_record_formats() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                for with_addend in [false, true] {
                    let (bytes, sections) = fixture(class, endian, with_addend);

                    let result = read_relocation_summaries(
                        &mut Cursor::new(bytes),
                        &header(class, endian),
                        &sections,
                    )
                    .unwrap();

                    let record = &result[0].preview[0];

                    assert_eq!(result[0].total, 1);
                    assert_eq!(record.offset, 0x1234);
                    assert_eq!(record.info, encoded_info(class, 1, 2));

                    assert_eq!(record.addend, if with_addend { Some(-7) } else { None });

                    let symbol = record.symbol.as_ref().unwrap();

                    assert_eq!(symbol.index, 1);
                    assert_eq!(symbol.relocation_type, 2);
                    assert_eq!(symbol.name, b"example_symbol");
                    assert!(!symbol.name_truncated);
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_record_size() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[0].entry_size = 16;
        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_partial_record() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[0].size -= 1;
        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_invalid_symbol_table_link() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[0].link = 999;
        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_invalid_target_section() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[0].info = 999;
        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_truncated_table() {
        let (mut bytes, sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        bytes.truncate(23);
        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn enforces_record_limit() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[0].size = 24 * (MAX_RELOCATION_COUNT + 1);
        let error = read_default(bytes, &sections).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn ignores_non_relocation_sections() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[0].section_type = 1;
        assert!(read_default(bytes, &sections).unwrap().is_empty());
    }

    #[test]
    fn rejects_symbol_index_at_table_end() {
        let (mut bytes, sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        replace_info(&mut bytes, encoded_info(ElfClass::Elf64, 2, 2));
        let error = read_default(bytes, &sections).unwrap_err();
        assert!(error.to_string().contains("indeks symbolu 2 poza tablicą"));
    }

    #[test]
    fn accepts_zero_symbol_index() {
        let (mut bytes, sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        replace_info(&mut bytes, encoded_info(ElfClass::Elf64, 0, 8));

        let result = read_default(bytes, &sections).unwrap();
        let symbol = result[0].preview[0].symbol.as_ref().unwrap();

        assert_eq!(symbol.index, 0);
        assert!(symbol.name.is_empty());
    }

    #[test]
    fn preserves_raw_info_for_other_architectures() {
        let (mut bytes, sections) = fixture(ElfClass::Elf64, Endianness::Little, true);

        let info = encoded_info(ElfClass::Elf64, 999, 2);
        replace_info(&mut bytes, info);

        let mut header = header(ElfClass::Elf64, Endianness::Little);
        header.machine = 183;

        let result =
            read_relocation_summaries(&mut Cursor::new(bytes), &header, &sections).unwrap();

        assert_eq!(result[0].preview[0].info, info);
        assert!(result[0].preview[0].symbol.is_none());
    }

    #[test]
    fn rejects_invalid_linked_symbol_record_size() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[1].entry_size = 16;
        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_invalid_symbol_string_link() {
        let (bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);
        sections[1].link = 999;
        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn rejects_symbol_name_outside_strings() {
        let (mut bytes, sections) = fixture(ElfClass::Elf64, Endianness::Little, true);

        let symbol_one_offset = (sections[1].offset + 24) as usize;

        bytes[symbol_one_offset..symbol_one_offset + 4].copy_from_slice(&999_u32.to_le_bytes());

        assert!(read_default(bytes, &sections).is_err());
    }

    #[test]
    fn truncates_long_symbol_name_preview() {
        let (mut bytes, mut sections) = fixture(ElfClass::Elf64, Endianness::Little, true);

        bytes.truncate(sections[2].offset as usize);
        bytes.push(0);
        bytes.extend(vec![b'a'; 300]);
        bytes.push(0);
        sections[2].size = 302;

        let result = read_default(bytes, &sections).unwrap();
        let symbol = result[0].preview[0].symbol.as_ref().unwrap();

        assert_eq!(symbol.name.len(), MAX_NAME_BYTES);
        assert!(symbol.name_truncated);
    }
}
