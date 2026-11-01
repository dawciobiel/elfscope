use std::io::{self, BufReader, Read, Seek, SeekFrom};

use crate::elf::{ElfClass, ElfHeader, Endianness};
use crate::sections::SectionHeader;

const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;

const MAX_RELOCATION_COUNT: u64 = 1_000_000;
const MAX_RELOCATION_TABLES: usize = 128;
const MAX_PREVIEW_RECORDS: usize = 10;

#[derive(Debug, PartialEq, Eq)]
pub struct RelocationPreview {
    pub index: u64,
    pub offset: u64,
    pub info: u64,
    pub addend: Option<i64>,
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
    })
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

        let end = section
            .offset
            .checked_add(section.size)
            .ok_or_else(|| invalid_data("Przepełnienie zakresu relokacji"))?;

        if end > file_size {
            return Err(invalid_data("Tablica relokacji wykracza poza plik"));
        }

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

            if preview.len() < MAX_PREVIEW_RECORDS {
                preview.push(record);
            }
        }

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

    fn fixture(
        class: ElfClass,
        endian: Endianness,
        with_addend: bool,
    ) -> (Vec<u8>, Vec<SectionHeader>) {
        let size = entry_size(class, with_addend);
        let mut bytes = Vec::new();

        push(&mut bytes, 0x1234, class, endian);
        push(&mut bytes, 0x5678, class, endian);

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
            size: symbol_size,
            link: 0,
            entry_size: symbol_size,
            ..relocation.clone()
        };

        bytes.resize((size + symbol_size) as usize, 0);

        (bytes, vec![relocation, symbols])
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

                    assert_eq!(result.len(), 1);
                    assert_eq!(result[0].total, 1);
                    assert_eq!(result[0].symbol_table_index, 1);
                    assert_eq!(result[0].preview[0].offset, 0x1234);
                    assert_eq!(result[0].preview[0].info, 0x5678);

                    assert_eq!(
                        result[0].preview[0].addend,
                        if with_addend { Some(-7) } else { None }
                    );
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
}
