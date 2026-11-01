use std::io::{self, BufReader, Read, Seek, SeekFrom};

use crate::elf::{ElfClass, ElfHeader, Endianness};
use crate::sections::SectionHeader;

const SHT_SYMTAB: u32 = 2;
const SHT_DYNSYM: u32 = 11;

const SHN_UNDEF: u16 = 0;
const SHN_XINDEX: u16 = 0xffff;

// Łączny limit wpisów we wszystkich tablicach jednego pliku.
const MAX_SYMBOL_COUNT: u64 = 1_000_000;

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
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn record_layout(class: ElfClass) -> (usize, usize, usize) {
    match class {
        // Rozmiar rekordu, offset st_info, offset st_shndx.
        ElfClass::Elf32 => (16, 12, 14),
        ElfClass::Elf64 => (24, 4, 6),
    }
}

fn decode_section_index(bytes: [u8; 2], endian: Endianness) -> u16 {
    match endian {
        Endianness::Little => u16::from_le_bytes(bytes),
        Endianness::Big => u16::from_be_bytes(bytes),
    }
}

pub fn read_symbol_summaries(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
    sections: &[SectionHeader],
) -> io::Result<Vec<SymbolTableSummary>> {
    let (record_size, info_offset, index_offset) = record_layout(header.ident.class);

    let mut reader = BufReader::new(reader);
    let file_size = reader.seek(SeekFrom::End(0))?;

    let mut summaries = Vec::new();
    let mut total_symbols = 0_u64;

    for (section_index, section) in sections.iter().enumerate() {
        if !matches!(section.section_type, SHT_SYMTAB | SHT_DYNSYM) {
            continue;
        }

        if section.entry_size != record_size as u64 {
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
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Liczba symboli przekracza limit narzędzia: 1000000",
            ));
        }

        let end = section
            .offset
            .checked_add(section.size)
            .ok_or_else(|| invalid_data("Przepełnienie zakresu tablicy symboli"))?;

        if end > file_size {
            return Err(invalid_data("Tablica symboli wykracza poza plik"));
        }

        reader.seek(SeekFrom::Start(section.offset))?;

        let mut summary = SymbolTableSummary {
            section_index,
            total: count,
            ..SymbolTableSummary::default()
        };

        let mut bytes = [0_u8; 24];

        for _ in 0..count {
            reader.read_exact(&mut bytes[..record_size])?;

            let info = bytes[info_offset];
            let binding = info >> 4;
            let symbol_type = info & 0x0f;

            let section_index = decode_section_index(
                [bytes[index_offset], bytes[index_offset + 1]],
                header.ident.endianness,
            );

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

            if section_index == SHN_UNDEF {
                summary.undefined += 1;
            }

            if section_index == SHN_XINDEX {
                summary.extended_indices += 1;
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

    fn section(record_size: usize, count: usize) -> SectionHeader {
        SectionHeader {
            name_offset: 0,
            section_type: SHT_SYMTAB,
            flags: 0,
            address: 0,
            offset: 0,
            size: (record_size * count) as u64,
            link: 0,
            info: 0,
            alignment: 1,
            entry_size: record_size as u64,
        }
    }

    fn records(class: ElfClass, endian: Endianness) -> Vec<u8> {
        let (size, info_offset, index_offset) = record_layout(class);
        let mut bytes = vec![0_u8; size * 3];

        // Wpis 0: LOCAL, NOTYPE, SHN_UNDEF.
        // Wpis 1: GLOBAL, FUNC, sekcja 1.
        bytes[size + info_offset] = 0x12;

        let index = match endian {
            Endianness::Little => 1_u16.to_le_bytes(),
            Endianness::Big => 1_u16.to_be_bytes(),
        };

        bytes[size + index_offset..size + index_offset + 2].copy_from_slice(&index);

        // Wpis 2: WEAK, OBJECT, SHN_UNDEF.
        bytes[size * 2 + info_offset] = 0x21;

        bytes
    }

    #[test]
    fn summarizes_all_record_layouts() {
        for class in [ElfClass::Elf32, ElfClass::Elf64] {
            for endian in [Endianness::Little, Endianness::Big] {
                let (size, _, _) = record_layout(class);
                let sections = [section(size, 3)];

                let result = read_symbol_summaries(
                    &mut Cursor::new(records(class, endian)),
                    &header(class, endian),
                    &sections,
                )
                .unwrap();

                assert_eq!(
                    result,
                    vec![SymbolTableSummary {
                        section_index: 0,
                        total: 3,
                        functions: 1,
                        objects: 1,
                        locals: 1,
                        globals: 1,
                        weaks: 1,
                        undefined: 2,
                        extended_indices: 0,
                    }]
                );
            }
        }
    }

    #[test]
    fn ignores_non_symbol_sections() {
        let mut section = section(24, 1);
        section.section_type = 1;

        let result = read_symbol_summaries(
            &mut Cursor::new(Vec::<u8>::new()),
            &header(ElfClass::Elf64, Endianness::Little),
            &[section],
        )
        .unwrap();

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_wrong_record_size() {
        let mut section = section(24, 1);
        section.entry_size = 16;

        assert!(
            read_symbol_summaries(
                &mut Cursor::new(vec![0_u8; 24]),
                &header(ElfClass::Elf64, Endianness::Little),
                &[section],
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_partial_record() {
        let mut section = section(24, 1);
        section.size = 23;

        assert!(
            read_symbol_summaries(
                &mut Cursor::new(vec![0_u8; 24]),
                &header(ElfClass::Elf64, Endianness::Little),
                &[section],
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_truncated_table() {
        assert!(
            read_symbol_summaries(
                &mut Cursor::new(vec![0_u8; 23]),
                &header(ElfClass::Elf64, Endianness::Little),
                &[section(24, 1)],
            )
            .is_err()
        );
    }

    #[test]
    fn enforces_symbol_limit() {
        let mut section = section(24, 0);
        section.size = 24 * (MAX_SYMBOL_COUNT + 1);

        let error = read_symbol_summaries(
            &mut Cursor::new(Vec::<u8>::new()),
            &header(ElfClass::Elf64, Endianness::Little),
            &[section],
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn accepts_empty_table() {
        let result = read_symbol_summaries(
            &mut Cursor::new(Vec::<u8>::new()),
            &header(ElfClass::Elf64, Endianness::Little),
            &[section(24, 0)],
        )
        .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].total, 0);
    }

    #[test]
    fn rejects_overflowing_table_range() {
        let mut section = section(24, 1);
        section.offset = u64::MAX;

        assert!(
            read_symbol_summaries(
                &mut Cursor::new(Vec::<u8>::new()),
                &header(ElfClass::Elf64, Endianness::Little),
                &[section],
            )
            .is_err()
        );
    }
}
