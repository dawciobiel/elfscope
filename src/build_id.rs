use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use crate::elf::{ElfHeader, Endianness};
use crate::sections::SectionTable;

const SHT_NOTE: u32 = 7;
const NT_GNU_BUILD_ID: u32 = 3;
const MAX_TOTAL_NOTE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BUILD_IDS: usize = 64;
const MAX_BUILD_ID_BYTES: usize = 4096;
const MAX_NOTES_PER_SECTION: usize = 100_000;

#[derive(Debug, PartialEq, Eq)]
pub struct BuildId {
    pub section_index: usize,
    pub bytes: Vec<u8>,
}

impl fmt::Display for BuildId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(formatter, "{:02x}", byte)?;
        }
        Ok(())
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
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

fn align4(value: usize) -> io::Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| invalid_data("Przepełnienie wyrównania notatki"))
}

fn parse_notes(bytes: &[u8], endian: Endianness, section_index: usize) -> io::Result<Vec<BuildId>> {
    let mut position = 0_usize;
    let mut note_count = 0_usize;
    let mut result = Vec::new();

    while position < bytes.len() {
        note_count += 1;
        if note_count > MAX_NOTES_PER_SECTION {
            return Err(unsupported("Przekroczono limit notatek w sekcji"));
        }

        let header_end = position
            .checked_add(12)
            .ok_or_else(|| invalid_data("Przepełnienie nagłówka notatki"))?;
        if header_end > bytes.len() {
            return Err(invalid_data("Ucięty nagłówek notatki ELF"));
        }

        let name_size = usize::try_from(u32_at(bytes, position, endian))
            .map_err(|_| invalid_data("Rozmiar właściciela nie mieści się w usize"))?;
        let desc_size = usize::try_from(u32_at(bytes, position + 4, endian))
            .map_err(|_| invalid_data("Rozmiar deskryptora nie mieści się w usize"))?;
        let note_type = u32_at(bytes, position + 8, endian);

        let name_end = header_end
            .checked_add(name_size)
            .ok_or_else(|| invalid_data("Przepełnienie zakresu właściciela"))?;
        let desc_start = align4(name_end)?;
        let desc_end = desc_start
            .checked_add(desc_size)
            .ok_or_else(|| invalid_data("Przepełnienie zakresu deskryptora"))?;
        let next = align4(desc_end)?;

        if name_end > bytes.len() || next > bytes.len() {
            return Err(invalid_data(
                "Notatka lub jej wyrównanie wykracza poza sekcję",
            ));
        }

        let owner = &bytes[header_end..name_end];
        if !owner.is_empty() && owner.last() != Some(&0) {
            return Err(invalid_data("Właściciel notatki nie jest zakończony zerem"));
        }

        if owner == b"GNU\0" && note_type == NT_GNU_BUILD_ID {
            if desc_size == 0 {
                return Err(invalid_data("GNU Build ID ma pusty deskryptor"));
            }
            if desc_size > MAX_BUILD_ID_BYTES {
                return Err(unsupported("GNU Build ID przekracza limit 4096 bajtów"));
            }
            if result.len() >= MAX_BUILD_IDS {
                return Err(unsupported(
                    "Przekroczono limit 64 identyfikatorów Build ID",
                ));
            }
            result.push(BuildId {
                section_index,
                bytes: bytes[desc_start..desc_end].to_vec(),
            });
        }
        position = next;
    }
    Ok(result)
}

pub fn read_build_ids(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
    sections: &SectionTable,
) -> io::Result<Vec<BuildId>> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let mut total_bytes = 0_u64;
    let mut result = Vec::new();

    for (index, section) in sections.headers.iter().enumerate() {
        if section.section_type != SHT_NOTE
            || sections.name(index) != Some(&b".note.gnu.build-id"[..])
        {
            continue;
        }

        // Ten etap obsługuje konwencjonalne notatki z wyrównaniem 4.
        if !matches!(section.alignment, 0 | 1 | 4) {
            return Err(unsupported("Nieobsługiwane wyrównanie sekcji GNU Build ID"));
        }

        total_bytes = total_bytes
            .checked_add(section.size)
            .ok_or_else(|| invalid_data("Przepełnienie rozmiaru sekcji Build ID"))?;
        if total_bytes > MAX_TOTAL_NOTE_BYTES {
            return Err(unsupported(
                "Sekcje GNU Build ID przekraczają łącznie 16 MiB",
            ));
        }

        let end = section
            .offset
            .checked_add(section.size)
            .ok_or_else(|| invalid_data("Przepełnienie zakresu sekcji Build ID"))?;
        if end > file_size {
            return Err(invalid_data("Sekcja GNU Build ID wykracza poza plik"));
        }

        let size = usize::try_from(section.size)
            .map_err(|_| invalid_data("Rozmiar sekcji nie mieści się w usize"))?;
        reader.seek(SeekFrom::Start(section.offset))?;
        let mut bytes = vec![0_u8; size];
        reader.read_exact(&mut bytes)?;

        let parsed = parse_notes(&bytes, header.ident.endianness, index)?;
        if result.len() + parsed.len() > MAX_BUILD_IDS {
            return Err(unsupported(
                "Przekroczono limit 64 identyfikatorów Build ID",
            ));
        }
        result.extend(parsed);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(owner: &[u8], kind: u32, desc: &[u8], endian: Endianness) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [owner.len() as u32, desc.len() as u32, kind] {
            let encoded = match endian {
                Endianness::Little => value.to_le_bytes(),
                Endianness::Big => value.to_be_bytes(),
            };
            bytes.extend_from_slice(&encoded);
        }
        bytes.extend_from_slice(owner);
        bytes.resize(align4(bytes.len()).unwrap(), 0);
        bytes.extend_from_slice(desc);
        bytes.resize(align4(bytes.len()).unwrap(), 0);
        bytes
    }

    #[test]
    fn reads_build_id_in_both_byte_orders() {
        for endian in [Endianness::Little, Endianness::Big] {
            let bytes = note(b"GNU\0", 3, &[0x01, 0xab, 0xff], endian);
            let ids = parse_notes(&bytes, endian, 7).unwrap();
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0].section_index, 7);
            assert_eq!(ids[0].bytes, [0x01, 0xab, 0xff]);
            assert_eq!(ids[0].to_string(), "01abff");
        }
    }

    #[test]
    fn handles_padding_and_multiple_notes() {
        let mut bytes = note(b"GNU\0", 3, &[1, 2, 3, 4, 5], Endianness::Little);
        bytes.extend(note(b"GNU\0", 3, &[6], Endianness::Little));
        let ids = parse_notes(&bytes, Endianness::Little, 1).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[1].bytes, [6]);
    }

    #[test]
    fn ignores_other_owners() {
        let bytes = note(b"OTHER\0", 3, &[1], Endianness::Little);
        assert!(
            parse_notes(&bytes, Endianness::Little, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_truncated_descriptor() {
        let mut bytes = note(b"GNU\0", 3, &[1, 2, 3, 4], Endianness::Little);
        bytes.pop();
        assert!(parse_notes(&bytes, Endianness::Little, 0).is_err());
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(parse_notes(&[0_u8; 11], Endianness::Little, 0).is_err());
    }

    #[test]
    fn rejects_empty_build_id() {
        let bytes = note(b"GNU\0", 3, &[], Endianness::Little);
        assert!(parse_notes(&bytes, Endianness::Little, 0).is_err());
    }

    #[test]
    fn rejects_unterminated_owner() {
        let bytes = note(b"GNUx", 3, &[1], Endianness::Little);
        assert!(parse_notes(&bytes, Endianness::Little, 0).is_err());
    }

    #[test]
    fn rejects_oversized_build_id() {
        let bytes = note(
            b"GNU\0",
            3,
            &vec![1; MAX_BUILD_ID_BYTES + 1],
            Endianness::Little,
        );
        let error = parse_notes(&bytes, Endianness::Little, 0).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
