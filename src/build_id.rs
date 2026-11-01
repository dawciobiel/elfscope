use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use crate::elf::{ElfHeader, Endianness, ProgramHeader};
use crate::sections::SectionTable;

const SHT_NOTE: u32 = 7;
const PT_NOTE: u32 = 4;
const NT_GNU_BUILD_ID: u32 = 3;
const SHF_COMPRESSED: u64 = 0x800;
const MAX_TOTAL_NOTE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_BUILD_IDS: usize = 64;
const MAX_BUILD_ID_BYTES: usize = 4096;
const MAX_NOTES_PER_RANGE: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteSource {
    Section(usize),
    Segment(usize),
}

impl fmt::Display for NoteSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Section(index) => write!(f, "sekcja #{}", index),
            Self::Segment(index) => write!(f, "segment #{}", index),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BuildId {
    pub sources: Vec<NoteSource>,
    pub note_offset: u64,
    pub bytes: Vec<u8>,
}

impl fmt::Display for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

struct NoteRange {
    offset: u64,
    size: u64,
    alignment: u64,
    source: NoteSource,
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
fn note_alignment(declared: u64) -> io::Result<usize> {
    match declared {
        0 | 1 | 4 => Ok(4),
        8 => Ok(8),
        _ => Err(unsupported(
            "Nieobsługiwane wyrównanie notatek: dozwolone 0, 1, 4, 8",
        )),
    }
}
fn align(value: usize, alignment: usize) -> io::Result<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or_else(|| invalid_data("Przepełnienie wyrównania notatki"))
}

fn parse_notes(bytes: &[u8], endian: Endianness, range: &NoteRange) -> io::Result<Vec<BuildId>> {
    let alignment = note_alignment(range.alignment)?;
    let mut position = 0_usize;
    let mut note_count = 0_usize;
    let mut result = Vec::new();
    while position < bytes.len() {
        note_count += 1;
        if note_count > MAX_NOTES_PER_RANGE {
            return Err(unsupported("Przekroczono limit notatek w jednym zakresie"));
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
        let desc_start = align(name_end, alignment)?;
        let desc_end = desc_start
            .checked_add(desc_size)
            .ok_or_else(|| invalid_data("Przepełnienie zakresu deskryptora"))?;
        let next = align(desc_end, alignment)?;
        if name_end > bytes.len() || next > bytes.len() {
            return Err(invalid_data(
                "Notatka lub jej wyrównanie wykracza poza sekcję lub segment",
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
            let note_offset = range
                .offset
                .checked_add(position as u64)
                .ok_or_else(|| invalid_data("Przepełnienie offsetu notatki"))?;
            result.push(BuildId {
                sources: vec![range.source],
                note_offset,
                bytes: bytes[desc_start..desc_end].to_vec(),
            });
        }
        position = next;
    }
    Ok(result)
}

fn merge_build_ids(result: &mut Vec<BuildId>, parsed: Vec<BuildId>) -> io::Result<()> {
    for id in parsed {
        if let Some(existing) = result
            .iter_mut()
            .find(|existing| existing.note_offset == id.note_offset)
        {
            if existing.bytes != id.bytes {
                return Err(invalid_data(
                    "Sprzeczne interpretacje Build ID pod tym samym offsetem",
                ));
            }
            for source in id.sources {
                if !existing.sources.contains(&source) {
                    existing.sources.push(source);
                }
            }
        } else {
            if result.len() >= MAX_BUILD_IDS {
                return Err(unsupported(
                    "Przekroczono limit 64 identyfikatorów Build ID",
                ));
            }
            result.push(id);
        }
    }
    Ok(())
}

pub fn read_build_ids(
    reader: &mut (impl Read + Seek),
    header: &ElfHeader,
    sections: &SectionTable,
    program_headers: &[ProgramHeader],
) -> io::Result<Vec<BuildId>> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let mut ranges = Vec::new();
    for (index, section) in sections.headers.iter().enumerate() {
        if section.section_type != SHT_NOTE
            || sections.name(index) != Some(&b".note.gnu.build-id"[..])
        {
            continue;
        }
        if section.flags & SHF_COMPRESSED != 0 {
            return Err(unsupported(
                "Skompresowana sekcja GNU Build ID nie jest obsługiwana",
            ));
        }
        ranges.push(NoteRange {
            offset: section.offset,
            size: section.size,
            alignment: section.alignment,
            source: NoteSource::Section(index),
        });
    }
    for (index, segment) in program_headers.iter().enumerate() {
        if segment.segment_type == PT_NOTE {
            ranges.push(NoteRange {
                offset: segment.offset,
                size: segment.file_size,
                alignment: segment.alignment,
                source: NoteSource::Segment(index),
            });
        }
    }
    let mut total_bytes = 0_u64;
    let mut result = Vec::new();
    for range in ranges {
        note_alignment(range.alignment)?;
        total_bytes = total_bytes
            .checked_add(range.size)
            .ok_or_else(|| invalid_data("Przepełnienie rozmiaru danych notatek"))?;
        if total_bytes > MAX_TOTAL_NOTE_BYTES {
            return Err(unsupported(
                "Dane notatek przekraczają łącznie limit odczytu 16 MiB",
            ));
        }
        let end = range
            .offset
            .checked_add(range.size)
            .ok_or_else(|| invalid_data("Przepełnienie zakresu notatek"))?;
        if end > file_size {
            return Err(invalid_data("Zakres notatek wykracza poza plik"));
        }
        let size = usize::try_from(range.size)
            .map_err(|_| invalid_data("Rozmiar notatek nie mieści się w usize"))?;
        reader.seek(SeekFrom::Start(range.offset))?;
        let mut bytes = vec![0_u8; size];
        reader.read_exact(&mut bytes)?;
        let parsed = parse_notes(&bytes, header.ident.endianness, &range).map_err(|error| {
            io::Error::new(error.kind(), format!("{}: {}", range.source, error))
        })?;
        merge_build_ids(&mut result, parsed)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn note_aligned(
        owner: &[u8],
        kind: u32,
        desc: &[u8],
        endian: Endianness,
        alignment: usize,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        for value in [owner.len() as u32, desc.len() as u32, kind] {
            let encoded = match endian {
                Endianness::Little => value.to_le_bytes(),
                Endianness::Big => value.to_be_bytes(),
            };
            bytes.extend_from_slice(&encoded);
        }
        bytes.extend_from_slice(owner);
        bytes.resize(align(bytes.len(), alignment).unwrap(), 0);
        bytes.extend_from_slice(desc);
        bytes.resize(align(bytes.len(), alignment).unwrap(), 0);
        bytes
    }
    fn note(owner: &[u8], kind: u32, desc: &[u8], endian: Endianness) -> Vec<u8> {
        note_aligned(owner, kind, desc, endian, 4)
    }
    fn parse(bytes: &[u8], endian: Endianness) -> io::Result<Vec<BuildId>> {
        parse_notes(
            bytes,
            endian,
            &NoteRange {
                offset: 0,
                size: bytes.len() as u64,
                alignment: 4,
                source: NoteSource::Section(7),
            },
        )
    }
    #[test]
    fn reads_build_id_in_both_byte_orders() {
        for endian in [Endianness::Little, Endianness::Big] {
            let bytes = note(b"GNU\0", 3, &[1, 0xab, 0xff], endian);
            let ids = parse(&bytes, endian).unwrap();
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0].sources, vec![NoteSource::Section(7)]);
            assert_eq!(ids[0].to_string(), "01abff");
        }
    }
    #[test]
    fn handles_padding_and_multiple_notes() {
        let mut bytes = note(b"GNU\0", 3, &[1, 2, 3, 4, 5], Endianness::Little);
        bytes.extend(note(b"GNU\0", 3, &[6], Endianness::Little));
        let ids = parse(&bytes, Endianness::Little).unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[1].bytes, [6]);
    }
    #[test]
    fn ignores_other_owners() {
        assert!(
            parse(
                &note(b"OTHER\0", 3, &[1], Endianness::Little),
                Endianness::Little
            )
            .unwrap()
            .is_empty()
        );
    }
    #[test]
    fn rejects_truncated_descriptor() {
        let mut bytes = note(b"GNU\0", 3, &[1, 2, 3, 4], Endianness::Little);
        bytes.pop();
        assert!(parse(&bytes, Endianness::Little).is_err());
    }
    #[test]
    fn rejects_truncated_header() {
        assert!(parse(&[0_u8; 11], Endianness::Little).is_err());
    }
    #[test]
    fn rejects_empty_build_id() {
        assert!(
            parse(
                &note(b"GNU\0", 3, &[], Endianness::Little),
                Endianness::Little
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_unterminated_owner() {
        assert!(
            parse(
                &note(b"GNUx", 3, &[1], Endianness::Little),
                Endianness::Little
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_oversized_build_id() {
        let error = parse(
            &note(
                b"GNU\0",
                3,
                &vec![1; MAX_BUILD_ID_BYTES + 1],
                Endianness::Little,
            ),
            Endianness::Little,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
    #[test]
    fn reads_eight_byte_aligned_notes() {
        let bytes = note_aligned(b"GNU\0", 3, &[1, 2, 3, 4, 5], Endianness::Little, 8);
        let range = NoteRange {
            offset: 128,
            size: bytes.len() as u64,
            alignment: 8,
            source: NoteSource::Segment(0),
        };
        let ids = parse_notes(&bytes, Endianness::Little, &range).unwrap();
        assert_eq!(ids[0].bytes, [1, 2, 3, 4, 5]);
        assert_eq!(ids[0].note_offset, 128);
    }
    #[test]
    fn merges_same_note_from_section_and_segment() {
        let mut ids = vec![BuildId {
            sources: vec![NoteSource::Section(3)],
            note_offset: 100,
            bytes: vec![1, 2],
        }];
        merge_build_ids(
            &mut ids,
            vec![BuildId {
                sources: vec![NoteSource::Segment(7)],
                note_offset: 100,
                bytes: vec![1, 2],
            }],
        )
        .unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(
            ids[0].sources,
            vec![NoteSource::Section(3), NoteSource::Segment(7)]
        );
    }
    #[test]
    fn preserves_distinct_notes_with_same_value() {
        let mut ids = vec![BuildId {
            sources: vec![NoteSource::Section(3)],
            note_offset: 100,
            bytes: vec![1, 2],
        }];
        merge_build_ids(
            &mut ids,
            vec![BuildId {
                sources: vec![NoteSource::Segment(7)],
                note_offset: 200,
                bytes: vec![1, 2],
            }],
        )
        .unwrap();
        assert_eq!(ids.len(), 2);
    }
    #[test]
    fn rejects_unsupported_alignment() {
        assert!(note_alignment(16).is_err());
    }
}
