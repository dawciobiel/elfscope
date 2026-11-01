#![cfg(target_os = "linux")]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);
const ID_HEX: &str = "000102";

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> io::Result<Self> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base)?;
        for _ in 0..1000 {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                "elfscope-note-sources-{}-{}",
                std::process::id(),
                id
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Brak katalogu testowego",
        ))
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    bytes: Vec<u8>,
    id_note_offset: usize,
}

fn put(bytes: &mut [u8], offset: usize, width: usize, value: u64) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn note(owner: &[u8], kind: u32, descriptor: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 12];
    put(&mut bytes, 0, 4, owner.len() as u64);
    put(&mut bytes, 4, 4, descriptor.len() as u64);
    put(&mut bytes, 8, 4, u64::from(kind));
    bytes.extend_from_slice(owner);
    bytes.resize((bytes.len() + 3) & !3, 0);
    bytes.extend_from_slice(descriptor);
    bytes.resize((bytes.len() + 3) & !3, 0);
    bytes
}

fn write_section(bytes: &mut [u8], base: usize, fields: [u64; 10]) {
    let widths = [4, 4, 8, 8, 8, 8, 4, 4, 8, 8];
    let mut position = base;
    for (value, width) in fields.into_iter().zip(widths) {
        put(bytes, position, width, value);
        position += width;
    }
}

fn fixture(prefix: bool, duplicate: bool, custom_name: bool) -> Fixture {
    const ELF_HEADER_SIZE: usize = 64;
    const PROGRAM_HEADER_SIZE: usize = 56;
    const SECTION_HEADER_SIZE: usize = 64;
    let section_offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
    let segment_offset = section_offset + 3 * SECTION_HEADER_SIZE;

    let build_id_note = note(b"GNU\0", 3, &[0, 1, 2]);
    let mut notes = if prefix {
        note(b"OTHER\0", 3, &[0xaa])
    } else {
        Vec::new()
    };
    let id_note_offset = segment_offset + notes.len();
    notes.extend_from_slice(&build_id_note);
    if duplicate {
        notes.extend_from_slice(&build_id_note);
    }

    let mut names = vec![0_u8];
    let note_name: &[u8] = if custom_name {
        b".custom.note\0"
    } else {
        b".note.gnu.build-id\0"
    };
    names.extend_from_slice(note_name);
    let names_name_offset = names.len();
    names.extend_from_slice(b".shstrtab\0");
    let names_offset = segment_offset + notes.len();
    let mut bytes = vec![0_u8; names_offset + names.len()];

    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put(&mut bytes, 16, 2, 3);
    put(&mut bytes, 18, 2, 62);
    put(&mut bytes, 20, 4, 1);
    put(&mut bytes, 32, 8, ELF_HEADER_SIZE as u64);
    put(&mut bytes, 40, 8, section_offset as u64);
    put(&mut bytes, 52, 2, ELF_HEADER_SIZE as u64);
    put(&mut bytes, 54, 2, PROGRAM_HEADER_SIZE as u64);
    put(&mut bytes, 56, 2, 1);
    put(&mut bytes, 58, 2, SECTION_HEADER_SIZE as u64);
    put(&mut bytes, 60, 2, 3);
    put(&mut bytes, 62, 2, 2);

    // PT_NOTE obejmuje wszystkie notatki, w tym ewentualny prefiks.
    let ph = ELF_HEADER_SIZE;
    put(&mut bytes, ph, 4, 4);
    put(&mut bytes, ph + 4, 4, 4);
    put(&mut bytes, ph + 8, 8, segment_offset as u64);
    put(&mut bytes, ph + 32, 8, notes.len() as u64);
    put(&mut bytes, ph + 40, 8, notes.len() as u64);
    put(&mut bytes, ph + 48, 8, 4);

    // Sekcja opisuje tylko pierwszą notatkę GNU Build ID.
    write_section(
        &mut bytes,
        section_offset + SECTION_HEADER_SIZE,
        [
            1,
            7,
            2,
            0,
            id_note_offset as u64,
            build_id_note.len() as u64,
            0,
            0,
            4,
            0,
        ],
    );
    write_section(
        &mut bytes,
        section_offset + 2 * SECTION_HEADER_SIZE,
        [
            names_name_offset as u64,
            3,
            0,
            0,
            names_offset as u64,
            names.len() as u64,
            0,
            0,
            1,
            0,
        ],
    );

    bytes[segment_offset..names_offset].copy_from_slice(&notes);
    bytes[names_offset..].copy_from_slice(&names);
    Fixture {
        bytes,
        id_note_offset,
    }
}

fn inspect(bytes: &[u8]) -> io::Result<String> {
    let directory = TestDirectory::new()?;
    let path = directory.0.join("notes.elf");
    fs::write(&path, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg(path)
        .output()?;
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn id_lines(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|line| line.trim_start().starts_with("GNU Build ID:"))
        .collect()
}

#[test]
fn deduplicates_note_with_different_section_and_segment_starts() -> io::Result<()> {
    let fixture = fixture(true, false, false);
    let stdout = inspect(&fixture.bytes)?;
    let expected = format!("  GNU Build ID: {} (sekcja #1, segment #0)", ID_HEX);
    assert_eq!(id_lines(&stdout), vec![expected.as_str()]);
    Ok(())
}

#[test]
fn preserves_equal_ids_at_distinct_file_offsets() -> io::Result<()> {
    let fixture = fixture(false, true, false);
    let stdout = inspect(&fixture.bytes)?;
    let first = format!("  GNU Build ID: {} (sekcja #1, segment #0)", ID_HEX);
    let second = format!("  GNU Build ID: {} (segment #0)", ID_HEX);
    assert_eq!(id_lines(&stdout), vec![first.as_str(), second.as_str()]);
    Ok(())
}

#[test]
fn discovers_build_id_through_segment_with_custom_section_name() -> io::Result<()> {
    let fixture = fixture(false, false, true);
    let stdout = inspect(&fixture.bytes)?;
    let expected = format!("  GNU Build ID: {} (segment #0)", ID_HEX);
    assert_eq!(id_lines(&stdout), vec![expected.as_str()]);
    Ok(())
}

#[test]
fn section_name_alone_does_not_make_a_note_a_build_id() -> io::Result<()> {
    let mut fixture = fixture(false, false, false);
    // Właściciel GNU pozostaje bez zmian, ale typ nie jest NT_GNU_BUILD_ID.
    put(&mut fixture.bytes, fixture.id_note_offset + 8, 4, 99);
    let stdout = inspect(&fixture.bytes)?;
    assert!(stdout.contains(
        "GNU Build ID: nie znaleziono w sekcji .note.gnu.build-id ani w segmentach PT_NOTE"
    ));
    assert!(!stdout.contains(&format!("GNU Build ID: {}", ID_HEX)));
    Ok(())
}
