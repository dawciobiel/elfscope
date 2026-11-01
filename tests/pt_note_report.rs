#![cfg(target_os = "linux")]
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base)?;
        for _ in 0..1000 {
            let path = base.join(format!(
                "elfscope-pt-note-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
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
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone, Copy)]
enum Class {
    Elf32,
    Elf64,
}
#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}
fn put(bytes: &mut [u8], at: usize, width: usize, value: u64, endian: Endian) {
    match endian {
        Endian::Little => bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]),
        Endian::Big => bytes[at..at + width].copy_from_slice(&value.to_be_bytes()[8 - width..]),
    }
}
fn fixture(class: Class, endian: Endian, alignment: usize) -> (Vec<u8>, usize) {
    let (ehsize, phsize, width) = match class {
        Class::Elf32 => (52, 32, 4),
        Class::Elf64 => (64, 56, 8),
    };
    let note_offset = (ehsize + phsize + alignment - 1) & !(alignment - 1);
    let mut note = vec![0_u8; 12];
    put(&mut note, 0, 4, 4, endian);
    put(&mut note, 4, 4, 5, endian);
    put(&mut note, 8, 4, 3, endian);
    note.extend_from_slice(b"GNU\0");
    note.resize((note.len() + alignment - 1) & !(alignment - 1), 0);
    note.extend_from_slice(&[0, 1, 0xab, 0xcd, 0xff]);
    note.resize((note.len() + alignment - 1) & !(alignment - 1), 0);
    let mut bytes = vec![0_u8; note_offset + note.len()];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = match class {
        Class::Elf32 => 1,
        Class::Elf64 => 2,
    };
    bytes[5] = match endian {
        Endian::Little => 1,
        Endian::Big => 2,
    };
    bytes[6] = 1;
    put(&mut bytes, 16, 2, 3, endian);
    put(
        &mut bytes,
        18,
        2,
        match class {
            Class::Elf32 => 3,
            Class::Elf64 => 62,
        },
        endian,
    );
    put(&mut bytes, 20, 4, 1, endian);
    let (phoff_field, sizes_field) = match class {
        Class::Elf32 => (28, 40),
        Class::Elf64 => (32, 52),
    };
    put(&mut bytes, phoff_field, width, ehsize as u64, endian);
    put(&mut bytes, sizes_field, 2, ehsize as u64, endian);
    put(&mut bytes, sizes_field + 2, 2, phsize as u64, endian);
    put(&mut bytes, sizes_field + 4, 2, 1, endian);
    let fields: Vec<(usize, u64)> = match class {
        Class::Elf32 => vec![
            (4, 4),
            (4, note_offset as u64),
            (4, 0),
            (4, 0),
            (4, note.len() as u64),
            (4, note.len() as u64),
            (4, 4),
            (4, alignment as u64),
        ],
        Class::Elf64 => vec![
            (4, 4),
            (4, 4),
            (8, note_offset as u64),
            (8, 0),
            (8, 0),
            (8, note.len() as u64),
            (8, note.len() as u64),
            (8, alignment as u64),
        ],
    };
    let mut at = ehsize;
    for (width, value) in fields {
        put(&mut bytes, at, width, value, endian);
        at += width;
    }
    bytes[note_offset..].copy_from_slice(&note);
    (bytes, note_offset)
}
fn run(path: &Path) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg(path)
        .output()
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn reads_pt_note_without_section_headers_in_all_layouts() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("note.elf");
    for class in [Class::Elf32, Class::Elf64] {
        for endian in [Endian::Little, Endian::Big] {
            let (bytes, _) = fixture(class, endian, 4);
            fs::write(&path, bytes)?;
            let output = run(&path)?;
            success(&output);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("GNU Build ID: 0001abcdff (segment #0)"));
            assert!(stdout.contains("  Sekcje:\n    Brak"));
        }
    }
    Ok(())
}
#[test]
fn reads_eight_byte_aligned_pt_note() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("aligned.elf");
    let (bytes, _) = fixture(Class::Elf64, Endian::Little, 8);
    fs::write(&path, bytes)?;
    let output = run(&path)?;
    success(&output);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("GNU Build ID: 0001abcdff (segment #0)")
    );
    Ok(())
}
#[test]
fn rejects_descriptor_outside_pt_note() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("bad-note.elf");
    let (mut bytes, offset) = fixture(Class::Elf64, Endian::Little, 4);
    put(&mut bytes, offset + 4, 4, 4096, Endian::Little);
    fs::write(&path, bytes)?;
    let output = run(&path)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("wykracza poza sekcję lub segment"));
    Ok(())
}
