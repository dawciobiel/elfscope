#![cfg(target_os = "linux")]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY_ID: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> io::Result<Self> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base)?;

        for _ in 0..1000 {
            let id = NEXT_DIRECTORY_ID.fetch_add(1, Ordering::Relaxed);

            let path = base.join(format!(
                "elfscope-header-report-{}-{}",
                std::process::id(),
                id
            ));

            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Nie udało się utworzyć katalogu testowego",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn minimal_elf64(abi_version: u8) -> Vec<u8> {
    let mut bytes = vec![0_u8; 64];

    bytes[..4].copy_from_slice(b"\x7fELF");

    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[7] = 0;
    bytes[8] = abi_version;

    // ET_REL, x86-64, wersja ELF 1.
    bytes[16..18].copy_from_slice(&1_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());

    // Rozmiar głównego nagłówka, bez tabel programu i sekcji.
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());

    bytes
}

fn numeric_field(stdout: &str, label: &str) -> u32 {
    let value = stdout
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(label))
        .unwrap_or_else(|| panic!("Brak pola {:?} w raporcie:\n{}", label, stdout));

    value
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("Nieprawidłowa wartość pola {:?}: {:?}", label, value))
}

fn verify_abi_version(expected: u8) -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let path = directory.path().join("header.elf");

    fs::write(&path, minimal_elf64(expected))?;

    let output = Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg(&path)
        .output()?;

    assert!(
        output.status.success(),
        "Analiza nie powiodła się.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(numeric_field(&stdout, "Wersja ABI:"), u32::from(expected));

    assert_eq!(numeric_field(&stdout, "Wersja ident.:"), 1);
    assert_eq!(numeric_field(&stdout, "Wersja ELF:"), 1);

    Ok(())
}

#[test]
fn reports_nonzero_abi_version_separately() -> io::Result<()> {
    verify_abi_version(7)
}

#[test]
fn reports_zero_abi_version_without_substitution() -> io::Result<()> {
    verify_abi_version(0)
}
