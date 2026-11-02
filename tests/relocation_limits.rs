#![cfg(target_os = "linux")]
use serde_json::Value;
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
                "elfscope-many-relocs-{}-{}",
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
fn put(bytes: &mut [u8], at: usize, width: usize, value: u64) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn sh(bytes: &mut [u8], at: usize, fields: [u64; 10]) {
    let mut at = at;
    for (value, width) in fields.into_iter().zip([4, 4, 8, 8, 8, 8, 4, 4, 8, 8]) {
        put(bytes, at, width, value);
        at += width;
    }
}
fn name(names: &[u8], wanted: &[u8]) -> u64 {
    names
        .windows(wanted.len())
        .position(|part| part == wanted)
        .unwrap() as u64
}
fn fixture(count: usize, corrupt_last: bool) -> Vec<u8> {
    let names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0.rela.text\0";
    let symbol_names = b"\0external\0";
    let section_count = 5 + count;
    let text = 64 + section_count * 64;
    let symbols = text + 8;
    let strings = symbols + 48;
    let relocations = strings + symbol_names.len();
    let names_offset = relocations + count * 24;
    let mut bytes = vec![0_u8; names_offset + names.len()];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put(&mut bytes, 16, 2, 1);
    put(&mut bytes, 18, 2, 62);
    put(&mut bytes, 20, 4, 1);
    put(&mut bytes, 40, 8, 64);
    put(&mut bytes, 52, 2, 64);
    put(&mut bytes, 58, 2, 64);
    put(&mut bytes, 60, 2, section_count as u64);
    put(&mut bytes, 62, 2, 4);
    sh(
        &mut bytes,
        128,
        [name(names, b".text\0"), 1, 6, 0, text as u64, 8, 0, 0, 1, 0],
    );
    sh(
        &mut bytes,
        192,
        [
            name(names, b".symtab\0"),
            2,
            0,
            0,
            symbols as u64,
            48,
            3,
            1,
            1,
            24,
        ],
    );
    sh(
        &mut bytes,
        256,
        [
            name(names, b".strtab\0"),
            3,
            0,
            0,
            strings as u64,
            symbol_names.len() as u64,
            0,
            0,
            1,
            0,
        ],
    );
    sh(
        &mut bytes,
        320,
        [
            name(names, b".shstrtab\0"),
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
    put(&mut bytes, symbols + 24, 4, 1);
    bytes[symbols + 28] = 0x10;
    bytes[strings..strings + symbol_names.len()].copy_from_slice(symbol_names);
    for index in 0..count {
        let offset = relocations + index * 24;
        sh(
            &mut bytes,
            64 + (5 + index) * 64,
            [
                name(names, b".rela.text\0"),
                4,
                0,
                0,
                offset as u64,
                24,
                2,
                1,
                1,
                24,
            ],
        );
        let symbol = if corrupt_last && index + 1 == count {
            2
        } else {
            1
        };
        put(&mut bytes, offset + 8, 8, (symbol << 32) | 2);
        put(&mut bytes, offset + 16, 8, (-4_i64) as u64);
    }
    bytes[names_offset..].copy_from_slice(names);
    bytes
}
fn run(bytes: &[u8], settings: &[(&str, &str)]) -> io::Result<Output> {
    let dir = Directory::new()?;
    let path = dir.0.join("many.o");
    fs::write(&path, bytes)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_elfscope"));
    for key in [
        "ELFSCOPE_MAX_RELOCATION_TABLES",
        "ELFSCOPE_MAX_RELOCATIONS",
        "ELFSCOPE_MAX_RELOCATION_PREVIEWS",
    ] {
        command.env_remove(key);
    }
    for (key, value) in settings {
        command.env(key, value);
    }
    command.args(["--json", "--quiet"]).arg(path).output()
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
fn scans_more_than_128_tables_by_default() -> io::Result<()> {
    let output = run(&fixture(129, false), &[])?;
    success(&output);
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["relocation_tables"].as_array().unwrap().len(), 129);
    Ok(())
}
#[test]
fn explicit_small_table_limit_is_enforced() -> io::Result<()> {
    let output = run(
        &fixture(129, false),
        &[("ELFSCOPE_MAX_RELOCATION_TABLES", "128")],
    )?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("limit tablic relokacji: 128"));
    Ok(())
}
#[test]
fn zero_preview_budget_preserves_complete_table_statistics() -> io::Result<()> {
    let output = run(
        &fixture(129, false),
        &[("ELFSCOPE_MAX_RELOCATION_PREVIEWS", "0")],
    )?;
    success(&output);
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["relocation_tables"].as_array().unwrap().len(), 129);
    Ok(())
}
#[test]
fn still_validates_records_after_preview_budget_is_exhausted() -> io::Result<()> {
    let output = run(
        &fixture(129, true),
        &[("ELFSCOPE_MAX_RELOCATION_PREVIEWS", "5")],
    )?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("indeks symbolu 2 poza tablicą"));
    Ok(())
}
#[test]
fn global_record_limit_remains_enforced() -> io::Result<()> {
    let output = run(&fixture(129, false), &[("ELFSCOPE_MAX_RELOCATIONS", "128")])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Liczba relokacji przekracza limit 128")
    );
    Ok(())
}
#[test]
fn invalid_configuration_exits_with_argument_error_code() -> io::Result<()> {
    let output = run(
        &fixture(1, false),
        &[("ELFSCOPE_MAX_RELOCATION_TABLES", "abc")],
    )?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Nieprawidłowa konfiguracja limitów relokacji")
    );
    Ok(())
}
