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
                "elfscope-selection-{}-{}",
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
fn bytes(class: u8, kind: u16, machine: u16) -> Vec<u8> {
    let size = if class == 1 { 52 } else { 64 };
    let mut bytes = vec![0_u8; size];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = class;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&kind.to_le_bytes());
    bytes[18..20].copy_from_slice(&machine.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    let at = if class == 1 { 40 } else { 52 };
    bytes[at..at + 2].copy_from_slice(&(size as u16).to_le_bytes());
    bytes
}
fn run(flags: &[&str], path: &Path) -> io::Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_elfscope"));
    for key in [
        "ELFSCOPE_MAX_RELOCATION_TABLES",
        "ELFSCOPE_MAX_RELOCATIONS",
        "ELFSCOPE_MAX_RELOCATION_PREVIEWS",
    ] {
        command.env_remove(key);
    }
    command
        .args(["--json", "--quiet"])
        .args(flags)
        .arg(path)
        .output()
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn records(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
#[test]
fn selects_exec_and_dyn_without_rel() -> io::Result<()> {
    let dir = Directory::new()?;
    for (name, kind) in [("rel", 1), ("exec", 2), ("dyn", 3)] {
        fs::write(dir.0.join(name), bytes(2, kind, 62))?;
    }
    let output = run(
        &["--elf-type", "exec", "--elf-type", "dyn", "--json-stats"],
        &dir.0,
    )?;
    success(&output);
    let records = records(&output);
    assert_eq!(
        records
            .iter()
            .filter(|record| record["kind"] == "elf")
            .count(),
        2
    );
    assert_eq!(records.last().unwrap()["counts"]["filtered_elf_files"], 1);
    Ok(())
}
#[test]
fn selects_elf_class() -> io::Result<()> {
    let dir = Directory::new()?;
    fs::write(dir.0.join("32"), bytes(1, 1, 3))?;
    fs::write(dir.0.join("64"), bytes(2, 1, 62))?;
    let output = run(&["--class", "32"], &dir.0)?;
    success(&output);
    let records = records(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["header"]["class"], "ELF32");
    Ok(())
}
#[test]
fn selects_machine_by_numeric_identifier() -> io::Result<()> {
    let dir = Directory::new()?;
    fs::write(dir.0.join("x86"), bytes(2, 1, 62))?;
    fs::write(dir.0.join("arm"), bytes(2, 1, 183))?;
    let output = run(&["--machine", "183"], &dir.0)?;
    success(&output);
    let records = records(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["header"]["machine"], 183);
    Ok(())
}
#[test]
fn applies_inclusive_size_limit_before_opening_content() -> io::Result<()> {
    let dir = Directory::new()?;
    fs::write(dir.0.join("small"), bytes(2, 1, 62))?;
    let mut large = bytes(2, 1, 62);
    large.push(0);
    fs::write(dir.0.join("large"), large)?;
    let output = run(&["--max-size", "64", "--json-stats"], &dir.0)?;
    success(&output);
    let records = records(&output);
    assert_eq!(
        records
            .iter()
            .filter(|record| record["kind"] == "elf")
            .count(),
        1
    );
    assert_eq!(records.last().unwrap()["counts"]["size_limited_files"], 1);
    Ok(())
}
#[test]
fn filtered_headers_do_not_trigger_heavy_table_parsing() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("broken-tables.o");
    let mut data = bytes(2, 1, 62);
    data[32..40].copy_from_slice(&4096_u64.to_le_bytes());
    data[54..56].copy_from_slice(&56_u16.to_le_bytes());
    data[56..58].copy_from_slice(&1_u16.to_le_bytes());
    fs::write(&path, data)?;
    let output = run(&["--elf-type", "dyn", "--json-stats"], &path)?;
    success(&output);
    assert_eq!(records(&output)[0]["counts"]["filtered_elf_files"], 1);
    let output = run(&[], &path)?;
    assert_eq!(output.status.code(), Some(1));
    Ok(())
}
#[test]
fn default_selection_keeps_all_header_types() -> io::Result<()> {
    let dir = Directory::new()?;
    for (name, kind) in [("rel", 1), ("exec", 2), ("dyn", 3)] {
        fs::write(dir.0.join(name), bytes(2, kind, 62))?;
    }
    let output = run(&[], &dir.0)?;
    success(&output);
    assert_eq!(records(&output).len(), 3);
    Ok(())
}
#[test]
fn summary_records_filter_configuration() -> io::Result<()> {
    let dir = Directory::new()?;
    let output = run(
        &[
            "--elf-type",
            "dyn",
            "--machine",
            "x86_64",
            "--class",
            "64",
            "--max-size",
            "1024",
            "--json-stats",
        ],
        &dir.0,
    )?;
    success(&output);
    let record = &records(&output)[0];
    assert_eq!(
        record["configuration"]["elf_selection"]["file_types"],
        serde_json::json!([3])
    );
    assert_eq!(
        record["configuration"]["elf_selection"]["machines"],
        serde_json::json!([62])
    );
    assert_eq!(record["configuration"]["elf_selection"]["class"], "ELF64");
    assert_eq!(record["scope_limited"], true);
    Ok(())
}
#[test]
fn invalid_filter_is_argument_error() -> io::Result<()> {
    let dir = Directory::new()?;
    let output = run(&["--elf-type", "bad"], &dir.0)?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    Ok(())
}
