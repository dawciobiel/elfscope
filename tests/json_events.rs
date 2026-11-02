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
                "elfscope-json-events-{}-{}",
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
fn write_elf(path: &Path) -> io::Result<()> {
    let mut bytes = vec![0_u8; 64];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&1_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    fs::write(path, bytes)
}
fn run(args: &[&str], path: &Path, env: &[(&str, &str)]) -> io::Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_elfscope"));
    for key in [
        "ELFSCOPE_MAX_RELOCATION_TABLES",
        "ELFSCOPE_MAX_RELOCATIONS",
        "ELFSCOPE_MAX_RELOCATION_PREVIEWS",
    ] {
        command.env_remove(key);
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command.args(args).arg(path).output()
}
fn records(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn exports_error_and_success_records() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("good.elf"))?;
    fs::write(dir.0.join("bad.elf"), b"\x7fELF")?;
    let output = run(&["--json", "--json-errors", "--quiet"], &dir.0, &[])?;
    assert_eq!(output.status.code(), Some(1));
    let records = records(&output);
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record["kind"] == "elf"));
    let error = records
        .iter()
        .find(|record| record["kind"] == "error")
        .unwrap();
    assert_eq!(error["error"]["category"], "unexpected_eof");
    assert!(error["path_bytes_hex"].is_string());
    Ok(())
}
#[test]
fn adds_final_summary_with_effective_limits() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("one.elf"))?;
    let output = run(&["--json", "--json-stats", "--quiet"], &dir.0, &[])?;
    success(&output);
    let records = records(&output);
    assert_eq!(records.len(), 2);
    let summary = records.last().unwrap();
    assert_eq!(summary["kind"], "scan_summary");
    assert_eq!(summary["counts"]["elf_files"], 1);
    assert_eq!(
        summary["configuration"]["relocation_limits"]["tables"],
        4096
    );
    assert_eq!(summary["status"], "finished");
    assert!(output.stderr.is_empty());
    Ok(())
}
#[test]
fn empty_directory_still_produces_summary() -> io::Result<()> {
    let dir = Directory::new()?;
    let output = run(&["--json", "--json-stats", "--quiet"], &dir.0, &[])?;
    success(&output);
    let records = records(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["counts"]["regular_files_attempted"], 0);
    Ok(())
}
#[test]
fn missing_root_produces_error_then_summary() -> io::Result<()> {
    let dir = Directory::new()?;
    let output = run(
        &["--json", "--json-errors", "--json-stats", "--quiet"],
        &dir.0.join("missing"),
        &[],
    )?;
    assert_eq!(output.status.code(), Some(1));
    let records = records(&output);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["error"]["category"], "not_found");
    assert_eq!(records[1]["kind"], "scan_summary");
    assert_eq!(records[1]["had_errors"], true);
    Ok(())
}
#[test]
fn summary_distinguishes_file_limit_stop() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("a.elf"))?;
    write_elf(&dir.0.join("b.elf"))?;
    let output = run(
        &["--json", "--json-stats", "--quiet", "--max-files", "1"],
        &dir.0,
        &[],
    )?;
    success(&output);
    let records = records(&output);
    let summary = records.last().unwrap();
    assert_eq!(summary["status"], "stopped_at_file_limit");
    assert_eq!(summary["scope_limited"], true);
    assert_eq!(summary["counts"]["errors"], 0);
    Ok(())
}
#[test]
fn json_event_flags_require_json_mode() -> io::Result<()> {
    let dir = Directory::new()?;
    let output = run(&["--json-stats"], &dir.0, &[])?;
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    Ok(())
}
#[test]
fn default_json_stream_still_contains_only_elf_records() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("good.elf"))?;
    fs::write(dir.0.join("bad.elf"), b"\x7fELF")?;
    let output = run(&["--json", "--quiet"], &dir.0, &[])?;
    assert_eq!(output.status.code(), Some(1));
    let records = records(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["kind"], "elf");
    Ok(())
}
#[test]
fn summary_reflects_overridden_relocation_budget() -> io::Result<()> {
    let dir = Directory::new()?;
    let output = run(
        &["--json", "--json-stats", "--quiet"],
        &dir.0,
        &[("ELFSCOPE_MAX_RELOCATION_TABLES", "8192")],
    )?;
    success(&output);
    assert_eq!(
        records(&output)[0]["configuration"]["relocation_limits"]["tables"],
        8192
    );
    Ok(())
}
