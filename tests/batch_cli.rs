#![cfg(target_os = "linux")]
use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
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
                "elfscope-batch-cli-{}-{}",
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
fn run(args: &[&str], path: &Path) -> io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .args(args)
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
fn records(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
fn counter(output: &Output, label: &str) -> u64 {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix(label))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}
#[test]
fn exports_valid_json_record() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("one.elf");
    write_elf(&path)?;
    let output = run(&["--json"], &path)?;
    success(&output);
    let records = records(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["schema_version"], 1);
    assert_eq!(records[0]["header"]["class"], "ELF64");
    assert_eq!(records[0]["header"]["entry_hex"], "0x0");
    assert_eq!(records[0]["header"]["section_header_count"], 0);
    Ok(())
}
#[test]
fn sorts_sibling_paths_deterministically() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("z.elf"))?;
    write_elf(&dir.0.join("a.elf"))?;
    let output = run(&["--json"], &dir.0)?;
    success(&output);
    let records = records(&output);
    assert!(records[0]["path"].as_str().unwrap().ends_with("a.elf"));
    assert!(records[1]["path"].as_str().unwrap().ends_with("z.elf"));
    Ok(())
}
#[test]
fn depth_zero_does_not_expand_root_directory() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("one.elf"))?;
    let output = run(&["--json", "--max-depth", "0"], &dir.0)?;
    success(&output);
    assert!(output.stdout.is_empty());
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 0);
    Ok(())
}
#[test]
fn no_recursive_scans_only_direct_files() -> io::Result<()> {
    let dir = Directory::new()?;
    fs::create_dir(dir.0.join("nested"))?;
    write_elf(&dir.0.join("one.elf"))?;
    write_elf(&dir.0.join("nested/two.elf"))?;
    let output = run(&["--json", "--no-recursive"], &dir.0)?;
    success(&output);
    assert_eq!(records(&output).len(), 1);
    Ok(())
}
#[test]
fn excludes_named_directory() -> io::Result<()> {
    let dir = Directory::new()?;
    fs::create_dir(dir.0.join("skip"))?;
    write_elf(&dir.0.join("keep.elf"))?;
    write_elf(&dir.0.join("skip/hidden.elf"))?;
    let output = run(&["--json", "--exclude", "skip"], &dir.0)?;
    success(&output);
    assert_eq!(records(&output).len(), 1);
    assert_eq!(counter(&output, "Wykluczone wpisy:"), 1);
    Ok(())
}
#[test]
fn caps_attempted_regular_files() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("a.elf"))?;
    write_elf(&dir.0.join("b.elf"))?;
    let output = run(&["--json", "--max-files", "1"], &dir.0)?;
    success(&output);
    assert_eq!(records(&output).len(), 1);
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Przerwano po limicie plików: tak"));
    Ok(())
}
#[test]
fn emits_null_separated_raw_paths() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir
        .0
        .join(OsString::from_vec(b"non-utf8-\xff\n.elf".to_vec()));
    write_elf(&path)?;
    let output = run(&["--paths", "--null"], &path)?;
    success(&output);
    let mut expected = path.as_os_str().as_bytes().to_vec();
    expected.push(0);
    assert_eq!(output.stdout, expected);
    Ok(())
}
#[test]
fn quiet_suppresses_counters() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("one.elf");
    write_elf(&path)?;
    let output = run(&["--summary", "--quiet"], &path)?;
    success(&output);
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.is_empty());
    Ok(())
}
#[test]
fn version_does_not_scan() -> io::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg("--version")
        .output()?;
    success(&output);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("elfscope {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
    Ok(())
}
#[test]
fn rejects_conflicting_output_flags() -> io::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .args(["--json", "--summary", "."])
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    Ok(())
}
#[test]
fn json_preserves_escaped_path_and_raw_bytes() -> io::Result<()> {
    let dir = Directory::new()?;
    let path = dir.0.join("quote\"newline\nbackslash\\.elf");
    write_elf(&path)?;
    let output = run(&["--json"], &path)?;
    success(&output);
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    let records = records(&output);
    assert_eq!(records[0]["path"], path.to_string_lossy().as_ref());
    let expected: String = path
        .as_os_str()
        .as_bytes()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();
    assert_eq!(records[0]["path_bytes_hex"], expected);
    Ok(())
}
#[test]
fn json_keeps_successes_valid_when_other_file_fails() -> io::Result<()> {
    let dir = Directory::new()?;
    write_elf(&dir.0.join("good.elf"))?;
    fs::write(dir.0.join("broken.elf"), b"\x7fELF")?;
    let output = run(&["--json", "--quiet"], &dir.0)?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(records(&output).len(), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("broken.elf"));
    Ok(())
}
