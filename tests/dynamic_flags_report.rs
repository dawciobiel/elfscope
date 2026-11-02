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
                "elfscope-dynamic-flags-{}-{}",
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
fn fixture(entries: &[(u64, u64)], relro: bool) -> Vec<u8> {
    let phnum = if relro { 2 } else { 1 };
    let offset = 64 + phnum * 56;
    let size = (entries.len() + 1) * 16;
    let mut bytes = vec![0_u8; offset + size];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put(&mut bytes, 16, 2, 3);
    put(&mut bytes, 18, 2, 62);
    put(&mut bytes, 20, 4, 1);
    put(&mut bytes, 32, 8, 64);
    put(&mut bytes, 52, 2, 64);
    put(&mut bytes, 54, 2, 56);
    put(&mut bytes, 56, 2, phnum as u64);
    put(&mut bytes, 64, 4, 2);
    put(&mut bytes, 68, 4, 6);
    put(&mut bytes, 72, 8, offset as u64);
    put(&mut bytes, 96, 8, size as u64);
    put(&mut bytes, 104, 8, size as u64);
    put(&mut bytes, 112, 8, 8);
    if relro {
        put(&mut bytes, 120, 4, 0x6474e552);
        put(&mut bytes, 124, 4, 4);
        put(&mut bytes, 168, 8, 1);
    }
    for (index, (tag, value)) in entries.iter().enumerate() {
        put(&mut bytes, offset + index * 16, 8, *tag);
        put(&mut bytes, offset + index * 16 + 8, 8, *value);
    }
    bytes
}
fn run(entries: &[(u64, u64)], relro: bool, json: bool) -> io::Result<Output> {
    let dir = Directory::new()?;
    let path = dir.0.join("flags.elf");
    fs::write(&path, fixture(entries, relro))?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_elfscope"));
    for key in [
        "ELFSCOPE_MAX_RELOCATION_TABLES",
        "ELFSCOPE_MAX_RELOCATIONS",
        "ELFSCOPE_MAX_RELOCATION_PREVIEWS",
    ] {
        command.env_remove(key);
    }
    if json {
        command.args(["--json", "--quiet"]);
    }
    let output = command.arg(path).output()?;
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}
#[test]
fn exports_flags_now_pie_and_textrel() -> io::Result<()> {
    let output = run(&[(30, 12), (0x6ffffffb, 0x08000001)], true, true)?;
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["dynamic"]["flags_hex"], "0xc");
    assert_eq!(value["dynamic"]["flags_1_hex"], "0x8000001");
    assert_eq!(value["dynamic"]["bind_now_requested"], true);
    assert_eq!(value["dynamic"]["pie_flag_set"], true);
    assert_eq!(value["dynamic"]["textrel_requested"], true);
    Ok(())
}
#[test]
fn supports_legacy_presence_tags() -> io::Result<()> {
    let output = run(&[(24, 0), (22, 0)], false, true)?;
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["dynamic"]["bind_now_tag"], true);
    assert_eq!(value["dynamic"]["textrel_tag"], true);
    assert_eq!(value["dynamic"]["bind_now_requested"], true);
    assert!(value["dynamic"]["flags_hex"].is_null());
    Ok(())
}
#[test]
fn zero_flags_do_not_imply_pie_or_now() -> io::Result<()> {
    let output = run(&[(30, 0), (0x6ffffffb, 0)], false, true)?;
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["dynamic"]["flags_hex"], "0x0");
    assert_eq!(value["dynamic"]["pie_flag_set"], false);
    assert_eq!(value["dynamic"]["bind_now_requested"], false);
    Ok(())
}
#[test]
fn text_report_combines_relro_and_now_without_runtime_verdict() -> io::Result<()> {
    let output = run(&[(0x6ffffffb, 0x08000001)], true, false)?;
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(out.contains("Wiązanie NOW: zadeklarowane"));
    assert!(out.contains("Marker DF_1_PIE: ustawiony"));
    assert!(out.contains("PT_GNU_RELRO + NOW: obie deklaracje obecne"));
    assert!(out.contains("Nie potwierdzono pełnego RELRO ani rzeczywistych uprawnień procesu"));
    Ok(())
}
