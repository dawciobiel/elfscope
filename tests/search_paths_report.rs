#![cfg(target_os = "linux")]
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
        fs::create_dir_all(base)?;
        for _ in 0..1000 {
            let path = base.join(format!(
                "elfscope-search-paths-{}-{}",
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
fn fixture(rpath: Option<&[u8]>, runpath: Option<&[u8]>, needed: &[&[u8]]) -> Vec<u8> {
    let mut strings = vec![0_u8];
    let mut tags = Vec::new();
    for name in needed {
        let offset = strings.len() as u64;
        strings.extend_from_slice(name);
        strings.push(0);
        tags.push((1, offset));
    }
    for (tag, raw) in [(15, rpath), (29, runpath)] {
        if let Some(raw) = raw {
            let offset = strings.len() as u64;
            strings.extend_from_slice(raw);
            strings.push(0);
            tags.push((tag, offset));
        }
    }
    let dynamic_offset = 176;
    let dynamic_size = (tags.len() + 3) * 16;
    let strings_offset = dynamic_offset + dynamic_size;
    tags.push((5, 0x400000 + strings_offset as u64));
    tags.push((10, strings.len() as u64));
    tags.push((0, 0));
    let mut bytes = vec![0_u8; strings_offset + strings.len()];
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
    put(&mut bytes, 56, 2, 2);
    let size = bytes.len() as u64;
    put(&mut bytes, 64, 4, 1);
    put(&mut bytes, 68, 4, 4);
    put(&mut bytes, 80, 8, 0x400000);
    put(&mut bytes, 96, 8, size);
    put(&mut bytes, 104, 8, size);
    put(&mut bytes, 112, 8, 1);
    put(&mut bytes, 120, 4, 2);
    put(&mut bytes, 124, 4, 6);
    put(&mut bytes, 128, 8, dynamic_offset as u64);
    put(&mut bytes, 136, 8, 0x400000 + dynamic_offset as u64);
    put(&mut bytes, 152, 8, dynamic_size as u64);
    put(&mut bytes, 160, 8, dynamic_size as u64);
    put(&mut bytes, 168, 8, 8);
    for (index, (tag, value)) in tags.iter().enumerate() {
        put(&mut bytes, dynamic_offset + index * 16, 8, *tag);
        put(&mut bytes, dynamic_offset + index * 16 + 8, 8, *value);
    }
    bytes[strings_offset..].copy_from_slice(&strings);
    bytes
}
fn inspect(rpath: Option<&[u8]>, runpath: Option<&[u8]>, needed: &[&[u8]]) -> io::Result<Value> {
    let dir = Directory::new()?;
    let path = dir.0.join("search-paths.elf");
    fs::write(&path, fixture(rpath, runpath, needed))?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_elfscope"));
    for key in [
        "ELFSCOPE_MAX_RELOCATION_TABLES",
        "ELFSCOPE_MAX_RELOCATIONS",
        "ELFSCOPE_MAX_RELOCATION_PREVIEWS",
    ] {
        command.env_remove(key);
    }
    let output = command.args(["--json", "--quiet"]).arg(path).output()?;
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout).unwrap())
}
#[test]
fn runpath_takes_precedence_without_removing_raw_rpath() -> io::Result<()> {
    let value = inspect(Some(b"/old"), Some(b"/new"), &[b"libx.so"])?;
    let paths = &value["dynamic"]["search_paths"];
    assert_eq!(paths["selected_tag"], "RUNPATH");
    assert_eq!(paths["rpath_ignored_due_to_runpath"], true);
    assert_eq!(value["dynamic"]["rpath"]["text"], "/old");
    Ok(())
}
#[test]
fn classifies_list_components_and_tokens() -> io::Result<()> {
    let value = inspect(None, Some(b":/usr/lib:relative:$ORIGIN/lib:"), &[])?;
    let counts = &value["dynamic"]["search_paths"]["runpath"]["counts"];
    assert_eq!(counts["entries"], 5);
    assert_eq!(counts["empty_components"], 2);
    assert_eq!(counts["absolute_literal"], 1);
    assert_eq!(counts["relative_literal"], 1);
    assert_eq!(counts["tokenized"], 1);
    Ok(())
}
#[test]
fn wholly_empty_runpath_is_not_a_current_directory_component() -> io::Result<()> {
    let value = inspect(Some(b"/old"), Some(b""), &[])?;
    let paths = &value["dynamic"]["search_paths"];
    assert_eq!(paths["selected_tag"], "RUNPATH");
    assert_eq!(paths["rpath_ignored_due_to_runpath"], true);
    assert_eq!(paths["runpath"]["explicitly_empty"], true);
    assert_eq!(paths["runpath"]["counts"]["entries"], 0);
    Ok(())
}
#[test]
fn classifies_needed_names_paths_and_tokens() -> io::Result<()> {
    let value = inspect(
        None,
        None,
        &[
            b"libx.so",
            b"../libx.so",
            b"/opt/libx.so",
            b"$ORIGIN/libx.so",
        ],
    )?;
    let counts = &value["dynamic"]["search_paths"]["needed"]["counts"];
    assert_eq!(counts["entries"], 4);
    assert_eq!(counts["search_names"], 1);
    assert_eq!(counts["relative_paths"], 1);
    assert_eq!(counts["absolute_paths"], 1);
    assert_eq!(counts["tokenized"], 1);
    Ok(())
}
