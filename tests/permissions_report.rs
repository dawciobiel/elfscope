#![cfg(target_os = "linux")]
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
                "elfscope-permissions-{}-{}",
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
fn inspect(headers: &[(u32, u32, u64)]) -> io::Result<String> {
    let dir = Directory::new()?;
    let path = dir.0.join("declarations.elf");
    let mut bytes = vec![0_u8; 64 + headers.len() * 56];
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
    put(&mut bytes, 56, 2, headers.len() as u64);
    for (index, &(kind, flags, memory_size)) in headers.iter().enumerate() {
        let at = 64 + index * 56;
        put(&mut bytes, at, 4, u64::from(kind));
        put(&mut bytes, at + 4, 4, u64::from(flags));
        put(&mut bytes, at + 40, 8, memory_size);
        put(&mut bytes, at + 48, 8, 1);
    }
    fs::write(&path, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_elfscope"))
        .arg(path)
        .output()?;
    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
#[test]
fn reports_stack_without_execute_flag() -> io::Result<()> {
    let out = inspect(&[(0x6474e551, 6, 0)])?;
    assert!(out.contains("Stos: PT_GNU_STACK #0 RW- — brak PF_X"));
    assert!(out.contains("Niepuste LOAD z W+X: brak"));
    Ok(())
}
#[test]
fn reports_executable_stack_and_relro_as_declarations() -> io::Result<()> {
    let out = inspect(&[(0x6474e551, 7, 0), (0x6474e552, 4, 0)])?;
    assert!(out.contains("Stos: PT_GNU_STACK #0 RWX — zadeklarowano PF_X"));
    assert!(out.contains("PT_GNU_RELRO: #1"));
    assert!(out.contains("Nie potwierdzono pełnego RELRO ani rzeczywistych uprawnień procesu"));
    Ok(())
}
#[test]
fn reports_unspecified_stack_and_writable_executable_load() -> io::Result<()> {
    let out = inspect(&[(1, 7, 4096)])?;
    assert!(out.contains("Stos: brak PT_GNU_STACK — nieustalone"));
    assert!(out.contains("Niepuste LOAD z W+X: #0"));
    assert!(out.contains("To deklaracje pliku, nie pomiar uprawnień działającego procesu"));
    Ok(())
}
