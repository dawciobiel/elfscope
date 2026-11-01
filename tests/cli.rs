#![cfg(target_os = "linux")]

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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

            let path = base.join(format!("elfscope-cli-{}-{}", std::process::id(), id));

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
            "Nie udało się utworzyć osobnego katalogu testowego",
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

fn executable() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_elfscope"))
}

fn run(path: &Path) -> io::Result<Output> {
    Command::new(executable()).arg(path).output()
}

fn run_summary(path: &Path) -> io::Result<Output> {
    Command::new(executable())
        .arg("--summary")
        .arg(path)
        .output()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "Program zakończył się błędem.\n\
         Kod: {:?}\n\
         stdout:\n{}\n\
         stderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn counter(output: &Output, label: &str) -> u64 {
    let stderr = String::from_utf8_lossy(&output.stderr);

    let value = stderr
        .lines()
        .find_map(|line| line.strip_prefix(label))
        .unwrap_or_else(|| panic!("Nie znaleziono licznika {:?} w stderr:\n{}", label, stderr));

    value
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("Nieprawidłowa wartość licznika: {:?}", value))
}

#[test]
fn rejects_missing_argument() -> io::Result<()> {
    let output = Command::new(executable()).output()?;

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Użycie:"));

    Ok(())
}

#[test]
fn rejects_extra_arguments() -> io::Result<()> {
    let output = Command::new(executable())
        .args(["first", "second"])
        .output()?;

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Użycie:"));

    Ok(())
}

#[test]
fn scans_empty_directory() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let output = run(directory.path())?;

    assert_success(&output);
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 0);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 0);
    assert_eq!(counter(&output, "Pominięte wpisy:"), 0);
    assert_eq!(counter(&output, "Błędy:"), 0);
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn ignores_non_elf_files() -> io::Result<()> {
    let directory = TestDirectory::new()?;

    fs::write(directory.path().join("empty.bin"), b"")?;
    fs::write(directory.path().join("short.bin"), b"abc")?;
    fs::write(
        directory.path().join("message.txt"),
        b"This is not an ELF file.",
    )?;

    let output = run(directory.path())?;

    assert_success(&output);
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 3);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 0);
    assert_eq!(counter(&output, "Błędy:"), 0);
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn finds_elf_in_nested_directory() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let nested = directory.path().join("first").join("second");

    fs::create_dir_all(&nested)?;

    fs::copy(executable(), nested.join("sample.elf"))?;
    fs::write(directory.path().join("note.txt"), b"ordinary text")?;

    let output = run(directory.path())?;

    assert_success(&output);
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 2);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 1);
    assert_eq!(counter(&output, "Błędy:"), 0);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("sample.elf"));
    assert!(stdout.contains("Nagłówki programu:"));
    assert!(stdout.contains("Sekcje:"));
    assert!(stdout.contains("Sekcje w LOAD i TLS"));

    Ok(())
}

#[test]
fn skips_symbolic_links() -> io::Result<()> {
    let directory = TestDirectory::new()?;

    let target = directory.path().join("target.txt");
    let link = directory.path().join("link.txt");

    fs::write(&target, b"ordinary text")?;
    symlink(&target, &link)?;

    let output = run(directory.path())?;

    assert_success(&output);
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 1);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 0);
    assert_eq!(counter(&output, "Pominięte wpisy:"), 1);
    assert_eq!(counter(&output, "Błędy:"), 0);

    Ok(())
}

#[test]
fn reports_truncated_elf_and_continues_scanning() -> io::Result<()> {
    let directory = TestDirectory::new()?;

    fs::write(directory.path().join("broken.elf"), b"\x7fELF")?;
    fs::write(directory.path().join("ordinary.txt"), b"ordinary text")?;

    let output = run(directory.path())?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 2);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 0);
    assert_eq!(counter(&output, "Błędy:"), 1);

    assert!(String::from_utf8_lossy(&output.stderr).contains("broken.elf"));

    Ok(())
}

#[test]
fn reports_nonexistent_path() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let missing = directory.path().join("does-not-exist");

    let output = run(&missing)?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 0);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 0);
    assert_eq!(counter(&output, "Błędy:"), 1);

    Ok(())
}

#[test]
fn scanning_preserves_input_file_contents() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let sample = directory.path().join("sample.elf");

    fs::copy(executable(), &sample)?;

    let before = fs::read(&sample)?;
    let output = run(&sample)?;
    let after = fs::read(&sample)?;

    assert_success(&output);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 1);

    assert!(
        before == after,
        "Zawartość pliku zmieniła się po skanowaniu"
    );

    Ok(())
}

#[test]
fn help_exits_successfully_without_scanning() -> io::Result<()> {
    let output = Command::new(executable()).arg("--help").output()?;

    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("Użycie:"));
    assert!(stdout.contains("--summary"));
    assert!(stdout.contains("Kody zakończenia:"));
    assert!(output.stderr.is_empty());

    Ok(())
}

#[test]
fn summary_prints_one_line_per_elf() -> io::Result<()> {
    let directory = TestDirectory::new()?;

    fs::copy(executable(), directory.path().join("first.elf"))?;
    fs::copy(executable(), directory.path().join("second.elf"))?;
    fs::write(directory.path().join("ordinary.txt"), b"ordinary text")?;

    let output = run_summary(directory.path())?;

    assert_success(&output);
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 3);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 2);
    assert_eq!(counter(&output, "Błędy:"), 0);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    assert_eq!(lines.len(), 2);

    assert!(stdout.contains("first.elf"));
    assert!(stdout.contains("second.elf"));

    for line in lines {
        assert!(line.contains(" | typ="));
        assert!(line.contains(" | sekcje="));
        assert!(line.contains(" | DT_NEEDED="));
    }

    assert!(!stdout.contains("Nagłówki programu:"));
    assert!(!stdout.contains("  Sekcje:"));
    assert!(!stdout.contains("Sekcje w LOAD i TLS"));

    Ok(())
}

#[test]
fn summary_still_reports_analysis_errors() -> io::Result<()> {
    let directory = TestDirectory::new()?;
    let broken = directory.path().join("broken.elf");

    fs::write(&broken, b"\x7fELF")?;

    let output = run_summary(&broken)?;

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 1);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 0);
    assert_eq!(counter(&output, "Błędy:"), 1);
    assert!(output.stdout.is_empty());

    Ok(())
}

#[test]
fn separator_allows_option_like_filename() -> io::Result<()> {
    let directory = TestDirectory::new()?;

    fs::copy(executable(), directory.path().join("--summary"))?;

    let output = Command::new(executable())
        .current_dir(directory.path())
        .args(["--", "--summary"])
        .output()?;

    assert_success(&output);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 1);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("\"--summary\""));
    assert!(stdout.contains("Nagłówki programu:"));

    Ok(())
}

#[test]
fn scans_non_utf8_filename() -> io::Result<()> {
    let directory = TestDirectory::new()?;

    let filename = OsString::from_vec(b"sample-\xff.elf".to_vec());
    let sample = directory.path().join(filename);

    fs::copy(executable(), &sample)?;

    let output = run_summary(&sample)?;

    assert_success(&output);
    assert_eq!(counter(&output, "Sprawdzone zwykłe pliki:"), 1);
    assert_eq!(counter(&output, "Przeanalizowane ELF:"), 1);
    assert_eq!(counter(&output, "Błędy:"), 0);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.contains(" | DT_NEEDED="));

    Ok(())
}
