use crate::cli::{OutputFormat, ScanOptions};
use crate::relocations::RelocationLimits;
use crate::{inspection, json_report, report};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

#[derive(Default)]
pub(crate) struct ScanStats {
    pub files: u64,
    pub elf_files: u64,
    pub skipped: u64,
    pub errors: u64,
    pub excluded: u64,
    pub depth_limited: u64,
    pub max_files_reached: bool,
}
fn error(path: &Path, cause: &io::Error, stats: &mut ScanStats) {
    stats.errors += 1;
    eprintln!("Błąd dla {:?}: {}", path, cause);
}
fn excluded(options: &ScanOptions, path: &Path, depth: usize) -> bool {
    depth != 0
        && path.file_name().is_some_and(|name| {
            options
                .excludes
                .iter()
                .any(|excluded| excluded.as_os_str() == name)
        })
}
fn depth_limited(options: &ScanOptions, depth: usize) -> bool {
    options.max_depth.is_some_and(|limit| depth >= limit)
}
#[cfg(unix)]
fn path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}
#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().as_bytes().to_vec()
}
fn output(
    options: &ScanOptions,
    path: &Path,
    inspection: &inspection::Inspection,
) -> io::Result<()> {
    match options.format {
        OutputFormat::Text => report::print_inspection(path, inspection, options.mode),
        OutputFormat::JsonLines => {
            let mut bytes = serde_json::to_vec(&json_report::record(path, inspection))
                .map_err(io::Error::other)?;
            bytes.push(b'\n');
            io::stdout().lock().write_all(&bytes)?;
        }
        OutputFormat::Paths => {
            let mut bytes = path_bytes(path);
            bytes.push(if options.null_separator { 0 } else { b'\n' });
            io::stdout().lock().write_all(&bytes)?;
        }
    }
    Ok(())
}
pub(crate) fn scan(options: &ScanOptions, limits: &RelocationLimits) -> io::Result<ScanStats> {
    let mut stats = ScanStats::default();
    let mut pending = vec![(options.path.clone(), 0_usize)];
    while let Some((path, depth)) = pending.pop() {
        if excluded(options, &path, depth) {
            stats.excluded += 1;
            continue;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(cause) => {
                error(&path, &cause, &mut stats);
                continue;
            }
        };
        if metadata.is_symlink() {
            stats.skipped += 1;
            continue;
        }
        if metadata.is_dir() {
            if depth_limited(options, depth) {
                stats.depth_limited += 1;
                continue;
            }
            let entries = match fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(cause) => {
                    error(&path, &cause, &mut stats);
                    continue;
                }
            };
            let mut children = Vec::new();
            for entry in entries {
                match entry {
                    Ok(entry) => children.push(entry.path()),
                    Err(cause) => error(&path, &cause, &mut stats),
                }
            }
            children.sort();
            let next_depth = depth
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Przepełnienie głębokości skanowania"))?;
            for child in children.into_iter().rev() {
                pending.push((child, next_depth));
            }
            continue;
        }
        if !metadata.is_file() {
            stats.skipped += 1;
            continue;
        }
        if options.max_files.is_some_and(|limit| stats.files >= limit) {
            stats.max_files_reached = true;
            break;
        }
        stats.files += 1;
        match inspection::inspect_file(&path, limits) {
            Ok(Some(inspection)) => {
                stats.elf_files += 1;
                output(options, &path, &inspection)?;
            }
            Ok(None) => {}
            Err(cause) => error(&path, &cause, &mut stats),
        }
    }
    Ok(stats)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{self, Action};
    use std::ffi::OsString;
    fn options() -> ScanOptions {
        match cli::parse(["--exclude", "target", "root"].map(OsString::from)).unwrap() {
            Action::Scan(options) => options,
            _ => panic!(),
        }
    }
    #[test]
    fn exclusions_match_exact_names() {
        let options = options();
        assert!(excluded(&options, Path::new("root/target"), 1));
        assert!(!excluded(&options, Path::new("root/target-copy"), 1));
    }
    #[test]
    fn explicit_root_is_not_excluded() {
        assert!(!excluded(&options(), Path::new("target"), 0));
    }
    #[test]
    fn depth_limit_applies_to_directory_expansion() {
        let mut options = options();
        options.max_depth = Some(1);
        assert!(!depth_limited(&options, 0));
        assert!(depth_limited(&options, 1));
    }
}
