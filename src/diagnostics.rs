use crate::cli::ScanOptions;
use crate::relocations::RelocationLimits;
use crate::scanner::ScanStats;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

fn category(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::InvalidData => "invalid_data",
        io::ErrorKind::UnexpectedEof => "unexpected_eof",
        io::ErrorKind::Unsupported => "unsupported_or_limit",
        io::ErrorKind::InvalidInput => "invalid_input",
        _ => "io_error",
    }
}
#[cfg(unix)]
fn path_hex(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    Some(
        path.as_os_str()
            .as_bytes()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect(),
    )
}
#[cfg(not(unix))]
fn path_hex(_path: &Path) -> Option<String> {
    None
}

pub(crate) fn error_record(path: &Path, error: &io::Error) -> Value {
    json!({
        "schema_version": 1, "kind": "error", "path": path.to_string_lossy(), "path_bytes_hex": path_hex(path),
        "error": { "category": category(error.kind()), "message": error.to_string() }
    })
}
pub(crate) fn summary(
    options: &ScanOptions,
    limits: &RelocationLimits,
    stats: &ScanStats,
    elapsed: Duration,
) -> Value {
    let excluded_names: Vec<Value> = options
        .excludes
        .iter()
        .map(|name| {
            let path = Path::new(name);
            json!({"text": name.to_string_lossy(), "bytes_hex": path_hex(path)})
        })
        .collect();
    json!({
        "schema_version": 1, "kind": "scan_summary", "program_version": env!("CARGO_PKG_VERSION"),
        "root": options.path.to_string_lossy(), "root_bytes_hex": path_hex(&options.path),
        "status": if stats.max_files_reached { "stopped_at_file_limit" } else { "finished" },
        "had_errors": stats.errors != 0,
        "scope_limited": options.max_depth.is_some() || !options.excludes.is_empty() || stats.max_files_reached,
        "elapsed_ms": elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        "counts": {
            "regular_files_attempted": stats.files, "elf_files": stats.elf_files, "errors": stats.errors,
            "skipped_entries": stats.skipped, "excluded_entries": stats.excluded,
            "depth_limited_directories": stats.depth_limited
        },
        "configuration": {
            "max_depth": options.max_depth, "max_files": options.max_files,
            "excluded_names": excluded_names,
            "relocation_limits": { "tables": limits.tables, "records": limits.records, "previews": limits.previews }
        }
    })
}
pub(crate) fn write_json(value: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    bytes.push(b'\n');
    io::stdout().lock().write_all(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{self, Action};
    use std::ffi::OsString;
    #[test]
    fn classifies_known_error_kinds() {
        assert_eq!(category(io::ErrorKind::UnexpectedEof), "unexpected_eof");
        assert_eq!(
            category(io::ErrorKind::PermissionDenied),
            "permission_denied"
        );
    }
    #[test]
    fn does_not_misclassify_unsupported_as_definite_corruption() {
        assert_eq!(category(io::ErrorKind::Unsupported), "unsupported_or_limit");
    }
    #[test]
    fn error_json_escapes_paths_and_messages() {
        let record = error_record(
            Path::new("quote\"\n.elf"),
            &io::Error::new(io::ErrorKind::InvalidData, "bad\nvalue"),
        );
        let line = serde_json::to_string(&record).unwrap();
        assert!(!line.contains('\n'));
        let decoded: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded["error"]["message"], "bad\nvalue");
    }
    #[test]
    fn summary_reports_effective_configuration() {
        let Action::Scan(options) =
            cli::parse(["--json", "--max-files", "2", "root"].map(OsString::from)).unwrap()
        else {
            panic!()
        };
        let stats = ScanStats {
            files: 2,
            max_files_reached: true,
            ..ScanStats::default()
        };
        let limits = RelocationLimits {
            tables: 8192,
            ..RelocationLimits::default()
        };
        let value = summary(&options, &limits, &stats, Duration::from_millis(12));
        assert_eq!(value["status"], "stopped_at_file_limit");
        assert_eq!(value["elapsed_ms"], 12);
        assert_eq!(value["configuration"]["relocation_limits"]["tables"], 8192);
    }
}
