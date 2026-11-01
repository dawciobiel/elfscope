use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Detailed,
    Summary,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Help,
    Scan { path: PathBuf, mode: OutputMode },
}

pub const HELP: &str = "\
Użycie: elfscope [--summary] <katalog-lub-plik>
       elfscope --help
       elfscope [--summary] -- <katalog-lub-plik>

Opcje:
  --summary   Jedna linia wyniku dla każdego przeanalizowanego ELF-a
  -h, --help  Wyświetl pomoc
  --          Zakończ rozpoznawanie opcji

Bez --summary program wyświetla pełny raport.

Program analizuje pliki tylko do odczytu.
Dowiązania symboliczne są pomijane.

Kody zakończenia:
  0  Skanowanie bez błędów lub wyświetlenie pomocy
  1  Co najmniej jeden błąd skanowania lub analizy
  2  Nieprawidłowe argumenty
";

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Action, String> {
    let mut path = None;
    let mut mode = OutputMode::Detailed;
    let mut options_enabled = true;

    for arg in args {
        if options_enabled {
            if arg == "--" {
                options_enabled = false;
                continue;
            }

            if arg == "--help" || arg == "-h" {
                return Ok(Action::Help);
            }

            if arg == "--summary" {
                mode = OutputMode::Summary;
                continue;
            }

            if arg.to_string_lossy().starts_with('-') {
                return Err(format!(
                    "Nieznana opcja: {:?}. Dla ścieżki zaczynającej się od '-' użyj --.",
                    arg
                ));
            }
        }

        if path.is_some() {
            return Err("Podaj dokładnie jedną ścieżkę do pliku lub katalogu".to_string());
        }

        path = Some(PathBuf::from(arg));
    }

    let path = path.ok_or_else(|| "Brak ścieżki do pliku lub katalogu".to_string())?;

    Ok(Action::Scan { path, mode })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn defaults_to_detailed_output() {
        assert_eq!(
            parse(args(&["example"])).unwrap(),
            Action::Scan {
                path: PathBuf::from("example"),
                mode: OutputMode::Detailed,
            }
        );
    }

    #[test]
    fn enables_summary_output() {
        assert_eq!(
            parse(args(&["--summary", "example"])).unwrap(),
            Action::Scan {
                path: PathBuf::from("example"),
                mode: OutputMode::Summary,
            }
        );
    }

    #[test]
    fn rejects_missing_path() {
        assert!(parse(args(&[])).is_err());
        assert!(parse(args(&["--summary"])).is_err());
    }

    #[test]
    fn rejects_multiple_paths() {
        assert!(parse(args(&["first", "second"])).is_err());
    }

    #[test]
    fn rejects_unknown_options() {
        assert!(parse(args(&["--unknown", "example"])).is_err());
    }

    #[test]
    fn recognizes_help() {
        assert_eq!(parse(args(&["--help"])).unwrap(), Action::Help);
        assert_eq!(parse(args(&["-h"])).unwrap(), Action::Help);
    }

    #[test]
    fn accepts_option_like_path_after_separator() {
        assert_eq!(
            parse(args(&["--summary", "--", "--example"])).unwrap(),
            Action::Scan {
                path: PathBuf::from("--example"),
                mode: OutputMode::Summary,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_path() {
        use std::os::unix::ffi::OsStringExt;

        let raw = OsString::from_vec(b"example-\xff".to_vec());
        let expected = PathBuf::from(raw.clone());

        assert_eq!(
            parse(vec![raw]).unwrap(),
            Action::Scan {
                path: expected,
                mode: OutputMode::Detailed,
            }
        );
    }
}
