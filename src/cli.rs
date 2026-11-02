use std::ffi::OsString;
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Detailed,
    Summary,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    JsonLines,
    Paths,
}
#[derive(Debug, PartialEq, Eq)]
pub struct ScanOptions {
    pub path: PathBuf,
    pub mode: OutputMode,
    pub format: OutputFormat,
    pub max_depth: Option<usize>,
    pub max_files: Option<u64>,
    pub excludes: Vec<OsString>,
    pub null_separator: bool,
    pub quiet: bool,
    pub json_errors: bool,
    pub json_stats: bool,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Help,
    Version,
    Scan(ScanOptions),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Selection {
    Summary,
    Json,
    Paths,
}
pub const HELP: &str = "\
Użycie: elfscope [opcje] <katalog-lub-plik>
       elfscope --help
       elfscope --version

Wyjście (opcje wzajemnie wykluczające się):
  --summary           Jedna linia tekstu dla każdego ELF-a
  --json              Jeden obiekt JSON na linię (JSON Lines)
  --paths             Same ścieżki przeanalizowanych ELF-ów
  --null              Separator NUL, tylko razem z --paths
  --json-errors       Dodaj rekordy kind=error; wymaga --json
  --json-stats        Dodaj końcowy rekord kind=scan_summary; wymaga --json

Skanowanie:
  --max-depth N       Maksymalna głębokość; ścieżka startowa ma głębokość 0
  --no-recursive      Odpowiednik --max-depth 1
  --max-files N       Maksymalna liczba sprawdzanych zwykłych plików; N > 0
  --exclude NAME      Pomijaj potomne wpisy o dokładnie tej nazwie; opcja powtarzalna
  --quiet             Nie wypisuj końcowych liczników na stderr; nie ukrywa błędów

Pozostałe:
  -h, --help          Pomoc
  -V, --version       Wersja programu
  --                 Koniec opcji; dalej ścieżka może zaczynać się od '-'

Bez opcji wyjścia program pokazuje pełny raport.
Każdy tryb wykonuje pełną zaimplementowaną analizę.
Katalogi są przechodzone w deterministycznej kolejności po posortowaniu wpisów.
--exclude nie obsługuje globów i nie wyklucza jawnej ścieżki startowej.
Dowiązania symboliczne i pliki specjalne są pomijane.
Program nie modyfikuje ani nie uruchamia analizowanych plików.

Kody zakończenia:
  0  Brak zgłoszonych błędów; także kontrolowane zakończenie po limicie
  1  Błąd skanowania, analizy lub zapisu wyniku
  2  Nieprawidłowe argumenty lub konfiguracja limitów
";
fn select(current: &mut Option<Selection>, value: Selection) -> Result<(), String> {
    if current.is_some_and(|previous| previous != value) {
        return Err("--summary, --json i --paths są wzajemnie wykluczające się".into());
    }
    *current = Some(value);
    Ok(())
}
fn value(args: &mut impl Iterator<Item = OsString>, option: &str) -> Result<OsString, String> {
    args.next()
        .ok_or_else(|| format!("Brak wartości dla {}", option))
}
fn depth(current: &mut Option<usize>, value: usize) -> Result<(), String> {
    if current.is_some_and(|previous| previous != value) {
        return Err("Sprzeczne ograniczenia głębokości".into());
    }
    *current = Some(value);
    Ok(())
}
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Action, String> {
    let mut args = args.into_iter();
    let mut path = None;
    let mut selection = None;
    let mut options_enabled = true;
    let mut max_depth = None;
    let mut max_files = None;
    let mut excludes = Vec::new();
    let mut null_separator = false;
    let mut quiet = false;
    let mut json_errors = false;
    let mut json_stats = false;
    while let Some(arg) = args.next() {
        if options_enabled {
            if arg == "--" {
                options_enabled = false;
                continue;
            }
            if arg == "--help" || arg == "-h" {
                return Ok(Action::Help);
            }
            if arg == "--version" || arg == "-V" {
                return Ok(Action::Version);
            }
            if arg == "--summary" {
                select(&mut selection, Selection::Summary)?;
                continue;
            }
            if arg == "--json" {
                select(&mut selection, Selection::Json)?;
                continue;
            }
            if arg == "--paths" {
                select(&mut selection, Selection::Paths)?;
                continue;
            }
            if arg == "--null" {
                null_separator = true;
                continue;
            }
            if arg == "--quiet" {
                quiet = true;
                continue;
            }
            if arg == "--json-errors" {
                json_errors = true;
                continue;
            }
            if arg == "--json-stats" {
                json_stats = true;
                continue;
            }
            if arg == "--no-recursive" {
                depth(&mut max_depth, 1)?;
                continue;
            }
            if arg == "--max-depth" {
                let raw = value(&mut args, "--max-depth")?;
                let number = raw
                    .to_str()
                    .and_then(|text| text.parse::<usize>().ok())
                    .ok_or_else(|| "--max-depth wymaga nieujemnej liczby całkowitej".to_string())?;
                depth(&mut max_depth, number)?;
                continue;
            }
            if arg == "--max-files" {
                let raw = value(&mut args, "--max-files")?;
                let number = raw
                    .to_str()
                    .and_then(|text| text.parse::<u64>().ok())
                    .filter(|number| *number != 0)
                    .ok_or_else(|| "--max-files wymaga dodatniej liczby całkowitej".to_string())?;
                if max_files.is_some_and(|previous| previous != number) {
                    return Err("Sprzeczne limity liczby plików".into());
                }
                max_files = Some(number);
                continue;
            }
            if arg == "--exclude" {
                let name = value(&mut args, "--exclude")?;
                let candidate = Path::new(&name);
                if candidate.components().count() != 1
                    || candidate.file_name() != Some(name.as_os_str())
                {
                    return Err("--exclude wymaga pojedynczej nazwy, nie ścieżki".into());
                }
                excludes.push(name);
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
            return Err("Podaj dokładnie jedną ścieżkę do pliku lub katalogu".into());
        }
        path = Some(PathBuf::from(arg));
    }
    let path = path.ok_or_else(|| "Brak ścieżki do pliku lub katalogu".to_string())?;
    let (mode, format) = match selection {
        None => (OutputMode::Detailed, OutputFormat::Text),
        Some(Selection::Summary) => (OutputMode::Summary, OutputFormat::Text),
        Some(Selection::Json) => (OutputMode::Detailed, OutputFormat::JsonLines),
        Some(Selection::Paths) => (OutputMode::Detailed, OutputFormat::Paths),
    };
    if null_separator && format != OutputFormat::Paths {
        return Err("--null wymaga --paths".into());
    }
    if (json_errors || json_stats) && format != OutputFormat::JsonLines {
        return Err("--json-errors i --json-stats wymagają --json".into());
    }
    Ok(Action::Scan(ScanOptions {
        path,
        mode,
        format,
        max_depth,
        max_files,
        excludes,
        null_separator,
        quiet,
        json_errors,
        json_stats,
    }))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    fn scan(values: &[&str]) -> ScanOptions {
        match parse(args(values)).unwrap() {
            Action::Scan(options) => options,
            other => panic!("{:?}", other),
        }
    }
    #[test]
    fn defaults_to_detailed_output() {
        assert_eq!(scan(&["example"]).mode, OutputMode::Detailed);
    }
    #[test]
    fn enables_summary_output() {
        assert_eq!(scan(&["--summary", "example"]).mode, OutputMode::Summary);
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
        assert_eq!(scan(&["--", "--example"]).path, PathBuf::from("--example"));
    }
    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_path() {
        use std::os::unix::ffi::OsStringExt;
        let raw = OsString::from_vec(b"example-\xff".to_vec());
        match parse(vec![raw.clone()]).unwrap() {
            Action::Scan(options) => assert_eq!(options.path, PathBuf::from(raw)),
            _ => panic!(),
        }
    }
    #[test]
    fn enables_json_lines() {
        assert_eq!(scan(&["--json", "example"]).format, OutputFormat::JsonLines);
    }
    #[test]
    fn enables_null_separated_paths() {
        let options = scan(&["--paths", "--null", "example"]);
        assert!(options.null_separator);
        assert_eq!(options.format, OutputFormat::Paths);
    }
    #[test]
    fn rejects_null_without_paths() {
        assert!(parse(args(&["--null", "example"])).is_err());
    }
    #[test]
    fn rejects_conflicting_output_modes() {
        assert!(parse(args(&["--json", "--summary", "example"])).is_err());
    }
    #[test]
    fn reads_numeric_limits() {
        let options = scan(&["--max-depth", "2", "--max-files", "10", "example"]);
        assert_eq!(options.max_depth, Some(2));
        assert_eq!(options.max_files, Some(10));
    }
    #[test]
    fn rejects_invalid_limits() {
        for values in [
            &["--max-files", "0", "example"][..],
            &["--max-depth", "-1", "example"][..],
            &["--max-depth"][..],
        ] {
            assert!(parse(args(values)).is_err());
        }
    }
    #[test]
    fn reads_exact_excluded_names() {
        assert_eq!(
            scan(&["--exclude", "target", "--exclude", ".git", "example"]).excludes,
            args(&["target", ".git"])
        );
        assert!(parse(args(&["--exclude", "a/b", "example"])).is_err());
    }
    #[test]
    fn recognizes_version() {
        assert_eq!(parse(args(&["-V"])).unwrap(), Action::Version);
    }
    #[test]
    fn enables_quiet_counters() {
        assert!(scan(&["--quiet", "example"]).quiet);
    }
    #[test]
    fn no_recursive_means_depth_one() {
        assert_eq!(scan(&["--no-recursive", "example"]).max_depth, Some(1));
        assert!(parse(args(&["--no-recursive", "--max-depth", "2", "example"])).is_err());
    }
    #[test]
    fn enables_json_error_events() {
        assert!(scan(&["--json-errors", "--json", "example"]).json_errors);
    }
    #[test]
    fn enables_json_summary_events() {
        assert!(scan(&["--json", "--json-stats", "--quiet", "example"]).json_stats);
    }
    #[test]
    fn requires_json_for_event_options() {
        for flag in ["--json-errors", "--json-stats"] {
            assert!(parse(args(&[flag, "example"])).is_err());
        }
    }
}
