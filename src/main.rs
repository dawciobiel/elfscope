mod build_id;
mod cli;
mod diagnostics;
mod dynamic;
mod elf;
mod inspection;
mod interpreter;
mod json_report;
mod mapping;
mod relocations;
mod report;
mod scanner;
mod sections;
mod symbols;
use cli::Action;
use std::env;
use std::io;
use std::process::ExitCode;
use std::time::Instant;
fn output_error(error: io::Error) -> ExitCode {
    if error.kind() == io::ErrorKind::BrokenPipe {
        ExitCode::SUCCESS
    } else {
        eprintln!("Błąd skanowania lub zapisu wyniku: {}", error);
        ExitCode::FAILURE
    }
}
fn main() -> ExitCode {
    let action = match cli::parse(env::args_os().skip(1)) {
        Ok(action) => action,
        Err(error) => {
            eprintln!("Błąd argumentów: {}\n\n{}", error, cli::HELP);
            return ExitCode::from(2);
        }
    };
    let options = match action {
        Action::Help => {
            print!("{}", cli::HELP);
            return ExitCode::SUCCESS;
        }
        Action::Version => {
            println!("elfscope {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Action::Scan(options) => options,
    };
    let limits = match relocations::RelocationLimits::from_env() {
        Ok(limits) => limits,
        Err(error) => {
            eprintln!("Nieprawidłowa konfiguracja limitów relokacji: {}", error);
            return ExitCode::from(2);
        }
    };
    let started = Instant::now();
    let stats = match scanner::scan(&options, &limits) {
        Ok(stats) => stats,
        Err(error) => return output_error(error),
    };
    if options.json_stats {
        if let Err(error) = diagnostics::write_json(&diagnostics::summary(
            &options,
            &limits,
            &stats,
            started.elapsed(),
        )) {
            return output_error(error);
        }
    }
    if !options.quiet {
        eprintln!();
        eprintln!("Sprawdzone zwykłe pliki: {}", stats.files);
        eprintln!("Przeanalizowane ELF:     {}", stats.elf_files);
        eprintln!("Pominięte wpisy:         {}", stats.skipped);
        eprintln!("Błędy:                   {}", stats.errors);
        eprintln!("Wykluczone wpisy:        {}", stats.excluded);
        eprintln!("Ograniczone katalogi:    {}", stats.depth_limited);
        eprintln!(
            "Przerwano po limicie plików: {}",
            if stats.max_files_reached {
                "tak"
            } else {
                "nie"
            }
        );
    }
    if stats.errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
