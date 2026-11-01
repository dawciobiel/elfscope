mod build_id;
mod cli;
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
    let stats = match scanner::scan(&options) {
        Ok(stats) => stats,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Błąd skanowania lub zapisu wyniku: {}", error);
            return ExitCode::FAILURE;
        }
    };
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
