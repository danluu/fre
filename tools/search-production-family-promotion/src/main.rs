use std::process::ExitCode;

fn main() -> ExitCode {
    match search_production_family_promotion::run_cli(std::env::args_os()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Search production-family promotion refused: {error}");
            ExitCode::FAILURE
        }
    }
}
