use std::{env, error::Error, io, path::PathBuf};

use fre_search_v26_development_gate::materialize_cells;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let destination = arguments.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: fre-search-v26-materialize-cells OUTPUT.jsonl",
        )
    })?;
    if arguments.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: fre-search-v26-materialize-cells OUTPUT.jsonl",
        )
        .into());
    }
    materialize_cells(&destination)?;
    Ok(())
}
