use std::{env, error::Error, path::Path};

use rust_regex_conformance::{
    CandidateIdentity, build_regex_automata_state_codec_report, read_regex_automata_adapter_report,
    read_regex_automata_corpus_report, validate_regex_automata_state_codec_strict_gain,
    write_regex_automata_adapter_report,
};

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 5 {
        return Err("usage: state_codec_report INVENTORY PREVIOUS OUTPUT REVISION TREE".into());
    }
    let inventory = read_regex_automata_corpus_report(Path::new(&arguments[0]))?;
    let previous = read_regex_automata_adapter_report(Path::new(&arguments[1]), &inventory)?;
    let current = build_regex_automata_state_codec_report(
        &inventory,
        &previous,
        CandidateIdentity {
            revision: arguments[3].clone(),
            tree: arguments[4].clone(),
            tracked_and_untracked_worktree_clean: true,
        },
    )?;
    let gain = validate_regex_automata_state_codec_strict_gain(&inventory, &previous, &current)?;
    if (gain.gained_unique_cases, gain.gained_mode_memberships) != (2, 2) {
        return Err("state-codec report delta changed".into());
    }
    write_regex_automata_adapter_report(Path::new(&arguments[2]), &current, &inventory)?;
    Ok(())
}
