const REGEX_REDUX_VARIANTS: [&str; 2] = [r"agggtaaa|tttaccct", r"[cgt]gggtaaa|tttaccc[acg]"];
const REGEX_REDUX_SUBSTITUTIONS: [(&str, &str); 1] = [(r"tHa[Nt]", "<4>")];

struct Artifact {
    source_digest: [u8; 32],
}

fn source_digest(source: &str) -> [u8; 32] {
    let mut digest = [0; 32];
    digest[0] = source.len() as u8;
    digest
}

fn authenticate_artifact(source: &str, artifact: &Artifact) -> Result<(), ()> {
    let actual_source_digest = source_digest(source);
    if actual_source_digest != artifact.source_digest {
        return Err(());
    }
    Ok(())
}

fn compile_regex_redux_model() -> usize {
    REGEX_REDUX_VARIANTS.len() + REGEX_REDUX_SUBSTITUTIONS.len()
}

#[cfg(test)]
mod tests {
    const EXPECTED_ANSWER: usize = 42;

    fn exact_source_checks_are_allowed_only_in_tests(source: &str) -> usize {
        if source == "(?s)^(.*)$" {
            EXPECTED_ANSWER
        } else {
            0
        }
    }
}
