use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies the benchmark manifest path"),
    );
    let object = manifest
        .join("../../evidence/c3-count-v2/implementation.o")
        .canonicalize()
        .expect("retained C3 implementation object");
    println!("cargo:rerun-if-changed={}", object.display());
    println!(
        "cargo:rustc-link-arg-bin=fre-aot-count-benchmark={}",
        object.display()
    );
}
