use std::{env, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo supplies the benchmark manifest path"),
    );
    if env::var_os("CARGO_FEATURE_QUALIFICATION_BENCHMARK").is_some() {
        let evidence = manifest.join("../../evidence/c5-count-v2-candidate");
        for name in ["final-image-glue.o", "implementation.o"] {
            let object = evidence
                .join(name)
                .canonicalize()
                .unwrap_or_else(|error| panic!("retained C5 {name}: {error}"));
            println!("cargo:rerun-if-changed={}", object.display());
            println!(
                "cargo:rustc-link-arg-bin=fre-aot-count-qualified-benchmark={}",
                object.display()
            );
        }
        println!(
            "cargo:rustc-link-arg-bin=fre-aot-count-qualified-benchmark=-Wl,-segprot,__FRE_CONST,r,r"
        );
        println!("cargo:rustc-link-arg-bin=fre-aot-count-qualified-benchmark=-Wl,-reproducible");
    }

    println!("cargo:rerun-if-env-changed=FRE_C5_PRODUCTION_OBJECT_DIR");
    if env::var_os("CARGO_FEATURE_PROMOTION_CORRECTNESS").is_some() {
        let object_dir = PathBuf::from(
            env::var_os("FRE_C5_PRODUCTION_OBJECT_DIR")
                .expect("promotion correctness requires FRE_C5_PRODUCTION_OBJECT_DIR"),
        )
        .canonicalize()
        .expect("canonical C5 production object directory");
        for name in ["final-image-glue.o", "implementation.o"] {
            let object = object_dir
                .join(name)
                .canonicalize()
                .unwrap_or_else(|error| panic!("C5 production correctness {name}: {error}"));
            println!("cargo:rerun-if-changed={}", object.display());
            println!(
                "cargo:rustc-link-arg-bin=fre-aot-count-promoted-correctness={}",
                object.display()
            );
        }
        println!(
            "cargo:rustc-link-arg-bin=fre-aot-count-promoted-correctness=-Wl,-segprot,__FRE_CONST,r,r"
        );
        println!("cargo:rustc-link-arg-bin=fre-aot-count-promoted-correctness=-Wl,-reproducible");
    }
}
