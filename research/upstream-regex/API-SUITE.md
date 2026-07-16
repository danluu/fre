# Rust `regex` 1.12.4 non-corpus API audit

This audit is pinned to crate version 1.12.4, VCS revision
`7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1`, and crates.io package SHA-256
`f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba`.
It distinguishes upstream Rust integration/API tests from the TOML testdata
already inventoried by `regex-1.12.4-inventory.json`.

| Upstream source | Status in the report-producing tool |
| --- | --- |
| `tests/replace.rs` | Complete executable adapter: 26/26 named obligations, each with a mandatory disposition |
| `tests/searcher.rs` | Eleven behaviors have executable FRE coverage in `crates/fre/tests/upstream_searcher.rs`; a payload-hashed tool report remains |
| `tests/misc.rs` | Source-level constructor, capture metadata/indexing and pathological-search audit remains |
| `tests/regression.rs` | Ten source-level regression tests remain to be moved into mandatory receipts |
| `tests/regression_fuzz.rs` | Five source-level fuzz regressions, including one ignored expensive case, remain |
| `tests/suite_{string,bytes,string_set,bytes_set}.rs` | These are upstream adapters over the TOML corpus; their input obligations are covered by the existing 16,450-row report rather than counted again |
| crate doctests | Not yet inventoried as individual obligations |
| Cargo feature matrix | Feature declarations are pinned by authenticated `Cargo.toml.orig`, but build/test combinations are not yet mandatory dispositions |

The replacement adapter authenticates `.cargo_vcs_info.json`,
`Cargo.toml.orig`, and the entire `tests/replace.rs` byte stream before running.
The source file SHA-256 is
`78ff9bf7f78783ad83a78041bb7ee0705c7efc85b4d12301581d0ce5b2a59325`.
Its fixed obligation order prevents omission or filtering: report validation
rejects missing, reordered, duplicated, falsely passing, or source-unbound
receipts.
