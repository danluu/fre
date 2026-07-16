# Rust `regex` 1.12.4 non-corpus API audit

This audit is pinned to crate version 1.12.4, VCS revision
`7b96fdc9d5fe6a0cb4efe30e6689b050493fc1e1`, and crates.io package SHA-256
`f1292b7759ae1cb9ec195452d1390a074f0cd8541ab7a5a8c31cd6db45d4a6ba`.
It distinguishes upstream Rust integration/API tests from the TOML testdata
already inventoried by `regex-1.12.4-inventory.json`.

| Upstream source | Status in the report-producing tool |
| --- | --- |
| `tests/replace.rs` | Complete executable adapter: 26/26 named obligations, each with a mandatory disposition |
| `tests/searcher.rs` | Complete executable adapter: 11/11 named obligations, each with a mandatory disposition |
| `tests/misc.rs` | Complete 10/10 mandatory dispositions; constructor, metadata, capture, and search behavior execute where FRE exposes the upstream surface |
| `tests/regression.rs` | Complete 10/10 mandatory dispositions with executable constructor, capture, and search checks |
| `tests/regression_fuzz.rs` | Complete 5/5 mandatory dispositions; the upstream ignored expensive case remains explicit unsupported evidence |
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

The misc/regression adapter independently authenticates those package and VCS
files plus all bytes of `tests/misc.rs`, `tests/regression.rs`, and
`tests/regression_fuzz.rs`. Its fixed 25-obligation order admits only pass,
mismatch, unsupported, or fault receipts. Unsupported formatting/index
operator/type-lifetime surfaces execute through FRE's bounded borrowed text
capture view. The upstream ignored expensive constructor remains visible as
the suite's sole unsupported receipt rather than being silently filtered.

The searcher adapter independently authenticates the same package identity and
the complete `tests/searcher.rs` byte stream (SHA-256
`04152e5c86431deec0c196d2564a11bc4ec36f14c77e8c16a2f9d1cbc9fc574e`).
It executes every upstream empty, adjacent, rejected-range, zero-width and
Unicode step-sequence obligation through FRE's real aggregate search-step API.
All 11 fixed-order obligations must produce pass, mismatch, unsupported or
fault receipts; omission and filtering are not report states.
