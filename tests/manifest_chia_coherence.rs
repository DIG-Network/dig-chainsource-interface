//! The regression guard for #5: this crate MUST NEVER again declare two different minor lines of
//! the same `chia-*` family.
//!
//! ## The defect this exists to catch
//!
//! Published 0.3.1 shipped INTERNALLY SPLIT: `chia-bls`/`chia-protocol`/`chia-puzzle-types`/
//! `chia-traits` declared at `^0.36.1` beside `chia-sdk-driver`/`chia-sdk-test`/`chia-sdk-types` at
//! `^0.34`. Two lines of the same family in one crate compile only while every consumer happens to
//! be stale in the matching way; the moment one is not, the crate exposes two incompatible copies
//! of the same types. Nothing mechanically prevented it, and no *behavioural* test can: both halves
//! run correctly in isolation, so the split is invisible to every test of what the code DOES.
//!
//! The defect was **manifest coherence**, and manifest coherence is mechanically assertable. That
//! is what these tests assert.
//!
//! ## Why the manifest, and not `Cargo.lock`
//!
//! #5 is about the versions this crate DECLARES. The resolved lock legitimately contains older
//! chia lines we neither choose nor control — `clvmr` vendors `chia-sha2 0.34.0` and `chia-bls
//! 0.28.2` internally, and `chialisp` (via `rue-lir`) pulls `chia-bls 0.42.1`. A lock-based
//! assertion would therefore have to carve those out by name and would go red every time an
//! upstream evaluator re-vendored something, which is noise rather than signal. The manifest is the
//! surface this crate owns, so it is the surface the guard pins.
//!
//! ## Why per-FAMILY, and not "all chia crates are equal"
//!
//! The ecosystem ceiling is deliberately NOT uniform, so a test asserting one global version would
//! be wrong on green code: `chia-sdk-*` tops out at 0.36.0 while the primitives publish 0.36.1, and
//! `chia-puzzles` (0.20.x) and `clvmr` (0.16.x) have never shared a version line with either. What
//! must agree is the `MAJOR.MINOR` **line** within a family — which is exactly the granularity the
//! 0.34-vs-0.36 defect violated, and exactly the granularity the legitimate 0.36.0-vs-0.36.1 patch
//! spread does not.

use std::collections::BTreeSet;
use std::fs;

/// A declared dependency: its crate name and the version requirement in the manifest.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Declared {
    name: String,
    version: String,
}

impl Declared {
    /// The `MAJOR.MINOR` line this requirement sits on — the granularity a family must agree at.
    fn line(&self) -> String {
        self.version
            .split('.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".")
    }
}

/// The families that MUST each be internally coherent, with the line each is pinned to.
///
/// `chia-sdk-*` and the chia/clvm primitives share the 0.36 line: they are listed as ONE family
/// precisely because the shipped defect split them apart. `chia-puzzles` and `clvmr` version
/// independently of both and of each other, so each is its own family.
const FAMILIES: &[(&str, &str, &[&str])] = &[
    (
        "the chia 0.36 line (chia-sdk-* + the chia/clvm primitives)",
        "0.36",
        &[
            "chia-bls",
            "chia-protocol",
            "chia-puzzle-types",
            "chia-sdk-driver",
            "chia-sdk-test",
            "chia-sdk-types",
            "chia-traits",
            "clvm-traits",
            "clvm-utils",
        ],
    ),
    ("the chia-puzzles line", "0.20", &["chia-puzzles"]),
    ("the clvmr line", "0.16", &["clvmr"]),
];

/// Reads every `chia-*`/`clvm*` requirement declared in `[dependencies]` and `[dev-dependencies]`.
///
/// Read at RUNTIME rather than `include_str!`d so that reverting a version in the manifest and
/// re-running the suite is a genuine end-to-end proof of the guard, with no recompilation subtlety
/// standing between the edit and the verdict.
fn declared_chia_deps() -> Vec<Declared> {
    let manifest = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("the crate's own Cargo.toml is readable");

    let mut section = String::new();
    let mut found = Vec::new();

    for raw in manifest.lines() {
        let line = raw.trim();
        // Comments carry example version numbers (including this guard's own rationale), so they
        // must never be parsed as declarations.
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = line.to_string();
            continue;
        }
        if section != "[dependencies]" && section != "[dev-dependencies]" {
            continue;
        }
        let Some((name, rest)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !(name.starts_with("chia") || name.starts_with("clvm")) {
            continue;
        }
        let version = extract_version(rest.trim()).unwrap_or_else(|| {
            panic!("dependency `{name}` declares no literal version this guard can read: {line}")
        });
        found.push(Declared {
            name: name.to_string(),
            version,
        });
    }

    found
}

/// Pulls the version literal out of either `"0.36.1"` or `{ version = "0.36.1", optional = true }`.
fn extract_version(rest: &str) -> Option<String> {
    let quoted = if rest.starts_with('{') {
        let at = rest.find("version")?;
        &rest[at..]
    } else {
        rest
    };
    let mut parts = quoted.split('"');
    parts.next()?;
    parts.next().map(str::to_string)
}

#[test]
fn every_chia_family_declares_a_single_minor_line() {
    let declared = declared_chia_deps();

    for (family, expected_line, members) in FAMILIES {
        for member in *members {
            let Some(dep) = declared.iter().find(|d| d.name == *member) else {
                continue; // absence is the cardinality test's job, below.
            };
            assert_eq!(
                dep.line(),
                *expected_line,
                "#5 REGRESSION: `{}` is declared at {} but {family} is pinned to {expected_line}.x. \
                 Two minor lines of one chia family in one manifest is the internal split that \
                 shipped as 0.3.1. Move the whole family together, or re-state the family's line here.",
                dep.name,
                dep.version,
            );
        }
    }
}

#[test]
fn every_declared_chia_dep_belongs_to_a_classified_family() {
    let classified: BTreeSet<&str> = FAMILIES
        .iter()
        .flat_map(|(_, _, members)| members.iter().copied())
        .collect();

    for dep in declared_chia_deps() {
        assert!(
            classified.contains(dep.name.as_str()),
            "`{}` is a chia/clvm dependency this coherence guard does not classify. A new chia \
             dependency can silently arrive on a foreign version line, which is exactly how the \
             0.3.1 split went unnoticed. Add it to the family it belongs to in FAMILIES.",
            dep.name,
        );
    }
}

#[test]
fn the_declared_chia_dependency_set_is_exactly_the_expected_one() {
    // Pinned by exact membership, not by count: a guard that only counts cannot tell a dropped
    // dependency from a substituted one, and both are ways for a family to lose a member without
    // the coherence test above ever seeing it (it skips names it cannot find).
    let expected: BTreeSet<&str> = BTreeSet::from([
        "chia-bls",
        "chia-protocol",
        "chia-puzzle-types",
        "chia-puzzles",
        "chia-sdk-driver",
        "chia-sdk-test",
        "chia-sdk-types",
        "chia-traits",
        "clvm-traits",
        "clvm-utils",
        "clvmr",
    ]);

    let actual: BTreeSet<String> = declared_chia_deps().into_iter().map(|d| d.name).collect();
    let actual: BTreeSet<&str> = actual.iter().map(String::as_str).collect();

    assert_eq!(
        actual, expected,
        "the crate's chia/clvm dependency set changed. Confirm the new set is on ONE line per \
         family, then update this expectation in the same commit.",
    );
}
