//! # dig-chainsource-interface — the DIG Network canonical `ChainSource` provider interface
//!
//! This crate defines the ONE `ChainSource` trait (and its query/result/error types) that every
//! Chia chain-source provider implements and every DIG consumer depends on. There is a single
//! canonical contract for reading Chia chain state across the ecosystem — never a per-crate copy
//! that could byte-drift.
//!
//! It is a pure **leaf**: a trait, its typed query inputs and results, a typed error, and
//! known-answer tests for the type shapes. It performs NO I/O, holds NO keys, opens NO network,
//! and ships NO concrete provider. Providers (coinset.org, a local wallet/full node, DIG peers)
//! live in their own crates; `chia-query` is the registry + aggregating canonical source that
//! composes them. Consumers depend on THIS trait, not on any provider.
//!
//! This is the v0.0.0 bootstrap skeleton — the v0.1.0 unit fills in the trait surface.

/// The crate version, sourced from `Cargo.toml` at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_reported() {
        assert!(!VERSION.is_empty());
    }
}
