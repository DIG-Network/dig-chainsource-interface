//! # dig-chainsource-interface — the DIG Network canonical `ChainSource` provider interface
//!
//! This crate defines the ONE [`ChainSource`] trait (and its query/result/error types) that every
//! Chia chain-source provider implements and every DIG consumer depends on. There is a single
//! canonical contract for reading Chia chain state across the ecosystem — never a per-crate copy
//! that could byte-drift.
//!
//! It is a pure **leaf**: a trait, its typed query inputs and results, a typed error, an optional
//! in-memory mock, and known-answer tests. It performs NO I/O, holds NO keys, opens NO network,
//! and ships NO concrete provider. Providers (coinset.org, a local wallet/full node, DIG peers)
//! live in their own crates; `chia-query` is the registry + aggregating canonical source that
//! composes them. Consumers depend on THIS trait, not on any provider.
//!
//! ## Reads only — no broadcast, ever (custody stance)
//!
//! Nothing in this crate can broadcast, push, or submit to the chain: there is no such method, by
//! design. It is a pure reader. Write/spend/broadcast paths — which touch keys and funds — live
//! entirely outside this crate, so depending on it can never move value.
//!
//! ## Fail-closed: `Ok(None)` vs `Err` (the soundness contract)
//!
//! Every read distinguishes two outcomes consumers MUST treat differently:
//! - `Ok(None)` / an empty `Vec` — the source reliably answered and the thing genuinely does not
//!   exist. Safe to act on.
//! - `Err(_)` — the source could NOT reliably answer (transport/timeout/malformed/unsupported).
//!   The answer is unknown; the consumer MUST fail closed, never treating it as an absence.
//!
//! Absence is NEVER an error variant; an error is NEVER degraded to a value.
//!
//! ## Money-critical parent-walk enablement
//!
//! A Chia coin's `puzzle_hash` is attacker-chosen, so a `launcher_id ==` equality check is
//! spoofable. Authenticating a coin as a genuine singleton requires walking
//! [`ChainSource::parent_spend`] back toward the real launcher, proving each hop from the parent's
//! actual reveal+solution — a spoofed curried-puzzle coin has no genuine recreation parent-spend,
//! so the walk fails closed. This crate supplies that primitive (and [`SingletonLineage`], whose
//! authority is MEMBERSHIP, not tip-equality); consumers supply the trust logic on top.

mod error;
mod lineage;
mod provider;
mod record;
mod source;

#[cfg(feature = "testing")]
mod testing;

pub use error::ChainSourceError;
pub use lineage::SingletonLineage;
pub use provider::{ProviderId, ProviderInfo, ProviderKind};
pub use record::CoinRecord;
pub use source::{ChainSource, ChainSourceProvider};

#[cfg(feature = "testing")]
pub use testing::MockChainSource;

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
