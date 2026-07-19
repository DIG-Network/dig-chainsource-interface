//! The [`ChainSource`] trait — the ONE canonical, reads-only interface for consulting Chia chain
//! state, and [`ChainSourceProvider`], the self-describing form a registry composes.
//!
//! The trait is deliberately **synchronous and object-safe**: every method takes `&self` and
//! returns a plain `Result`, so `Box<dyn ChainSource<Error = _>>` works and an async backend can
//! present a blocking facade at the aggregator boundary (see the async->sync bridge note in the
//! crate docs). It is **reads-only** — there is NO broadcast/push/submit method anywhere in this
//! crate, by design (SPEC §1).

use chia_protocol::{Bytes32, CoinSpend};

use crate::lineage::SingletonLineage;
use crate::provider::ProviderInfo;
use crate::record::CoinRecord;

/// A reads-only view of Chia chain state — the single canonical contract every provider implements
/// and every consumer depends on.
///
/// ## Fail-closed `None` vs `Err` (the crux)
///
/// Every fallible method distinguishes two outcomes that consumers MUST treat differently:
/// - `Ok(None)` / an empty `Vec` — the source reliably answered and the thing genuinely does not
///   exist (an unlaunched singleton, an unspent coin, a melted lineage). Safe to act on.
/// - `Err(_)` — the source could NOT reliably answer (transport, timeout, malformed, unsupported).
///   The answer is unknown; the consumer MUST fail closed and never treat it as an absence.
///
/// ## Reads only
///
/// This trait cannot broadcast, push, or submit anything to the chain — there is no such method,
/// deliberately. It is a pure reader; write/spend paths live entirely outside this crate.
pub trait ChainSource {
    /// The source's own transport/parse error. [`crate::ChainSourceError`] is the recommended type
    /// for registry participants, but any `Display` error is accepted.
    type Error: core::fmt::Display;

    /// Reads the coin with id `coin_id`.
    ///
    /// `Ok(None)` = the coin genuinely does not exist per this source; `Err(_)` = could not answer.
    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error>;

    /// Reads all coins paying to `puzzle_hash`, optionally including already-spent coins.
    ///
    /// An empty `Vec` = no matching coins; `Err(_)` = could not answer.
    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error>;

    /// Reads all coins whose parent is `parent_coin_id` — the direct children created by spending
    /// that coin.
    ///
    /// An empty `Vec` = no known children; `Err(_)` = could not answer.
    fn coin_records_by_parent(
        &self,
        parent_coin_id: Bytes32,
    ) -> Result<Vec<CoinRecord>, Self::Error>;

    /// Reads the spend that SPENT `coin_id` (the spend whose input coin is `coin_id`).
    ///
    /// `Ok(None)` = `coin_id` is unspent or unknown; `Err(_)` = could not answer.
    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error>;

    /// Reads the spend that CREATED `coin_id` — i.e. the spend of `coin_id`'s parent — by resolving
    /// the coin's parent and reading that parent's spend. This is the **money-critical parent-walk
    /// primitive**.
    ///
    /// A coin's `puzzle_hash` is attacker-chosen: anyone can pay a coin whose puzzle hash equals a
    /// victim singleton's outer hash, so a bare `launcher_id ==` check is spoofable. Authenticating
    /// a coin as a genuine singleton requires walking `parent_spend` back toward the real launcher,
    /// where each hop is proven from the parent's actual reveal+solution. A spoofed curried-puzzle
    /// coin has no genuine recreation parent-spend, so the walk fails closed rather than trusting
    /// the cheap equality. Consumers MUST walk this primitive, never trust puzzle-hash equality.
    ///
    /// The default implementation composes [`coin_record`](Self::coin_record) +
    /// [`coin_spend`](Self::coin_spend); a source may override it with a direct query. `Ok(None)` =
    /// the parent is unspent/unknown (a gap → fail closed mid-walk); `Err(_)` = could not answer.
    fn parent_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        let Some(record) = self.coin_record(coin_id)? else {
            return Ok(None);
        };
        self.coin_spend(record.coin.parent_coin_info)
    }

    /// Resolves the singleton launched at `launcher_id` to its authenticated [`SingletonLineage`]
    /// (every coin id from launcher to current tip).
    ///
    /// This MUST be a genuine forward walk from the launcher to its tip — each coin the singleton
    /// recreation of the previous — NEVER an echo of a caller-supplied coin, or membership becomes
    /// meaningless (SPEC §4, the money-critical requirement). `Ok(None)` = the launcher never
    /// existed or the singleton has been fully melted; `Err(_)` = could not answer.
    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error>;

    /// Reads the current peak (fully-synced) block height, if the source tracks one.
    ///
    /// `Ok(None)` = the source does not expose a peak; `Err(_)` = could not answer.
    fn peak_height(&self) -> Result<Option<u32>, Self::Error>;

    /// Reads the Unix timestamp of the block at `height`.
    ///
    /// `Ok(None)` = no such block or no timestamp index; `Err(_)` = could not answer.
    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error>;
}

/// A [`ChainSource`] that describes itself to the aggregating registry.
///
/// The registry uses [`provider_info`](Self::provider_info) to order and trust-weight providers
/// (see [`ProviderInfo`]).
pub trait ChainSourceProvider: ChainSource {
    /// This provider's registration descriptor (identity, kind, priority, trust posture).
    fn provider_info(&self) -> ProviderInfo;
}
