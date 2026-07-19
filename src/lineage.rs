//! [`SingletonLineage`] — the authenticated coin set of a Chia singleton, where authority is
//! **membership**, not tip-equality.
//!
//! A singleton (a DID, a DataStore, any Chia singleton) advances one coin per spend: launcher ->
//! `C1` -> `C2` -> ... -> tip. Any coin minted from a genuine lineage coin is rooted in that
//! singleton — minting one requires the singleton's key — while an attacker's look-alike coin is
//! never a member. So a consumer asks "is this coin IN the lineage?" ([`SingletonLineage::contains`]),
//! never "does this coin equal the tip?".
//!
//! This type is byte-coherent with dig-did's `SingletonLineage` so the two crates share one shape.

use std::collections::BTreeSet;

use chia_protocol::Bytes32;

/// The lineage of a Chia singleton: every coin id from the launcher spend forward to the current
/// unspent tip.
///
/// Authority is MEMBERSHIP in this set, not equality with the tip (see the module docs): a coin
/// launched from ANY genuine lineage coin is rooted in the singleton, while an attacker's coin —
/// never a member — is not. The [`contains`](Self::contains) test is the authority check consumers
/// rely on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingletonLineage {
    /// The current unspent singleton tip coin id (the singleton's current on-chain state handle).
    tip: Bytes32,
    /// Every coin id in the lineage (launcher -> tip inclusive). Always contains `tip`.
    members: BTreeSet<Bytes32>,
}

impl SingletonLineage {
    /// Builds a lineage from its `tip` and full member set. `tip` is always treated as a member, so
    /// a caller need not include it in `members` explicitly.
    pub fn new(tip: Bytes32, members: impl IntoIterator<Item = Bytes32>) -> Self {
        let mut members: BTreeSet<Bytes32> = members.into_iter().collect();
        members.insert(tip);
        Self { tip, members }
    }

    /// A degenerate single-coin lineage (the tip is the only member) — a singleton never spent
    /// since launch.
    pub fn single(tip: Bytes32) -> Self {
        Self::new(tip, [tip])
    }

    /// The current unspent singleton tip coin id.
    pub fn tip(&self) -> Bytes32 {
        self.tip
    }

    /// Whether `coin_id` is a genuine coin in this singleton's lineage — the authority membership
    /// test. A coin that is not a member is NOT rooted in this singleton.
    pub fn contains(&self, coin_id: Bytes32) -> bool {
        self.members.contains(&coin_id)
    }

    /// The number of coins in the lineage (launcher -> tip inclusive).
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the lineage has no members. Always `false` for a well-formed lineage (the tip is a
    /// member), but provided so `len`/`is_empty` stay consistent for lints and callers.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lineage_membership_includes_tip_and_ancestors() {
        let launcher = Bytes32::new([1u8; 32]);
        let cn = Bytes32::new([2u8; 32]);
        let tip = Bytes32::new([3u8; 32]);
        let lineage = SingletonLineage::new(tip, [launcher, cn]);

        assert!(lineage.contains(launcher));
        assert!(lineage.contains(cn));
        assert!(lineage.contains(tip));
        assert!(!lineage.contains(Bytes32::new([9u8; 32])));
        assert_eq!(lineage.tip(), tip);
        assert_eq!(lineage.len(), 3);
        assert!(!lineage.is_empty());
    }

    #[test]
    fn single_lineage_is_tip_only() {
        let tip = Bytes32::new([7u8; 32]);
        let lineage = SingletonLineage::single(tip);
        assert_eq!(lineage.len(), 1);
        assert!(lineage.contains(tip));
    }
}
