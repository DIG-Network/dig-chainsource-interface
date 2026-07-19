//! Known-answer tests pinning the byte-level shapes this crate re-exports, so a provider or
//! consumer can rely on them without re-deriving. These are fixed vectors: any drift in coin-id
//! hashing or spend serialization would break them.

use chia_protocol::{Bytes32, Coin, CoinSpend, CoinState, Program};
use chia_traits::Streamable;
use dig_chainsource_interface::{CoinRecord, SingletonLineage};

/// A coin's id is `SHA-256` of its fields — pinned so downstream code can trust the hashing.
#[test]
fn coin_id_matches_pinned_vector() {
    let coin = Coin::new(
        Bytes32::new([0x11u8; 32]),
        Bytes32::new([0x22u8; 32]),
        1_000_000,
    );
    assert_eq!(
        hex::encode(coin.coin_id()),
        "a20457fc968660c1f5c053be6d76ba811aabe6625446d57e89b8524680d3178c",
    );
}

/// A `CoinSpend` streams to a pinned byte layout (coin || puzzle_reveal || solution).
#[test]
fn coin_spend_streams_to_pinned_bytes() {
    let coin = Coin::new(
        Bytes32::new([0x11u8; 32]),
        Bytes32::new([0x22u8; 32]),
        1_000_000,
    );
    let spend = CoinSpend::new(
        coin,
        Program::from(vec![0x01u8]),
        Program::from(vec![0x80u8]),
    );
    assert_eq!(
        hex::encode(spend.to_bytes().expect("spend serializes")),
        "1111111111111111111111111111111111111111111111111111111111111111\
         2222222222222222222222222222222222222222222222222222222222222222\
         00000000000f42400180",
    );
}

/// `CoinRecord::from(CoinState)` maps `created_height -> confirmed_height`, preserves `spent_height`,
/// and defaults the fields a `CoinState` cannot carry.
#[test]
fn coin_record_from_coin_state_maps_fields() {
    let coin = Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 42);
    let state = CoinState {
        coin,
        spent_height: Some(500),
        created_height: Some(400),
    };
    let record = CoinRecord::from(state);

    assert_eq!(record.coin, coin);
    assert_eq!(record.confirmed_height, Some(400));
    assert_eq!(record.spent_height, Some(500));
    assert_eq!(record.timestamp, None);
    assert!(!record.coinbase);
    assert!(record.is_spent());
}

/// `SingletonLineage` always carries its tip as a member, and membership — not tip-equality — is
/// the authority test.
#[test]
fn singleton_lineage_membership_invariants() {
    let launcher = Bytes32::new([1u8; 32]);
    let mid = Bytes32::new([2u8; 32]);
    let tip = Bytes32::new([3u8; 32]);
    let lineage = SingletonLineage::new(tip, [launcher, mid]);

    assert_eq!(lineage.tip(), tip);
    assert_eq!(lineage.len(), 3);
    assert!(lineage.contains(launcher));
    assert!(lineage.contains(tip));
    assert!(!lineage.contains(Bytes32::new([9u8; 32])));

    let single = SingletonLineage::single(tip);
    assert_eq!(single.len(), 1);
    assert!(single.contains(tip));
    assert!(!single.is_empty());
}
