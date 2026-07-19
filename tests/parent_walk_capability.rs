//! Adversarial capability tests (needs `--features testing`).
//!
//! These prove the interface is *sufficient* to authenticate a singleton soundly and that every
//! adversarial class from the #1239 threat set fails CLOSED. The mini-walk below is a minimal
//! stand-in for a real consumer: it uses ONLY [`ChainSource::parent_spend`] and a local
//! terminal-launcher marker (NO SDK, NO puzzle parsing) — enough to show the interface enables the
//! genuine forward walk and forbids the spoofable shortcuts.

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use dig_chainsource_interface::{
    ChainSource, ChainSourceError, ChainSourceProvider, MockChainSource, SingletonLineage,
};

/// The sentinel puzzle hash marking a coin as a singleton launcher in these fixtures. A real
/// consumer proves this via the SDK's `SINGLETON_LAUNCHER_HASH`; here a marker keeps the test SDK-free.
const LAUNCHER_MARKER: [u8; 32] = [0xAAu8; 32];

/// A depth bound for the mini-walk — small so the DoS-guard test can trip it cheaply.
const MAX_HOPS: usize = 8;

/// The outcome of authenticating a coin as a genuine singleton by walking its parent spends.
#[derive(Debug, PartialEq, Eq)]
enum Authenticated {
    /// The walk reached a genuine launcher coin, yielding its authenticated launcher id.
    Launcher(Bytes32),
    /// The walk hit a gap (unspent/unknown parent) before a launcher — fail closed, not a singleton.
    NotASingleton,
    /// The walk exceeded [`MAX_HOPS`] — a DoS guard against a cyclic/unbounded parent chain.
    TooDeep,
}

/// Walks `parent_spend` from `coin_id` toward a launcher, using ONLY the interface primitive.
/// Read errors propagate verbatim (never degraded to a value); a mid-walk gap fails closed.
fn authenticate<S: ChainSource>(source: &S, coin_id: Bytes32) -> Result<Authenticated, S::Error> {
    let mut current = coin_id;
    for _ in 0..MAX_HOPS {
        let Some(spend) = source.parent_spend(current)? else {
            return Ok(Authenticated::NotASingleton);
        };
        let parent = spend.coin;
        if parent.puzzle_hash == Bytes32::new(LAUNCHER_MARKER) {
            return Ok(Authenticated::Launcher(parent.coin_id()));
        }
        current = parent.coin_id();
    }
    Ok(Authenticated::TooDeep)
}

/// Builds a coin whose id and metadata the mock can index.
fn coin(parent: Bytes32, puzzle_hash: [u8; 32], amount: u64) -> Coin {
    Coin::new(parent, Bytes32::new(puzzle_hash), amount)
}

/// Loads `coin` into the mock as both a coin record and the spend that created it (i.e. the spend
/// of its parent, keyed by parent id — the [`ChainSource::coin_spend`] contract the default
/// `parent_spend` composes).
fn record(coin: Coin) -> dig_chainsource_interface::CoinRecord {
    dig_chainsource_interface::CoinRecord {
        coin,
        confirmed_height: Some(1),
        spent_height: None,
        timestamp: None,
        coinbase: false,
    }
}

/// A spend of `parent` (its id keys the entry, so `parent_spend(child)` finds it via the child's
/// `parent_coin_info`).
fn spend_of(parent: Coin) -> CoinSpend {
    CoinSpend::new(
        parent,
        Program::from(vec![0x01u8]),
        Program::from(vec![0x80u8]),
    )
}

/// (1) THE MONEY TEST. A source that ECHOES a caller-supplied coin into a lineage that does not
/// contain the queried coin must fail the membership test — authority is membership, never an echo.
#[test]
fn echoed_foreign_lineage_fails_membership() {
    let launcher = Bytes32::new([0x01u8; 32]);
    let genuine_tip = Bytes32::new([0x02u8; 32]);
    let attacker_coin = Bytes32::new([0x66u8; 32]);

    // The source resolves the launcher to its GENUINE lineage — which does NOT include the
    // attacker's coin. A sound consumer's `contains` check is the authority test.
    let source = MockChainSource::new()
        .with_lineage(launcher, SingletonLineage::new(genuine_tip, [launcher]));

    let lineage = source
        .resolve_singleton_lineage(launcher)
        .expect("read ok")
        .expect("launcher exists");

    assert!(lineage.contains(genuine_tip));
    assert!(lineage.contains(launcher));
    assert!(
        !lineage.contains(attacker_coin),
        "an attacker coin is never a lineage member, so it holds no authority",
    );
}

/// (2) A coin whose puzzle hash merely EQUALS a singleton's outer hash has no genuine launcher
/// parent-spend, so the parent walk never reaches a launcher — the spoof is rejected.
#[test]
fn spoofed_curry_has_no_launcher_parent() {
    // A spoof coin exists, but there is NO spend that created it (no genuine parent chain).
    let spoof = coin(Bytes32::new([0x33u8; 32]), [0x22u8; 32], 1);
    let source = MockChainSource::new().with_coin(spoof.coin_id(), record(spoof));

    assert_eq!(
        authenticate(&source, spoof.coin_id()).expect("read ok"),
        Authenticated::NotASingleton,
        "a bare puzzle-hash match is not a singleton without a launcher parent-spend",
    );
}

/// (3) A launcher that never existed (or a fully melted singleton) resolves to `Ok(None)` — an
/// honest absence, not an error.
#[test]
fn melted_or_unlaunched_is_none() {
    let source = MockChainSource::new();
    let missing = Bytes32::new([0x44u8; 32]);
    assert_eq!(source.resolve_singleton_lineage(missing), Ok(None));
    assert_eq!(source.coin_record(missing), Ok(None));
}

/// (4) A gap mid-walk (a parent with no known creating spend) fails closed — the coin is NOT
/// authenticated, rather than being assumed genuine.
#[test]
fn parent_gap_fails_closed() {
    // child exists; its parent coin exists but has NO creating spend, so the walk gaps out.
    let parent = coin(Bytes32::new([0x55u8; 32]), [0x22u8; 32], 1);
    let child = coin(parent.coin_id(), [0x22u8; 32], 1);
    let source = MockChainSource::new()
        .with_coin(child.coin_id(), record(child))
        .with_coin(parent.coin_id(), record(parent));
    // Note: no spend loaded for `parent`, so `parent_spend(child)` -> coin_spend(parent) -> None.

    assert_eq!(
        authenticate(&source, child.coin_id()).expect("read ok"),
        Authenticated::NotASingleton,
    );
}

/// (5) A transport error propagates as `Err` and is NEVER degraded into a value or an absence.
#[test]
fn transport_error_propagates() {
    let source =
        MockChainSource::new().fail_with(ChainSourceError::Transport("backend down".into()));
    let any = Bytes32::new([0x77u8; 32]);

    assert_eq!(
        authenticate(&source, any),
        Err(ChainSourceError::Transport("backend down".into())),
    );
    assert!(source.coin_record(any).is_err());
    assert!(source.resolve_singleton_lineage(any).is_err());
}

/// (6) A cyclic parent chain (a coin whose parent-spend points back at itself) is bounded by the
/// hop limit and errors out rather than looping forever.
#[test]
fn over_deep_walk_is_bounded() {
    // A parent chain longer than MAX_HOPS, none of whose coins is a launcher. `parent_spend` links
    // each coin to the next via its `parent_coin_info`, so the walk descends the whole chain — and
    // the hop bound trips before it reaches the (deliberately absent) launcher, proving the DoS
    // guard bounds rather than loops.
    let ph = [0x22u8; 32];
    let depth = MAX_HOPS + 4;

    // Build the chain from the deepest ancestor up, so each coin's parent is the next one down.
    let mut chain = vec![coin(Bytes32::new([0xEEu8; 32]), ph, 1)];
    for _ in 1..depth {
        let child = coin(chain.last().unwrap().coin_id(), ph, 1);
        chain.push(child);
    }

    let mut source = MockChainSource::new();
    for link in &chain {
        source = source
            .with_coin(link.coin_id(), record(*link))
            .with_spend(link.coin_id(), spend_of(*link));
    }
    let start = chain.last().unwrap().coin_id();

    assert_eq!(
        authenticate(&source, start).expect("read ok"),
        Authenticated::TooDeep,
        "an over-long parent chain is bounded, not looped",
    );
}

/// The trait MUST be object-safe: a boxed dynamic source over the canonical error compiles.
#[test]
fn chain_source_is_object_safe() {
    let boxed: Box<dyn ChainSource<Error = ChainSourceError>> = Box::new(MockChainSource::new());
    let missing = Bytes32::new([0x00u8; 32]);
    assert_eq!(boxed.coin_record(missing), Ok(None));
    assert_eq!(boxed.peak_height(), Ok(None));
}

/// A provider reports its registration descriptor.
#[test]
fn provider_reports_info() {
    let source = MockChainSource::new().with_peak(42);
    let info = source.provider_info();
    assert_eq!(info.id.0.as_ref(), "mock");
    assert_eq!(source.peak_height(), Ok(Some(42)));
}
