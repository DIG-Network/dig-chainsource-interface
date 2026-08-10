//! Adversarial tests for the canonical singleton lineage walk (needs
//! `--features lineage-walk,testing`).
//!
//! The authentic cases run against REAL singleton spends produced by the in-process Chia simulator —
//! a genuine launcher, its eve, a recreation, and a melt — so the walk is exercised on chain data it
//! did not invent. The fail-closed cases use [`MockChainSource`], which can lie in ways a simulator
//! cannot.
//!
//! The load-bearing test is [`a_lookalike_coin_wearing_the_singleton_puzzle_hash_is_not_a_member`]:
//! a coin that genuinely exists on chain, genuinely wears the victim singleton's outer puzzle hash,
//! and genuinely has the same amount — but was created by an ordinary spend rather than by a
//! singleton recreation. Nothing about the coin itself distinguishes it from the real tip; only the
//! derivation does. A walk that recognised coins instead of deriving them would admit it.

#![cfg(all(feature = "lineage-walk", feature = "testing"))]

use std::cell::Cell;

use anyhow::Result;
use chia_bls::{PublicKey, SecretKey};
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::singleton::{SingletonArgs, SingletonSolution};
use chia_puzzle_types::{EveProof, LineageProof, Memos, Proof};
use chia_sdk_driver::{
    Launcher, Layer, SingletonLayer, Spend, SpendContext, SpendWithConditions, StandardLayer,
};
use chia_sdk_test::Simulator;
use chia_sdk_types::{Condition, Conditions};
use clvm_utils::TreeHash;
use dig_chainsource_interface::{
    walk_singleton_lineage, walk_singleton_lineage_bounded, ChainSource, ChainSourceError,
    CoinRecord, LineageWalkError, MockChainSource, SingletonLineage,
};

// ---------------------------------------------------------------------------------------------
// A chain view backed entirely by the real simulator.
// ---------------------------------------------------------------------------------------------

/// An honest [`ChainSource`] over the in-process simulator: every read is answered from real
/// simulated chain state, so nothing in these fixtures is hand-forged.
struct SimSource<'a> {
    sim: &'a Simulator,
    /// How many times the walk consulted [`ChainSource::coin_records_by_parent`]. A sound walk
    /// DERIVES its successor from the parent's own spend, so this must stay zero: any reliance on
    /// the child list hands a source the power to steer the lineage (see
    /// [`a_genuine_sibling_of_the_successor_is_not_selected_as_the_successor`]).
    children_reads: Cell<usize>,
    /// A coin whose SPEND this source withholds while still reporting the coin as spent — an
    /// otherwise honest source that has simply lost one spend (a pruned node, a partial index).
    withheld_spend: Option<Bytes32>,
    /// A coin whose RECORD this source withholds, so a derived successor cannot be bound to real
    /// chain state. Drives [`require_coin_exists`]'s guard.
    withheld_record: Option<Bytes32>,
}

impl ChainSource for SimSource<'_> {
    type Error = ChainSourceError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        if self.withheld_record == Some(coin_id) {
            return Ok(None);
        }
        Ok(self.sim.coin_state(coin_id).map(CoinRecord::from))
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(self
            .sim
            .unspent_coins(puzzle_hash, false)
            .into_iter()
            .filter_map(|coin| self.sim.coin_state(coin.coin_id()))
            .map(CoinRecord::from)
            .filter(|record| include_spent || !record.is_spent())
            .collect())
    }

    fn coin_records_by_parent(
        &self,
        parent_coin_id: Bytes32,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.children_reads.set(self.children_reads.get() + 1);
        Ok(self
            .sim
            .children(parent_coin_id)
            .into_iter()
            .map(CoinRecord::from)
            .collect())
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        if self.withheld_spend == Some(coin_id) {
            return Ok(None);
        }
        Ok(self.sim.coin_spend(coin_id))
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        // The helper under test is the whole point; delegating here proves the one-line body works.
        dig_chainsource_interface::resolve_singleton_lineage_via_walk(self, launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(None)
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------------------------
// Fixture construction: a real singleton, advanced by real spends.
// ---------------------------------------------------------------------------------------------

/// A live singleton in the simulator, tracked as the test advances it.
struct Singleton {
    launcher_id: Bytes32,
    /// Launcher -> ... -> tip, in walk order.
    trail: Vec<Coin>,
    proof: Proof,
    inner_puzzle_hash: Bytes32,
    pk: PublicKey,
    sk: SecretKey,
}

impl Singleton {
    fn tip(&self) -> Coin {
        *self.trail.last().expect("a launched singleton has a tip")
    }

    /// The full (singleton-wrapped) puzzle hash the singleton's coins wear.
    fn outer_puzzle_hash(&self) -> Bytes32 {
        SingletonArgs::curry_tree_hash(self.launcher_id, TreeHash::from(self.inner_puzzle_hash))
            .into()
    }
}

/// Launches a real singleton with a standard p2 inner puzzle and settles it, returning the launcher
/// coin, the eve coin, and everything needed to advance it.
fn launch(sim: &mut Simulator, ctx: &mut SpendContext) -> Result<Singleton> {
    launch_with_amount(sim, ctx, 1)
}

/// [`launch`] with a chosen singleton amount, so a spend can both recreate the singleton (an odd
/// amount) AND pay an even-amount decoy out of the same coin.
fn launch_with_amount(
    sim: &mut Simulator,
    ctx: &mut SpendContext,
    amount: u64,
) -> Result<Singleton> {
    let owner = sim.bls(amount);
    let launcher = Launcher::new(owner.coin.coin_id(), amount);
    let launcher_coin = launcher.coin();
    let (conditions, eve) = launcher.spend(ctx, owner.puzzle_hash, ())?;
    StandardLayer::new(owner.pk).spend(ctx, owner.coin, conditions)?;
    sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))?;

    Ok(Singleton {
        launcher_id: launcher_coin.coin_id(),
        trail: vec![launcher_coin, eve],
        proof: Proof::Eve(EveProof {
            parent_parent_coin_info: launcher_coin.parent_coin_info,
            parent_amount: launcher_coin.amount,
        }),
        inner_puzzle_hash: owner.puzzle_hash,
        pk: owner.pk,
        sk: owner.sk,
    })
}

/// Advances the singleton by one genuine recreation spend, appending the new tip to the trail.
fn advance(sim: &mut Simulator, ctx: &mut SpendContext, singleton: &mut Singleton) -> Result<()> {
    advance_paying(sim, ctx, singleton, singleton.tip().amount, None)
}

/// Advances the singleton, recreating it with `recreate_amount` and optionally paying an extra
/// even-amount coin to `decoy` out of the SAME spend — so the recreation gets a genuine sibling.
fn advance_paying(
    sim: &mut Simulator,
    ctx: &mut SpendContext,
    singleton: &mut Singleton,
    recreate_amount: u64,
    decoy: Option<(Bytes32, u64)>,
) -> Result<()> {
    let tip = singleton.tip();
    let sk = singleton.sk.clone();

    let mut conditions =
        Conditions::new().create_coin(singleton.inner_puzzle_hash, recreate_amount, Memos::None);
    if let Some((puzzle_hash, amount)) = decoy {
        conditions = conditions.create_coin(puzzle_hash, amount, Memos::None);
    }
    let inner = StandardLayer::new(singleton.pk).spend_with_conditions(ctx, conditions)?;
    let layer = SingletonLayer::new(singleton.launcher_id, StandardLayer::new(singleton.pk));
    let solution = SingletonSolution {
        lineage_proof: singleton.proof,
        amount: tip.amount,
        inner_solution: inner.solution,
    };
    let puzzle = layer.construct_puzzle(ctx)?;
    let solution = ctx.alloc(&solution)?;
    ctx.spend(tip, Spend::new(puzzle, solution))?;
    sim.spend_coins(ctx.take(), std::slice::from_ref(&sk))?;

    singleton.proof = Proof::Lineage(LineageProof {
        parent_parent_coin_info: tip.parent_coin_info,
        parent_inner_puzzle_hash: singleton.inner_puzzle_hash,
        parent_amount: tip.amount,
    });
    singleton.trail.push(Coin::new(
        tip.coin_id(),
        singleton.outer_puzzle_hash(),
        recreate_amount,
    ));
    Ok(())
}

fn source(sim: &Simulator) -> SimSource<'_> {
    SimSource {
        sim,
        children_reads: Cell::new(0),
        withheld_spend: None,
        withheld_record: None,
    }
}

// ---------------------------------------------------------------------------------------------
// The authentic walk.
// ---------------------------------------------------------------------------------------------

#[test]
fn walk_returns_every_coin_from_the_launcher_to_the_tip() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let mut singleton = launch(&mut sim, ctx)?;
    advance(&mut sim, ctx, &mut singleton)?;
    advance(&mut sim, ctx, &mut singleton)?;

    let src = source(&sim);
    let lineage = walk_singleton_lineage(&src, singleton.launcher_id)?
        .expect("a live singleton has a lineage");

    assert_eq!(lineage.tip(), singleton.tip().coin_id());
    assert_eq!(lineage.len(), singleton.trail.len());
    for coin in &singleton.trail {
        assert!(
            lineage.contains(coin.coin_id()),
            "genuine lineage coin {} is missing",
            coin.coin_id()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// THE ADVERSARIAL TEST.
// ---------------------------------------------------------------------------------------------

/// A coin that exists on chain, wears the victim singleton's exact outer puzzle hash, and carries
/// the same amount — but was created by an ordinary payment, not by a singleton recreation.
///
/// Nothing observable about the coin distinguishes it from the genuine tip, so this is precisely the
/// fixture a walk that RECOGNISES coins (by puzzle hash, by curried launcher id, or by picking a
/// plausible child) cannot survive. It must be neither a member nor the tip.
#[test]
fn a_lookalike_coin_wearing_the_singleton_puzzle_hash_is_not_a_member() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let mut singleton = launch(&mut sim, ctx)?;
    advance(&mut sim, ctx, &mut singleton)?;

    // An unrelated party pays 1 mojo to the victim singleton's outer puzzle hash.
    let attacker = sim.bls(1);
    let spoofed_puzzle_hash = singleton.outer_puzzle_hash();
    StandardLayer::new(attacker.pk).spend(
        ctx,
        attacker.coin,
        Conditions::new().create_coin(spoofed_puzzle_hash, 1, Memos::None),
    )?;
    sim.spend_coins(ctx.take(), std::slice::from_ref(&attacker.sk))?;
    let spoof = Coin::new(attacker.coin.coin_id(), spoofed_puzzle_hash, 1);

    // The spoof really is on chain and really does wear the singleton's puzzle hash.
    assert!(sim.coin_state(spoof.coin_id()).is_some());
    assert_eq!(spoof.puzzle_hash, singleton.tip().puzzle_hash);
    assert_ne!(spoof.coin_id(), singleton.tip().coin_id());

    let src = source(&sim);
    let lineage = walk_singleton_lineage(&src, singleton.launcher_id)?.expect("live singleton");

    assert!(
        !lineage.contains(spoof.coin_id()),
        "a look-alike coin with no genuine recreation parent-spend was admitted"
    );
    assert_eq!(lineage.tip(), singleton.tip().coin_id());
    Ok(())
}

/// The walk must not be steerable by a look-alike that is a GENUINE SIBLING of the real successor
/// — the nearest wrong implementation picks the successor out of
/// [`ChainSource::coin_records_by_parent`].
///
/// The singleton spend here recreates itself (odd amount 3) and, out of the SAME coin, pays a decoy
/// (even amount 2) wearing the successor's EXACT full puzzle hash. So the parent has two children
/// with identical puzzle hashes, and a child-selecting walk has nothing to choose between them. A
/// derivation has: only one of the two is the coin the parent's own solution creates as its odd
/// continuation.
#[test]
fn a_genuine_sibling_of_the_successor_is_not_selected_as_the_successor() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let mut singleton = launch_with_amount(&mut sim, ctx, 5)?;

    let successor_puzzle_hash = singleton.outer_puzzle_hash();
    let eve = singleton.tip();
    advance_paying(
        &mut sim,
        ctx,
        &mut singleton,
        3,
        Some((successor_puzzle_hash, 2)),
    )?;
    let decoy = Coin::new(eve.coin_id(), successor_puzzle_hash, 2);

    // The fixture is only distinguishing if the decoy really is a sibling wearing the same hash.
    let src = source(&sim);
    let children = src.coin_records_by_parent(eve.coin_id())?;
    assert_eq!(children.len(), 2, "the successor must have a real sibling");
    assert!(children
        .iter()
        .all(|child| child.coin.puzzle_hash == successor_puzzle_hash));
    assert!(sim.coin_state(decoy.coin_id()).is_some());

    src.children_reads.set(0);
    let lineage = walk_singleton_lineage(&src, singleton.launcher_id)?.expect("live singleton");
    assert_eq!(lineage.tip(), singleton.tip().coin_id());
    assert!(
        !lineage.contains(decoy.coin_id()),
        "an even-amount sibling wearing the successor's puzzle hash was admitted"
    );
    // The outcome above is order-dependent for a child-selecting walk — it could pick the genuine
    // successor by luck. This is the assertion that is NOT: a sound walk never asks for the child
    // list at all, so no ordering, and no source, can steer it.
    assert_eq!(
        src.children_reads.get(),
        0,
        "the walk consulted the child list, so a source could choose its successor"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Three-valued discipline: absence vs unreadable vs unsupported.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unknown_launcher_is_a_genuine_absence() -> Result<()> {
    let sim = Simulator::new();
    let src = source(&sim);
    assert_eq!(
        walk_singleton_lineage(&src, Bytes32::new([0x11; 32]))?,
        None
    );
    Ok(())
}

#[test]
fn a_coin_that_is_not_a_launcher_is_a_genuine_absence() -> Result<()> {
    let mut sim = Simulator::new();
    let ordinary = sim.bls(1);
    let src = source(&sim);
    assert_eq!(
        walk_singleton_lineage(&src, ordinary.coin.coin_id())?,
        None,
        "an ordinary coin's id names no singleton"
    );
    Ok(())
}

#[test]
fn a_transport_failure_is_never_reported_as_an_absent_lineage() {
    let source = MockChainSource::new().fail_with(ChainSourceError::Transport("socket".into()));
    let error = walk_singleton_lineage(&source, Bytes32::new([0x22; 32]))
        .expect_err("a read failure must not resolve");
    assert_eq!(
        error,
        LineageWalkError::Source(ChainSourceError::Transport("socket".into())),
        "the source's own error must survive the walk verbatim"
    );
}

#[test]
fn an_unsupported_read_stays_distinguishable_from_unreadable_and_from_absent() {
    let source = MockChainSource::new().fail_with(ChainSourceError::Unsupported("coin_record"));
    let projected: ChainSourceError = walk_singleton_lineage(&source, Bytes32::new([0x33; 32]))
        .expect_err("unsupported is not an absence")
        .into();
    assert_eq!(projected, ChainSourceError::Unsupported("coin_record"));
    assert_ne!(projected, ChainSourceError::Malformed("coin_record".into()));
}

#[test]
fn a_melted_singleton_has_no_lineage() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let mut singleton = launch(&mut sim, ctx)?;

    // Melt: spend the eve emitting NO odd-amount successor.
    let tip = singleton.tip();
    let sk = singleton.sk.clone();
    // A melt is an odd-amount CREATE_COIN with the singleton melt marker (-113), which the top
    // layer turns into an ORDINARY coin — so the singleton emits no successor and ceases to exist.
    let melt = ctx.alloc(&(51, (singleton.inner_puzzle_hash, (-113, ()))))?;
    let inner = StandardLayer::new(singleton.pk)
        .spend_with_conditions(ctx, Conditions::new().with(Condition::Other(melt)))?;
    let layer = SingletonLayer::new(singleton.launcher_id, StandardLayer::new(singleton.pk));
    let puzzle = layer.construct_puzzle(ctx)?;
    let solution = ctx.alloc(&SingletonSolution {
        lineage_proof: singleton.proof,
        amount: tip.amount,
        inner_solution: inner.solution,
    })?;
    ctx.spend(tip, Spend::new(puzzle, solution))?;
    sim.spend_coins(ctx.take(), std::slice::from_ref(&sk))?;

    singleton.trail.push(tip);
    let src = source(&sim);
    assert_eq!(walk_singleton_lineage(&src, singleton.launcher_id)?, None);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Bounds and lying sources.
// ---------------------------------------------------------------------------------------------

/// The bound must be a REFUSAL, not a truncation: a partial member set would answer `false` for
/// genuine members, which is a fail-open membership answer on a money path.
#[test]
fn exceeding_the_hop_bound_refuses_rather_than_truncating() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let mut singleton = launch(&mut sim, ctx)?;
    advance(&mut sim, ctx, &mut singleton)?;
    advance(&mut sim, ctx, &mut singleton)?;

    let src = source(&sim);

    // The chain is launcher -> eve -> C2 -> C3, i.e. exactly THREE spends. One under the bound must
    // refuse rather than return the first three coins as if they were the whole lineage.
    assert_eq!(singleton.trail.len(), 4);
    let error = walk_singleton_lineage_bounded(&src, singleton.launcher_id, 2)
        .expect_err("an over-deep walk must not resolve");
    assert_eq!(error, LineageWalkError::TooDeep { limit: 2 });
    assert_eq!(
        ChainSourceError::from(error),
        ChainSourceError::LineageTooDeep { limit: 2 },
        "the over-deep refusal must stay distinguishable from every other failure"
    );

    // AT the bound it resolves — a limit pinned only from below could only confirm itself.
    let lineage = walk_singleton_lineage_bounded(&src, singleton.launcher_id, 3)?
        .expect("the walk completes at exactly the bound");
    assert_eq!(lineage.tip(), singleton.tip().coin_id());
    Ok(())
}

#[test]
fn a_spend_of_the_wrong_coin_fails_closed() {
    let launcher_ph = Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH);
    let launcher = Coin::new(Bytes32::new([0x01; 32]), launcher_ph, 1);
    let other = Coin::new(Bytes32::new([0x02; 32]), launcher_ph, 1);

    let source = MockChainSource::new()
        .with_coin(launcher.coin_id(), record(launcher))
        .with_spend(
            launcher.coin_id(),
            CoinSpend::new(other, Program::from(vec![0x01]), Program::from(vec![0x80])),
        );

    let error = walk_singleton_lineage(&source, launcher.coin_id())
        .expect_err("a mismatched spend must fail closed");
    assert!(matches!(error, LineageWalkError::Malformed(_)));
}

#[test]
fn a_reveal_that_does_not_hash_to_the_coin_fails_closed() {
    let launcher_ph = Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH);
    let launcher = Coin::new(Bytes32::new([0x03; 32]), launcher_ph, 1);

    // `(q . ())` is a valid program, but it is not the launcher puzzle, so it cannot hash to the
    // launcher puzzle hash — the source is passing off someone else's reveal.
    let source = MockChainSource::new()
        .with_coin(launcher.coin_id(), record(launcher))
        .with_spend(
            launcher.coin_id(),
            CoinSpend::new(
                launcher,
                Program::from(vec![0x01, 0x80]),
                Program::from(vec![0x80]),
            ),
        );

    let error = walk_singleton_lineage(&source, launcher.coin_id())
        .expect_err("a foreign reveal must fail closed");
    assert!(matches!(error, LineageWalkError::Malformed(_)));
}

/// A launcher coin that was never spent has minted no eve, so there is no singleton state yet.
#[test]
fn an_unspent_launcher_has_no_singleton_state() {
    let launcher_ph = Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH);
    let launcher = Coin::new(Bytes32::new([0x04; 32]), launcher_ph, 1);
    let source = MockChainSource::new().with_coin(launcher.coin_id(), record(launcher));

    assert_eq!(
        walk_singleton_lineage(&source, launcher.coin_id()),
        Ok(None)
    );
}

/// A launcher whose spend creates a NON-singleton eve: the launcher puzzle emits whatever
/// `CREATE_COIN` its solution names, so a launcher can perfectly well create an ordinary coin.
///
/// The eve then exists, is genuinely the launcher's child, and is genuinely spendable — and is still
/// not a singleton. Only parsing the eve's own reveal as a singleton layer can tell, which is why
/// the walk does exactly that rather than trusting the launcher's word.
#[test]
fn an_eve_that_is_not_a_singleton_fails_closed() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let owner = sim.bls(1);

    let launcher_coin = Coin::new(
        owner.coin.coin_id(),
        Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH),
        1,
    );
    StandardLayer::new(owner.pk).spend(
        ctx,
        owner.coin,
        Conditions::new().create_coin(launcher_coin.puzzle_hash, 1, Memos::None),
    )?;

    // Spend the launcher so it creates an ORDINARY standard coin rather than a singleton.
    let launcher_puzzle = ctx.alloc(&Program::from(chia_puzzles::SINGLETON_LAUNCHER.to_vec()))?;
    let launcher_solution = ctx.alloc(&(owner.puzzle_hash, (1, (Vec::<Bytes32>::new(), ()))))?;
    ctx.spend(
        launcher_coin,
        Spend::new(launcher_puzzle, launcher_solution),
    )?;
    sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))?;

    // Spend the fake eve so the walk reaches its reveal (an unspent coin would end the walk first).
    let fake_eve = Coin::new(launcher_coin.coin_id(), owner.puzzle_hash, 1);
    StandardLayer::new(owner.pk).spend(ctx, fake_eve, Conditions::new())?;
    sim.spend_coins(ctx.take(), std::slice::from_ref(&owner.sk))?;

    let src = source(&sim);
    let error = walk_singleton_lineage(&src, launcher_coin.coin_id())
        .expect_err("a non-singleton eve must not resolve to a lineage");
    assert_eq!(
        error,
        LineageWalkError::NotASingleton {
            coin_id: fake_eve.coin_id()
        }
    );
    Ok(())
}

#[test]
fn a_launcher_record_for_the_wrong_coin_fails_closed() {
    let launcher_ph = Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH);
    let asked_for = Coin::new(Bytes32::new([0x05; 32]), launcher_ph, 1);
    let returned = Coin::new(Bytes32::new([0x06; 32]), launcher_ph, 1);

    let source = MockChainSource::new().with_coin(asked_for.coin_id(), record(returned));

    let error = walk_singleton_lineage(&source, asked_for.coin_id())
        .expect_err("a record for a different coin must fail closed");
    assert!(matches!(error, LineageWalkError::Malformed(_)));
}

#[test]
fn every_failure_reports_itself_distinguishably() {
    let coin_id = Bytes32::new([0x07; 32]);
    let messages = [
        LineageWalkError::Source(ChainSourceError::Timeout).to_string(),
        LineageWalkError::<ChainSourceError>::Malformed("bad".into()).to_string(),
        LineageWalkError::<ChainSourceError>::NotASingleton { coin_id }.to_string(),
        LineageWalkError::<ChainSourceError>::TooDeep { limit: 9 }.to_string(),
    ];
    assert!(messages.iter().all(|message| !message.is_empty()));
    assert_eq!(
        messages
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        messages.len(),
        "each failure must read differently in a log"
    );

    assert_eq!(
        ChainSourceError::from(LineageWalkError::<ChainSourceError>::NotASingleton { coin_id }),
        ChainSourceError::Malformed(format!(
            "coin {coin_id} is not a genuine singleton of this launcher"
        ))
    );
    assert_eq!(
        ChainSourceError::from(LineageWalkError::<ChainSourceError>::Malformed("x".into())),
        ChainSourceError::Malformed("x".into())
    );
}

// ---------------------------------------------------------------------------------------------
// A spend the source cannot serve is UNKNOWN, never a tip (the `Ok(None)` ambiguity).
// ---------------------------------------------------------------------------------------------

/// `ChainSource::coin_spend` returns `Ok(None)` for "unspent OR unknown", and only the coin's own
/// `spent_height` tells the two apart. A walk that conflates them reports the last coin it could
/// read as the unspent tip.
///
/// Here the chain is launcher -> eve -> C2 -> C3 and the source is honest about every coin's
/// record — it has simply lost C2's spend, as a pruned or partially-indexed node would. C2 is
/// therefore recorded as SPENT while its spend reads as absent. Answering `C2` as the tip would
/// assert that a superseded state is current; the walk must refuse instead.
#[test]
fn a_spent_coin_whose_spend_the_source_cannot_serve_is_never_reported_as_the_tip() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let mut singleton = launch(&mut sim, ctx)?;
    advance(&mut sim, ctx, &mut singleton)?;
    advance(&mut sim, ctx, &mut singleton)?;

    let stale = singleton.trail[2];
    let tip = singleton.tip();

    // The fixture only distinguishes anything if C2 really is spent and really is NOT the tip.
    let spent_state = sim.coin_state(stale.coin_id()).expect("C2 is on chain");
    assert!(
        spent_state.spent_height.is_some(),
        "C2 must be spent for the ambiguity to exist"
    );
    assert_ne!(stale.coin_id(), tip.coin_id());

    let mut src = source(&sim);
    src.withheld_spend = Some(stale.coin_id());

    let error = walk_singleton_lineage(&src, singleton.launcher_id)
        .expect_err("a spend the source cannot serve is an unknown, not a tip");
    assert!(
        matches!(error, LineageWalkError::Malformed(_)),
        "expected a refusal, got {error:?}"
    );

    // And the honest control: with the same source telling the whole truth, the walk resolves.
    let honest = source(&sim);
    assert_eq!(
        walk_singleton_lineage(&honest, singleton.launcher_id)?
            .expect("the honest chain resolves")
            .tip(),
        tip.coin_id(),
    );
    Ok(())
}

/// The same ambiguity at the LAUNCHER degrades an unknown into "this singleton never existed" —
/// the SPEC §3 violation, and the one that reads as a genuine absence rather than a stale tip.
#[test]
fn a_spent_launcher_whose_spend_the_source_cannot_serve_is_not_an_absence() {
    let launcher_ph = Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH);
    let launcher = Coin::new(Bytes32::new([0x08; 32]), launcher_ph, 1);

    let source = MockChainSource::new().with_coin(launcher.coin_id(), spent_record(launcher, 12));

    let error = walk_singleton_lineage(&source, launcher.coin_id())
        .expect_err("a spent launcher with no readable spend is unknown, not unlaunched");
    assert!(
        matches!(error, LineageWalkError::Malformed(_)),
        "expected a refusal, got {error:?}"
    );

    // The control: the SAME launcher recorded as UNSPENT is a genuine absence, so the refusal above
    // is driven by `spent_height`, not merely by the missing spend.
    let unspent = MockChainSource::new().with_coin(launcher.coin_id(), record(launcher));
    assert_eq!(
        walk_singleton_lineage(&unspent, launcher.coin_id()),
        Ok(None)
    );
}

// ---------------------------------------------------------------------------------------------
// The anti-lying-source guards, each pinned by a test that dies with it.
// ---------------------------------------------------------------------------------------------

/// SPEC §4a requirement 2: a derived successor must be bound to a real `coin_record`.
///
/// A solution is not committed to by the coin's puzzle hash, so a source that pairs a genuine
/// reveal with a fabricated solution can name any successor it likes. This fixture is the readable
/// half of that: the successor C2 is derived from a genuine spend, but the source does not admit
/// the coin exists. Deleting the existence check makes the walk sail past C2 to the real tip and
/// answer `Ok(Some(..))`, so this test is what keeps the check alive.
#[test]
fn a_derived_successor_the_source_does_not_know_fails_closed() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let mut singleton = launch(&mut sim, ctx)?;
    advance(&mut sim, ctx, &mut singleton)?;
    advance(&mut sim, ctx, &mut singleton)?;

    let unknown = singleton.trail[2];
    let mut src = source(&sim);
    src.withheld_record = Some(unknown.coin_id());

    let error = walk_singleton_lineage(&src, singleton.launcher_id)
        .expect_err("a successor the source does not know must fail closed");
    match error {
        LineageWalkError::Malformed(detail) => assert!(
            detail.contains(&unknown.coin_id().to_string()),
            "the refusal must name the unknown coin: {detail}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // The control: without the veil, the very same chain resolves to the real tip — so the failure
    // above is the guard biting, not a broken fixture.
    let honest = source(&sim);
    assert_eq!(
        walk_singleton_lineage(&honest, singleton.launcher_id)?
            .expect("the honest chain resolves")
            .tip(),
        singleton.tip().coin_id(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The documented return table, pinned.
// ---------------------------------------------------------------------------------------------

/// A launcher spent into an eve that is still UNSPENT resolves to a two-coin lineage whose tip is
/// the eve — even though the eve's own singleton structure cannot be proven until it is spent.
///
/// This is a deliberate, documented limitation, not an oversight: the launcher's `CREATE_COIN`
/// carries the eve's FULL puzzle hash, which is non-invertible, so nothing but the launcher's own
/// spender chose it. It fails closed with `NotASingleton` the moment the eve is spent. The test
/// exists so the documented behaviour is enforced rather than merely described.
#[test]
fn an_unspent_eve_is_the_tip_of_a_two_coin_lineage() -> Result<()> {
    let mut sim = Simulator::new();
    let ctx = &mut SpendContext::new();
    let singleton = launch(&mut sim, ctx)?;

    let eve = singleton.tip();
    assert!(
        sim.coin_spend(eve.coin_id()).is_none(),
        "the eve must be unspent for this to be the documented case"
    );

    let src = source(&sim);
    let lineage =
        walk_singleton_lineage(&src, singleton.launcher_id)?.expect("a freshly launched singleton");
    assert_eq!(lineage.tip(), eve.coin_id());
    assert_eq!(lineage.len(), 2);
    assert!(lineage.contains(singleton.launcher_id));
    Ok(())
}

fn record(coin: Coin) -> CoinRecord {
    CoinRecord {
        coin,
        confirmed_height: Some(1),
        spent_height: None,
        timestamp: None,
        coinbase: false,
    }
}

/// [`record`] for a coin the source reports as SPENT — the state no fixture could express while
/// `spent_height` was hardcoded to `None`.
fn spent_record(coin: Coin, spent_height: u32) -> CoinRecord {
    CoinRecord {
        spent_height: Some(spent_height),
        ..record(coin)
    }
}
