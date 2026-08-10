//! The walk under a source that never stops answering (needs `--features lineage-walk,testing`).
//!
//! A cycle guard catches only a REPEATED coin. A hostile source can instead serve an unbounded,
//! ever-advancing chain of DISTINCT recreations — every hop structurally valid, every coin new — and
//! nothing in a hop-count cap bounds the WALL-CLOCK time or the CLVM memory that costs. [`ChainSource`]
//! is synchronous, so a walk that runs long blocks its caller's thread; inside `dig-app` that thread is
//! carrying a real-money mint ceremony.
//!
//! [`HostileSource`] below is that adversary, built from real chia puzzles rather than stubs: a genuine
//! singleton launcher, a genuine curried singleton top layer, and an inner puzzle that recreates the
//! singleton at the SAME outer puzzle hash forever. Each hop therefore produces a coin the walk has
//! never seen, at zero network cost.

#![cfg(all(feature = "lineage-walk", feature = "testing"))]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;
use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::singleton::{SingletonArgs, SingletonSolution};
use chia_puzzle_types::{EveProof, Proof};
use chia_sdk_driver::SpendContext;
use clvm_utils::tree_hash;
use clvmr::serde::{node_from_bytes, node_to_bytes_backrefs};
use clvmr::{Allocator, NodePtr};
use dig_chainsource_interface::{
    walk_singleton_lineage_within, ChainSource, ChainSourceError, CoinRecord, LineageWalkError,
    SingletonLineage, WalkBounds,
};

/// The `c` (cons) CLVM operator.
const CONS: i64 = 4;
/// The `q` (quote) CLVM operator.
const QUOTE: i64 = 1;
/// The CLVM opcode for `CREATE_COIN`.
const CREATE_COIN: i64 = 51;
/// The environment path selecting the FIRST element of the solution.
const FIRST_SOLUTION_ARG: i64 = 2;
/// The serialization tag introducing a CLVM back-reference.
const BACKREF_TAG: u8 = 0xFE;

/// Re-serializes `program` in the compressed, back-reference-bearing form, preserving its tree hash.
fn compress(ctx: &mut SpendContext, program: &Program) -> Result<Program> {
    let node = node_from_bytes(ctx, program.as_ref())?;
    Ok(Program::from(node_to_bytes_backrefs(ctx, node)?))
}

/// A singleton inner puzzle that recreates the singleton at whatever inner puzzle hash its solution
/// names: `(c (c (q . 51) (c 2 (c (q . 1) ()))) ())`, i.e. it emits `((51 <solution[0]> 1))`.
///
/// Reading the recreation target from the SOLUTION rather than quoting it is what makes an endless
/// chain expressible at all. A puzzle that quoted its own tree hash could not exist — the hash would
/// have to be known before the puzzle containing it was built — so a self-perpetuating singleton
/// needs the hash supplied from outside, exactly as this one does.
fn endless_inner_puzzle(ctx: &mut SpendContext) -> Result<NodePtr> {
    let quoted_amount = ctx.alloc(&(QUOTE, QUOTE))?;
    let quoted_opcode = ctx.alloc(&(QUOTE, CREATE_COIN))?;
    let cons = ctx.alloc(&CONS)?;
    let target = ctx.alloc(&FIRST_SOLUTION_ARG)?;

    let amount_tail = ctx.alloc(&vec![cons, quoted_amount, NodePtr::NIL])?;
    let arguments = ctx.alloc(&vec![cons, target, amount_tail])?;
    let condition = ctx.alloc(&vec![cons, quoted_opcode, arguments])?;
    Ok(ctx.alloc(&vec![cons, condition, NodePtr::NIL])?)
}

/// A [`ChainSource`] that serves an infinite, structurally valid singleton lineage.
///
/// Every coin it reports is genuinely derivable from the previous coin's spend, so no guard in the
/// walk can refuse it on its merits: the chain is not malformed, it is merely endless. Only a bound
/// stops it.
struct HostileSource {
    launcher: Coin,
    /// The outer puzzle hash every coin after the launcher wears. Constant by construction: the
    /// inner puzzle recreates itself, so the curry never changes.
    outer_puzzle_hash: Bytes32,
    launcher_reveal: Program,
    launcher_solution: Program,
    singleton_reveal: Program,
    singleton_solution: Program,
    /// Coins minted so far, extended lazily as the walk asks about them.
    known: RefCell<HashMap<Bytes32, Coin>>,
    /// The deepest coin minted so far — the point the chain grows from.
    frontier: RefCell<Coin>,
    /// Every primitive read the walk has performed, so a measurement can report reads alongside
    /// elapsed time.
    reads: Cell<usize>,
}

impl HostileSource {
    fn new(ctx: &mut SpendContext) -> Result<Self> {
        let launcher = Coin::new(
            Bytes32::new([0xA1; 32]),
            Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH),
            1,
        );
        let launcher_id = launcher.coin_id();

        let inner = endless_inner_puzzle(ctx)?;
        let inner_puzzle_hash = Bytes32::from(tree_hash(ctx, inner));
        let singleton = ctx.curry(SingletonArgs::new(launcher_id, inner))?;
        let outer_puzzle_hash = Bytes32::from(tree_hash(ctx, singleton));

        let inner_solution = ctx.alloc(&vec![inner_puzzle_hash])?;
        let singleton_solution = ctx.alloc(&SingletonSolution {
            // The walk never inspects the lineage proof — it authenticates by DERIVING the successor,
            // not by trusting a proof — so any well-formed proof serves here.
            lineage_proof: Proof::Eve(EveProof {
                parent_parent_coin_info: launcher.parent_coin_info,
                parent_amount: 1,
            }),
            amount: 1,
            inner_solution,
        })?;
        let launcher_reveal =
            ctx.alloc(&Program::from(chia_puzzles::SINGLETON_LAUNCHER.to_vec()))?;
        let launcher_solution =
            ctx.alloc(&(outer_puzzle_hash, (1, (Vec::<Bytes32>::new(), ()))))?;

        let eve = Coin::new(launcher_id, outer_puzzle_hash, 1);
        Ok(Self {
            launcher,
            outer_puzzle_hash,
            launcher_reveal: ctx.serialize(&launcher_reveal)?,
            launcher_solution: ctx.serialize(&launcher_solution)?,
            singleton_reveal: ctx.serialize(&singleton)?,
            singleton_solution: ctx.serialize(&singleton_solution)?,
            known: RefCell::new(HashMap::from([(eve.coin_id(), eve)])),
            frontier: RefCell::new(eve),
            reads: Cell::new(0),
        })
    }

    /// Re-serializes both puzzle reveals in the COMPRESSED, back-reference-bearing form a full node
    /// emits, leaving every tree hash — and therefore every coin — unchanged.
    fn with_backref_compressed_reveals(mut self, ctx: &mut SpendContext) -> Result<Self> {
        self.singleton_reveal = compress(ctx, &self.singleton_reveal)?;
        assert!(
            self.singleton_reveal.as_ref().contains(&BACKREF_TAG),
            "the control is only load-bearing if the reveal really carries a back-reference"
        );
        self.launcher_reveal = compress(ctx, &self.launcher_reveal)?;
        Ok(self)
    }

    fn launcher_id(&self) -> Bytes32 {
        self.launcher.coin_id()
    }

    /// Resolves `coin_id`, minting one more generation if the walk has reached the frontier.
    ///
    /// The walk asks about coins strictly in order, so one extension always suffices; the loop is a
    /// guard against a caller that skips, not an expectation.
    fn coin(&self, coin_id: Bytes32) -> Option<Coin> {
        for _ in 0..2 {
            if let Some(coin) = self.known.borrow().get(&coin_id) {
                return Some(*coin);
            }
            let mut frontier = self.frontier.borrow_mut();
            let next = Coin::new(frontier.coin_id(), self.outer_puzzle_hash, 1);
            *frontier = next;
            self.known.borrow_mut().insert(next.coin_id(), next);
        }
        None
    }

    fn record(&self, coin: Coin) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height: Some(1),
            // Every coin is SPENT, so the walk never finds a tip and never stops of its own accord.
            spent_height: Some(2),
            timestamp: None,
            coinbase: false,
        }
    }
}

impl ChainSource for HostileSource {
    type Error = ChainSourceError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        self.reads.set(self.reads.get() + 1);
        if coin_id == self.launcher_id() {
            return Ok(Some(self.record(self.launcher)));
        }
        Ok(self.coin(coin_id).map(|coin| self.record(coin)))
    }

    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(Vec::new())
    }

    fn coin_records_by_parent(
        &self,
        _parent_coin_id: Bytes32,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(Vec::new())
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        self.reads.set(self.reads.get() + 1);
        if coin_id == self.launcher_id() {
            return Ok(Some(CoinSpend::new(
                self.launcher,
                self.launcher_reveal.clone(),
                self.launcher_solution.clone(),
            )));
        }
        Ok(self.coin(coin_id).map(|coin| {
            CoinSpend::new(
                coin,
                self.singleton_reveal.clone(),
                self.singleton_solution.clone(),
            )
        }))
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        dig_chainsource_interface::resolve_singleton_lineage_via_walk(self, launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(None)
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }
}

/// The fixture is only adversarial if the chain really is endless and really is well formed — an
/// endless source the walk refuses on the FIRST hop would make every bound below vacuous.
#[test]
fn the_hostile_chain_is_genuinely_endless_and_genuinely_well_formed() -> Result<()> {
    let ctx = &mut SpendContext::new();
    let source = HostileSource::new(ctx)?;

    // A hop cap far above any plausible refusal-on-the-first-hop still ends in TooDeep, so the walk
    // really did follow 64 valid recreations rather than tripping a guard.
    let error = walk_singleton_lineage_within(&source, source.launcher_id(), WalkBounds::hops(64))
        .expect_err("an endless chain never reaches a tip");
    assert_eq!(error, LineageWalkError::TooDeep { limit: 64 });
    Ok(())
}

/// The hop cap alone bounds neither elapsed time nor memory, so the walk carries a WALL-CLOCK budget.
///
/// This is the defense `chia-query`'s walk calls its PRIMARY one, and the reason is arithmetic: at
/// the 100,000-hop default and 20 ms per read, a source that simply keeps answering holds the calling
/// thread for the better part of an hour. `ChainSource` is synchronous, so that is a hang, not a
/// slow query.
#[test]
fn an_endless_chain_is_refused_on_the_wall_clock_budget() -> Result<()> {
    let ctx = &mut SpendContext::new();
    let source = HostileSource::new(ctx)?;

    let budget = Duration::from_millis(50);
    let started = Instant::now();
    let error = walk_singleton_lineage_within(
        &source,
        source.launcher_id(),
        // The hop cap is left at its default so it CANNOT be what stops the walk: only the budget can.
        WalkBounds::default().within(budget),
    )
    .expect_err("an endless chain must not resolve");
    let elapsed = started.elapsed();

    assert_eq!(error, LineageWalkError::DeadlineExceeded { budget });
    assert!(
        elapsed < Duration::from_secs(10),
        "the budget must actually stop the walk; it ran for {elapsed:?}"
    );
    assert_eq!(
        ChainSourceError::from(error),
        ChainSourceError::Timeout,
        "running out of time is a timeout, distinct from malformed chain data and from too-deep"
    );
    Ok(())
}

/// The budget must not refuse an HONEST short walk — a bound tested only by what it rejects could be
/// satisfied by a walk that refuses everything.
#[test]
fn a_short_honest_walk_finishes_well_inside_its_budget() -> Result<()> {
    let ctx = &mut SpendContext::new();
    let source = HostileSource::new(ctx)?;

    // Four hops of the same endless chain, taken with a generous budget: the walk reaches the hop
    // cap, which proves it was the CAP and not the clock that stopped it.
    let error = walk_singleton_lineage_within(
        &source,
        source.launcher_id(),
        WalkBounds::hops(4).within(Duration::from_secs(30)),
    )
    .expect_err("four hops of an endless chain still exhaust the cap");
    assert_eq!(
        error,
        LineageWalkError::TooDeep { limit: 4 },
        "a generous budget must leave the hop cap in charge"
    );
    Ok(())
}

/// A measurement, not a gate: run with
/// `cargo test --release --features lineage-walk,testing --test hostile_lineage_walk -- --ignored
/// --nocapture` to re-measure the cost of the hostile chain at the DEFAULT hop bound.
///
/// # Why the per-hop allocator is not pinned by a RUNNING assertion
///
/// Exhausting the arena costs roughly a fixed number of CLVM pair allocations however the fixture is
/// shaped, so any test that observes the difference must pay it: ~6s in release and far longer in a
/// debug CI run. A peak-working-set assertion would be cheaper and is worse — peak working set is
/// monotonic per process, so a sibling test that had already raised it would make the delta zero and
/// the assertion vacuously green.
///
/// The reset is therefore pinned STRUCTURALLY instead: `successor_of` owns its allocator as a local,
/// so nothing above it holds one to hoist. Restoring the defect means changing that function's
/// signature and its call site, not deleting a line. This measurement is the empirical backstop, and
/// it compiles on every run so it cannot silently rot.
///
/// Measured on this fixture: **28.9 MB** peak and `TooDeep { limit: 100000 }` with the per-hop
/// allocator, against **276.5 MB** and `Malformed("too many pairs")` with it hoisted — the documented
/// hop bound unreachable, and the failure misattributed to the source.
#[test]
#[ignore = "a multi-second DoS measurement, not a correctness gate"]
fn measure_the_cost_of_the_default_hop_bound() -> Result<()> {
    let ctx = &mut SpendContext::new();
    let source = HostileSource::new(ctx)?;

    let started = Instant::now();
    let outcome = walk_singleton_lineage_within(
        &source,
        source.launcher_id(),
        // A budget large enough that the HOP cap is what ends the walk, so the measurement reports
        // the full cost of 100,000 hops rather than the cost of one deadline.
        WalkBounds::default().within(Duration::from_secs(3600)),
    );

    println!(
        "hops={} elapsed={:.2}s reads={} peak_working_set={:.1} MB outcome={:?}",
        dig_chainsource_interface::MAX_LINEAGE_DEPTH,
        started.elapsed().as_secs_f64(),
        source.reads.get(),
        peak_working_set_bytes() as f64 / (1024.0 * 1024.0),
        outcome
    );
    Ok(())
}

/// A CLVM **back-reference decompression bomb**: a few dozen bytes that decode into a `depth`-level
/// self-referential DAG, i.e. a tree of `2^depth` leaves.
///
/// Back-references are what make this expressible. The compressed serializer writes a repeated
/// subtree once and points at it thereafter, so consing a node with ITSELF `depth` times costs about
/// three bytes per level on the wire while doubling the notional tree at every level. A hash walk
/// that does not memoize therefore pays `2^depth` hash operations for an input a source can send for
/// free.
fn backref_bomb(depth: u32) -> Program {
    let mut allocator = Allocator::new();
    let mut node = allocator
        .new_atom(&[1])
        .expect("a one-byte atom always fits");
    for _ in 0..depth {
        node = allocator
            .new_pair(node, node)
            .expect("a self-cons adds one pair");
    }
    let bytes = node_to_bytes_backrefs(&allocator, node).expect("the DAG serializes");
    Program::from(bytes)
}

/// A source whose launcher record is honest and whose launcher SPEND is a decompression bomb.
///
/// This is the cheapest possible attack: the reveal-binding check at the top of the first hop must
/// hash the reveal BEFORE it can compare it, so a source that never owned a singleton and never
/// funded a coin can detonate on read.
struct BombSource {
    launcher: Coin,
    bomb: Program,
}

impl BombSource {
    fn at_depth(depth: u32) -> Self {
        Self {
            launcher: Coin::new(
                Bytes32::new([0xB0; 32]),
                Bytes32::new(chia_puzzles::SINGLETON_LAUNCHER_HASH),
                1,
            ),
            bomb: backref_bomb(depth),
        }
    }
}

impl ChainSource for BombSource {
    type Error = ChainSourceError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        if coin_id != self.launcher.coin_id() {
            return Ok(None);
        }
        Ok(Some(CoinRecord {
            coin: self.launcher,
            confirmed_height: Some(1),
            spent_height: Some(2),
            timestamp: None,
            coinbase: false,
        }))
    }

    fn coin_records_by_puzzle_hash(
        &self,
        _puzzle_hash: Bytes32,
        _include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(Vec::new())
    }

    fn coin_records_by_parent(
        &self,
        _parent_coin_id: Bytes32,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        Ok(Vec::new())
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        if coin_id != self.launcher.coin_id() {
            return Ok(None);
        }
        Ok(Some(CoinSpend::new(
            self.launcher,
            self.bomb.clone(),
            // NIL: the solution is never reached, because the reveal check refuses the spend first.
            Program::from(vec![0x80]),
        )))
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        dig_chainsource_interface::resolve_singleton_lineage_via_walk(self, launcher_id)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        Ok(None)
    }

    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }
}

/// A ~74-byte puzzle reveal must not cost minutes of CPU — the reveal hash must be MEMOIZED.
///
/// # Why this asserts on the clock and not only on the outcome
///
/// The bomb's hash cannot possibly equal the launcher's puzzle hash, so the walk refuses it either
/// way: the outcome is `Malformed` whether the hash took 151 µs or 140 seconds. Only elapsed time
/// distinguishes a memoizing hash from a non-memoizing one, so elapsed time is what is asserted.
///
/// # Why the wall-clock BUDGET does not cover this
///
/// The budget is checked at the top of each hop, before the spend is read. On the first iteration no
/// time has passed, so the check passes and the hop then runs unbounded — the budget bounds the
/// NUMBER of hops, never the cost of one.
///
/// Measured on this fixture at depth 24 (74 serialized bytes), debug: **140.4 s** with the
/// non-memoizing `clvm_utils::tree_hash`, **151 µs** with `tree_hash_from_bytes`. The threshold below
/// sits three orders of magnitude beneath the unfixed cost, so it cannot be met by a slow machine.
#[test]
fn a_backref_decompression_bomb_in_a_puzzle_reveal_is_hashed_in_bounded_time() -> Result<()> {
    let source = BombSource::at_depth(24);

    let started = Instant::now();
    let error = walk_singleton_lineage_within(
        &source,
        source.launcher.coin_id(),
        // A budget far larger than the threshold asserted below, so the BUDGET cannot be what makes
        // this test pass — if the hash were unbounded the walk would still be inside its first hop.
        WalkBounds::hops(4).within(Duration::from_secs(600)),
    )
    .expect_err("a reveal that does not hash to the coin's puzzle hash is refused");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, LineageWalkError::Malformed(ref message) if message.contains("puzzle reveal")),
        "the bomb is refused as a reveal that does not match the coin, not by any other guard: \
         {error:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "hashing a {}-byte reveal must be memoized; it took {elapsed:?}",
        source.bomb.as_ref().len()
    );
    Ok(())
}

/// The bomb must be refused because it is MEMOIZED, never because back-references were banned again.
///
/// Rejecting every back-reference would pass the test above while re-introducing the defect
/// `node_from_bytes_backrefs` was adopted to fix: a genuine compressed reveal — the form a full node
/// emits — read as malformed chain data. This is the honest control, and it uses the same
/// serializer the bomb does.
#[test]
fn a_genuinely_backref_compressed_reveal_is_still_accepted() -> Result<()> {
    let ctx = &mut SpendContext::new();
    let source = HostileSource::new(ctx)?.with_backref_compressed_reveals(ctx)?;

    // Reaching the hop cap means every reveal along the way HASHED to its coin's puzzle hash, so
    // the compressed form was read correctly rather than refused.
    let error = walk_singleton_lineage_within(
        &source,
        source.launcher_id(),
        WalkBounds::hops(4).within(Duration::from_secs(60)),
    )
    .expect_err("four hops of an endless chain still exhaust the cap");
    assert_eq!(
        error,
        LineageWalkError::TooDeep { limit: 4 },
        "a back-reference-compressed reveal must be accepted, not reported as malformed"
    );
    Ok(())
}

/// This process's peak working set, in bytes.
#[cfg(windows)]
fn peak_working_set_bytes() -> u64 {
    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    extern "system" {
        fn GetCurrentProcess() -> isize;
        fn K32GetProcessMemoryInfo(
            process: isize,
            counters: *mut ProcessMemoryCounters,
            size: u32,
        ) -> i32;
    }

    let mut counters = ProcessMemoryCounters {
        cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
        ..Default::default()
    };
    // SAFETY: `counters` is a live, correctly sized `PROCESS_MEMORY_COUNTERS` and the pseudo-handle
    // from `GetCurrentProcess` is always valid.
    unsafe {
        K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb);
    }
    counters.peak_working_set_size as u64
}

/// Peak working set is a Windows measurement; elsewhere the elapsed/reads figures still stand.
#[cfg(not(windows))]
fn peak_working_set_bytes() -> u64 {
    0
}
