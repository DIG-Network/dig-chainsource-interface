//! [`walk_singleton_lineage`] — the ONE canonical launcher → tip singleton walk, composed purely
//! from the [`ChainSource`] primitives (feature `lineage-walk`).
//!
//! ## Why this exists
//!
//! [`ChainSource::resolve_singleton_lineage`] is the only trait method with no default body, yet it
//! is the most trust-critical one: its result IS the authority set consumers test membership
//! against. A source backed only by primitive reads (`coin_record`, `coin_spend`, …) would
//! otherwise have to hand-roll money-critical singleton authentication, and a second hand-rolled
//! copy is a byte-drift bug waiting to happen. This module supplies the composition once, so such a
//! source's method body is a one-line delegation to
//! [`resolve_singleton_lineage_via_walk`].
//!
//! ## Why the walk, and why puzzle-hash equality is NOT enough (the soundness crux)
//!
//! A Chia coin's `puzzle_hash` is attacker-chosen: anyone can pay to a coin whose puzzle hash
//! equals a victim singleton's outer hash for a victim launcher. Such a coin is not a singleton —
//! it has no genuine recreation history — so a `launcher_id ==` or `puzzle_hash ==` check is
//! spoofable, and so is picking a "child that looks right" out of
//! [`ChainSource::coin_records_by_parent`].
//!
//! This walk therefore never *recognises* the next coin; it **derives** it. At each hop it reads
//! the current coin's own spend, proves the puzzle reveal hashes to that coin's puzzle hash, parses
//! the reveal as a singleton (reading the *curried* launcher id and re-checking it against the
//! launcher under resolution), RUNS the inner puzzle, and reconstructs the odd-amount successor's
//! full puzzle hash from the launcher id and the successor's inner puzzle hash. Only a coin the
//! chain provably created that way enters the lineage; a look-alike coin can never be admitted,
//! because admission is by construction rather than by comparison.
//!
//! ## Three-valued discipline
//!
//! - `Ok(None)` — no singleton state exists: the launcher id names no coin, names a coin that is
//!   not a launcher, was never spent into an eve, or the singleton has been fully melted.
//! - `Ok(Some(_))` — an authenticated lineage, launcher → tip inclusive.
//! - `Err(_)` — the walk could NOT answer (a source read failed, the chain data is inconsistent, or
//!   the hop bound was exceeded). NEVER collapsed into "no lineage": a caller that reads a
//!   transport failure as an absence is the class of bug that spends money twice.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::time::{Duration, Instant};

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::singleton::SingletonArgs;
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_driver::{Layer, Puzzle, SingletonLayer};
use chia_sdk_types::run_puzzle_with_cost;
use clvm_traits::FromClvm;
use clvm_utils::{tree_hash_from_bytes, TreeHash};
use clvmr::serde::node_from_bytes_backrefs;
use clvmr::{Allocator, NodePtr, SExp};

use crate::error::ChainSourceError;
use crate::lineage::SingletonLineage;
use crate::record::CoinRecord;
use crate::source::ChainSource;

/// The maximum number of SPENDS [`walk_singleton_lineage`] follows before failing closed with
/// [`LineageWalkError::TooDeep`].
///
/// A genuine singleton advances exactly one coin per spend, so the bound is exactly the number of
/// times the singleton may ever have been spent (a lineage of `n` coins has `n - 1` spends). A DID or DataStore under heavy use might accumulate
/// thousands of states over its lifetime, so the bound is deliberately generous — it is a DoS guard,
/// not a policy limit. Its purpose is that a hostile or malformed source cannot make the walk loop
/// forever or allocate without end: the member set is capped at this many `Bytes32`, i.e. ~3.2 MB.
///
/// # The canonical bound — depend on this constant, never re-declare the literal
///
/// This is the ecosystem's SINGLE source of truth for how deep a singleton lineage walk may go.
/// Every DIG crate that bounds such a walk MUST read it from here rather than declaring its own
/// `100_000`: two literals that must agree, with nothing enforcing it, drift the moment one is
/// tuned, and the two walks then disagree about what "too deep" means on a money path.
///
/// This crate is `00-foundation`, so every consumer sits strictly above it and the dependency is a
/// legal downward edge. Known re-declarations still to adopt it: `dig_did::resolve` and
/// `dig_evidence::MAX_LINEAGE_DEPTH`.
pub const MAX_LINEAGE_DEPTH: usize = 100_000;

/// The wall-clock budget an entire [`walk_singleton_lineage`] may consume.
///
/// # Why a hop cap is not enough
///
/// [`MAX_LINEAGE_DEPTH`] bounds how many spends the walk follows; it bounds neither the total time
/// nor the per-hop CLVM cost of following them. A hostile source that answers every hop with a
/// structurally valid, ever-advancing chain of DISTINCT recreations trips no guard — the cycle guard
/// sees no repeat and every hop authenticates — so it holds the walk for as long as it keeps
/// serving. [`ChainSource`] is SYNCHRONOUS, so that is the caller's thread: at the default hop bound
/// and 20 ms per read, an attacker buys the better part of an hour of hang, inside whatever ceremony
/// the caller was performing.
///
/// # What this budget actually guarantees
///
/// It is checked BETWEEN hops, never inside one, so it is a **backstop** rather than a hard
/// deadline: the walk returns after at most `budget + one worst-case hop`. That second term is only
/// meaningful because it is itself bounded — [`MAX_REVEAL_EXPANDED_BYTES`] caps what a hop may hash
/// and [`MAX_HOP_CLVM_COST`] caps what it may evaluate. Without those two, this budget bounds
/// nothing at all, because a single hop can be made arbitrarily expensive.
pub const DEFAULT_WALK_BUDGET: Duration = Duration::from_secs(45);

/// The CLVM cost ceiling for evaluating ONE spend's inner puzzle.
///
/// # Why not the block cost
///
/// `chia_sdk_types::run_puzzle` evaluates at `MAINNET_CONSTANTS.max_block_cost_clvm` — eleven
/// billion, a whole block — and a spend's SOLUTION is bound to nothing: the reveal-binding hash
/// commits the coin to its puzzle, but the source chooses the solution freely. One hop may therefore
/// legitimately burn an entire block's worth of evaluation, which makes
/// [`DEFAULT_WALK_BUDGET`]'s between-hops check a promise the walk cannot keep.
///
/// # Why this value
///
/// Measured cost of the puzzles a hop actually runs: the singleton launcher spend that opens every
/// lineage costs **11,932**, and a `p2_delegated_puzzle_or_hidden_puzzle` inner spend emitting one
/// recreation costs **18,092**. This ceiling is ~5,500x the larger of those and ~110x below a full
/// block, which leaves ample room for heavier inner layers (DID, NFT state + ownership + royalty,
/// vault member trees) while capping a hop's evaluation at roughly a tenth of a second.
///
/// A spend that exceeds it is reported as [`LineageWalkError::Malformed`], because the evaluator
/// reports cost exhaustion the same way it reports any other failure to run.
pub const MAX_HOP_CLVM_COST: u64 = 100_000_000;

/// How far, and for how long, a lineage walk may run before failing closed.
///
/// Both bounds are always present: [`WalkBounds::default`] is what [`walk_singleton_lineage`] uses,
/// so a provider whose `resolve_singleton_lineage` is a one-line delegation INHERITS the
/// denial-of-service guards rather than having to remember them.
///
/// # Why the fields are private
///
/// They are guards. Public fields make `WalkBounds { max_hops: usize::MAX, budget: Duration::MAX }`
/// a struct literal that disables both of them with nothing in the diff to signal it, and the
/// constructors below cannot be bypassed the same way: [`WalkBounds::hops`] CLAMPS to
/// [`MAX_LINEAGE_DEPTH`], so no caller can widen the walk past the ecosystem's canonical bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct WalkBounds {
    /// The maximum number of spends to follow ([`LineageWalkError::TooDeep`] beyond it).
    max_hops: usize,
    /// The wall-clock budget for the whole walk ([`LineageWalkError::DeadlineExceeded`] beyond it).
    budget: Duration,
}

impl Default for WalkBounds {
    fn default() -> Self {
        Self {
            max_hops: MAX_LINEAGE_DEPTH,
            budget: DEFAULT_WALK_BUDGET,
        }
    }
}

impl WalkBounds {
    /// The default bounds with a chosen hop cap, CLAMPED to [`MAX_LINEAGE_DEPTH`] — the form tests
    /// use to exercise [`LineageWalkError::TooDeep`] over a short chain.
    #[must_use]
    pub fn hops(max_hops: usize) -> Self {
        Self {
            max_hops: max_hops.min(MAX_LINEAGE_DEPTH),
            ..Self::default()
        }
    }

    /// These bounds with a chosen wall-clock budget.
    #[must_use]
    pub fn within(self, budget: Duration) -> Self {
        Self { budget, ..self }
    }

    /// The maximum number of spends this walk will follow.
    #[must_use]
    pub fn max_hops(self) -> usize {
        self.max_hops
    }

    /// The wall-clock budget for the whole walk.
    #[must_use]
    pub fn budget(self) -> Duration {
        self.budget
    }
}

/// Why a singleton lineage walk could not answer.
///
/// Every variant means **the walk does not know** — none of them means "there is no lineage", which
/// is `Ok(None)`. The source's own error is preserved verbatim in [`Source`](Self::Source) so a
/// caller can still distinguish *unsupported* from *unreadable* (the distinction the ecosystem's
/// fail-closed contract rests on); it is never flattened into a string by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LineageWalkError<E> {
    /// A [`ChainSource`] read failed. The source's own error, unmodified.
    Source(E),

    /// The chain data the source returned is internally inconsistent or undecodable — a spend that
    /// is not the spend of the coin it was asked for, a reveal that does not hash to the coin's
    /// puzzle hash, an unparseable puzzle, a derived successor the source does not know, or a
    /// repeated coin id (a cycle). The read is untrustworthy → fail closed.
    Malformed(String),

    /// A coin on the walk is not a genuine singleton for the launcher under resolution: its reveal
    /// does not parse as a singleton layer, or its curried launcher id names a different singleton.
    NotASingleton {
        /// The coin whose singleton structure could not be proven.
        coin_id: Bytes32,
    },

    /// A coin's puzzle reveal expands, once its CLVM back-references are unfolded, beyond
    /// [`MAX_REVEAL_EXPANDED_BYTES`] — so the walk will not authenticate it.
    ///
    /// Deliberately NOT [`Malformed`](Self::Malformed): the reveal may be entirely well-formed and
    /// may even hash to the coin's puzzle hash. It is refused for its SIZE, and a consumer that
    /// cannot tell "too big" from "corrupt" cannot tell a hostile source from a heavy one.
    RevealTooLarge {
        /// The coin whose reveal was refused.
        coin_id: Bytes32,
        /// The expanded-size bound the walk refused to exceed.
        limit: usize,
    },

    /// The walk exceeded its hop bound. The lineage found so far is INCOMPLETE and is deliberately
    /// discarded rather than returned as a truncated member set.
    TooDeep {
        /// The hop bound the walk refused to exceed.
        limit: usize,
    },

    /// The walk outlasted its wall-clock budget. Like [`TooDeep`](Self::TooDeep) the partial lineage
    /// is discarded; unlike it, nothing about the chain was necessarily wrong — the walk simply ran
    /// out of time, which is why it reports as a timeout rather than as inconsistent chain data.
    DeadlineExceeded {
        /// The budget the walk refused to exceed.
        budget: Duration,
    },
}

impl<E: fmt::Display> fmt::Display for LineageWalkError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "chain source read failed: {error}"),
            Self::Malformed(detail) => write!(f, "inconsistent chain data: {detail}"),
            Self::NotASingleton { coin_id } => {
                write!(
                    f,
                    "coin {coin_id} is not a genuine singleton of this launcher"
                )
            }
            Self::RevealTooLarge { coin_id, limit } => {
                write!(
                    f,
                    "the puzzle reveal of coin {coin_id} expands beyond the {limit}-byte bound"
                )
            }
            Self::TooDeep { limit } => {
                write!(f, "singleton lineage walk exceeded its {limit}-hop bound")
            }
            Self::DeadlineExceeded { budget } => {
                write!(
                    f,
                    "singleton lineage walk exceeded its {budget:?} wall-clock budget"
                )
            }
        }
    }
}

impl<E: fmt::Display + fmt::Debug> std::error::Error for LineageWalkError<E> {}

impl From<LineageWalkError<ChainSourceError>> for ChainSourceError {
    /// Projects a walk failure onto the shared error type, PRESERVING the source's own variant.
    ///
    /// A [`LineageWalkError::Source`] passes through unchanged, so an `Unsupported`/`Timeout`/
    /// `RateLimited` read stays distinguishable from a genuine data problem — flattening it to
    /// `Malformed` would erase exactly the distinction the fail-closed contract depends on.
    fn from(error: LineageWalkError<ChainSourceError>) -> Self {
        match error {
            LineageWalkError::Source(error) => error,
            LineageWalkError::Malformed(detail) => ChainSourceError::Malformed(detail),
            LineageWalkError::NotASingleton { coin_id } => ChainSourceError::Malformed(format!(
                "coin {coin_id} is not a genuine singleton of this launcher"
            )),
            // Size, not corruption — so it keeps its own variant rather than collapsing into
            // `Malformed`, which would accuse an honest source of serving bad data for the crime of
            // serving a big one.
            LineageWalkError::RevealTooLarge { limit, .. } => {
                ChainSourceError::RevealTooLarge { limit }
            }
            LineageWalkError::TooDeep { limit } => ChainSourceError::LineageTooDeep { limit },
            // A budget overrun is exactly what `Timeout` means — "the read did not complete within
            // the deadline, so whether an answer exists is unknown". Mapping it to `Malformed` would
            // accuse an honest source of serving bad data for the crime of being slow.
            LineageWalkError::DeadlineExceeded { .. } => ChainSourceError::Timeout,
        }
    }
}

/// Resolves `launcher_id`'s authenticated lineage for a source whose `Error` is the shared
/// [`ChainSourceError`] — the drop-in body for [`ChainSource::resolve_singleton_lineage`].
///
/// ```ignore
/// fn resolve_singleton_lineage(
///     &self,
///     launcher_id: Bytes32,
/// ) -> Result<Option<SingletonLineage>, Self::Error> {
///     resolve_singleton_lineage_via_walk(self, launcher_id)
/// }
/// ```
///
/// Semantics are exactly [`walk_singleton_lineage`]'s; only the error is projected (see the
/// [`From`] impl above, which preserves the source's own variant).
pub fn resolve_singleton_lineage_via_walk<S>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<Option<SingletonLineage>, ChainSourceError>
where
    S: ChainSource<Error = ChainSourceError>,
{
    walk_singleton_lineage(source, launcher_id).map_err(Into::into)
}

/// Walks the singleton launched at `launcher_id` forward to its current unspent tip, returning
/// every coin id on the walk as an authenticated [`SingletonLineage`].
///
/// This is a genuine forward walk: it starts at the launcher coin and derives each successive coin
/// from the previous coin's actual spend (see the module docs for why derivation, not recognition,
/// is the only sound construction). It never echoes a caller-supplied coin, and the caller supplies
/// nothing but the launcher id.
///
/// Bounded by [`WalkBounds::default`] — [`MAX_LINEAGE_DEPTH`] hops within [`DEFAULT_WALK_BUDGET`];
/// use [`walk_singleton_lineage_within`] to choose other bounds.
///
/// # Returns
///
/// | Case | Result |
/// |---|---|
/// | `launcher_id` names no coin | `Ok(None)` |
/// | it names a coin that is not a singleton launcher | `Ok(None)` |
/// | the launcher was never spent (no eve minted) | `Ok(None)` |
/// | the singleton was melted (a spend with no odd successor) | `Ok(None)` |
/// | the launcher minted an eve that is still unspent | `Ok(Some(lineage))`, launcher + eve (see below) |
/// | a live singleton | `Ok(Some(lineage))`, launcher → tip inclusive |
/// | a source read failed | `Err(LineageWalkError::Source(_))` |
/// | the chain data is inconsistent, incl. a spent coin whose spend the source cannot serve | `Err(LineageWalkError::Malformed(_))` |
/// | a coin is not a genuine singleton of this launcher | `Err(LineageWalkError::NotASingleton { .. })` |
/// | the hop bound was exceeded | `Err(LineageWalkError::TooDeep { .. })` |
/// | the wall-clock budget was exceeded | `Err(LineageWalkError::DeadlineExceeded { .. })` |
///
/// # The unspent eve (SPEC §4a)
///
/// An eve that has never been spent is admitted on its launcher's word alone: a launcher's
/// `CREATE_COIN` carries the eve's FULL puzzle hash, and the walk cannot yet parse a reveal to
/// confirm the eve really wears a singleton curried to this launcher. So a launcher spent into an
/// ordinary coin resolves to `Ok(Some(_))` with that coin as the tip, not `Ok(None)`.
///
/// This is sound rather than merely tolerated. The full hash is non-invertible, so only the
/// launcher's own spender could have chosen it — nothing an attacker supplies reaches this
/// decision. And it fails closed at the very next hop: the moment the eve is spent, its reveal is
/// parsed and a non-singleton yields [`LineageWalkError::NotASingleton`]. A consumer that needs a
/// *proven* singleton, rather than a launched one, must therefore require a tip beyond the eve.
pub fn walk_singleton_lineage<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>> {
    walk_singleton_lineage_within(source, launcher_id, WalkBounds::default())
}

/// [`walk_singleton_lineage`] with an explicit hop bound, at the default wall-clock budget.
///
/// Retained as the narrow, hop-only form; [`walk_singleton_lineage_within`] takes both bounds.
pub fn walk_singleton_lineage_bounded<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
    max_hops: usize,
) -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>> {
    walk_singleton_lineage_within(source, launcher_id, WalkBounds::hops(max_hops))
}

/// [`walk_singleton_lineage`] with explicit [`WalkBounds`].
///
/// Both bounds are exposed so each can be exercised over a short real chain with a tiny value,
/// rather than only by a fixture no test would build.
pub fn walk_singleton_lineage_within<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
    bounds: WalkBounds,
) -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>> {
    let started = Instant::now();
    let Some(launcher) = read_launcher_coin(source, launcher_id)? else {
        return Ok(None);
    };

    let mut members = BTreeSet::from([launcher_id]);
    let mut current = launcher.coin;
    // Carried alongside `current` because `coin_spend` answers `Ok(None)` for "unspent OR unknown";
    // only the coin's OWN record tells those apart (see [`read_spend_of`]).
    let mut current_spent_height = launcher.spent_height;
    // The launcher's own spend is structurally different from a singleton spend (its CREATE_COIN
    // already carries the eve's FULL puzzle hash), so the first hop obeys a different rule.
    let mut rule = HopRule::Launch;

    // `max_hops` counts SPENDS followed, so the loop runs one extra time: the final read is the one
    // that discovers the tip is unspent, and it follows no spend.
    for _hop in 0..=bounds.max_hops {
        if started.elapsed() > bounds.budget {
            return Err(LineageWalkError::DeadlineExceeded {
                budget: bounds.budget,
            });
        }

        let Some(spend) = read_spend_of(source, current, current_spent_height)? else {
            // An unspent coin is the tip — unless it is the launcher itself, in which case no
            // singleton state was ever minted.
            let at_launcher = matches!(rule, HopRule::Launch);
            return Ok((!at_launcher).then(|| SingletonLineage::new(current.coin_id(), members)));
        };

        let Some(successor) = successor_of(current, &spend, rule)? else {
            // The spend emitted no odd-amount successor: the singleton was melted, so it has no
            // current coin. A melt is a genuine absence, not a failure.
            return Ok(None);
        };

        // A solution is NOT committed to by a coin's puzzle hash, so a dishonest source could pair a
        // genuine reveal with a fabricated solution and steer the walk onto a coin the chain never
        // created. Requiring the derived successor to exist on chain binds every hop to real state.
        let record = require_coin_exists(source, successor)?;

        admit_member(&mut members, successor.coin_id())?;
        current = successor;
        current_spent_height = record.spent_height;
        rule = HopRule::Recreate { launcher_id };
    }

    Err(LineageWalkError::TooDeep {
        limit: bounds.max_hops,
    })
}

/// Which rule authenticates the hop about to be followed.
#[derive(Debug, Clone, Copy)]
enum HopRule {
    /// The LAUNCHER's own spend: its `CREATE_COIN` already carries the eve's FULL puzzle hash, and
    /// no reveal has yet been parsed as a singleton.
    Launch,
    /// A singleton spend: the reveal must parse as a singleton layer curried to this launcher, and
    /// the successor's puzzle hash is recomputed from it.
    Recreate { launcher_id: Bytes32 },
}

/// Derives the successor `spend` creates for `coin`, or `None` when the spend ends the lineage.
///
/// # Why the allocator is created HERE, once per hop
///
/// A [`clvmr::Allocator`] is an arena: it allocates monotonically and frees nothing until it is
/// dropped. An allocator hoisted outside the walk's loop therefore accumulates every hop's puzzle,
/// solution and evaluation for the whole walk, so a hostile source's ever-advancing chain buys
/// unbounded memory alongside unbounded time. Measured over the endless chain in
/// `tests/hostile_lineage_walk.rs`, hoisting the allocator costs **276.5 MB** of peak working set
/// against **28.9 MB** when each hop starts clean. Worse, the arena's own node ceiling is reached
/// well BEFORE [`MAX_LINEAGE_DEPTH`] is, so the hoisted walk never reaches its documented
/// [`LineageWalkError::TooDeep`] refusal and fails as [`LineageWalkError::Malformed`] instead —
/// accusing an honest source of serving inconsistent chain data when the truth is that the walk ran
/// out of room. A long-lived singleton with tens of thousands of states would be libelled the same
/// way.
///
/// Owning the allocator inside this function is what makes that unhoistable: nothing above it holds
/// one, so the per-hop reset cannot be quietly undone by moving a line.
fn successor_of<E>(
    coin: Coin,
    spend: &CoinSpend,
    rule: HopRule,
) -> Result<Option<Coin>, LineageWalkError<E>> {
    let allocator = &mut Allocator::new();
    let (puzzle, solution) = parse_spend(allocator, spend)?;
    match rule {
        HopRule::Launch => eve_created_by_launcher(allocator, coin, puzzle, solution),
        HopRule::Recreate { launcher_id } => {
            singleton_successor(allocator, coin, launcher_id, puzzle, solution)
        }
    }
}

/// Records `coin_id` as a lineage member, refusing a repeat.
///
/// Fused with the insertion on purpose: a cycle guard that can be deleted without also dropping the
/// member is a guard nothing protects, and the walk's completeness test only notices the missing
/// member. Written as one operation, weakening the refusal means editing this function, where the
/// unit test below sits.
fn admit_member<E>(
    members: &mut BTreeSet<Bytes32>,
    coin_id: Bytes32,
) -> Result<(), LineageWalkError<E>> {
    if members.insert(coin_id) {
        return Ok(());
    }
    Err(LineageWalkError::Malformed(format!(
        "coin {coin_id} repeats in the lineage (a cycle)"
    )))
}

/// Reads the launcher coin named by `launcher_id`, or `None` when no singleton was launched there.
///
/// A coin id that names nothing, or names a coin that is not wearing the well-known singleton
/// launcher puzzle, means the singleton genuinely does not exist — not that the read failed.
///
/// The whole record is returned, not just the coin: the walk needs `spent_height` to tell an
/// unspent launcher from one whose spend the source cannot serve.
fn read_launcher_coin<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<Option<CoinRecord>, LineageWalkError<S::Error>> {
    let Some(record) = source
        .coin_record(launcher_id)
        .map_err(LineageWalkError::Source)?
    else {
        return Ok(None);
    };
    if record.coin.coin_id() != launcher_id {
        return Err(LineageWalkError::Malformed(format!(
            "source returned coin {} for id {launcher_id}",
            record.coin.coin_id()
        )));
    }
    if record.coin.puzzle_hash != Bytes32::new(SINGLETON_LAUNCHER_HASH) {
        return Ok(None);
    }
    Ok(Some(record))
}

/// Reads the spend of `coin`, proving the returned spend really is that coin's and that its puzzle
/// reveal hashes to the coin's own puzzle hash. `spent_height` is `coin`'s own record field.
///
/// Both proofs defend against a lying source: without them, an attacker-supplied reveal could be
/// run in place of the coin's real puzzle and emit any successor it liked.
///
/// `Ok(None)` means the coin is genuinely UNSPENT, never merely that no spend came back.
/// [`ChainSource::coin_spend`] returns `Ok(None)` for "unspent **or unknown**", and the coin's own
/// `spent_height` is the only thing that separates them. Conflating the two lets an honest-looking
/// source that has simply lost a spend present a superseded coin as the current tip — and if the
/// lost spend was the MELT, a dead singleton would authenticate as live. A spent coin whose spend
/// cannot be served is a "could not answer", so it fails closed.
fn read_spend_of<S: ChainSource>(
    source: &S,
    coin: Coin,
    spent_height: Option<u32>,
) -> Result<Option<CoinSpend>, LineageWalkError<S::Error>> {
    let Some(spend) = source
        .coin_spend(coin.coin_id())
        .map_err(LineageWalkError::Source)?
    else {
        return match spent_height {
            Some(height) => Err(LineageWalkError::Malformed(format!(
                "coin {} is recorded as spent at height {height}, but the source served no spend \
                 for it",
                coin.coin_id()
            ))),
            None => Ok(None),
        };
    };
    if spend.coin != coin {
        return Err(LineageWalkError::Malformed(format!(
            "source returned a spend of coin {} when asked for {}",
            spend.coin.coin_id(),
            coin.coin_id()
        )));
    }
    // BEFORE the reveal is hashed, parsed or run. Every later use of these bytes — the binding hash
    // here, `Puzzle::parse`, the CLVM evaluator — is downstream of this guard, which is the only
    // placement that bounds all three (see `require_expandable_reveal`).
    require_expandable_reveal(coin.coin_id(), &spend.puzzle_reveal)?;
    let revealed = program_tree_hash(&spend.puzzle_reveal)?;
    if Bytes32::from(revealed) != coin.puzzle_hash {
        return Err(LineageWalkError::Malformed(format!(
            "puzzle reveal does not hash to the puzzle hash of coin {}",
            coin.coin_id()
        )));
    }
    Ok(Some(spend))
}

/// Requires `coin` to be known to the source, binding a derived successor to real chain state, and
/// returns that coin's record.
///
/// Equality is over the whole [`Coin`], so a source cannot satisfy the check with a different coin
/// that merely shares an id-shaped field. The record travels back to the caller because the next
/// hop needs its `spent_height` (see [`read_spend_of`]) — this is the same read either way, so
/// nothing extra is asked of the source.
fn require_coin_exists<S: ChainSource>(
    source: &S,
    coin: Coin,
) -> Result<CoinRecord, LineageWalkError<S::Error>> {
    source
        .coin_record(coin.coin_id())
        .map_err(LineageWalkError::Source)?
        .filter(|record| record.coin == coin)
        .ok_or_else(|| {
            LineageWalkError::Malformed(format!(
                "the spend claims to create coin {}, which the source does not know",
                coin.coin_id()
            ))
        })
}

/// Reconstructs the eve singleton a launcher spend creates.
///
/// A launcher's `CREATE_COIN` puzzle hash is already the eve's FULL (singleton-wrapped) puzzle hash,
/// so the eve is built directly from the condition. The eve's curried launcher id is not verifiable
/// here — it is proven at the NEXT hop, where the eve's own reveal is parsed as a singleton layer
/// and its curried launcher id is checked against the launcher under resolution.
fn eve_created_by_launcher<E>(
    allocator: &mut Allocator,
    launcher: Coin,
    puzzle: Puzzle,
    solution: NodePtr,
) -> Result<Option<Coin>, LineageWalkError<E>> {
    Ok(
        match run_for_continuation(allocator, puzzle.ptr(), solution)? {
            Continuation::Ends => None,
            Continuation::Recreates(puzzle_hash, amount) => {
                Some(Coin::new(launcher.coin_id(), puzzle_hash, amount))
            }
        },
    )
}

/// Reconstructs the exact singleton successor `parent` creates, or `None` when the spend melts the
/// singleton (no odd-amount child).
///
/// The successor's puzzle hash is COMPUTED from `launcher_id` and the successor's inner puzzle hash
/// — never read from an untrusted field — which is what makes the hop an authentication rather than
/// a comparison. `parent` must itself parse as a singleton curried to `launcher_id`, so a coin that
/// merely wears a matching puzzle hash cannot extend the lineage.
fn singleton_successor<E>(
    allocator: &mut Allocator,
    parent: Coin,
    launcher_id: Bytes32,
    puzzle: Puzzle,
    solution: NodePtr,
) -> Result<Option<Coin>, LineageWalkError<E>> {
    let layer = SingletonLayer::<Puzzle>::parse_puzzle(allocator, puzzle)
        .map_err(|error| LineageWalkError::Malformed(format!("undecodable puzzle: {error}")))?
        .filter(|layer| layer.launcher_id == launcher_id)
        .ok_or(LineageWalkError::NotASingleton {
            coin_id: parent.coin_id(),
        })?;

    let solution = SingletonLayer::<Puzzle>::parse_solution(allocator, solution)
        .map_err(|error| LineageWalkError::Malformed(format!("undecodable solution: {error}")))?;
    Ok(
        match run_for_continuation(allocator, layer.inner_puzzle.ptr(), solution.inner_solution)? {
            Continuation::Ends => None,
            Continuation::Recreates(inner_puzzle_hash, amount) => {
                let full =
                    SingletonArgs::curry_tree_hash(launcher_id, TreeHash::from(inner_puzzle_hash));
                Some(Coin::new(parent.coin_id(), full.into(), amount))
            }
        },
    )
}

/// The `CREATE_COIN` amount a singleton's inner puzzle emits to MELT the singleton: the top layer
/// turns that output into an ordinary coin instead of a singleton recreation, ending the lineage.
const SINGLETON_MELT_AMOUNT: i64 = -113;

/// What running a spend's puzzle says about the singleton's continuation.
#[derive(Debug)]
enum Continuation {
    /// The spend recreates the singleton as `(inner_or_full_puzzle_hash, amount)`.
    Recreates(Bytes32, u64),
    /// The spend melts the singleton (or emits no odd-amount child at all): the lineage ends here.
    Ends,
}

/// Runs `puzzle` against `solution` and reports whether the spend continues or ends the singleton.
///
/// Odd amount is the singleton's continuation marker: a singleton spend emits at most one
/// odd-amount child and that child is the recreated singleton. Even-amount children are ordinary
/// payments — a singleton spend may pay anyone — and are deliberately ignored.
///
/// The amount is decoded as a SIGNED integer on purpose. CLVM atoms carry no sign, so decoding the
/// melt marker `-113` into a `u64` silently yields `143`: an odd, positive amount that reads as a
/// perfectly ordinary recreation. A walk that made that mistake would invent a phantom successor
/// for every melted singleton instead of reporting the melt.
fn run_for_continuation<E>(
    allocator: &mut Allocator,
    puzzle: NodePtr,
    solution: NodePtr,
) -> Result<Continuation, LineageWalkError<E>> {
    // An EXPLICIT ceiling, not `run_puzzle`'s whole-block default: the solution is attacker-chosen
    // (only the reveal is hash-bound to the coin), so a hop's evaluation is bounded here or nowhere.
    let output = run_puzzle_with_cost(allocator, puzzle, solution, MAX_HOP_CLVM_COST, false)
        .map_err(|error| LineageWalkError::Malformed(format!("puzzle did not run: {error}")))?
        .1;
    let conditions = Vec::<NodePtr>::from_clvm(allocator, output).map_err(|error| {
        LineageWalkError::Malformed(format!("undecodable condition list: {error}"))
    })?;

    let mut recreation: Option<(Bytes32, u64)> = None;
    for condition in conditions {
        // Decode the OPCODE first and the arguments separately. Skipping a condition that fails to
        // decode as a whole would turn an unparseable CREATE_COIN — or one whose amount overflows
        // `i64` — into a silent "no successor", i.e. a phantom melt: the walk would stop early and
        // report a superseded coin as the tip. Once a condition is known to be a CREATE_COIN, an
        // argument list the walk cannot read is a refusal, never an omission.
        let Ok((opcode, arguments)) = ConditionHead::from_clvm(allocator, condition) else {
            continue;
        };
        if opcode != CREATE_COIN {
            continue;
        }
        let (puzzle_hash, (signed_amount, _memos)) =
            CreateCoinArguments::from_clvm(allocator, arguments).map_err(|error| {
                LineageWalkError::Malformed(format!("undecodable CREATE_COIN condition: {error}"))
            })?;

        // The AMOUNT decides what the puzzle hash has to be, so it is read first. A melt's puzzle
        // hash is canonically NIL and an odd recreation's is a 32-byte address; demanding 32 bytes
        // up front would refuse every melt standard tooling emits (see `CreateCoinArguments`).
        if signed_amount == SINGLETON_MELT_AMOUNT {
            return Ok(Continuation::Ends);
        }
        let amount = u64::try_from(signed_amount).map_err(|_| {
            LineageWalkError::Malformed(format!(
                "CREATE_COIN with the negative amount {signed_amount}, which is not the singleton \
                 melt marker {SINGLETON_MELT_AMOUNT}"
            ))
        })?;
        // Decoded BEFORE the parity skip, not after. Every non-melt CREATE_COIN addresses a real
        // coin, so an unreadable puzzle hash is inconsistent chain data whatever the amount's
        // parity; deferring this past the skip would quietly accept a malformed hash on an
        // even-amount payment, which is strictly less strict for no benefit.
        let puzzle_hash = Bytes32::from_clvm(allocator, puzzle_hash).map_err(|error| {
            LineageWalkError::Malformed(format!(
                "undecodable CREATE_COIN condition: recreation puzzle hash: {error}"
            ))
        })?;
        if amount % 2 == 0 {
            continue;
        }
        if recreation.is_some() {
            return Err(LineageWalkError::Malformed(
                "a singleton spend emitted more than one odd-amount child".to_string(),
            ));
        }
        recreation = Some((puzzle_hash, amount));
    }

    Ok(match recreation {
        Some((puzzle_hash, amount)) => Continuation::Recreates(puzzle_hash, amount),
        None => Continuation::Ends,
    })
}

/// The CLVM opcode for `CREATE_COIN`.
const CREATE_COIN: i64 = 51;

/// Any condition, split into its opcode and its still-undecoded arguments: `(opcode . arguments)`.
/// A condition whose opcode is not even an integer is not `CREATE_COIN` and is skipped.
type ConditionHead = (i64, NodePtr);

/// A `CREATE_COIN`'s arguments decoded with a SIGNED amount, so the melt marker survives (see
/// [`run_for_continuation`]): `(puzzle_hash, (amount, memos))`. Decoded only AFTER the opcode is
/// known to be `CREATE_COIN`, so a failure here is a refusal rather than a skip.
///
/// # Why the puzzle hash stays a raw [`NodePtr`] here
///
/// The canonical chia melt condition is `(51 () -113)` — a NIL puzzle hash. `chia_sdk_types`
/// declares it that way (`MeltSingleton { puzzle_hash: () if () }`), and it is what every melt
/// built by standard chia-wallet-sdk tooling carries. Demanding [`Bytes32`] as part of THIS decode
/// would therefore refuse the canonical melt outright, making any singleton melted with standard
/// tooling permanently unanswerable. The amount is the discriminant, so the hash is resolved only
/// once the amount proves the condition is an odd-amount recreation.
type CreateCoinArguments = (NodePtr, (i64, NodePtr));

/// Deserializes a spend's puzzle reveal and solution into `allocator`.
fn parse_spend<E>(
    allocator: &mut Allocator,
    spend: &CoinSpend,
) -> Result<(Puzzle, NodePtr), LineageWalkError<E>> {
    let puzzle = alloc(allocator, &spend.puzzle_reveal)?;
    let solution = alloc(allocator, &spend.solution)?;
    Ok((Puzzle::parse(allocator, puzzle), solution))
}

/// Deserializes a [`Program`] into an allocated [`NodePtr`], accepting CLVM **back-references**.
///
/// Back-references are the compressed serialization full nodes accept and block generators emit: a
/// repeated subtree is written once and pointed at thereafter, which a curried singleton puzzle
/// does heavily. [`Program`]'s own `ToClvm` uses the NON-backref reader, so allocating through it
/// makes a genuine compressed reveal unreadable — reported as [`LineageWalkError::Malformed`],
/// i.e. blaming an honest source for chain data the chain itself considers valid. `Program::run`
/// reads back-references for exactly this reason, and the walk matches it.
fn alloc<E>(allocator: &mut Allocator, program: &Program) -> Result<NodePtr, LineageWalkError<E>> {
    node_from_bytes_backrefs(allocator, program.as_ref())
        .map_err(|error| LineageWalkError::Malformed(format!("undecodable program: {error}")))
}

/// How many bytes a puzzle reveal may feed into SHA-256 once its CLVM back-references are
/// **expanded**, before the walk refuses to authenticate it.
///
/// # Why an EXPANDED-size bound, and not a bound on the serialized reveal
///
/// CLVM back-references are a compression: a repeated subtree is written once and pointed at
/// thereafter, so the bytes on the wire describe a shared DAG rather than a tree. Every consumer of
/// that DAG — the reveal-binding hash, `Puzzle::parse`, the CLVM evaluator — sees the TREE the DAG
/// unfolds into, and a `k`-level self-referential DAG unfolds into `2^k` nodes. The serialized size
/// is therefore no evidence at all about the cost of using it: measured through this crate's public
/// API, a **1,120-byte** reveal (a singleton curried around a 28-level self-cons) costs **75
/// seconds**, and each additional 3 bytes on the wire DOUBLES that. A byte-length cap large enough
/// for an honest singleton is orders of magnitude larger than the bomb, so it bounds nothing.
///
/// This bound is measured on the expansion instead, which is exactly the quantity the work is
/// proportional to (see [`expanded_hash_input_bytes`]). Amplification is then capped at 1 by
/// construction: no serialized size, at any depth, can buy more work than this.
///
/// # Why this value
///
/// Measured expansion of real reveals, curried from the canonical chia puzzles:
///
/// | reveal | serialized | expanded |
/// |---|---|---|
/// | `p2_delegated_puzzle_or_hidden_puzzle` alone | 291 B | 8.1 KB |
/// | `singleton(p2)` — the plainest singleton there is | 1.4 KB | 41.2 KB |
/// | `singleton(did_innerpuz(p2))`, empty metadata | 2.5 KB | 75.0 KB |
/// | `singleton(nft state + ownership + royalty)`, 8 long URIs | 6.3 KB | 136.5 KB |
/// | `singleton(did_innerpuz(p2))` carrying 8 KB of curried metadata | 34.5 KB | 632.7 KB |
///
/// 4 MiB is **30x** the heaviest realistic reveal there (the extravagant NFT) and **6.6x** the
/// deliberately absurd 8 KB-metadata DID, so the bound has room for singletons far heavier than
/// anything the ecosystem builds — the failure it must never produce is refusing an honest
/// singleton on a money path. At the same time it caps a hop's hashing at roughly two milliseconds,
/// which leaves [`DEFAULT_WALK_BUDGET`] the effective outer bound on the walk as a whole rather than
/// something reveal size can steer past.
///
/// It is a hostile-input guard, not a policy limit: a reveal beyond it is refused as
/// [`LineageWalkError::RevealTooLarge`], which says "too big to authenticate", never "malformed".
pub const MAX_REVEAL_EXPANDED_BYTES: usize = 4 * 1024 * 1024;

/// The number of bytes `clvm_utils::tree_hash` would feed into SHA-256 for the tree `root` expands
/// into, saturating at `limit + 1` so a bomb is detected rather than computed.
///
/// This is the CLVM tree-hash cost model, stated exactly: an atom contributes its `0x01` prefix
/// plus its own bytes, and a pair contributes its `0x02` prefix plus its two 32-byte child hashes.
/// Bounding it therefore bounds every downstream tree-hash of the same reveal — including the
/// NON-memoizing `clvm_utils::tree_hash` that `chia_sdk_driver::Puzzle::parse` performs, which no
/// cache protects and which is the site the 1,120-byte bomb above detonates.
///
/// Runs in time linear in the DAG (each distinct node is costed once, memoized by [`NodePtr`]), and
/// iteratively rather than recursively, because the DAG may be tens of thousands of levels deep.
fn expanded_hash_input_bytes(allocator: &Allocator, root: NodePtr, limit: usize) -> usize {
    /// One `0x01` prefix byte precedes an atom's own bytes.
    const ATOM_PREFIX: usize = 1;
    /// One `0x02` prefix byte precedes a pair's two 32-byte child hashes.
    const PAIR_COST: usize = 1 + 32 + 32;

    // One byte past the limit is enough to refuse, and clamping every partial sum here is what
    // keeps the doubling from ever being computed — or from overflowing `usize`.
    let ceiling = limit.saturating_add(1);

    enum Step {
        /// Cost this node, descending into it if it is an unseen pair.
        Cost(NodePtr),
        /// Both children of this pair are costed and on `costed`; combine them.
        Combine(NodePtr),
    }

    let mut sizes: HashMap<NodePtr, usize> = HashMap::new();
    let mut steps = vec![Step::Cost(root)];
    let mut costed: Vec<usize> = Vec::new();

    while let Some(step) = steps.pop() {
        match step {
            Step::Cost(node) => {
                if let Some(&known) = sizes.get(&node) {
                    costed.push(known);
                    continue;
                }
                match allocator.sexp(node) {
                    SExp::Atom => {
                        let size = ATOM_PREFIX
                            .saturating_add(allocator.atom_len(node))
                            .min(ceiling);
                        sizes.insert(node, size);
                        costed.push(size);
                    }
                    SExp::Pair(left, right) => {
                        steps.push(Step::Combine(node));
                        steps.push(Step::Cost(right));
                        steps.push(Step::Cost(left));
                    }
                }
            }
            Step::Combine(node) => {
                let (right, left) = (
                    costed.pop().expect("a pair's right child was costed first"),
                    costed.pop().expect("a pair's left child was costed first"),
                );
                let size = PAIR_COST
                    .saturating_add(left)
                    .saturating_add(right)
                    .min(ceiling);
                sizes.insert(node, size);
                costed.push(size);
            }
        }
    }

    costed
        .pop()
        .expect("the traversal leaves the root's cost on the stack")
}

/// Refuses a puzzle reveal whose expansion exceeds [`MAX_REVEAL_EXPANDED_BYTES`], BEFORE anything
/// hashes, parses or runs it.
///
/// # Why this runs first, and on its own allocator
///
/// The reveal-binding check is the first thing a hop does with attacker-supplied bytes, so every
/// later use of the reveal is downstream of it. Placing the bound here means the guard covers not
/// just the binding hash but `parse_spend`, `Puzzle::parse` and the CLVM evaluator too — a bound
/// applied at the binding hash alone would leave the non-memoizing hash inside `Puzzle::parse`
/// reachable one hop deeper, which is exactly how the 1,120-byte bomb defeats a size cap placed
/// there. The scratch allocator is dropped on return, so measuring costs no arena the hop keeps.
///
/// Deserialization failure is reported as [`LineageWalkError::Malformed`] with the same wording
/// [`alloc`] uses, because it is the same fact about the same bytes.
fn require_expandable_reveal<E>(
    coin_id: Bytes32,
    reveal: &Program,
) -> Result<(), LineageWalkError<E>> {
    let allocator = &mut Allocator::new();
    let node = alloc(allocator, reveal)?;
    if expanded_hash_input_bytes(allocator, node, MAX_REVEAL_EXPANDED_BYTES)
        > MAX_REVEAL_EXPANDED_BYTES
    {
        return Err(LineageWalkError::RevealTooLarge {
            coin_id,
            limit: MAX_REVEAL_EXPANDED_BYTES,
        });
    }
    Ok(())
}

/// The CLVM tree hash of a serialized [`Program`], without disturbing the walk's allocator.
///
/// Memoizing and back-reference-aware, so each shared node is hashed once. That is a performance
/// property, NOT the walk's defense against a decompression bomb — see
/// [`require_expandable_reveal`], which is what makes this call safe to reach.
fn program_tree_hash<E>(program: &Program) -> Result<TreeHash, LineageWalkError<E>> {
    tree_hash_from_bytes(program.as_ref())
        .map_err(|error| LineageWalkError::Malformed(format!("undecodable program: {error}")))
}

#[cfg(test)]
mod tests {
    use clvm_traits::ToClvm;

    use super::*;

    /// The cycle guard, pinned at the only level it can be: no end-to-end fixture can reach it.
    ///
    /// A successor's `parent_coin_info` is always the CURRENT coin's id, and
    /// [`require_coin_exists`] binds the successor to a real record by full [`Coin`] equality — so
    /// a member could only repeat if two distinct hops produced the same coin id, i.e. a SHA-256
    /// collision. The guard is therefore unreachable defense-in-depth today, and stays because a
    /// future hop rule must not be able to loop silently.
    #[test]
    fn admitting_the_same_coin_twice_is_refused_as_a_cycle() {
        let coin_id = Bytes32::new([0x5A; 32]);
        let mut members = BTreeSet::new();

        assert_eq!(
            admit_member::<ChainSourceError>(&mut members, coin_id),
            Ok(())
        );

        let repeat = admit_member::<ChainSourceError>(&mut members, coin_id)
            .expect_err("a repeated coin is a cycle");
        assert_eq!(
            repeat,
            LineageWalkError::Malformed(format!("coin {coin_id} repeats in the lineage (a cycle)"))
        );
        assert_eq!(members.len(), 1);
    }

    /// Quotes `value` so [`run_puzzle`] returns it verbatim, letting a test hand
    /// [`run_for_continuation`] a condition list the simulator would never mint — the CLVM
    /// validator rejects a malformed condition, so the only place this shape is reachable is a
    /// LYING source, which is exactly the case under test.
    fn quoting(allocator: &mut Allocator, value: NodePtr) -> NodePtr {
        let quote = allocator.one();
        allocator
            .new_pair(quote, value)
            .expect("a two-node pair always allocates")
    }

    /// Allocates the condition list `conditions`.
    fn condition_list(allocator: &mut Allocator, conditions: Vec<NodePtr>) -> NodePtr {
        conditions
            .to_clvm(allocator)
            .expect("a condition list always allocates")
    }

    fn continuation_of(
        allocator: &mut Allocator,
        conditions: Vec<NodePtr>,
    ) -> Result<Continuation, LineageWalkError<ChainSourceError>> {
        let list = condition_list(allocator, conditions);
        let puzzle = quoting(allocator, list);
        run_for_continuation(allocator, puzzle, NodePtr::NIL)
    }

    /// A CREATE_COIN the walk cannot decode must REFUSE, not be skipped.
    ///
    /// Skipping it leaves the spend looking like it emitted no odd-amount child, which the walk
    /// reads as a melt — a phantom one. The lineage would then stop early and report a superseded
    /// coin as the tip: the same not-known-presenting-as-a-tip defect as an unreadable spend,
    /// arrived at through the condition decoder.
    #[test]
    fn an_undecodable_create_coin_refuses_rather_than_reading_as_a_melt() {
        let allocator = &mut Allocator::new();
        let opcode = CREATE_COIN
            .to_clvm(allocator)
            .expect("the opcode allocates");
        // `(51)` — a CREATE_COIN with no puzzle hash and no amount at all.
        let truncated = allocator
            .new_pair(opcode, NodePtr::NIL)
            .expect("the condition allocates");

        let error = continuation_of(allocator, vec![truncated])
            .expect_err("an undecodable CREATE_COIN is not a melt");
        assert!(
            matches!(error, LineageWalkError::Malformed(detail) if detail.contains("CREATE_COIN")),
            "the refusal must name the condition it could not read"
        );
    }

    /// A negative amount that is NOT the melt marker is nonsense the walk must refuse, for the same
    /// reason: silently dropping it invents a melt.
    #[test]
    fn a_negative_non_melt_amount_refuses() {
        let allocator = &mut Allocator::new();
        let condition = (CREATE_COIN, (Bytes32::new([0x0C; 32]), (-7i64, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");

        let error = continuation_of(allocator, vec![condition])
            .expect_err("a negative non-melt amount is not a melt");
        assert!(matches!(error, LineageWalkError::Malformed(_)));
    }

    /// The control the two refusals above need: WELL-FORMED conditions still decode exactly as
    /// before, so the strictness bites only on what the walk genuinely cannot read.
    ///
    /// Without this, a `run_for_continuation` that refused everything would pass both tests.
    #[test]
    fn well_formed_conditions_still_decode_as_melt_and_as_recreation() {
        let allocator = &mut Allocator::new();
        let puzzle_hash = Bytes32::new([0x0D; 32]);

        let melt = (CREATE_COIN, (puzzle_hash, (SINGLETON_MELT_AMOUNT, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");
        assert!(matches!(
            continuation_of(allocator, vec![melt]),
            Ok(Continuation::Ends)
        ));

        let payment = (CREATE_COIN, (puzzle_hash, (2i64, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");
        let recreate = (CREATE_COIN, (puzzle_hash, (3i64, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");
        // The even-amount payment is an ordinary output and must still be ignored, not refused.
        assert!(matches!(
            continuation_of(allocator, vec![payment, recreate]),
            Ok(Continuation::Recreates(hash, 3)) if hash == puzzle_hash
        ));
    }

    /// The CANONICAL chia melt condition carries a NIL puzzle hash, not a 32-byte one.
    ///
    /// `chia_sdk_types::Condition::MeltSingleton` declares `puzzle_hash: () if ()`, so every melt
    /// built by standard chia-wallet-sdk tooling — which is what `dig-did` and `chip35_dl_coin`
    /// emit — is `(51 () -113)`. A decoder that forces `Bytes32` BEFORE testing the melt marker
    /// refuses it, and a DID or DataStore melted with standard tooling then becomes permanently
    /// unanswerable: the walk reports "the chain data is inconsistent" forever, blaming an honest
    /// source, where the truth is a plain, final absence.
    ///
    /// Both forms are minted in practice, so both must decode. The 32-byte form is covered by
    /// [`well_formed_conditions_still_decode_as_melt_and_as_recreation`]; this is the one that
    /// fixture cannot express.
    #[test]
    fn the_canonical_nil_puzzle_hash_melt_still_decodes_as_a_melt() {
        let allocator = &mut Allocator::new();
        let canonical_melt = (CREATE_COIN, ((), (SINGLETON_MELT_AMOUNT, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");

        assert!(
            matches!(
                continuation_of(allocator, vec![canonical_melt]),
                Ok(Continuation::Ends)
            ),
            "the canonical `(51 () -113)` melt must end the lineage, not refuse"
        );
    }

    /// Reading the melt marker first must NOT relax the refusal on an unreadable RECREATION.
    ///
    /// The whole point of decoding the puzzle hash late is that the melt no longer needs one. An
    /// odd, positive amount is a recreation, and a recreation the walk cannot address is still a
    /// refusal — otherwise the strictness this decoder exists for would have been traded away for
    /// the melt fix.
    #[test]
    fn a_recreation_whose_puzzle_hash_is_not_32_bytes_still_refuses() {
        let allocator = &mut Allocator::new();
        let short_hash = (CREATE_COIN, ([0x0Eu8; 31], (3i64, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");

        let error = continuation_of(allocator, vec![short_hash])
            .expect_err("a recreation with an unreadable puzzle hash is not a melt");
        assert!(
            matches!(error, LineageWalkError::Malformed(detail) if detail.contains("CREATE_COIN")),
            "the refusal must name the condition it could not read"
        );
    }

    /// An EVEN-amount CREATE_COIN with an unreadable puzzle hash refuses too — the parity skip must
    /// not become a place unreadable conditions hide.
    ///
    /// Even amounts are ordinary payments the walk deliberately ignores, so it is tempting to skip
    /// them before decoding their puzzle hash. That is strictly less strict than refusing: an
    /// even-amount condition still addresses a real coin, and chain data the walk cannot read is
    /// inconsistent whatever the amount's parity. The melt marker is the ONE case that legitimately
    /// carries no 32-byte hash, and it returns before this point.
    #[test]
    fn an_even_amount_create_coin_with_an_unreadable_puzzle_hash_still_refuses() {
        let allocator = &mut Allocator::new();
        let short_hash = (CREATE_COIN, ([0x0Eu8; 31], (2i64, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");

        let error = continuation_of(allocator, vec![short_hash])
            .expect_err("an unreadable puzzle hash is refused whatever the amount's parity");
        assert!(
            matches!(error, LineageWalkError::Malformed(detail) if detail.contains("CREATE_COIN")),
            "the refusal must name the condition it could not read"
        );
    }

    /// A singleton spend emits at most ONE odd-amount child; two is chain data the walk cannot
    /// interpret, and picking either would be a guess about which coin is the singleton.
    #[test]
    fn two_odd_amount_children_refuse_rather_than_choosing_one() {
        let allocator = &mut Allocator::new();
        let first = (CREATE_COIN, (Bytes32::new([0x1A; 32]), (1i64, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");
        let second = (CREATE_COIN, (Bytes32::new([0x1B; 32]), (3i64, ())))
            .to_clvm(allocator)
            .expect("the condition allocates");

        let error = continuation_of(allocator, vec![first, second])
            .expect_err("two odd-amount children are ambiguous");
        assert_eq!(
            error,
            LineageWalkError::Malformed(
                "a singleton spend emitted more than one odd-amount child".to_string()
            )
        );
    }

    /// The bound is pinned from BOTH sides on a node of exactly known cost.
    ///
    /// `nil` costs 1 (its `0x01` prefix, no bytes); a pair costs 65 (`0x02` plus two 32-byte child
    /// hashes). So `((nil . nil) . nil)` costs `65 + (65 + 1 + 1) + 1` = 133. A bound tested only
    /// from one side confirms itself: at 132 the node must be refused and at 133 it must be
    /// accepted, and only asserting both proves the comparison is `>` rather than `>=` or nothing.
    #[test]
    fn the_expanded_bound_admits_a_node_at_the_limit_and_refuses_one_byte_over() {
        let allocator = &mut Allocator::new();
        let inner = allocator
            .new_pair(NodePtr::NIL, NodePtr::NIL)
            .expect("a pair allocates");
        let node = allocator
            .new_pair(inner, NodePtr::NIL)
            .expect("a pair allocates");

        assert_eq!(
            expanded_hash_input_bytes(allocator, node, 133),
            133,
            "the cost model must be exactly 65 per pair and 1 + len per atom"
        );
        assert!(
            expanded_hash_input_bytes(allocator, node, 132) > 132,
            "one byte over the bound must be refused"
        );
    }

    /// A bomb must SATURATE rather than be computed — the whole point of the saturating traversal.
    ///
    /// 40 levels of self-cons is a notional 2^40 nodes. If the cost were accumulated honestly this
    /// test would not finish; that it returns `limit + 1` immediately is the property under test.
    #[test]
    fn a_self_referential_dag_saturates_instead_of_being_counted() {
        let allocator = &mut Allocator::new();
        let mut node = allocator.new_atom(&[1]).expect("a one-byte atom allocates");
        for _ in 0..40 {
            node = allocator
                .new_pair(node, node)
                .expect("a self-cons adds one pair");
        }

        assert_eq!(
            expanded_hash_input_bytes(allocator, node, MAX_REVEAL_EXPANDED_BYTES),
            MAX_REVEAL_EXPANDED_BYTES + 1,
            "the traversal must stop one byte past the bound, never compute 2^40"
        );
    }

    /// An honest reveal-sized tree must NOT be refused — the nearest wrong fix is a bound so tight
    /// it rejects real singletons, and this is the control that would catch it.
    #[test]
    fn a_tree_the_size_of_a_heavy_honest_reveal_is_admitted() {
        // 137 KB expanded is the measured cost of a singleton wrapping an NFT state + ownership +
        // royalty stack with eight long URIs — the heaviest realistic reveal (see
        // `MAX_REVEAL_EXPANDED_BYTES`). Built here as a right-leaning list of 2,100 pairs, which
        // costs 65 each: ~136.5 KB.
        let allocator = &mut Allocator::new();
        let mut node = NodePtr::NIL;
        for _ in 0..2_100 {
            node = allocator
                .new_pair(NodePtr::NIL, node)
                .expect("a pair allocates");
        }

        let cost = expanded_hash_input_bytes(allocator, node, MAX_REVEAL_EXPANDED_BYTES);
        assert!(
            cost > 100_000,
            "the control is only load-bearing if it is genuinely reveal-sized; it cost {cost}"
        );
        assert!(
            cost <= MAX_REVEAL_EXPANDED_BYTES,
            "a reveal the size of a heavy honest one must be admitted; it cost {cost}"
        );
    }

    /// `successor_of` must keep owning its allocator, and the guard has to be mechanical.
    ///
    /// The doc comment on that function explains why the arena is created per hop. Hoisting it is a
    /// three-line change — add a parameter, create one in the caller, pass it — of exactly the shape
    /// a "stop reallocating per hop" optimisation takes, and NOTHING in the suite goes red when it
    /// happens: the endless-chain tests cap out at 64 hops, far below the arena's node ceiling. So
    /// the signature itself is asserted.
    #[test]
    fn successor_of_takes_no_allocator_parameter() {
        let source = include_str!("walk.rs");
        let signature = source
            .split_once("fn successor_of<E>(")
            .expect("successor_of is declared in this file")
            .1
            .split_once(") ->")
            .expect("its parameter list is closed")
            .0;

        assert!(
            !signature.contains("Allocator"),
            "successor_of must create its own allocator per hop, not accept a hoisted one: \
             ({signature})"
        );
    }

    /// A hop cap wider than the ecosystem's canonical bound is CLAMPED, not honoured.
    #[test]
    fn a_hop_cap_beyond_the_canonical_bound_is_clamped() {
        assert_eq!(WalkBounds::hops(usize::MAX).max_hops(), MAX_LINEAGE_DEPTH);
        assert_eq!(WalkBounds::hops(7).max_hops(), 7);
    }
}
