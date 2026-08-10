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

use std::collections::BTreeSet;
use std::fmt;

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_puzzle_types::singleton::SingletonArgs;
use chia_puzzles::SINGLETON_LAUNCHER_HASH;
use chia_sdk_driver::{Layer, Puzzle, SingletonLayer};
use chia_sdk_types::run_puzzle;
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::{tree_hash, TreeHash};
use clvmr::{Allocator, NodePtr};

use crate::error::ChainSourceError;
use crate::lineage::SingletonLineage;
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
/// The value matches `dig_did::resolve::MAX_LINEAGE_DEPTH`, so the two walks in the ecosystem refuse
/// at exactly the same depth rather than disagreeing about what "too deep" means.
pub const MAX_LINEAGE_DEPTH: usize = 100_000;

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

    /// The walk exceeded its hop bound. The lineage found so far is INCOMPLETE and is deliberately
    /// discarded rather than returned as a truncated member set.
    TooDeep {
        /// The hop bound the walk refused to exceed.
        limit: usize,
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
            Self::TooDeep { limit } => {
                write!(f, "singleton lineage walk exceeded its {limit}-hop bound")
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
            LineageWalkError::TooDeep { limit } => ChainSourceError::LineageTooDeep { limit },
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
/// Bounded at [`MAX_LINEAGE_DEPTH`] hops; use [`walk_singleton_lineage_bounded`] to choose another
/// bound.
///
/// # Returns
///
/// | Case | Result |
/// |---|---|
/// | `launcher_id` names no coin | `Ok(None)` |
/// | it names a coin that is not a singleton launcher | `Ok(None)` |
/// | the launcher was never spent (no eve minted) | `Ok(None)` |
/// | the singleton was melted (a spend with no odd successor) | `Ok(None)` |
/// | a live singleton | `Ok(Some(lineage))`, launcher → tip inclusive |
/// | a source read failed | `Err(LineageWalkError::Source(_))` |
/// | the chain data is inconsistent | `Err(LineageWalkError::Malformed(_))` |
/// | a coin is not a genuine singleton of this launcher | `Err(LineageWalkError::NotASingleton { .. })` |
/// | the hop bound was exceeded | `Err(LineageWalkError::TooDeep { .. })` |
pub fn walk_singleton_lineage<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>> {
    walk_singleton_lineage_bounded(source, launcher_id, MAX_LINEAGE_DEPTH)
}

/// [`walk_singleton_lineage`] with an explicit hop bound.
///
/// Factored out so the [`LineageWalkError::TooDeep`] behaviour can be exercised over a short real
/// chain with a tiny bound, rather than only by a 100,000-hop fixture that no test would build.
pub fn walk_singleton_lineage_bounded<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
    max_hops: usize,
) -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>> {
    let Some(launcher) = read_launcher_coin(source, launcher_id)? else {
        return Ok(None);
    };

    let mut allocator = Allocator::new();
    let mut members = BTreeSet::from([launcher_id]);
    let mut current = launcher;
    // The launcher's own spend is structurally different from a singleton spend (its CREATE_COIN
    // already carries the eve's FULL puzzle hash), so the first hop is handled separately.
    let mut at_launcher = true;

    // `max_hops` counts SPENDS followed, so the loop runs one extra time: the final read is the one
    // that discovers the tip is unspent, and it follows no spend.
    for _hop in 0..=max_hops {
        let Some(spend) = read_spend_of(source, current)? else {
            // An unspent coin is the tip — unless it is the launcher itself, in which case no
            // singleton state was ever minted.
            return Ok((!at_launcher).then(|| SingletonLineage::new(current.coin_id(), members)));
        };

        let (puzzle, solution) = parse_spend(&mut allocator, &spend)?;
        let successor = if at_launcher {
            eve_created_by_launcher(&mut allocator, current, puzzle, solution)?
        } else {
            singleton_successor(&mut allocator, current, launcher_id, puzzle, solution)?
        };
        let Some(successor) = successor else {
            // The spend emitted no odd-amount successor: the singleton was melted, so it has no
            // current coin. A melt is a genuine absence, not a failure.
            return Ok(None);
        };

        // A solution is NOT committed to by a coin's puzzle hash, so a dishonest source could pair a
        // genuine reveal with a fabricated solution and steer the walk onto a coin the chain never
        // created. Requiring the derived successor to exist on chain binds every hop to real state.
        require_coin_exists(source, successor)?;

        if !members.insert(successor.coin_id()) {
            return Err(LineageWalkError::Malformed(format!(
                "coin {} repeats in the lineage (a cycle)",
                successor.coin_id()
            )));
        }
        current = successor;
        at_launcher = false;
    }

    Err(LineageWalkError::TooDeep { limit: max_hops })
}

/// Reads the launcher coin named by `launcher_id`, or `None` when no singleton was launched there.
///
/// A coin id that names nothing, or names a coin that is not wearing the well-known singleton
/// launcher puzzle, means the singleton genuinely does not exist — not that the read failed.
fn read_launcher_coin<S: ChainSource>(
    source: &S,
    launcher_id: Bytes32,
) -> Result<Option<Coin>, LineageWalkError<S::Error>> {
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
    Ok(Some(record.coin))
}

/// Reads the spend of `coin`, proving the returned spend really is that coin's and that its puzzle
/// reveal hashes to the coin's own puzzle hash.
///
/// Both checks defend against a lying source: without them, an attacker-supplied reveal could be
/// run in place of the coin's real puzzle and emit any successor it liked.
fn read_spend_of<S: ChainSource>(
    source: &S,
    coin: Coin,
) -> Result<Option<CoinSpend>, LineageWalkError<S::Error>> {
    let Some(spend) = source
        .coin_spend(coin.coin_id())
        .map_err(LineageWalkError::Source)?
    else {
        return Ok(None);
    };
    if spend.coin != coin {
        return Err(LineageWalkError::Malformed(format!(
            "source returned a spend of coin {} when asked for {}",
            spend.coin.coin_id(),
            coin.coin_id()
        )));
    }
    let revealed = program_tree_hash(&spend.puzzle_reveal)?;
    if Bytes32::from(revealed) != coin.puzzle_hash {
        return Err(LineageWalkError::Malformed(format!(
            "puzzle reveal does not hash to the puzzle hash of coin {}",
            coin.coin_id()
        )));
    }
    Ok(Some(spend))
}

/// Requires `coin` to be known to the source, binding a derived successor to real chain state.
fn require_coin_exists<S: ChainSource>(
    source: &S,
    coin: Coin,
) -> Result<(), LineageWalkError<S::Error>> {
    let known = source
        .coin_record(coin.coin_id())
        .map_err(LineageWalkError::Source)?
        .is_some_and(|record| record.coin == coin);
    if !known {
        return Err(LineageWalkError::Malformed(format!(
            "the spend claims to create coin {}, which the source does not know",
            coin.coin_id()
        )));
    }
    Ok(())
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
    let output = run_puzzle(allocator, puzzle, solution)
        .map_err(|error| LineageWalkError::Malformed(format!("puzzle did not run: {error}")))?;
    let conditions = Vec::<NodePtr>::from_clvm(allocator, output).map_err(|error| {
        LineageWalkError::Malformed(format!("undecodable condition list: {error}"))
    })?;

    let mut recreation: Option<(Bytes32, u64)> = None;
    for condition in conditions {
        let Ok((opcode, (puzzle_hash, (signed_amount, _memos)))) =
            CreateCoin::from_clvm(allocator, condition)
        else {
            continue;
        };
        if opcode != CREATE_COIN {
            continue;
        }
        if signed_amount == SINGLETON_MELT_AMOUNT {
            return Ok(Continuation::Ends);
        }
        let Ok(amount) = u64::try_from(signed_amount) else {
            continue;
        };
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

/// A `CREATE_COIN` condition decoded with a SIGNED amount, so the melt marker survives (see
/// [`run_for_continuation`]): `(opcode, (puzzle_hash, (amount, memos)))`. Any condition with a
/// different shape simply fails to decode and is skipped.
type CreateCoin = (i64, (Bytes32, (i64, NodePtr)));

/// Deserializes a spend's puzzle reveal and solution into `allocator`.
fn parse_spend<E>(
    allocator: &mut Allocator,
    spend: &CoinSpend,
) -> Result<(Puzzle, NodePtr), LineageWalkError<E>> {
    let puzzle = alloc(allocator, &spend.puzzle_reveal)?;
    let solution = alloc(allocator, &spend.solution)?;
    Ok((Puzzle::parse(allocator, puzzle), solution))
}

/// Deserializes a [`Program`] into an allocated [`NodePtr`].
fn alloc<E>(allocator: &mut Allocator, program: &Program) -> Result<NodePtr, LineageWalkError<E>> {
    program
        .to_clvm(allocator)
        .map_err(|error| LineageWalkError::Malformed(format!("undecodable program: {error}")))
}

/// The CLVM tree hash of a serialized [`Program`], without disturbing the walk's allocator.
fn program_tree_hash<E>(program: &Program) -> Result<TreeHash, LineageWalkError<E>> {
    let mut allocator = Allocator::new();
    let ptr = alloc(&mut allocator, program)?;
    Ok(tree_hash(&allocator, ptr))
}
