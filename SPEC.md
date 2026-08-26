# dig-chainsource-interface — normative specification (v0.4.0)

This is the authoritative contract for the DIG Network canonical `ChainSource` interface. An
independent reimplementation of this crate, of a provider, or of a consumer MUST conform to this
document. The interface is a single ecosystem-wide contract — there is exactly ONE `ChainSource`,
never a per-crate copy.

## 1. Scope and leaf invariants

`dig-chainsource-interface` defines the reads-only interface for consulting Chia chain state and the
typed query/result/error shapes that cross it. It is a pure **leaf**:

- **No I/O, no network, no keys, no filesystem.** The crate performs zero side effects.
- **Reads only.** There is NO broadcast/push/submit/spend method anywhere in the crate, by design.
  Value-moving paths live entirely outside it.
- **No DIG-crate dependencies.** In the DEFAULT feature set, runtime dependencies are `chia-protocol`
  and `thiserror` ONLY. It depends on no DIG crate and no `async-trait` in any configuration. This
  keeps it the bottom of the crate hierarchy (level 00) and cleanly wasm-buildable.
  The non-default `lineage-walk` feature (§4a) additionally pulls a CLVM evaluator and the vetted
  singleton puzzle types — `chia-puzzle-types`, `chia-puzzles`, `chia-sdk-driver`, `chia-sdk-types`,
  `clvm-traits`, `clvm-utils`, `clvmr`. A consumer that only needs the trait does not pay for them.
  Every `chia-*` version is the **chia-wallet-sdk 0.36.0 ceiling**, never the newest on crates.io:
  the primitives publish at 0.48 but the SDK cannot reach them, so `0.36.1` primitives beside
  `0.36.0` `chia-sdk-*` is the coherent maximum. Mixing the two lines re-splits the crate.
- **Object-safe and synchronous.** `Box<dyn ChainSource<Error = E>>` MUST compile.

## 2. The `ChainSource` trait — per-method contract

`type Error: core::fmt::Display` — the source's own transport/parse error. `ChainSourceError` (§3)
is the recommended type for registry participants.

| Method | Signature | Contract |
|---|---|---|
| `coin_record` | `(Bytes32) -> Result<Option<CoinRecord>, Error>` | The coin with this id, or `None` if it does not exist. |
| `coin_records_by_puzzle_hash` | `(Bytes32, bool) -> Result<Vec<CoinRecord>, Error>` | All coins paying to the puzzle hash; the bool includes already-spent coins when true. Empty = none. |
| `coin_records_by_parent` | `(Bytes32) -> Result<Vec<CoinRecord>, Error>` | Direct children created by spending the given coin. Empty = none. |
| `coin_spend` | `(Bytes32) -> Result<Option<CoinSpend>, Error>` | The spend that SPENT this coin (input coin == the argument), or `None` if unspent/unknown. |
| `parent_spend` | `(Bytes32) -> Result<Option<CoinSpend>, Error>` | The spend that CREATED this coin (the spend of its parent), or `None` for an unspent/unknown parent. Default = `coin_record` then `coin_spend(parent_coin_info)`; a provider MAY override. |
| `resolve_singleton_lineage` | `(Bytes32) -> Result<Option<SingletonLineage>, Error>` | The authenticated lineage for a launcher id, or `None` if never launched / fully melted. |
| `peak_height` | `() -> Result<Option<u32>, Error>` | The current synced peak height, or `None` if not tracked. |
| `block_timestamp` | `(u32) -> Result<Option<u64>, Error>` | The Unix timestamp of the block at the height, or `None` if no such block / no index. |

`ChainSourceProvider: ChainSource` adds `provider_info() -> ProviderInfo` (§6).

## 3. Fail-closed: `None` vs `Err` (mandatory)

Every fallible method distinguishes:

| Result | Meaning | Consumer obligation |
|---|---|---|
| `Ok(None)` / empty `Vec` | The source reliably answered; the item genuinely does not exist. | MAY act on the absence. |
| `Err(_)` | The source could not reliably answer. | MUST fail closed — treat as unknown, NEVER as an absence or a permissive default. |

`ChainSourceError` variants (all mean "could not reliably answer"; `#[non_exhaustive]`):

- `Transport(String)` — connection/transport failure to the backend.
- `Malformed(String)` — response could not be parsed into the expected chain type.
- `Unsupported(&'static str)` — the backend does not support the query.
- `Timeout` — the read did not complete in time.
- `RateLimited` — the backend refused for rate-limiting.
- `NoProvider` — no provider was available (empty/exhausted registry).
- `TooManyRecords { count, limit }` — the backend returned more records than the consumer's
  hostile-input bound allows; distinct from `Malformed` (each record may be well-formed, but the
  count exceeds the cap) — the consumer fails closed the same as every other variant.
- `Timeout` — also carries a lineage walk that exceeded its wall-clock budget (§4a).
- `RevealTooLarge { limit }` — a puzzle reveal expands, once its CLVM back-references are unfolded,
  beyond the walk's bound (§4a). Distinct from `Malformed`: the reveal may be entirely well-formed
  chain data and merely larger than the walk will authenticate.
- `LineageTooDeep { limit }` — a singleton lineage walk exceeded its hop bound (§4a). The lineage it
  could build is INCOMPLETE, so it is refused rather than truncated: a partial member set would make
  `contains` answer `false` for genuine members, which is a fail-OPEN membership answer.

Absence MUST NOT be encoded as an error; an error MUST NOT be degraded to a value.

## 4. `SingletonLineage` — membership is authority

A `SingletonLineage` carries a `tip` and the full member set (launcher → tip inclusive; the tip is
always a member). Authority is **membership** (`contains(coin_id)`), NOT equality with the tip: a
coin launched from any genuine lineage coin is rooted in the singleton; an attacker's coin is never
a member.

**Money-critical requirement.** `resolve_singleton_lineage` MUST return a genuine forward walk from
the launcher to its current tip — each coin the singleton recreation of the previous. It MUST NEVER
echo a caller-supplied coin into the lineage. Echoing would make `contains` meaningless and allow a
foreign coin to claim authority. Consumers authenticate coins by walking `parent_spend` toward the
real launcher and testing lineage membership — never by puzzle-hash equality.

## 4a. The canonical lineage walk (feature `lineage-walk`)

`ChainSource::resolve_singleton_lineage` has no default body, so a source backed only by primitive
reads would have to hand-roll the §4 money-critical requirement. The optional, NON-DEFAULT
`lineage-walk` feature supplies that walk once, as free functions:

```rust
pub const MAX_LINEAGE_DEPTH: usize = 100_000;
pub const DEFAULT_WALK_BUDGET: Duration = Duration::from_secs(45);
pub const MAX_REVEAL_EXPANDED_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_HOP_CLVM_COST: u64 = 100_000_000;

// Fields are PRIVATE and `max_hops` is clamped to MAX_LINEAGE_DEPTH; the guards cannot be
// disabled through a struct literal. Default: the two bound constants above.
pub struct WalkBounds { /* private */ }
impl WalkBounds {
    pub fn hops(max_hops: usize) -> Self;   // clamped to MAX_LINEAGE_DEPTH
    pub fn within(self, budget: Duration) -> Self;
    pub fn max_hops(self) -> usize;
    pub fn budget(self) -> Duration;
}

pub enum LineageWalkError<E> {
    Source(E), Malformed(String), NotASingleton { coin_id },
    RevealTooLarge { coin_id, limit }, TooDeep { limit }, DeadlineExceeded { budget },
}

pub fn walk_singleton_lineage<S: ChainSource>(source: &S, launcher_id: Bytes32)
    -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>>;

pub fn walk_singleton_lineage_bounded<S: ChainSource>(source: &S, launcher_id: Bytes32, max_hops: usize)
    -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>>;

pub fn walk_singleton_lineage_within<S: ChainSource>(source: &S, launcher_id: Bytes32, bounds: WalkBounds)
    -> Result<Option<SingletonLineage>, LineageWalkError<S::Error>>;

pub fn resolve_singleton_lineage_via_walk<S: ChainSource<Error = ChainSourceError>>(
    source: &S, launcher_id: Bytes32) -> Result<Option<SingletonLineage>, ChainSourceError>;
```

A conforming walk MUST:

1. **Derive, never recognise.** At each hop it reads the current coin's own spend, requires the
   returned spend to BE that coin's spend, requires the puzzle reveal to hash to that coin's puzzle
   hash, parses the reveal as a singleton curried to the launcher under resolution, runs the inner
   puzzle, and RECONSTRUCTS the odd-amount successor's full puzzle hash from the launcher id and the
   successor's inner puzzle hash. It MUST NOT select the successor by puzzle-hash equality, by
   curried launcher id alone, or from `coin_records_by_parent` — every one of those is spoofable,
   because a coin's `puzzle_hash` is attacker-chosen.
2. **Bind each derived coin to chain state.** A CLVM solution is not committed to by a coin's puzzle
   hash, so a dishonest source could pair a genuine reveal with a fabricated solution. Each derived
   successor MUST be confirmed to exist via `coin_record` before it enters the lineage.
3. **Decode the `CREATE_COIN` amount as SIGNED, and decode it BEFORE the puzzle hash.** CLVM atoms
   carry no sign, so the singleton melt marker `-113` decodes into a `u64` as `143` — an odd,
   positive amount indistinguishable from an ordinary recreation. A walk that made that mistake
   would invent a phantom successor for every melted singleton instead of reporting the melt. The
   amount is also the DISCRIMINANT for the puzzle hash: the canonical melt condition is
   `(51 () -113)`, carrying a NIL puzzle hash, which is what standard chia-wallet-sdk tooling emits.
   A walk that required a 32-byte puzzle hash before testing the melt marker would refuse every such
   melt, making a singleton melted with standard tooling permanently unanswerable. Both the nil and
   the 32-byte melt forms MUST decode as a melt.
4. **Deserialize programs with the BACK-REFERENCE reader.** A puzzle reveal or solution may be
   serialized in the CLVM back-reference form — the compressed encoding full nodes accept and block
   generators emit, which a curried singleton reveal exercises heavily. A walk that reads only the
   non-backref form reports a genuine singleton as `Malformed`, blaming an honest source.
5. **Refuse, never truncate, past ANY bound** — `MAX_LINEAGE_DEPTH` spends and
   `DEFAULT_WALK_BUDGET` of wall-clock time by default — and reject a repeated coin id as a cycle.
   The hop cap alone is insufficient: it bounds neither elapsed time nor per-hop cost, so a hostile
   source serving a structurally valid, ever-advancing chain of DISTINCT recreations trips no other
   guard. `ChainSource` is synchronous, so that is the caller's thread. A budget overrun MUST report
   as `LineageWalkError::DeadlineExceeded` (projecting to `ChainSourceError::Timeout`), never as
   `TooDeep` or `Malformed` — the source may have been entirely honest.

   The wall-clock budget is checked BETWEEN hops, so it is a **backstop**, not a hard deadline: a
   conforming walk returns within `budget + one worst-case hop`. That guarantee is vacuous unless
   the cost of ONE hop is itself bounded, which is what §5a and §5b require.

5a. **Bound the EXPANDED size of a puzzle reveal, before hashing, parsing or running it.** CLVM
   back-references are a compression: the bytes on the wire describe a shared DAG, while every
   consumer of that DAG — the reveal-binding hash, curried-puzzle parsing, the evaluator — sees the
   tree it unfolds into, and a `k`-level self-referential DAG unfolds into `2^k` nodes. A conforming
   walk MUST refuse a reveal whose expansion exceeds `MAX_REVEAL_EXPANDED_BYTES`, reporting
   `LineageWalkError::RevealTooLarge` (projecting to `ChainSourceError::RevealTooLarge`) — never
   `Malformed`, because the reveal may be valid chain data that is merely too large.

   Two properties are normative, and each closes an attack the other does not. The bound MUST be on
   the EXPANSION, not on the serialized length: a serialized-length cap large enough for an honest
   singleton is orders of magnitude above the bomb, which is about a kilobyte. And the bound MUST be
   applied BEFORE the reveal-binding hash, so that every later use of those bytes is downstream of
   it: a bomb curried as the INNER puzzle of an otherwise genuine singleton passes the binding check
   truthfully — the walk derived that coin's puzzle hash from the bomb's own tree hash — and
   detonates in whatever parses the reveal next. Memoizing the binding hash does not close this;
   only bounding the expansion ahead of all of it does.

5b. **Bound the CLVM cost of ONE hop.** A spend's puzzle reveal is hash-bound to its coin, but its
   SOLUTION is bound to nothing — the source chooses it freely. A conforming walk MUST evaluate with
   an explicit per-hop ceiling (`MAX_HOP_CLVM_COST`), never the whole-block cost limit, or one hop
   may legitimately burn an entire block's worth of evaluation.
6. **Bound per-hop CLVM memory.** A CLVM allocator is an arena that frees nothing until dropped, so
   one shared across hops accumulates every hop's puzzle, solution and evaluation. A conforming walk
   MUST start each hop with a fresh allocator (or restore a checkpoint). Sharing one both costs
   memory linear in the chain length and exhausts the arena's own node ceiling BEFORE
   `MAX_LINEAGE_DEPTH` is reached, which makes the documented `TooDeep` refusal unreachable and
   misreports the exhaustion as `Malformed`.
7. **Preserve the three-valued discipline of §3.** `Ok(None)` means the launcher id names no coin,
   names a coin that is not wearing `SINGLETON_LAUNCHER_HASH`, was never spent into an eve, or the
   singleton was melted. Every read failure surfaces as `LineageWalkError::Source(_)` carrying the
   source's OWN error unchanged, so *unsupported* stays distinguishable from *unreadable* and
   neither is ever collapsed into an absence.
8. **Treat an unreadable spend as unknown, never as the tip.** `coin_spend` answers `Ok(None)` for
   "unspent **or** unknown" (§3), so a walk MUST consult the coin's own `spent_height` before
   concluding it has reached the tip. A coin recorded as SPENT whose spend the source does not serve
   MUST fail closed with `LineageWalkError::Malformed`. Reporting it as the tip would present a
   superseded state as current — and if the unserved spend was the melt, a dead singleton would
   authenticate as live; at the launcher it would degrade an unknown into "never launched",
   violating §3.
9. **Refuse an unreadable `CREATE_COIN`.** Once a condition's opcode is known to be `CREATE_COIN`,
   arguments the walk cannot decode (including an amount outside `i64`, or a negative amount that is
   not the melt marker) MUST be a refusal. Skipping such a condition makes a spend look as though it
   emitted no odd-amount child — a phantom melt, i.e. requirement 8's defect reached through the
   condition decoder.

`MAX_LINEAGE_DEPTH` is the ecosystem's SINGLE source of truth for this bound. A DIG crate that
bounds a singleton lineage walk MUST import it from this crate rather than re-declare the literal;
this crate is `00-foundation`, so every such consumer sits strictly above it.

**Stated limit — the unspent eve.** An eve coin that has never been spent is admitted on the evidence
of the launcher's own spend, which is the strongest evidence that exists: the eve is by definition the
coin the launcher created, and the launcher's `CREATE_COIN` carries the eve's FULL puzzle hash, which
is non-invertible — so nothing an attacker supplies reaches the decision. Consequently a launcher
spent into an ORDINARY coin resolves to `Ok(Some(_))` with that coin as the tip, not `Ok(None)`. The
eve's inner structure is constrained the moment it is itself spent, at which point the curried
launcher id is checked and a non-singleton yields `NotASingleton`. A consumer that requires a *proven*
singleton rather than a *launched* one MUST require a tip beyond the eve.

## 5. `CoinRecord` and `CoinState` conversion

`CoinRecord { coin: Coin, confirmed_height: Option<u32>, spent_height: Option<u32>,
timestamp: Option<u64>, coinbase: bool }`. `is_spent()` == `spent_height.is_some()`. `Option`
heights/timestamp mean "not known by this source", never "does not exist".

`From<CoinState>` (and `from_coin_state`) maps a wallet-protocol `CoinState { coin, spent_height,
created_height }`: `created_height -> confirmed_height`, `spent_height` preserved, `timestamp = None`,
`coinbase = false` (a `CoinState` carries neither).

## 6. Provider-registration descriptor

`ProviderInfo { id: ProviderId, kind: ProviderKind, priority: i32, trustless: bool }`.

- `ProviderId(Cow<'static, str>)` — a stable, human-readable id.
- `ProviderKind` ∈ `{ PublicOracle, LocalNode, DigPeers, Custom }`.
- `priority` — try-order; **lower is tried first**.
- `trustless` — whether answers are independently verifiable rather than taken on trust.

## 7. async → sync bridge

The trait is synchronous and object-safe so the interface stays a leaf with no async runtime
dependency. An async provider presents a blocking `ChainSource` facade at the aggregator boundary
(`chia-query`); a blocking consumer runs a lineage walk under `spawn_blocking`.

## 8. Known-answer vectors

- Coin `{ parent: 0x11*32, puzzle_hash: 0x22*32, amount: 1_000_000 }` has
  `coin_id == a20457fc968660c1f5c053be6d76ba811aabe6625446d57e89b8524680d3178c`.
- The `CoinSpend` of that coin with `puzzle_reveal = 0x01`, `solution = 0x80` streams (chia-traits
  `Streamable`) to
  `1111…1111 2222…2222 00000000000f42400180` (coin || puzzle_reveal || solution).

## 9. Conformance

A conforming provider MUST:

1. Preserve the `Ok(None)`-vs-`Err` semantics of §3 for every method.
2. Produce byte-identical `coin_id` / `CoinSpend` serialization as §8 (inherited from
   `chia-protocol`).
3. Map `CoinState` per §5.
4. Return a genuine forward-walked lineage from `resolve_singleton_lineage` per §4 — never an echo.
   A source backed only by primitive reads SHOULD delegate to the §4a walk rather than hand-roll one.
5. Report a `ProviderInfo` per §6.
6. Remain reads-only: expose no broadcast/spend path through this interface.
