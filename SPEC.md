# dig-chainsource-interface — normative specification (v0.1.0)

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
- **No DIG-crate dependencies.** Runtime dependencies are `chia-protocol` and `thiserror` ONLY.
  It does not depend on `chia-wallet-sdk`, `chia-puzzle-types`, `chia-puzzles`, `async-trait`, or any
  DIG crate. This keeps it the bottom of the crate hierarchy (level 00) and cleanly wasm-buildable.
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
5. Report a `ProviderInfo` per §6.
6. Remain reads-only: expose no broadcast/spend path through this interface.
