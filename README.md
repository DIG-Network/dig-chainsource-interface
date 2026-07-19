# dig-chainsource-interface

The DIG Network **canonical `ChainSource` provider interface**: the single pure trait + query types
every Chia chain-source provider implements and every consumer depends on.

There is ONE `ChainSource` contract for the whole ecosystem — never a per-crate copy that could
byte-drift. This crate is a pure **leaf**: a trait, its typed query/result/error types, an optional
in-memory mock, and known-answer tests. It performs **no I/O, holds no keys, opens no network, and
ships no concrete provider**. Providers (coinset.org, a local wallet/full node, DIG peers) implement
this trait in their own crates; [`chia-query`](https://github.com/DIG-Network/chia-query) is the
registry + aggregating canonical source that composes them. Consumers (`dig-did`, `dig-merkle`,
`dig-node`, `dig-wallet-backend`, the lineage middleware) depend on THIS trait.

## Reads only — no broadcast, ever

Nothing in this crate can broadcast, push, or submit to the chain — there is no such method, by
design. It is a pure reader; write/spend paths (which touch keys and funds) live entirely outside
it, so depending on this crate can never move value.

## Fail-closed: `Ok(None)` vs `Err`

Every read distinguishes two outcomes a consumer MUST treat differently:

| Outcome | Meaning | Consumer action |
|---|---|---|
| `Ok(None)` / empty `Vec` | The source reliably answered; the thing genuinely does not exist. | Safe to act on the absence. |
| `Err(_)` | The source could **not** reliably answer (transport, timeout, malformed, unsupported). | **Fail closed** — treat as unknown, never as an absence. |

Absence is never an error variant; an error is never degraded to a value.

## The trait

| Method | Returns | `None` / empty means |
|---|---|---|
| `coin_record(coin_id)` | `Option<CoinRecord>` | coin does not exist |
| `coin_records_by_puzzle_hash(ph, include_spent)` | `Vec<CoinRecord>` | no matching coins |
| `coin_records_by_parent(parent_id)` | `Vec<CoinRecord>` | no known children |
| `coin_spend(coin_id)` | `Option<CoinSpend>` | `coin_id` is unspent/unknown |
| `parent_spend(coin_id)` | `Option<CoinSpend>` | parent is unspent/unknown (a walk gap) |
| `resolve_singleton_lineage(launcher_id)` | `Option<SingletonLineage>` | launcher never existed / fully melted |
| `peak_height()` | `Option<u32>` | source exposes no peak |
| `block_timestamp(height)` | `Option<u64>` | no such block / no timestamp index |

`parent_spend` is the **money-critical parent-walk primitive**: a coin's puzzle hash is
attacker-chosen, so a `launcher_id ==` check is spoofable. A consumer authenticates a singleton by
walking `parent_spend` back toward the real launcher — a spoofed curried-puzzle coin has no genuine
recreation parent-spend, so the walk fails closed. `SingletonLineage` follows suit: authority is
**membership** (`contains`), never tip-equality.

## Implementing a provider

Implement `ChainSource` over your backend, choosing `type Error` (`ChainSourceError` is recommended
for registry participants). Map your backend's wallet-protocol `CoinState` with
`CoinRecord::from(state)` (which maps `created_height -> confirmed_height`). Implement
`ChainSourceProvider::provider_info` to register with the aggregator. Override the default
`parent_spend` if your backend can resolve a creating spend in one call.

## Depending on it as a consumer

Depend on the **trait**, never on a concrete provider, and be generic over `S: ChainSource`. Handle
`Ok(None)` and `Err(_)` distinctly (fail closed on `Err`).

**async -> sync bridge.** The trait is synchronous and object-safe. An async provider presents a
blocking `ChainSource` facade at `chia-query`'s native aggregator boundary; a blocking consumer runs
the walk under `spawn_blocking`. This keeps the interface a leaf with no async runtime dependency.

## The `testing` feature

Enable `features = ["testing"]` to get `MockChainSource`, an in-memory source you load with coins,
spends, and lineages (plus a forced-error switch) to exercise your own trust logic — including the
fail-closed paths.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
