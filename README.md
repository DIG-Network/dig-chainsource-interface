# dig-chainsource-interface

The DIG Network **canonical `ChainSource` provider interface**: the single pure trait + query types
every Chia chain-source provider implements and every consumer depends on.

There is ONE `ChainSource` contract for the whole ecosystem — never a per-crate copy that could
byte-drift. This crate is a pure **leaf**: a trait, its typed query/result/error types, and
known-answer tests. It performs **no I/O, holds no keys, opens no network, and ships no concrete
provider**. Providers (coinset.org, a local wallet/full node, DIG peers) implement this trait in
their own crates; [`chia-query`](https://github.com/DIG-Network/chia-query) is the registry +
aggregating canonical source that composes them. Consumers (`dig-did`, `dig-merkle`, `dig-node`,
`dig-wallet-backend`, the lineage middleware) depend on THIS trait.

> Status: v0.0.0 bootstrap skeleton. The v0.1.0 unit fills in the trait surface + the full
> interface documentation. See `SPEC.md` for the normative contract.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
