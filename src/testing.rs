//! [`MockChainSource`] — an in-memory [`ChainSource`](crate::ChainSource) for tests, gated behind
//! the `testing` feature so consumer crates can reuse it to exercise their trust logic.
//!
//! It is a pure lookup table over caller-loaded coins/spends/lineages plus an optional forced-error
//! switch that drives the fail-closed paths. It performs no I/O and holds no keys.

use std::collections::HashMap;

use chia_protocol::{Bytes32, CoinSpend};

use crate::error::ChainSourceError;
use crate::lineage::SingletonLineage;
use crate::provider::{ProviderId, ProviderInfo, ProviderKind};
use crate::record::CoinRecord;
use crate::source::{ChainSource, ChainSourceProvider};

/// An in-memory chain source for tests: load coins, spends, and lineages, then read them back
/// through the real [`ChainSource`] surface.
///
/// A consumer under test wires its trust logic to a `MockChainSource`, loads a fixture chain, and
/// asserts the outcome — including that a forced error ([`fail_with`](Self::fail_with)) fails
/// closed rather than degrading to a value.
#[derive(Debug, Default, Clone)]
pub struct MockChainSource {
    coins: HashMap<Bytes32, CoinRecord>,
    spends: HashMap<Bytes32, CoinSpend>,
    lineages: HashMap<Bytes32, SingletonLineage>,
    timestamps: HashMap<u32, u64>,
    peak: Option<u32>,
    forced_error: Option<ChainSourceError>,
}

impl MockChainSource {
    /// A new, empty mock chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads a coin record, keyed by its coin id.
    pub fn with_coin(mut self, coin_id: Bytes32, record: CoinRecord) -> Self {
        self.coins.insert(coin_id, record);
        self
    }

    /// Loads the spend that SPENT `coin_id` (as returned by [`ChainSource::coin_spend`]).
    pub fn with_spend(mut self, coin_id: Bytes32, spend: CoinSpend) -> Self {
        self.spends.insert(coin_id, spend);
        self
    }

    /// Loads the singleton lineage for `launcher_id`.
    pub fn with_lineage(mut self, launcher_id: Bytes32, lineage: SingletonLineage) -> Self {
        self.lineages.insert(launcher_id, lineage);
        self
    }

    /// Sets the timestamp reported for block `height`.
    pub fn with_timestamp(mut self, height: u32, timestamp: u64) -> Self {
        self.timestamps.insert(height, timestamp);
        self
    }

    /// Sets the reported peak height.
    pub fn with_peak(mut self, height: u32) -> Self {
        self.peak = Some(height);
        self
    }

    /// Forces every read to fail with `error`, to drive the consumer's fail-closed paths.
    pub fn fail_with(mut self, error: ChainSourceError) -> Self {
        self.forced_error = Some(error);
        self
    }

    /// Returns the forced error (as an `Err`) when one is armed, else `Ok(())`.
    fn guard(&self) -> Result<(), ChainSourceError> {
        match &self.forced_error {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }
}

impl ChainSource for MockChainSource {
    type Error = ChainSourceError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        self.guard()?;
        Ok(self.coins.get(&coin_id).cloned())
    }

    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.guard()?;
        Ok(self
            .coins
            .values()
            .filter(|record| record.coin.puzzle_hash == puzzle_hash)
            .filter(|record| include_spent || !record.is_spent())
            .cloned()
            .collect())
    }

    fn coin_records_by_parent(
        &self,
        parent_coin_id: Bytes32,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        self.guard()?;
        Ok(self
            .coins
            .values()
            .filter(|record| record.coin.parent_coin_info == parent_coin_id)
            .cloned()
            .collect())
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        self.guard()?;
        Ok(self.spends.get(&coin_id).cloned())
    }

    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        self.guard()?;
        Ok(self.lineages.get(&launcher_id).cloned())
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        self.guard()?;
        Ok(self.peak)
    }

    fn block_timestamp(&self, height: u32) -> Result<Option<u64>, Self::Error> {
        self.guard()?;
        Ok(self.timestamps.get(&height).copied())
    }
}

impl ChainSourceProvider for MockChainSource {
    fn provider_info(&self) -> ProviderInfo {
        ProviderInfo {
            id: ProviderId(std::borrow::Cow::Borrowed("mock")),
            kind: ProviderKind::Custom,
            priority: i32::MAX,
            trustless: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::{Coin, Program};

    fn coin(parent: [u8; 32], puzzle_hash: [u8; 32]) -> Coin {
        Coin::new(Bytes32::new(parent), Bytes32::new(puzzle_hash), 1)
    }

    fn record(coin: Coin, spent_height: Option<u32>) -> CoinRecord {
        CoinRecord {
            coin,
            confirmed_height: Some(1),
            spent_height,
            timestamp: None,
            coinbase: false,
        }
    }

    #[test]
    fn reads_loaded_coins_spends_lineages_and_context() {
        let parent = coin([0x01; 32], [0x22; 32]);
        let child = coin(parent.coin_id().into(), [0x33; 32]);
        let launcher = Bytes32::new([0x09; 32]);

        let source = MockChainSource::new()
            .with_coin(parent.coin_id(), record(parent, None))
            .with_coin(child.coin_id(), record(child, None))
            .with_spend(
                parent.coin_id(),
                CoinSpend::new(parent, Program::from(vec![1]), Program::from(vec![0x80])),
            )
            .with_lineage(launcher, SingletonLineage::single(launcher))
            .with_timestamp(7, 1_700_000_000)
            .with_peak(7);

        // Direct reads.
        assert_eq!(
            source.coin_record(parent.coin_id()),
            Ok(Some(record(parent, None)))
        );
        assert!(source.coin_spend(parent.coin_id()).unwrap().is_some());
        assert_eq!(source.peak_height(), Ok(Some(7)));
        assert_eq!(source.block_timestamp(7), Ok(Some(1_700_000_000)));
        assert_eq!(source.block_timestamp(8), Ok(None));
        assert_eq!(
            source.resolve_singleton_lineage(launcher),
            Ok(Some(SingletonLineage::single(launcher)))
        );

        // The default parent_spend composes coin_record + coin_spend to find the creating spend.
        assert!(source.parent_spend(child.coin_id()).unwrap().is_some());
        // A coin with no record yields no parent spend (Ok(None), not an error).
        assert_eq!(source.parent_spend(Bytes32::new([0xFF; 32])), Ok(None));
    }

    #[test]
    fn puzzle_hash_and_parent_queries_filter_correctly() {
        let ph = [0x22u8; 32];
        let unspent = coin([0x01; 32], ph);
        let spent = coin([0x02; 32], ph);
        let child = coin(unspent.coin_id().into(), [0x44; 32]);

        let source = MockChainSource::new()
            .with_coin(unspent.coin_id(), record(unspent, None))
            .with_coin(spent.coin_id(), record(spent, Some(9)))
            .with_coin(child.coin_id(), record(child, None));

        // include_spent=false drops the spent coin; =true keeps both.
        assert_eq!(
            source
                .coin_records_by_puzzle_hash(Bytes32::new(ph), false)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            source
                .coin_records_by_puzzle_hash(Bytes32::new(ph), true)
                .unwrap()
                .len(),
            2
        );
        // by_parent finds the one child of `unspent`.
        let by_parent = source.coin_records_by_parent(unspent.coin_id()).unwrap();
        assert_eq!(by_parent.len(), 1);
        assert_eq!(by_parent[0].coin, child);
    }

    #[test]
    fn forced_error_fails_every_read_closed() {
        let source = MockChainSource::new().fail_with(ChainSourceError::Timeout);
        let id = Bytes32::new([0x01; 32]);

        assert_eq!(source.coin_record(id), Err(ChainSourceError::Timeout));
        assert!(source.coin_records_by_puzzle_hash(id, true).is_err());
        assert!(source.coin_records_by_parent(id).is_err());
        assert!(source.coin_spend(id).is_err());
        assert!(source.parent_spend(id).is_err());
        assert!(source.resolve_singleton_lineage(id).is_err());
        assert!(source.peak_height().is_err());
        assert!(source.block_timestamp(1).is_err());
    }
}
