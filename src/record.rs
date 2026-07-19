//! [`CoinRecord`] — a coin plus the chain metadata a consumer needs to reason about it: where it
//! was confirmed, whether/when it was spent, its block timestamp, and whether it is a coinbase.

use chia_protocol::{Coin, CoinState};

/// A coin together with its on-chain lifecycle metadata, as read from a [`ChainSource`](crate::ChainSource).
///
/// This is the canonical result shape for coin reads across the ecosystem. Heights and the
/// timestamp are `Option` because a light source may know a coin exists without knowing its block
/// context — `None` means "not known by this source", never "does not exist".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinRecord {
    /// The coin itself (parent, puzzle hash, amount).
    pub coin: Coin,
    /// The block height at which the coin was created/confirmed, if known.
    pub confirmed_height: Option<u32>,
    /// The block height at which the coin was spent, if it has been spent and the source knows it.
    pub spent_height: Option<u32>,
    /// The Unix timestamp of the confirming block, if the source resolves timestamps.
    pub timestamp: Option<u64>,
    /// Whether the coin is a coinbase (farmer/pool reward) coin.
    pub coinbase: bool,
}

impl CoinRecord {
    /// Whether the coin has been spent (i.e. a spent height is known).
    pub fn is_spent(&self) -> bool {
        self.spent_height.is_some()
    }

    /// Builds a [`CoinRecord`] from a wallet-protocol [`CoinState`], mapping
    /// `created_height -> confirmed_height` and preserving `spent_height`.
    ///
    /// A `CoinState` carries no timestamp or coinbase flag, so those become `None`/`false` — a
    /// source that resolves them fills them in via the fuller read path.
    pub fn from_coin_state(state: CoinState) -> Self {
        Self {
            coin: state.coin,
            confirmed_height: state.created_height,
            spent_height: state.spent_height,
            timestamp: None,
            coinbase: false,
        }
    }
}

impl From<CoinState> for CoinRecord {
    fn from(state: CoinState) -> Self {
        Self::from_coin_state(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_protocol::Bytes32;

    fn sample_coin() -> Coin {
        Coin::new(Bytes32::new([1u8; 32]), Bytes32::new([2u8; 32]), 7)
    }

    #[test]
    fn from_coin_state_maps_created_to_confirmed_and_defaults() {
        let state = CoinState {
            coin: sample_coin(),
            spent_height: Some(200),
            created_height: Some(100),
        };
        let record = CoinRecord::from(state);

        assert_eq!(record.coin, sample_coin());
        assert_eq!(record.confirmed_height, Some(100));
        assert_eq!(record.spent_height, Some(200));
        assert_eq!(record.timestamp, None);
        assert!(!record.coinbase);
        assert!(record.is_spent());
    }

    #[test]
    fn unspent_record_reports_not_spent() {
        let state = CoinState {
            coin: sample_coin(),
            spent_height: None,
            created_height: Some(100),
        };
        let record = CoinRecord::from_coin_state(state);
        assert!(!record.is_spent());
    }
}
