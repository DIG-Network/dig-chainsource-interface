//! Provider-registration descriptors: how a concrete [`ChainSource`](crate::ChainSource) describes
//! itself to the aggregating registry (its identity, kind, try-order priority, and trust posture).

use std::borrow::Cow;

/// A stable, human-readable identifier for a chain-source provider (e.g. `"coinset.org"`,
/// `"local-node"`). Borrowed-or-owned so a static provider name costs no allocation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderId(pub Cow<'static, str>);

/// The category of a chain-source provider, so the registry can order and trust-weight providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// A public oracle/gateway (e.g. coinset.org) — convenient, but trusted only as chain data.
    PublicOracle,
    /// A local full/wallet node the operator controls — the most trustworthy source.
    LocalNode,
    /// Chain data served over the DIG peer network.
    DigPeers,
    /// Any other provider not covered by the categories above.
    Custom,
}

/// The self-description a provider hands the registry when it registers.
///
/// The registry uses [`priority`](Self::priority) to order providers (lower = tried first) and
/// [`trustless`](Self::trustless) to reason about whether an answer needs cross-checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderInfo {
    /// The provider's stable identifier.
    pub id: ProviderId,
    /// The provider's category.
    pub kind: ProviderKind,
    /// Try-order priority — lower is tried first.
    pub priority: i32,
    /// Whether the provider's answers are independently verifiable (e.g. merkle/lineage-proved)
    /// rather than taken on trust.
    pub trustless: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_info_carries_its_descriptor() {
        let info = ProviderInfo {
            id: ProviderId(Cow::Borrowed("coinset.org")),
            kind: ProviderKind::PublicOracle,
            priority: 10,
            trustless: false,
        };
        assert_eq!(info.id, ProviderId(Cow::Borrowed("coinset.org")));
        assert_eq!(info.kind, ProviderKind::PublicOracle);
        assert_eq!(info.priority, 10);
        assert!(!info.trustless);
    }
}
