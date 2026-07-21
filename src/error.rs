//! The typed error every registry-participating [`ChainSource`](crate::ChainSource) reports.
//!
//! Every variant means the same thing: **the source could not reliably answer**, so a consumer
//! MUST fail closed (treat it as "unknown", never as an absence or a permissive default). The
//! *absence* of a coin/spend/lineage is NEVER an error — that is `Ok(None)`. This split is the
//! crux of the fail-closed contract (SPEC §3): `Ok(None)` = "the chain genuinely has no such
//! thing"; `Err(_)` = "I don't know, and you must not assume".

use thiserror::Error;

/// The reason a [`ChainSource`](crate::ChainSource) could not reliably answer a read.
///
/// This is the recommended `type Error` for any provider that participates in the shared registry,
/// so aggregators can reason about failures uniformly. It is `#[non_exhaustive]`: new failure
/// modes may be added in a minor release, so consumers MUST include a wildcard match arm.
///
/// Every variant is a "could not reliably answer" signal — consumers fail closed on all of them.
/// The absence of a queried coin/spend/lineage is expressed as `Ok(None)`, never as an error here.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainSourceError {
    /// A transport/connection failure reaching the underlying backend (socket, HTTP, IPC). The
    /// message is the backend's own, carried verbatim for diagnostics.
    #[error("chain source transport error: {0}")]
    Transport(String),

    /// The backend responded, but the payload could not be parsed into the expected chain type
    /// (a truncated coin record, an undecodable spend). The read is untrustworthy → fail closed.
    #[error("malformed chain data: {0}")]
    Malformed(String),

    /// The backend does not support this query at all (e.g. a light source with no timestamp
    /// index). The `&'static str` names the unsupported capability.
    #[error("unsupported chain query: {0}")]
    Unsupported(&'static str),

    /// The read did not complete within the source's deadline. Whether the answer would have been
    /// present is unknown → fail closed.
    #[error("chain source request timed out")]
    Timeout,

    /// The backend refused the read for rate-limiting. The answer is unknown → fail closed.
    #[error("chain source rate limited the request")]
    RateLimited,

    /// No provider was available to answer (an empty/exhausted registry). Distinct from `Ok(None)`:
    /// the chain was never consulted, so the answer is unknown → fail closed.
    #[error("no chain source provider available")]
    NoProvider,

    /// The backend returned more records than the consumer's hostile-input bound allows.
    ///
    /// Distinct from [`Malformed`](Self::Malformed): each record may be individually well-formed, but
    /// the *count* exceeds the cap the consumer will accept, so the read is refused → fail closed. This
    /// lets a consumer distinguish "the data is corrupt" from "the response is too large".
    #[error("chain source returned {count} records, exceeding the {limit}-record cap")]
    TooManyRecords {
        /// The number of records the backend returned.
        count: usize,
        /// The maximum number of records the consumer will accept.
        limit: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_many_records_display_reports_count_and_limit() {
        let err = ChainSourceError::TooManyRecords {
            count: 100_001,
            limit: 100_000,
        };
        assert_eq!(
            err.to_string(),
            "chain source returned 100001 records, exceeding the 100000-record cap"
        );
    }

    #[test]
    fn too_many_records_is_distinct_from_malformed() {
        let too_many = ChainSourceError::TooManyRecords { count: 5, limit: 1 };
        let malformed = ChainSourceError::Malformed("truncated coin record".to_string());
        assert_ne!(too_many, malformed);
        assert!(matches!(too_many, ChainSourceError::TooManyRecords { .. }));
        assert!(!matches!(too_many, ChainSourceError::Malformed(_)));
    }
}
