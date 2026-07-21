# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.2.0] - 2026-07-21

### Features
- Add `ChainSourceError::TooManyRecords { count, limit }` — a dedicated over-cap record-count error, distinct from `Malformed` (#1352)

## [0.1.0] - 2026-07-19

### Features
- Canonical ChainSource provider interface (trait + query types + KATs) (#1)

### Chores
- Bootstrap dig-chainsource-interface (gate infra + v0.0.0 skeleton)


