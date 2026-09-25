# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Balance library: accounts, events and policies for zero-knowledge accounting, managed by cvld.
- Facade plus policies over `cssr` (issuer) and `cvfy` (verifier); `cvld` manages it only through this facade.
- Server only: no client or prover code (that is `cwlt`).
- Never stores balances, counterparts, receipts or history; only the current commitment, version and settlement markers.
- Never knows its holders.
- This crate is FSL-1.1-ALv2 (own substantive logic). Commodity wrappers around established libraries belong in LGPL crates in corbet-foss, not here.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use GHA, Crow as fallback.
