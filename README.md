# cblc

**Balance library for zero-knowledge accounting.**

`cblc` will be the server-side balance library: accounts with balances, events that move them, and policies for the normal range (start, refill, cap, decay) and for accounts out of tune. Many balance objects (message budget, invites, quotas, credits) are built on it. Zero-knowledge accounting is the standard; policies are its main logic.

Status: name reserved, no implementation yet.

## Boundaries

What it does:

- Facade plus policies over `cssr` (issuer) and `cvfy` (verifier); `cvld` manages it only through this facade.

What it never does:

- Server only: no client or prover code (that is `cwlt`).
- Never stores balances, counterparts, receipts or history; only the current commitment, version and settlement markers.
- Never knows its holders.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md)
(FSL-1.1-ALv2).
