# Implemented balance contract

cblc is a server facade, called by cvld. It owns reciprocity v2 policy; cssr owns
atomic record mechanics, cvfy the bounded proof-verifier process, and czkp
encoding/crypto adapters. The holder keeps openings, counterpart data and receipts.

The account API retains the existing signed v2 public statement and policy
encoding. Existing domain strings stay unchanged to preserve proofs/signatures.
The issuer checks admission and root-authorized device signatures, one genesis,
current common enrollment checkpoint, proof/circuit/VK scope, immutable policy,
clock monotonicity, deadlines, previous version/commitment and spent markers.
It rechecks mutable predicates after proof verification under the write lock.
There is no default accepting proof verifier.

Only the current commitment/version, its bound root key and policy, the latest
signed acceptance, settlement markers, common checkpoints and a community-wide
clock floor persist. The last acceptance supports exact retry; a superseded
acceptance is discarded. Status authenticates a fresh challenge and returns
no private opening. No request log, login date or historical receipt table exists.

The small AccountStorage trait is implemented by cssr memory and crlt/libSQL
stores. All SQL is namespace-scoped and index-backed; one database per community
is the deployment contract. `with_store` permits service composition using a
pre-scoped crlt community and the shared migration history. Standalone `open`
creates the issuer schema. Async services call the synchronous facade through
a blocking executor.

Reciprocity v2 preserves reservations in both directions, prepared/active
separation, Answer refunds, recipient Close, fixed original outgoing deadlines,
one common budget, admission windows, bounded refill, no catch-up issuance and
prospective waiting-period tuning. See reciprocity-policy.md for the relation.
Tests copied from cfrm retain their behavioral assertions except historical
acceptance counts/recovery, deliberately changed to the current-only boundary.

No plaintext allocation ledger or holder/prover API is exported. Historical
holder and browser harnesses are test fixtures, not deployment code. Existing
proof artifacts do not yet support punishment, change tokens or public counters;
extension activation must be separate from v2 acceptance.

Extension issuer APIs (`with_extensions`, `apply_extended`, `deposit`,
`obligations`, `public_record`) and their activation boundary are specified in
[EXTENSIONS.md](EXTENSIONS.md). They are not enabled by the legacy v2 verifier.
