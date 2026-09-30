//! Real issuer transactions with an explicitly test-only signed verifier boundary.
//! Signatures here test binding/atomicity; they are NOT a production ZK relation.
use super::*;
use cblc::extensions::*;

struct SignedBoundary(SigningKey);
impl ExtensionVerifier for SignedBoundary {
    fn scope(&self) -> AccountProofScope {
        AccountProofScope {
            circuit_digest: [51; 32],
            verifying_key_digest: [52; 32],
        }
    }
    fn verify(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        let sig = ed25519_dalek::Signature::from_slice(proof).map_err(|_| Error::Signature)?;
        self.0
            .verifying_key()
            .verify_strict(&serde_json::to_vec(statement).unwrap(), &sig)
            .map_err(|_| Error::Signature)
    }
}
fn backend() -> SignedBoundary {
    SignedBoundary(SigningKey::from_bytes(&[50; 32]))
}
fn settings() -> ExtensionPolicy {
    ExtensionPolicy {
        revision: 1,
        public_record_quorum: 5,
        change_token_cost: 1,
    }
}
fn proof(statement: &ExtensionStatement) -> Vec<u8> {
    backend()
        .0
        .sign(&serde_json::to_vec(statement).unwrap())
        .to_bytes()
        .to_vec()
}
fn signed_update(
    mut request: AccountRequest,
    update: &ExtendedUpdate,
    f: &Fixture,
) -> AccountRequest {
    request.proof_scope = backend().scope();
    request.proof = proof(&ExtensionStatement::Update {
        policy: settings(),
        account: Box::new(request.statement.clone()),
        update: update.clone(),
    });
    sign(&mut request, &f.device);
    request
}
fn deposit_for(request: &AccountRequest, id: u8) -> Deposit {
    Deposit {
        community: request.statement.community,
        recipient: request.statement.owner,
        nullifier: [id; 32],
        burn_nullifier: [id + 1; 32],
        obligation: [id + 2; 32],
    }
}
fn deposit_proof(value: &Deposit) -> Vec<u8> {
    proof(&ExtensionStatement::Deposit {
        policy: settings(),
        deposit: value.clone(),
    })
}

#[test]
fn punishment_cannot_be_ignored_replayed_or_reset_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger");
    let f = Fixture::new();
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend())
        .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let mut update = ExtendedUpdate {
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 120,
        )
        .unwrap();
    let token = deposit_for(&first, 60);
    let inbox = ledger.deposit(&token, &deposit_proof(&token)).unwrap();
    assert_eq!(
        ledger.deposit(&token, &deposit_proof(&token)).unwrap(),
        inbox
    );
    let mut reused = token.clone();
    reused.nullifier = [80; 32];
    assert_eq!(
        ledger.deposit(&reused, &deposit_proof(&reused)),
        Err(Error::Replay)
    );
    let mut tampered = token.clone();
    tampered.obligation = [81; 32];
    assert_eq!(
        ledger.deposit(&tampered, &deposit_proof(&token)),
        Err(Error::Signature)
    );
    drop(ledger);
    let mut ledger = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend())
        .unwrap();
    let next = signed_update(successor(&first, &f, 11), &update, &f);
    assert_eq!(
        ledger.apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &update,
            || 130
        ),
        Err(Error::Replay)
    );
    // The old entry point cannot bypass the inbox, even on a stale handle.
    let mut old = open(&path, &f, StorageOnlyVerifier::default());
    assert_eq!(
        old.apply(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &genesis(&f),
            || 130
        ),
        Err(Error::UnsupportedCapability)
    );
    assert_eq!(
        ledger.obligations(first.statement.owner, 0, 1).unwrap(),
        (inbox.clone(), vec![token.obligation])
    );
    update.inbox = inbox;
    let next = signed_update(successor(&first, &f, 12), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &update,
            || 130,
        )
        .unwrap();
    assert_eq!(
        ledger.apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 130
        ),
        Err(Error::Replay)
    );
}

#[test]
fn relative_record_is_bound_to_quorum_current_state_and_every_obligation() {
    let f = Fixture::new();
    let mut ledger = AccountLedger::with_store(
        cblc::storage::MemoryStore::default(),
        f.trust.clone(),
        policy(),
        StorageOnlyVerifier::default(),
        SigningKey::from_bytes(&[9; 32]),
    )
    .unwrap()
    .with_extensions(settings(), backend())
    .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let update = ExtendedUpdate {
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 120,
        )
        .unwrap();
    let mut record = PublicRecord {
        context: RecordContext {
            purpose: RecordUse::ForumListing,
            challenge: [1; 32],
            expires_at: 180,
        },
        community: first.statement.community,
        owner: first.statement.owner,
        version: 0,
        state: first.statement.next_state,
        inbox: Inbox::default(),
        shares: None,
    };
    let sign_record = |r: &PublicRecord| {
        proof(&ExtensionStatement::Record {
            policy: settings(),
            record: r.clone(),
        })
    };
    assert_eq!(
        ledger
            .check_record(
                record.owner,
                &record.context,
                &record,
                &sign_record(&record),
                || 130
            )
            .unwrap(),
        None
    );
    record.shares = Some([6000, 2000, 2000]);
    let signed = sign_record(&record);
    assert_eq!(
        ledger
            .check_record(record.owner, &record.context, &record, &signed, || 130)
            .unwrap(),
        record.shares
    );
    record.shares = Some([5000, 3000, 2000]);
    assert_eq!(
        ledger.check_record(record.owner, &record.context, &record, &signed, || 130),
        Err(Error::Signature)
    );
    record.shares = Some([10000, 10000, 0]);
    assert_eq!(
        ledger.check_record(
            record.owner,
            &record.context,
            &record,
            &sign_record(&record),
            || 130
        ),
        Err(Error::InvalidInput)
    );
    record.shares = Some([6000, 2000, 2000]);
    let token = deposit_for(&first, 70);
    ledger.deposit(&token, &deposit_proof(&token)).unwrap();
    assert_eq!(
        ledger.check_record(record.owner, &record.context, &record, &signed, || 130),
        Err(Error::Replay)
    );
    let wire = serde_json::to_value(&record).unwrap();
    assert!(wire.get("counts").is_none());
    assert!(wire.get("total").is_none());
    let mut wrong = settings();
    wrong.public_record_quorum = 1;
    assert_ne!(
        proof(&ExtensionStatement::Record {
            policy: wrong,
            record
        }),
        signed
    );
}

#[test]
fn change_token_is_a_bound_single_successor_spend() {
    let dir = tempfile::tempdir().unwrap();
    let f = Fixture::new();
    let mut ledger = open(&dir.path().join("db"), &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend())
        .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let initial = ExtendedUpdate {
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &initial, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &initial,
            || 120,
        )
        .unwrap();
    let change = ExtendedUpdate {
        inbox: Inbox::default(),
        effect: Effect::Change { binding: [90; 32] },
    };
    let next = signed_update(successor(&first, &f, 11), &change, &f);
    let accepted = ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &change,
            || 130,
        )
        .unwrap();
    assert_eq!(
        ledger
            .apply_extended(
                &f.grant(7, &f.device),
                &f.authorize(7, &f.device),
                &next,
                &change,
                || 130
            )
            .unwrap(),
        accepted
    );
    let operator = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    verify_extended_acceptance(&accepted, &next, &change, &settings(), &operator).unwrap();
    let changed = ExtendedUpdate {
        effect: Effect::Change { binding: [91; 32] },
        ..change
    };
    assert_eq!(
        verify_extended_acceptance(&accepted, &next, &changed, &settings(), &operator),
        Err(Error::Replay)
    );
    assert_eq!(
        ledger.apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &next,
            &changed,
            || 130
        ),
        Err(Error::Replay)
    );
}

struct PausedExtension {
    entered: Sender<()>,
    release: Receiver<()>,
}
impl ExtensionVerifier for PausedExtension {
    fn scope(&self) -> AccountProofScope {
        backend().scope()
    }
    fn verify(&self, statement: &ExtensionStatement, proof: &[u8]) -> Result<(), Error> {
        backend().verify(statement, proof)?;
        self.entered.send(()).map_err(|_| Error::CryptoProvider)?;
        self.release
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| Error::CryptoProvider)
    }
}
#[test]
fn a_deposit_racing_verification_cannot_be_skipped_at_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let f = Fixture::new();
    let mut fast = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), backend())
        .unwrap();
    fast.admit_checkpoint(0, fr(8)).unwrap();
    let update = ExtendedUpdate {
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    fast.apply_extended(
        &f.grant(7, &f.device),
        &f.authorize(7, &f.device),
        &first,
        &update,
        || 120,
    )
    .unwrap();
    let next = signed_update(successor(&first, &f, 11), &update, &f);
    let (entered, observed) = mpsc::channel();
    let (resume, release) = mpsc::channel();
    let mut slow = open(&path, &f, StorageOnlyVerifier::default())
        .with_extensions(settings(), PausedExtension { entered, release })
        .unwrap();
    let g = f.grant(7, &f.device);
    let a = f.authorize(7, &f.device);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| slow.apply_extended(&g, &a, &next, &update, || 130));
        observed.recv_timeout(Duration::from_secs(10)).unwrap();
        let token = deposit_for(&first, 60);
        let deposited = fast.deposit(&token, &deposit_proof(&token));
        resume.send(()).unwrap();
        assert_eq!(deposited.unwrap().sequence, 1);
        assert_eq!(worker.join().unwrap(), Err(Error::Replay));
    });
    assert_eq!(
        inspect(&path)
            .query_row("SELECT version FROM frontiers", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn contact_and_listing_require_fresh_current_record_even_below_quorum() {
    let f = Fixture::new();
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = open(
        &dir.path().join("record"),
        &f,
        StorageOnlyVerifier::default(),
    )
    .with_extensions(settings(), backend())
    .unwrap();
    ledger.admit_checkpoint(0, fr(8)).unwrap();
    let update = ExtendedUpdate {
        inbox: Inbox::default(),
        effect: Effect::Update,
    };
    let first = signed_update(genesis(&f), &update, &f);
    ledger
        .apply_extended(
            &f.grant(7, &f.device),
            &f.authorize(7, &f.device),
            &first,
            &update,
            || 120,
        )
        .unwrap();
    for purpose in [RecordUse::FirstContact, RecordUse::ForumListing] {
        let context = RecordContext {
            purpose,
            challenge: [23; 32],
            expires_at: 180,
        };
        let record = PublicRecord {
            context: context.clone(),
            community: first.statement.community,
            owner: first.statement.owner,
            version: 0,
            state: first.statement.next_state,
            inbox: Inbox::default(),
            shares: None,
        };
        let signed = proof(&ExtensionStatement::Record {
            policy: settings(),
            record: record.clone(),
        });
        assert_eq!(
            ledger.check_record(record.owner, &context, &record, &[], || 130),
            Err(Error::InvalidInput)
        );
        assert_eq!(
            ledger.check_record(record.owner, &context, &record, &signed, || 130),
            Ok(None)
        );
        assert_eq!(
            ledger.check_record(record.owner, &context, &record, &signed, || 180),
            Err(Error::Expired)
        );
        let mut other = context.clone();
        other.challenge[0] ^= 1;
        assert_eq!(
            ledger.check_record(record.owner, &other, &record, &signed, || 130),
            Err(Error::Admission)
        );
        other = context.clone();
        other.purpose = if purpose == RecordUse::FirstContact {
            RecordUse::ForumListing
        } else {
            RecordUse::FirstContact
        };
        assert_eq!(
            ledger.check_record(record.owner, &other, &record, &signed, || 130),
            Err(Error::Admission)
        );
        let mut stale = record.clone();
        stale.version += 1;
        assert_eq!(
            ledger.check_record(record.owner, &context, &stale, &signed, || 130),
            Err(Error::Replay)
        );
    }
}
