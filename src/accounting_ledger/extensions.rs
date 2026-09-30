//! Atomic extension operations. Only the configured backend can authorize effects.
use super::*;
use crate::extensions::{
    self, Deposit, ExtendedUpdate, ExtensionPolicy, ExtensionStatement, ExtensionVerifier,
    Extensions, Inbox, PublicRecord,
};

impl<V: AccountProofVerifier> AccountLedger<V> {
    /// Pin a separate complete extension relation. Legacy handles then fail closed.
    /// Only host configuration may call this; never accept a verifier from a request.
    pub fn with_extensions(
        mut self,
        policy: ExtensionPolicy,
        verifier: impl ExtensionVerifier + 'static,
    ) -> Result<Self, Error> {
        policy.validate()?;
        let scope = verifier.scope();
        if scope == self.proof_scope
            || scope.circuit_digest == [0; 32]
            || scope.verifying_key_digest == [0; 32]
        {
            return Err(Error::PolicyMismatch);
        }
        let config =
            serde_json::to_vec(&(policy.clone(), &scope)).map_err(|_| Error::InvalidInput)?;
        let mut tx = self.connection.transaction()?;
        let old: Option<Vec<u8>> = tx.get(b"extensions")?;
        if old.as_ref().is_some_and(|v| v != &config) {
            return Err(Error::PolicyMismatch);
        }
        tx.put(b"extensions", &config)?;
        tx.commit()?;
        self.extensions = Some(Extensions {
            policy,
            verifier: Box::new(verifier),
            config,
        });
        Ok(self)
    }

    /// Verify the full extended account relation and consume the exact inbox frontier.
    pub fn apply_extended(
        &mut self,
        grant: &AdmissionGrant,
        authorization: &DeviceAuthorization,
        request: &AccountRequest,
        update: &ExtendedUpdate,
        clock: impl Fn() -> u64,
    ) -> Result<AccountAcceptance, Error> {
        self.apply_inner(grant, authorization, request, Some(update), clock)
    }

    /// Anonymous proof-authorized delivery: the punished member cannot veto it.
    /// Verification must prove recipient authority and a unique, already paid burn.
    pub fn deposit(&mut self, deposit: &Deposit, proof: &[u8]) -> Result<Inbox, Error> {
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if deposit.community != self.community
            || [
                deposit.recipient,
                deposit.nullifier,
                deposit.burn_nullifier,
                deposit.obligation,
            ]
            .contains(&[0; 32])
            || proof.is_empty()
            || proof.len() > self.policy.max_proof_bytes
        {
            return Err(Error::InvalidInput);
        }
        extensions.verifier.verify(
            &ExtensionStatement::Deposit {
                policy: extensions.policy.clone(),
                deposit: deposit.clone(),
            },
            proof,
        )?;
        let mut tx = self.connection.transaction()?;
        check_extension_config(&mut tx, Some(extensions))?;
        if tx
            .get::<Frontier>(&key(1, &[&deposit.recipient]))?
            .is_none()
        {
            return Err(Error::Admission);
        }
        let token_key = key(8, &[&deposit.nullifier]);
        let burn_key = key(9, &[&deposit.burn_nullifier]);
        // Markers retain a digest only: no deposit receipt or counterpart history.
        let digest: [u8; 32] =
            Sha256::digest(serde_json::to_vec(deposit).map_err(|_| Error::InvalidInput)?).into();
        if let Some(stored) = tx.get::<[u8; 32]>(&token_key)? {
            if stored != digest {
                return Err(Error::Replay);
            }
            return extensions::inbox(&mut tx, &deposit.recipient);
        }
        if tx.get::<bool>(&burn_key)?.is_some() {
            return Err(Error::Replay);
        }
        let previous = extensions::inbox(&mut tx, &deposit.recipient)?;
        let next = extensions::advance(&previous, deposit)?;
        tx.put(&token_key, &digest)?;
        tx.put(&burn_key, &true)?;
        tx.put(
            &key(6, &[&deposit.recipient, &next.sequence.to_be_bytes()]),
            &deposit.obligation,
        )?;
        tx.put(&key(5, &[&deposit.recipient]), &next)?;
        tx.commit()?;
        Ok(next)
    }

    /// Required gate for every first contact and every forum listing. A missing
    /// record or below-quorum claim without a proof cannot authorize either action.
    /// The caller supplies its expected context, independently of member input.
    pub fn check_record(
        &mut self,
        owner: [u8; 32],
        expected: &crate::extensions::RecordContext,
        record: &PublicRecord,
        proof: &[u8],
        clock: impl Fn() -> u64,
    ) -> Result<Option<[u16; 3]>, Error> {
        let now = clock();
        check_time(now, 0)?;
        if record.owner != owner || record.context != *expected || expected.challenge == [0; 32] {
            return Err(Error::Admission);
        }
        if expected.expires_at <= now
            || expected.expires_at > now.saturating_add(self.policy.max_authorization_seconds)
        {
            return Err(Error::Expired);
        }
        let result = self.public_record(record, proof)?;
        let completed = clock();
        check_time(completed, now)?;
        if completed >= expected.expires_at {
            return Err(Error::Expired);
        }
        Ok(result)
    }

    /// A pure proof check against current state. It records no display/request history.
    /// Stale records and unconsumed obligations are rejected before and after verification.
    pub(crate) fn public_record(
        &mut self,
        record: &PublicRecord,
        proof: &[u8],
    ) -> Result<Option<[u16; 3]>, Error> {
        let extensions = self
            .extensions
            .as_ref()
            .ok_or(Error::UnsupportedCapability)?;
        if record.community != self.community
            || proof.is_empty()
            || proof.len() > self.policy.max_proof_bytes
            || record
                .shares
                .is_some_and(|s| s.into_iter().map(u32::from).sum::<u32>() != 10_000)
        {
            return Err(Error::InvalidInput);
        }
        let check = |tx: &mut Transaction<'_>| -> Result<(), Error> {
            check_extension_config(tx, Some(extensions))?;
            let current: Frontier = tx.get(&key(1, &[&record.owner]))?.ok_or(Error::Admission)?;
            if current.version != record.version
                || current.state != record.state
                || extensions::inbox(tx, &record.owner)? != record.inbox
                || extensions::applied(tx, &record.owner)? != record.inbox
            {
                return Err(Error::Replay);
            }
            Ok(())
        };
        let mut tx = self.connection.transaction()?;
        check(&mut tx)?;
        tx.rollback()?;
        extensions.verifier.verify(
            &ExtensionStatement::Record {
                policy: extensions.policy.clone(),
                record: record.clone(),
            },
            proof,
        )?;
        let mut tx = self.connection.transaction()?;
        check(&mut tx)?;
        tx.rollback()?;
        Ok(record.shares)
    }

    /// Read opaque obligation commitments for an already authorized account.
    /// The service must authenticate the owner (as for status) before invoking it.
    /// Results are bounded and accessed with exact keys, never table scans.
    pub fn obligations(
        &mut self,
        owner: [u8; 32],
        after: u64,
        limit: u8,
    ) -> Result<(Inbox, Vec<[u8; 32]>), Error> {
        if limit == 0 || limit > 64 {
            return Err(Error::InvalidInput);
        }
        let mut tx = self.connection.transaction()?;
        let frontier = extensions::inbox(&mut tx, &owner)?;
        if after > frontier.sequence {
            return Err(Error::InvalidInput);
        }
        let end = after
            .saturating_add(u64::from(limit))
            .min(frontier.sequence);
        let mut values = Vec::new();
        for sequence in after + 1..=end {
            values.push(
                tx.get(&key(6, &[&owner, &sequence.to_be_bytes()]))?
                    .ok_or(Error::Storage)?,
            );
        }
        tx.rollback()?;
        Ok((frontier, values))
    }
}

pub(super) fn check_extension_config(
    tx: &mut Transaction<'_>,
    configured: Option<&Extensions>,
) -> Result<(), Error> {
    let stored: Option<Vec<u8>> = tx.get(b"extensions")?;
    if stored.as_deref() != configured.map(|e| e.config.as_slice()) {
        return Err(Error::UnsupportedCapability);
    }
    Ok(())
}
