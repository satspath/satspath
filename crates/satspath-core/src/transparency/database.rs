use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::privacy::{canonical_identifier, identifier_hash};
use crate::registry::Registry;
use crate::{Result, SatsPathError, SignedPaymentProfile};

use super::{
    IdentifierAttestation, NameEvent, TransparencyCheckpoint, TransparencyError, TransparencyLog,
};

const DB_FILE: &str = "satspath-transparency-v1.sqlite3";

fn db_error(error: impl std::fmt::Display) -> SatsPathError {
    SatsPathError::RegistryError(format!("transparency database: {error}"))
}

pub struct TransactionalTransparencyStore {
    home: PathBuf,
    path: PathBuf,
    log_id: String,
    read_only: bool,
}

impl TransactionalTransparencyStore {
    pub fn open(home: &Path) -> Result<Self> {
        std::fs::create_dir_all(home)?;
        let path = home.join(DB_FILE);
        let mut connection = Connection::open(&path).map_err(db_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(db_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(db_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS profiles(identifier_hash TEXT PRIMARY KEY, alias TEXT NOT NULL, profile_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS name_events(event_index INTEGER PRIMARY KEY, signed_event_hash TEXT NOT NULL UNIQUE, identifier_hash TEXT NOT NULL, event_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS checkpoints(checkpoint_index INTEGER PRIMARY KEY, checkpoint_hash TEXT NOT NULL UNIQUE, log_size INTEGER NOT NULL, checkpoint_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS pins(log_id TEXT PRIMARY KEY, pin_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS anchors(txid TEXT PRIMARY KEY, anchor_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS identifier_attestations(attestation_hash TEXT PRIMARY KEY, attestation_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS operator_state(log_id TEXT PRIMARY KEY, operator_pubkey TEXT, operator_sequence INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS lab_reservations(alias TEXT PRIMARY KEY, challenge_json TEXT NOT NULL, nonce TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS replica_heads(log_id TEXT PRIMARY KEY, pin_json TEXT NOT NULL, policy_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS replica_envelopes(log_id TEXT NOT NULL, identifier TEXT NOT NULL, envelope_json TEXT NOT NULL, PRIMARY KEY(log_id,identifier));
             CREATE TABLE IF NOT EXISTS replica_consistency(log_id TEXT NOT NULL, old_size INTEGER NOT NULL, new_size INTEGER NOT NULL, proof_json TEXT NOT NULL, PRIMARY KEY(log_id,old_size,new_size));
             CREATE TABLE IF NOT EXISTS replica_faults(log_id TEXT PRIMARY KEY, reason TEXT NOT NULL);
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);"
        ).map_err(db_error)?;
        let log_id: Option<String> = transaction
            .query_row("SELECT log_id FROM operator_state LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(db_error)?;
        let log_id = log_id.unwrap_or_else(|| format!("satspath:local:{}", uuid::Uuid::new_v4()));
        transaction
            .execute(
                "INSERT OR IGNORE INTO operator_state(log_id, operator_sequence) VALUES (?1, 0)",
                [&log_id],
            )
            .map_err(db_error)?;
        transaction.commit().map_err(db_error)?;
        let store = Self {
            home: home.to_owned(),
            path,
            log_id,
            read_only: false,
        };
        store.load_log()?;
        Ok(store)
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Open existing state without migrations, directory creation or write access.
    pub fn open_read_only(home: &Path) -> Result<Self> {
        let path = home.join(DB_FILE);
        let connection =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(db_error)?;
        let log_id = connection
            .query_row("SELECT log_id FROM operator_state LIMIT 1", [], |row| {
                row.get(0)
            })
            .map_err(db_error)?;
        let store = Self {
            home: home.to_owned(),
            path,
            log_id,
            read_only: true,
        };
        store.load_log()?;
        Ok(store)
    }

    /// Look up a local pin without initializing missing state. Existing corrupt
    /// or unreadable state is an error, not an absent profile.
    pub fn profile_read_only(home: &Path, alias: &str) -> Result<Option<SignedPaymentProfile>> {
        if !home.join(DB_FILE).try_exists()? {
            return Ok(None);
        }
        Self::open_read_only(home)?.profile(alias)
    }

    fn connection(&self) -> Result<Connection> {
        if self.read_only {
            return Connection::open_with_flags(
                &self.path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(db_error);
        }
        Connection::open(&self.path).map_err(db_error)
    }

    pub fn replica_pin(&self, log_id: &str) -> Result<Option<super::PinnedCheckpoint>> {
        let raw: Option<String> = self
            .connection()?
            .query_row(
                "SELECT pin_json FROM replica_heads WHERE log_id=?1",
                [log_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        raw.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }

    pub fn quarantine_replica(&self, log_id: &str, reason: &str) -> Result<()> {
        self.connection()?
            .execute(
                "INSERT OR REPLACE INTO replica_faults(log_id,reason) VALUES (?1,?2)",
                params![log_id, reason],
            )
            .map_err(db_error)?;
        Ok(())
    }

    /// Store only fully verified S2S envelopes at ONE checkpoint. The head and
    /// every envelope commit atomically; no local authority signatures are made.
    pub fn commit_replica_batch(
        &self,
        trusted: &super::NamespaceDescriptor,
        envelopes: &[super::ResolutionEnvelope],
        now: i64,
    ) -> Result<()> {
        if envelopes.is_empty() || envelopes.len() > 32 {
            return Err(db_error("replica batch requires 1..32 envelopes"));
        }
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let old: Option<(String, String)> = tx
            .query_row(
                "SELECT pin_json,policy_json FROM replica_heads WHERE log_id=?1",
                [&trusted.log_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        let policy = serde_json::to_string(trusted)?;
        let quarantined: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM replica_faults WHERE log_id=?1)",
                [&trusted.log_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if quarantined {
            return Err(db_error(
                "replica quarantined; operator investigation required",
            ));
        }
        if old.as_ref().is_some_and(|(_, p)| *p != policy) {
            return Err(db_error(
                "replica policy changed; explicit migration required",
            ));
        }
        let previous: Option<super::PinnedCheckpoint> =
            old.map(|(pin, _)| serde_json::from_str(&pin)).transpose()?;
        let checkpoint = &envelopes[0].checkpoint;
        let head_hash = checkpoint.checkpoint_hash()?;
        let mut names = std::collections::HashSet::new();
        for envelope in envelopes {
            if !names.insert(&envelope.identifier)
                || serde_json::to_vec(envelope)?.len() > 65_536
                || envelope.checkpoint.checkpoint_hash()? != head_hash
            {
                return Err(db_error(
                    "duplicate, oversized or mixed-checkpoint replica batch",
                ));
            }
            crate::lab::verify_resolution(
                &envelope.identifier,
                trusted,
                envelope,
                previous.as_ref(),
                now,
            )?;
        }
        // Invalidate the entire prior view so no old alias survives a new head.
        tx.execute(
            "DELETE FROM replica_envelopes WHERE log_id=?1",
            [&trusted.log_id],
        )
        .map_err(db_error)?;
        for envelope in envelopes {
            tx.execute(
                "INSERT INTO replica_envelopes(log_id,identifier,envelope_json) VALUES (?1,?2,?3)",
                params![
                    trusted.log_id,
                    envelope.identifier,
                    serde_json::to_string(envelope)?
                ],
            )
            .map_err(db_error)?;
            if let Some(proof) = &envelope.consistency_proof {
                // Only proofs actually verified against the previous durable pin.
                if previous
                    .as_ref()
                    .is_some_and(|p| p.tree_size < checkpoint.log_size)
                {
                    tx.execute("INSERT OR REPLACE INTO replica_consistency(log_id,old_size,new_size,proof_json) VALUES (?1,?2,?3,?4)",
                        params![trusted.log_id,proof.old_tree_size,proof.new_tree_size,serde_json::to_string(proof)?]).map_err(db_error)?;
                }
            }
        }
        let pin = super::PinnedCheckpoint {
            log_id: checkpoint.log_id.clone(),
            operator_pubkey: checkpoint.operator_pubkey.clone(),
            operator_sequence: checkpoint.operator_sequence,
            tree_size: checkpoint.log_size,
            root_hash: checkpoint.log_root.clone(),
            checkpoint_hash: head_hash,
            first_seen_at: previous.as_ref().map_or(now, |p| p.first_seen_at),
            last_seen_at: now,
        };
        tx.execute("INSERT INTO replica_heads(log_id,pin_json,policy_json) VALUES (?1,?2,?3) ON CONFLICT(log_id) DO UPDATE SET pin_json=excluded.pin_json,policy_json=excluded.policy_json",
            params![trusted.log_id,serde_json::to_string(&pin)?,policy]).map_err(db_error)?;
        tx.commit().map_err(db_error)
    }

    /// Reverify on every read, including after restart, corruption or expiry.
    pub fn replica_resolution(
        &self,
        trusted: &super::NamespaceDescriptor,
        alias: &str,
        now: i64,
    ) -> Result<super::ResolutionEnvelope> {
        let mut connection = self.connection()?;
        let tx = connection.transaction().map_err(db_error)?;
        let fault: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM replica_faults WHERE log_id=?1)",
                [&trusted.log_id],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if fault {
            return Err(db_error(
                "replica quarantined after invalid upstream evidence",
            ));
        }
        let (raw_pin, policy): (String, String) = tx
            .query_row(
                "SELECT pin_json,policy_json FROM replica_heads WHERE log_id=?1",
                [&trusted.log_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_error)?;
        if policy != serde_json::to_string(trusted)? {
            return Err(db_error("replica trust policy mismatch"));
        }
        let raw: String = tx
            .query_row(
                "SELECT envelope_json FROM replica_envelopes WHERE log_id=?1 AND identifier=?2",
                params![trusted.log_id, alias],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        let envelope: super::ResolutionEnvelope = serde_json::from_str(&raw)?;
        let pin: super::PinnedCheckpoint = serde_json::from_str(&raw_pin)?;
        crate::lab::verify_resolution(alias, trusted, &envelope, Some(&pin), now)?;
        Ok(envelope)
    }

    pub fn replica_consistency(
        &self,
        log_id: &str,
        from: u64,
        to: u64,
    ) -> Result<super::MerkleConsistencyProof> {
        let raw: String = self.connection()?.query_row("SELECT proof_json FROM replica_consistency WHERE log_id=?1 AND old_size=?2 AND new_size=?3",
            params![log_id,from,to], |r| r.get(0)).map_err(db_error)?;
        let proof: super::MerkleConsistencyProof = serde_json::from_str(&raw)?;
        if proof.old_tree_size != from
            || proof.new_tree_size != to
            || !super::verify_consistency_proof(&proof)?
        {
            return Err(db_error("corrupt replica consistency proof"));
        }
        Ok(proof)
    }

    /// Reserve only after an operator has explicitly authorized this name/key.
    /// Possession of an email address is never accepted as namespace authority.
    pub fn reserve_lab_name(
        &self,
        network: &str,
        enabled: bool,
        alias: &str,
        pubkey: &str,
        operator_pubkey: &str,
        approval: &str,
        expires_at: i64,
    ) -> Result<crate::lab::RegistrationChallenge> {
        crate::lab::require_lab(network, enabled, alias)?;
        crate::validation::validate_compressed_pubkey(pubkey)?;
        let now = chrono::Utc::now().timestamp();
        if expires_at <= now
            || expires_at > now + 600
            || !crate::verify_message_signature(
                &crate::lab::admission_message(&self.log_id, alias, pubkey, expires_at),
                approval,
                operator_pubkey,
            )?
        {
            return Err(db_error("invalid or expired operator admission"));
        }
        let challenge = crate::lab::RegistrationChallenge {
            namespace: crate::lab::LAB_NAMESPACE.into(),
            identifier: alias.into(),
            identity_pubkey: pubkey.into(),
            log_id: self.log_id.clone(),
            authority_pubkey: operator_pubkey.into(),
            operation: "register".into(),
            nonce: crate::generate_nonce(),
            expires_at,
        };
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM profiles WHERE identifier_hash=?1)",
                [identifier_hash(alias)],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        if exists {
            return Err(db_error("name already registered"));
        }
        tx.execute(
            "DELETE FROM lab_reservations WHERE alias=?1 AND consumed=0 AND expires_at<=?2",
            params![alias, now],
        )
        .map_err(db_error)?;
        tx.execute("INSERT INTO lab_reservations(alias,challenge_json,nonce,expires_at) VALUES (?1,?2,?3,?4)",
            params![alias, serde_json::to_string(&challenge)?, challenge.nonce, expires_at]).map_err(db_error)?;
        tx.commit().map_err(db_error)?;
        Ok(challenge)
    }

    /// Owner signatures and challenge consumption are checked before an atomic
    /// profile/event/checkpoint commit. No private identity key is accepted.
    pub fn complete_lab_registration(
        &self,
        network: &str,
        enabled: bool,
        challenge: &crate::lab::RegistrationChallenge,
        possession_signature: &str,
        profile: &SignedPaymentProfile,
        event: &NameEvent,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<()> {
        crate::lab::require_lab(network, enabled, &challenge.identifier)?;
        let now = chrono::Utc::now().timestamp();
        if challenge.namespace != crate::lab::LAB_NAMESPACE
            || challenge.operation != "register"
            || challenge.log_id != self.log_id
            || challenge.expires_at <= now
            || checkpoint.operator_pubkey != challenge.authority_pubkey
            || profile.profile.alias != challenge.identifier
            || profile.profile.identity_pubkey != challenge.identity_pubkey
            || profile.profile.revoked
            || profile.profile.expires_at.is_none_or(|t| t <= now)
            || profile.profile.updated_at > now + 300
            || event.action != super::NameAction::Register
            || event.sequence != 0
            || event.previous_event_hash.is_some()
            || !crate::verify_message_signature(
                &challenge.signing_message()?,
                possession_signature,
                &challenge.identity_pubkey,
            )?
        {
            return Err(db_error(
                "registration binding or possession verification failed",
            ));
        }
        self.commit_with_registration(
            &challenge.identifier,
            profile,
            event,
            checkpoint,
            Some(challenge),
        )
    }

    pub fn profile(&self, alias: &str) -> Result<Option<SignedPaymentProfile>> {
        let connection = self.connection()?;
        let key = identifier_hash(&canonical_identifier(alias));
        let raw: Option<String> = connection
            .query_row(
                "SELECT profile_json FROM profiles WHERE identifier_hash=?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        raw.map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    pub fn identifier_attestation(&self, hash: &str) -> Result<Option<IdentifierAttestation>> {
        let connection = self.connection()?;
        let raw: Option<String> = connection
            .query_row(
                "SELECT attestation_json FROM identifier_attestations WHERE attestation_hash=?1",
                [hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        raw.map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    pub fn store_identifier_attestation(&self, attestation: &IdentifierAttestation) -> Result<()> {
        let hash = attestation.attestation_hash()?;
        let json = serde_json::to_string(attestation)?;
        self.connection()?.execute(
            "INSERT OR REPLACE INTO identifier_attestations(attestation_hash,attestation_json) VALUES (?1,?2)",
            params![hash, json],
        ).map_err(db_error)?;
        Ok(())
    }

    pub fn load_log(&self) -> Result<TransparencyLog> {
        let connection = self.connection()?;
        let mut event_statement = connection
            .prepare("SELECT event_json FROM name_events ORDER BY event_index")
            .map_err(db_error)?;
        let events = event_statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(db_error)?
            .map(|row| {
                row.map_err(db_error)
                    .and_then(|raw| serde_json::from_str(&raw).map_err(Into::into))
            })
            .collect::<Result<Vec<NameEvent>>>()?;
        let mut checkpoint_statement = connection
            .prepare("SELECT checkpoint_json FROM checkpoints ORDER BY checkpoint_index")
            .map_err(db_error)?;
        let checkpoints = checkpoint_statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(db_error)?
            .map(|row| {
                row.map_err(db_error)
                    .and_then(|raw| serde_json::from_str(&raw).map_err(Into::into))
            })
            .collect::<Result<Vec<TransparencyCheckpoint>>>()?;
        let log = TransparencyLog::from_parts(
            self.home.join("transparency"),
            self.log_id.clone(),
            events,
            checkpoints,
        )?;
        let mut profile_statement = connection
            .prepare("SELECT identifier_hash,profile_json FROM profiles")
            .map_err(db_error)?;
        let profiles = profile_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_error)?;
        for row in profiles {
            let (identifier, raw) = row.map_err(db_error)?;
            let profile: SignedPaymentProfile = serde_json::from_str(&raw)?;
            let latest = log.history(&identifier).last().copied().ok_or_else(|| {
                TransparencyError::BrokenIdentifierHistory(
                    "profile exists without event history".into(),
                )
            })?;
            if !super::verify_event_profile(latest, &profile)?
                || profile.profile.sequence != Some(latest.sequence)
            {
                return Err(TransparencyError::ProfileHashMismatch.into());
            }
        }
        Ok(log)
    }

    /// Atomically commits the complete security state. SQLite's WAL recovers
    /// committed transactions and discards partial transactions after crashes.
    pub fn commit_profile_event_checkpoint(
        &self,
        alias: &str,
        profile: &SignedPaymentProfile,
        event: &NameEvent,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<()> {
        self.commit_with_registration(alias, profile, event, checkpoint, None)
    }

    fn commit_with_registration(
        &self,
        alias: &str,
        profile: &SignedPaymentProfile,
        event: &NameEvent,
        checkpoint: &TransparencyCheckpoint,
        registration: Option<&crate::lab::RegistrationChallenge>,
    ) -> Result<()> {
        Registry::validate_profile_write(alias, profile)?;
        let current = self.load_log()?;
        if registration.is_none()
            && event.action == super::NameAction::Register
            && canonical_identifier(alias).ends_with("@lab.satspath.test")
        {
            return Err(db_error("lab names require challenge registration"));
        }
        let candidate = current.prepare_append(event.clone(), profile)?;
        if checkpoint.log_id != self.log_id
            || checkpoint.log_size != candidate.events().len() as u64
            || checkpoint.log_root != candidate.prepare_checkpoint_pub_root()?
            || !super::verify_checkpoint(checkpoint)?
        {
            return Err(TransparencyError::CorruptCheckpointChain(
                "candidate checkpoint does not commit candidate event prefix".into(),
            )
            .into());
        }
        let expected_previous = current
            .checkpoints()
            .last()
            .map(TransparencyCheckpoint::checkpoint_hash)
            .transpose()?;
        if checkpoint.previous_checkpoint_hash != expected_previous {
            return Err(TransparencyError::CorruptCheckpointChain(
                "candidate checkpoint predecessor mismatch".into(),
            )
            .into());
        }
        if let Some(previous) = current.checkpoints().last() {
            let pin = super::PinnedCheckpoint {
                log_id: previous.log_id.clone(),
                operator_pubkey: previous.operator_pubkey.clone(),
                operator_sequence: previous.operator_sequence,
                tree_size: previous.log_size,
                root_hash: previous.log_root.clone(),
                checkpoint_hash: previous.checkpoint_hash()?,
                first_seen_at: previous.created_at,
                last_seen_at: previous.created_at,
            };
            let consistency = candidate.consistency(previous.log_size, checkpoint.log_size)?;
            super::verify_checkpoint_transition(&pin, checkpoint, Some(&consistency))?;
        } else if checkpoint.operator_sequence != 0 || checkpoint.operator_rotation.is_some() {
            return Err(TransparencyError::InvalidOperatorRotation.into());
        }
        let key = identifier_hash(&canonical_identifier(alias));
        let event_hash = event.signed_event_hash()?;
        let checkpoint_hash = checkpoint.checkpoint_hash()?;
        let profile_json = serde_json::to_string(profile)?;
        let event_json = serde_json::to_string(event)?;
        let checkpoint_json = serde_json::to_string(checkpoint)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let event_index: i64 = transaction
            .query_row("SELECT COUNT(*) FROM name_events", [], |row| row.get(0))
            .map_err(db_error)?;
        let checkpoint_index: i64 = transaction
            .query_row("SELECT COUNT(*) FROM checkpoints", [], |row| row.get(0))
            .map_err(db_error)?;
        if event_index != current.events().len() as i64
            || checkpoint_index != current.checkpoints().len() as i64
        {
            return Err(TransparencyError::CorruptStore(
                "concurrent transparency transaction; retry required".into(),
            )
            .into());
        }
        let stored_previous: Option<String> = transaction
            .query_row(
                "SELECT checkpoint_hash FROM checkpoints ORDER BY checkpoint_index DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        if stored_previous != expected_previous {
            return Err(
                TransparencyError::CorruptStore("checkpoint changed concurrently".into()).into(),
            );
        }
        if let Some(challenge) = registration {
            let changed = transaction.execute(
                "UPDATE lab_reservations SET consumed=1 WHERE alias=?1 AND nonce=?2 AND challenge_json=?3 AND consumed=0 AND expires_at>?4",
                params![alias, challenge.nonce, serde_json::to_string(challenge)?, chrono::Utc::now().timestamp()],
            ).map_err(db_error)?;
            if changed != 1 {
                return Err(db_error(
                    "registration challenge expired, replaced or consumed",
                ));
            }
        }
        transaction.execute("INSERT INTO name_events(event_index,signed_event_hash,identifier_hash,event_json) VALUES (?1,?2,?3,?4)", params![event_index, event_hash, event.identifier_hash, event_json]).map_err(db_error)?;
        transaction.execute("INSERT INTO profiles(identifier_hash,alias,profile_json) VALUES (?1,?2,?3) ON CONFLICT(identifier_hash) DO UPDATE SET alias=excluded.alias,profile_json=excluded.profile_json", params![key, canonical_identifier(alias), profile_json]).map_err(db_error)?;
        transaction.execute("INSERT INTO checkpoints(checkpoint_index,checkpoint_hash,log_size,checkpoint_json) VALUES (?1,?2,?3,?4)", params![checkpoint_index, checkpoint_hash, checkpoint.log_size, checkpoint_json]).map_err(db_error)?;
        transaction
            .execute(
                "UPDATE operator_state SET operator_pubkey=?1,operator_sequence=?2 WHERE log_id=?3",
                params![
                    checkpoint.operator_pubkey,
                    checkpoint.operator_sequence,
                    self.log_id
                ],
            )
            .map_err(db_error)?;
        transaction.commit().map_err(db_error)
    }

    pub fn replace_latest_checkpoint(
        &self,
        previous_hash: &str,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<()> {
        if !super::verify_checkpoint(checkpoint)? {
            return Err(TransparencyError::InvalidCheckpointSignature.into());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let latest: Option<(i64, String)> = transaction.query_row(
            "SELECT checkpoint_index,checkpoint_hash FROM checkpoints ORDER BY checkpoint_index DESC LIMIT 1",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(db_error)?;
        let (index, stored_hash) = latest.ok_or_else(|| {
            TransparencyError::CorruptCheckpointChain("no checkpoint to replace".into())
        })?;
        if stored_hash != previous_hash {
            return Err(TransparencyError::CorruptCheckpointChain(
                "checkpoint changed concurrently".into(),
            )
            .into());
        }
        let new_hash = checkpoint.checkpoint_hash()?;
        let json = serde_json::to_string(checkpoint)?;
        transaction.execute("UPDATE checkpoints SET checkpoint_hash=?1,checkpoint_json=?2 WHERE checkpoint_index=?3", params![new_hash, json, index]).map_err(db_error)?;
        transaction
            .execute(
                "INSERT OR REPLACE INTO anchors(txid,anchor_json) VALUES (?1,?2)",
                params![
                    checkpoint
                        .bitcoin_anchor
                        .as_ref()
                        .map(|a| a.txid.as_str())
                        .unwrap_or(""),
                    checkpoint
                        .bitcoin_anchor
                        .as_ref()
                        .map(serde_json::to_string)
                        .transpose()?
                        .unwrap_or_default()
                ],
            )
            .map_err(db_error)?;
        transaction.commit().map_err(db_error)
    }
}
