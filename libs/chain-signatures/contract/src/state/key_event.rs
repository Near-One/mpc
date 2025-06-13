use crate::crypto_shared::types::PublicKeyExtended;
use crate::errors::Error;
use crate::errors::KeyEventError;
use crate::errors::VoteError;
use crate::primitives::domain::DomainConfig;
use crate::primitives::key_state::KeyEventId;
use crate::primitives::key_state::{AttemptId, EpochId};
use crate::primitives::thresholds::ThresholdParameters;
use crate::state::AuthenticatedParticipantId;
use near_sdk::BlockHeight;
use near_sdk::{env, log, near};
use std::collections::BTreeSet;

/// Maintains the state for the current key generation or resharing.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEvent {
    /// The epoch ID that we're generating or resharing keys for.
    epoch_id: EpochId,
    /// The domain that we're generating or resharing the key for.
    domain: DomainConfig,
    /// The participants and threshold that shall participate in the key event.
    parameters: ThresholdParameters,
    /// If exists, the current attempt to generate or reshare the key.
    instance: Option<KeyEventInstance>,
    /// The ID of the next attempt to generate or reshare the key.
    next_attempt_id: AttemptId,
}

impl KeyEvent {
    pub fn new(
        epoch_id: EpochId,
        domain: DomainConfig,
        proposed_parameters: ThresholdParameters,
    ) -> Self {
        KeyEvent {
            epoch_id,
            domain,
            parameters: proposed_parameters,
            instance: None,
            next_attempt_id: AttemptId::new(),
        }
    }

    /// Start a new key event instance as the leader, if one isn't already active.
    /// The leader is always the participant with the lowest participant ID.
    pub fn start(&mut self, key_event_id: KeyEventId, timeout_blocks: u64) -> Result<(), Error> {
        self.cleanup_if_timed_out();
        if self.instance.is_some() {
            return Err(KeyEventError::ActiveKeyEvent.into());
        }
        let expected_key_event_id =
            KeyEventId::new(self.epoch_id, self.domain.id, self.next_attempt_id);
        if key_event_id != expected_key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        self.verify_leader()?;
        self.instance = Some(KeyEventInstance::new(self.next_attempt_id, timeout_blocks));
        self.next_attempt_id = self.next_attempt_id.next();
        Ok(())
    }

    /// Ensures that the signer account matches the leader participant.
    /// The leader is the one with the lowest participant ID.
    pub fn verify_leader(&self) -> Result<(), Error> {
        if self
            .parameters
            .participants()
            .participants()
            .iter()
            .min_by_key(|(_, participant_id, _)| participant_id)
            .unwrap()
            .0
            != env::signer_account_id()
        {
            return Err(VoteError::VoterNotLeader.into());
        }
        Ok(())
    }

    pub fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub fn domain(&self) -> DomainConfig {
        self.domain.clone()
    }

    pub fn proposed_parameters(&self) -> &ThresholdParameters {
        &self.parameters
    }

    /// Casts a vote for `public_key` in `key_event_id`.
    /// Fails if `signer` is not a candidate, if the candidate already voted or if there is no active key event.
    /// If this vote disagrees with an earlier vote on the public key, aborts the current attempt.
    /// Otherwise, returns true iff all participants have voted for the same public key.
    pub fn vote_success(
        &mut self,
        key_event_id: &KeyEventId,
        public_key: PublicKeyExtended,
    ) -> Result<bool, Error> {
        let candidate = self.verify_vote(key_event_id)?;
        match self
            .instance
            .as_mut()
            .unwrap()
            .vote_success(candidate, public_key)?
        {
            VoteSuccessResult::Voted(count) => {
                if count == self.parameters.participants().len() {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            VoteSuccessResult::PublicKeyDisagreement => {
                log!("Public key disagreement; aborting key event instance.");
                self.instance = None;
                Ok(false)
            }
        }
    }

    /// Casts a vote to abort the current keygen instance.
    /// A new instance needs to be started later to start a new keygen attempt.
    pub fn vote_abort(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        let candidate = self.verify_vote(&key_event_id)?;
        if self
            .instance
            .as_ref()
            .unwrap()
            .completed
            .contains(&candidate)
        {
            return Err(VoteError::VoteAlreadySubmitted.into());
        }
        self.instance = None;
        Ok(())
    }

    /// Convenience function to internally remove the current instance if it timed out.
    /// Whoever reads and parses the state must treat a timed out instance as equivalent to not
    /// having an instance at all; thus this function performs no functional change.
    fn cleanup_if_timed_out(&mut self) {
        if let Some(instance) = self.instance.as_ref() {
            if !instance.active() {
                self.instance = None;
            }
        }
    }

    /// Verifies that the signer is authorized to cast a vote and that the key event ID corresponds
    /// to the current generation attempt.
    fn verify_vote(
        &mut self,
        key_event_id: &KeyEventId,
    ) -> Result<AuthenticatedParticipantId, Error> {
        let candidate = AuthenticatedParticipantId::new(self.parameters.participants())?;
        self.cleanup_if_timed_out();
        let Some(instance) = self.instance.as_ref() else {
            return Err(KeyEventError::NoActiveKeyEvent.into());
        };
        if key_event_id.epoch_id != self.epoch_id
            || key_event_id.domain_id != self.domain.id
            || key_event_id.attempt_id != instance.attempt_id
        {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        Ok(candidate)
    }

    /// Returns the KeyEventId that identifies the current key generation or resharing attempt.
    /// It returns None if there is no active attempt (including if the attempt has timed out).
    pub fn current_key_event_id(&self) -> Option<KeyEventId> {
        let instance = self.instance.as_ref()?;
        if instance.expires_on <= env::block_height() {
            return None;
        }
        Some(KeyEventId::new(
            self.epoch_id,
            self.domain.id,
            instance.attempt_id,
        ))
    }

    /// Returns whether an attempt is active ()and not timed out).
    #[cfg(any(test, feature = "test-utils", feature = "dev-utils"))]
    pub fn is_active(&self) -> bool {
        self.current_key_event_id().is_some()
    }

    /// Returns the number of success votes in the current attempt (asserting that it is active).
    #[cfg(test)]
    pub fn num_completed(&self) -> usize {
        assert!(self.is_active());
        self.instance.as_ref().unwrap().completed.len()
    }

    pub fn domain_id(&self) -> crate::primitives::domain::DomainId {
        self.domain.id
    }
    /// Returns the current key event instance (or none)
    pub fn instance(&self) -> &Option<KeyEventInstance> {
        &self.instance
    }
    pub fn next_attempt_id(&self) -> AttemptId {
        self.next_attempt_id
    }
}

/// See KeyEventInstance::vote_success.
#[derive(Debug, PartialEq)]
enum VoteSuccessResult {
    /// Voted successfully, returning the number of votes so far.
    Voted(usize),
    /// Participants disagreed on the public key, consensus failed.
    PublicKeyDisagreement,
}

/// State for a single attempt at generating or resharing a key.
#[near(serializers=[borsh, json])]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyEventInstance {
    attempt_id: AttemptId,
    /// The block in which KeyEvent::start() was called.
    started_in: BlockHeight,
    /// The block that this attempt expires on. To clarify off-by-one behavior: if the contract were
    /// called *on* or after this height, the attempt is considered no longer existent.
    expires_on: BlockHeight,
    /// The participants that voted that they successfully completed the keygen or resharing.
    completed: BTreeSet<AuthenticatedParticipantId>,
    /// The public key currently voted for. This is None iff no one has voted.
    public_key: Option<PublicKeyExtended>,
}

impl KeyEventInstance {
    pub fn new(attempt_id: AttemptId, timeout_blocks: u64) -> Self {
        KeyEventInstance {
            attempt_id,
            started_in: env::block_height(),
            expires_on: env::block_height() + 1 + timeout_blocks,
            completed: BTreeSet::new(),
            public_key: None,
        }
    }
    pub fn completed(&self) -> &BTreeSet<AuthenticatedParticipantId> {
        &self.completed
    }

    pub fn active(&self) -> bool {
        env::block_height() < self.expires_on
    }

    pub fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }
    pub fn expires_on(&self) -> u64 {
        self.expires_on
    }

    /// Commits the vote of `candidate` to `public_key`, returning either Voted with the number of
    /// votes already cast, or PublicKeyDisagreement if this vote conflicts with an earlier vote's
    /// public key.
    /// Fails if the candidate already submitted a vote.
    fn vote_success(
        &mut self,
        candidate: AuthenticatedParticipantId,
        public_key: PublicKeyExtended,
    ) -> Result<VoteSuccessResult, Error> {
        if let Some(existing_public_key) = &self.public_key {
            if existing_public_key != &public_key {
                return Ok(VoteSuccessResult::PublicKeyDisagreement);
            }
        } else {
            self.public_key = Some(public_key);
        }
        // return error if the candidate alredy submitted a vote.
        if self.completed.contains(&candidate) {
            return Err(VoteError::VoteAlreadySubmitted.into());
        }
        // label candidate as complete
        self.completed.insert(candidate.clone());
        Ok(VoteSuccessResult::Voted(self.completed.len()))
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub mod tests {
    use crate::primitives::participants::ParticipantId;
    use crate::primitives::test_utils::{gen_account_id, gen_seed};
    use crate::state::key_event::KeyEvent;
    use near_sdk::{test_utils::VMContextBuilder, testing_env, AccountId, BlockHeight};
    use rand::Rng;

    pub struct Environment {
        pub signer: AccountId,
        pub block_height: BlockHeight,
        pub seed: [u8; 32],
    }
    impl Environment {
        pub fn new(
            block_height: Option<BlockHeight>,
            signer: Option<AccountId>,
            seed: Option<[u8; 32]>,
        ) -> Self {
            let seed = seed.unwrap_or(gen_seed());
            let mut ctx = VMContextBuilder::new();
            let block_height = block_height.unwrap_or(rand::thread_rng().gen());
            ctx.block_height(block_height);
            ctx.random_seed(seed);
            let signer = signer.unwrap_or(gen_account_id());
            ctx.signer_account_id(signer.clone());
            testing_env!(ctx.build());
            Environment {
                signer,
                block_height,
                seed,
            }
        }
        pub fn set_signer(&mut self, signer: &AccountId) {
            self.signer = signer.clone();
            self.set();
        }
        pub fn set(&self) {
            let mut ctx = VMContextBuilder::new();
            ctx.block_height(self.block_height);
            ctx.random_seed(self.seed);
            ctx.signer_account_id(self.signer.clone());
            testing_env!(ctx.build());
        }
        pub fn set_block_height(&mut self, block_height: BlockHeight) {
            self.block_height = block_height;
            self.set();
        }
        pub fn advance_block_height(&mut self, delta: BlockHeight) {
            self.block_height += delta;
            self.set();
        }
    }

    pub fn find_leader(kes: &KeyEvent) -> (AccountId, ParticipantId) {
        let (account_id, participant_id, _) = kes
            .proposed_parameters()
            .participants()
            .participants()
            .iter()
            .min_by_key(|(_, id, _)| id)
            .unwrap();
        (account_id.clone(), participant_id.clone())
    }
}
