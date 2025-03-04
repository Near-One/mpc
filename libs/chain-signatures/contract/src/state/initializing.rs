use super::key_state::{DKState, KeyEventId, KeyStateProposal};
use super::keygen::KeygenInstance;
use super::running::RunningContractState;
use super::votes::KeyStateVotes;
use crate::errors::VoteError;
use crate::errors::{Error, KeyEventError};
use near_sdk::{env, near, AccountId, PublicKey};

#[near(serializers=[borsh, json])]
#[derive(Debug)]
pub struct InitializingContractState {
    pub proposed_key_state: KeyStateProposal,
    pub current_keygen_instance: Option<KeygenInstance>,
}
impl InitializingContractState {
    /// Starts a new keygen instance.
    /// Returns an Error if the signer is not the leader of the current keygen leader or there is an active keygen ongoing
    pub fn start_keygen_instance(&mut self, dk_event_timeout_blocks: u64) -> Result<(), Error> {
        let signer = env::signer_account_id();
        // ensure there is no active keygen
        if self.has_active_keygen(dk_event_timeout_blocks) {
            return Err(KeyEventError::ActiveKeyEvent.into());
        }
        // ensure this function is called by the leader
        if signer != self.keygen_leader() {
            return Err(VoteError::VoterNotLeader.into());
        }

        // generate new key event id
        let key_event_id = KeyEventId::new(0, signer);
        // reset resharing instance:
        self.current_keygen_instance = Some(KeygenInstance::new(key_event_id));
        Ok(())
    }
    /// Casts a vote for `public_key` in `key_event_id`, removing any prior votes by `signer`.
    /// Fails if `signer` is not a candidate or if there is no active key event.
    /// Returns `RunningContractState` if `public_key` reaches the required votes.
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
        dk_event_timeout_blocks: u64,
    ) -> Result<Option<RunningContractState>, Error> {
        // ensure the signer is a participant
        let signer = env::signer_account_id();
        if !self.proposed_key_state.is_proposed(&signer) {
            return Err(VoteError::VoterNotParticipant.into());
        }
        // ensure there is an active reshare
        if !self.has_active_keygen(dk_event_timeout_blocks) {
            return Err(KeyEventError::NoActiveKeyEvent.into()); // todo: fix errors and clean them up
        }
        // Ensure the key_event_id matches
        let current = self.current_keygen_instance.as_mut().unwrap();
        if current.key_event_id != key_event_id {
            return Err(KeyEventError::KeyEventIdMismatch.into());
        }
        // Finally, vote for the reshare instance
        let n_votes = current.vote_pk(signer, public_key.clone())?;
        if self.proposed_key_state.key_event_threshold().value() <= n_votes {
            //return Ok(true);
            return Ok(Some(RunningContractState {
                key_state: DKState::from((
                    &self.proposed_key_state,
                    &public_key,
                    &self.current_keygen_instance.as_ref().unwrap().key_event_id,
                )),
                key_state_votes: KeyStateVotes::default(),
            }));
        }
        Ok(None)
    }
    /// returns true if there is an active reshare instance
    pub fn has_active_keygen(&self, dk_event_timeout_blocks: u64) -> bool {
        match &self.current_keygen_instance {
            None => false,
            Some(current) => current.active(dk_event_timeout_blocks),
        }
    }
    /// Returns the AccountId of the current keygen leader
    pub fn keygen_leader(&self) -> AccountId {
        let last_uid = if let Some(current_keygen) = &self.current_keygen_instance {
            current_keygen.key_event_id.uid()
        } else {
            0
        };
        let leader_idx = last_uid % self.proposed_key_state.n_proposed_participants();
        match self.proposed_key_state.candidate_by_index(leader_idx) {
            Ok(res) => res,
            Err(err) => env::panic_str(&err.to_string()),
        }
    }
}

impl From<&legacy_contract::InitializingContractState> for InitializingContractState {
    fn from(state: &legacy_contract::InitializingContractState) -> Self {
        InitializingContractState {
            proposed_key_state: state.into(),
            current_keygen_instance: None,
        }
    }
}
