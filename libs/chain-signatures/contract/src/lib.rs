pub mod config;
pub mod errors;
pub mod primitives;
pub mod state;
pub mod update;

use config::{ConfigV1, InitConfigV1};
use crypto_shared::{
    derive_epsilon, derive_key, kdf::check_ec_signature, near_public_key_to_affine_point,
    types::SignatureResponse, ScalarExt as _,
};
use errors::{
    ConversionError, InitError, InvalidParameters, InvalidState, JoinError, PublicKeyError,
    RespondError, SignError, VoteError,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Scalar;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::json_types::U128;
use near_sdk::store::Vector;
use near_sdk::{
    env, log, near_bindgen, AccountId, CryptoHash, Gas, GasWeight, NearToken, Promise,
    PromiseError, PublicKey,
};
use primitives::{
    CandidateInfo, Candidates, ContractSignatureRequest, Participants, PkVotes, SignRequest,
    SignaturePromiseError, SignatureRequest, SignatureResult, StorageKey, Votes, YieldIndex,
};
use std::cmp;
use std::collections::{BTreeMap, HashSet};

use crate::config::Config;
use crate::errors::Error;
use crate::update::{ProposeUpdateArgs, ProposedUpdates, UpdateId};
pub use state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
};
const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(10);

// Register used to receive data id from `promise_await_data`.
const DATA_ID_REGISTER: u64 = 0;

// Prepaid gas for a `return_signature_and_clean_state_on_success` call
const RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS: Gas = Gas::from_tgas(5);

// **DEPRECATED** Prepaid gas for a `clear_state_on_finish` call
const CLEAR_STATE_ON_FINISH_CALL_GAS: Gas = Gas::from_tgas(10);

// **DEPRECATED** Prepaid gas for a `return_signature_on_finish` call
const RETURN_SIGNATURE_ON_FINISH_CALL_GAS: Gas = Gas::from_tgas(5);

// Prepaid gas for a `update_config` call
const UPDATE_CONFIG_GAS: Gas = Gas::from_tgas(5);

#[derive(BorshDeserialize, BorshSerialize, Debug)]
#[cfg_attr(not(feature = "legacy"), near_bindgen)]
pub enum VersionedMpcContract {
    V0(MpcContract),
    V1(MpcContractV1),
}

impl Default for VersionedMpcContract {
    fn default() -> Self {
        env::panic_str("Calling default not allowed.");
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContractV1 {
    pub protocol_state: ProtocolContractState,
    pub pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    pub request_by_block_height: Vector<(u64, SignatureRequest)>,
    pub proposed_updates: ProposedUpdates,
    pub config: ConfigV1,
}

impl MpcContractV1 {
    fn remove_timed_out_requests(&mut self, max_num_to_remove: u32) -> u32 {
        let min_pending_request_height =
            cmp::max(env::block_height(), self.config.request_timeout_blocks)
                - self.config.request_timeout_blocks;
        let mut i = 0;
        for x in self.request_by_block_height.iter() {
            if (min_pending_request_height <= x.0) || (i > max_num_to_remove) {
                break;
            }
            self.pending_requests.remove(&x.1);
            i += 1;
        }
        self.request_by_block_height.drain(..i);
        cmp::max(i, 1) - 1
    }
    fn add_request(&mut self, request: &SignatureRequest, data_id: CryptoHash) {
        self.request_by_block_height
            .push((env::block_height(), request.clone()));
        self.pending_requests
            .insert(request, &YieldIndex { data_id });
    }
    fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        self.pending_requests.get(request)
    }
    pub fn init(
        threshold: usize,
        candidates: BTreeMap<AccountId, CandidateInfo>,
        init_config: Option<InitConfigV1>,
    ) -> Self {
        log!(
            "init: threshold={}, candidates={:?}, init_config={:?}",
            threshold,
            candidates,
            init_config,
        );

        MpcContractV1 {
            config: ConfigV1::from(init_config),
            protocol_state: ProtocolContractState::Initializing(InitializingContractState {
                candidates: Candidates { candidates },
                threshold,
                pk_votes: PkVotes::new(),
            }),
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            request_by_block_height: Vector::new(StorageKey::RequestsByTimestamp),
            proposed_updates: ProposedUpdates::default(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_counter: u32,
    proposed_updates: ProposedUpdates,
    config: Config,
}
impl MpcContract {
    fn remove_request(&mut self, request: SignatureRequest) -> Result<(), Error> {
        if self.pending_requests.remove(&request).is_some() {
            self.request_counter -= 1;
            Ok(())
        } else {
            Err(InvalidParameters::RequestNotFound.into())
        }
    }
    fn add_request(&mut self, request: &SignatureRequest, data_id: CryptoHash) {
        if self
            .pending_requests
            .insert(request, &YieldIndex { data_id })
            .is_none()
        {
            self.request_counter += 1;
        }
    }
    fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        self.pending_requests.get(request)
    }
    pub fn init(
        threshold: usize,
        candidates: BTreeMap<AccountId, CandidateInfo>,
        config: Option<Config>,
    ) -> Self {
        MpcContract {
            protocol_state: ProtocolContractState::Initializing(InitializingContractState {
                candidates: Candidates { candidates },
                threshold,
                pk_votes: PkVotes::new(),
            }),
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            request_counter: 0,
            proposed_updates: ProposedUpdates::default(),
            config: config.unwrap_or_default(),
        }
    }
}

// User contract API
#[cfg(not(feature = "legacy"))]
#[cfg_attr(not(feature = "legacy"), near_bindgen)]
impl VersionedMpcContract {
    pub fn remove_timed_out_requests(&mut self, max_num_to_remove: Option<u32>) -> u32 {
        match self {
            Self::V0(_) => 0,
            Self::V1(mpc_contract) => mpc_contract.remove_timed_out_requests(
                max_num_to_remove.unwrap_or(mpc_contract.config.max_num_requests_to_remove),
            ),
        }
    }
    /// `key_version` must be less than or equal to the value at `latest_key_version`
    /// To avoid overloading the network with too many requests,
    /// we ask for a small deposit for each signature request.
    /// The fee changes based on how busy the network is.
    #[handle_result]
    #[payable]
    pub fn sign(&mut self, request: SignRequest) {
        let SignRequest {
            payload,
            path,
            key_version,
        } = request;
        // First, clear the state.
        match self {
            Self::V0(_) => {}
            Self::V1(mpc_contract) => {
                mpc_contract
                    .remove_timed_out_requests(mpc_contract.config.max_num_requests_to_remove);
            }
        }
        // It's important we fail here because the MPC nodes will fail in an identical way.
        // This allows users to get the error message
        let payload = Scalar::from_bytes(payload).ok_or(
            InvalidParameters::MalformedPayload
                .message("Payload hash cannot be convereted to Scalar"),
        );
        if let Err(err) = payload {
            env::panic_str(&err.to_string())
        }
        let payload = payload.unwrap();
        if key_version > self.latest_key_version() {
            env::panic_str(&SignError::UnsupportedKeyVersion.to_string());
        }
        // Check deposit
        let deposit = env::attached_deposit();
        let required_deposit: u128 = self.experimental_signature_deposit().into();

        if deposit.as_yoctonear() < required_deposit {
            env::panic_str(
                &InvalidParameters::InsufficientDeposit
                    .message(format!(
                        "Attached {}, Required {}",
                        deposit.as_yoctonear(),
                        required_deposit,
                    ))
                    .to_string(),
            );
        }
        // Make sure sign call will not run out of gas doing yield/resume logic
        if env::prepaid_gas() < GAS_FOR_SIGN_CALL {
            env::panic_str(
                &InvalidParameters::InsufficientGas
                    .message(format!(
                        "Provided: {}, required: {}",
                        env::prepaid_gas(),
                        GAS_FOR_SIGN_CALL
                    ))
                    .to_string(),
            );
        }

        match self {
            Self::V0(mpc_contract) => {
                if mpc_contract.request_counter > 16 {
                    env::panic_str(&SignError::RequestLimitExceeded.to_string())
                }
            }
            Self::V1(_) => {}
        }
        let predecessor = env::predecessor_account_id();
        let request = SignatureRequest::new(payload, &predecessor, &path);
        if self.request_already_exists(&request) {
            env::panic_str(&SignError::PayloadCollision.to_string());
        }
        log!(
                "sign: predecessor={predecessor}, payload={payload:?}, path={path:?}, key_version={key_version}",
            );
        env::log_str(&serde_json::to_string(&near_sdk::env::random_seed_array()).unwrap());

        let required_deposit = NearToken::from_yoctonear(required_deposit);
        let contract_signature_request = ContractSignatureRequest {
            request,
            requester: predecessor,
            deposit,
            required_deposit,
        };

        let promise_index = match self {
            Self::V0(_) => {
                let yield_promise = env::promise_yield_create(
                    "clear_state_on_finish",
                    &serde_json::to_vec(&(&contract_signature_request,)).unwrap(),
                    CLEAR_STATE_ON_FINISH_CALL_GAS,
                    GasWeight(0),
                    DATA_ID_REGISTER,
                );
                env::promise_then(
                    yield_promise,
                    env::current_account_id(),
                    "return_signature_on_finish",
                    &[],
                    NearToken::from_near(0),
                    RETURN_SIGNATURE_ON_FINISH_CALL_GAS,
                )
            }
            Self::V1(_) => env::promise_yield_create(
                "return_signature_and_clean_state_on_success",
                &serde_json::to_vec(&(&contract_signature_request,)).unwrap(),
                RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS,
                GasWeight(0),
                DATA_ID_REGISTER,
            ),
        };

        // Store the request in the contract's local state
        let return_sig_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("read_register failed")
            .try_into()
            .expect("conversion to CryptoHash failed");

        match self {
            Self::V0(mpc_contract) => {
                mpc_contract.add_request(&contract_signature_request.request, return_sig_id);
            }
            Self::V1(mpc_contract) => {
                mpc_contract.add_request(&contract_signature_request.request, return_sig_id);
                Self::refund_on_success(&contract_signature_request);
            }
        }
        env::promise_return(promise_index);
    }

    /// This is the root public key combined from all the public keys of the participants.
    #[handle_result]
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        match self.state() {
            ProtocolContractState::Running(state) => Ok(state.public_key.clone()),
            ProtocolContractState::Resharing(state) => Ok(state.public_key.clone()),
            _ => Err(InvalidState::ProtocolStateNotRunningOrResharing.into()),
        }
    }

    /// This is the derived public key of the caller given path and predecessor
    /// if predecessor is not provided, it will be the caller of the contract
    #[handle_result]
    pub fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
    ) -> Result<PublicKey, Error> {
        let predecessor = predecessor.unwrap_or_else(env::predecessor_account_id);
        let epsilon = derive_epsilon(&predecessor, &path);
        let derived_public_key =
            derive_key(near_public_key_to_affine_point(self.public_key()?), epsilon);
        let encoded_point = derived_public_key.to_encoded_point(false);
        let slice: &[u8] = &encoded_point.as_bytes()[1..65];
        let mut data: Vec<u8> = vec![near_sdk::CurveType::SECP256K1 as u8];
        data.extend(slice.to_vec());
        PublicKey::try_from(data).map_err(|_| PublicKeyError::DerivedKeyConversionFailed.into())
    }

    /// Key versions refer new versions of the root key that we may choose to generate on cohort changes
    /// Older key versions will always work but newer key versions were never held by older signers
    /// Newer key versions may also add new security features, like only existing within a secure enclave
    /// Currently only 0 is a valid key version
    pub const fn latest_key_version(&self) -> u32 {
        0
    }

    /// This experimental function calculates the fee for a signature request.
    /// The fee is volatile and depends on the number of pending requests.
    /// If used on a client side, it can give outdate results.
    pub fn experimental_signature_deposit(&self) -> U128 {
        match self {
            Self::V0(mpc_contract) => {
                const CHEAP_REQUESTS: u32 = 3;
                let pending_requests = mpc_contract.request_counter;
                match pending_requests {
                    0..=CHEAP_REQUESTS => U128::from(1),
                    _ => {
                        let expensive_requests = (pending_requests - CHEAP_REQUESTS) as u128;
                        let price =
                            expensive_requests * NearToken::from_millinear(50).as_yoctonear();
                        U128::from(price)
                    }
                }
            }
            Self::V1(_) => U128::from(1),
        }
    }
}

// Node API
#[cfg(not(feature = "legacy"))]
#[cfg_attr(not(feature = "legacy"), near_bindgen)]
impl VersionedMpcContract {
    #[handle_result]
    pub fn respond(
        &mut self,
        request: SignatureRequest,
        response: SignatureResponse,
    ) -> Result<(), Error> {
        let protocol_state = self.mutable_state();

        if let ProtocolContractState::Running(_) = protocol_state {
            let signer = env::signer_account_id();
            log!(
                "respond: signer={}, request={:?} big_r={:?} s={:?}",
                &signer,
                &request,
                &response.big_r,
                &response.s
            );

            // generate the expected public key
            let pk = self.public_key()?;
            let expected_public_key =
                derive_key(near_public_key_to_affine_point(pk), request.epsilon.scalar);

            // Check the signature is correct
            if check_ec_signature(
                &expected_public_key,
                &response.big_r.affine_point,
                &response.s.scalar,
                request.payload_hash.scalar,
                response.recovery_id,
            )
            .is_err()
            {
                return Err(RespondError::InvalidSignature.into());
            }
            // First get the yield promise of the (potentially timed out) request.
            if let Some(YieldIndex { data_id }) = self.get_pending_request(&request) {
                // Only then clean up the state.
                // This order of execution ensures that the state is cleaned of the current
                // response, even if it belongs to an already timed out signature request.
                match self {
                    Self::V0(_) => {}
                    Self::V1(mpc_contract) => {
                        mpc_contract.remove_timed_out_requests(
                            mpc_contract.config.max_num_requests_to_remove,
                        );
                    }
                }
                // Finally, resolve the promise. This will have no effect if the request already timed.
                env::promise_yield_resume(&data_id, &serde_json::to_vec(&response).unwrap());
                Ok(())
            } else {
                Err(InvalidParameters::RequestNotFound.into())
            }
        } else {
            Err(InvalidState::ProtocolStateNotRunning.into())
        }
    }

    #[handle_result]
    pub fn join(
        &mut self,
        url: String,
        cipher_pk: primitives::hpke::PublicKey,
        sign_pk: PublicKey,
    ) -> Result<(), Error> {
        log!(
            "join: signer={}, url={}, cipher_pk={:?}, sign_pk={:?}",
            env::signer_account_id(),
            url,
            cipher_pk,
            sign_pk
        );
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                participants,
                ref mut candidates,
                ..
            }) => {
                let signer_account_id = env::signer_account_id();
                if participants.contains_key(&signer_account_id) {
                    return Err(JoinError::JoinAlreadyParticipant.into());
                }
                candidates.insert(
                    signer_account_id.clone(),
                    CandidateInfo {
                        account_id: signer_account_id,
                        url,
                        cipher_pk,
                        sign_pk,
                    },
                );
                Ok(())
            }
            _ => Err(InvalidState::ProtocolStateNotRunning.into()),
        }
    }

    #[handle_result]
    pub fn vote_join(&mut self, candidate: AccountId) -> Result<bool, Error> {
        log!(
            "vote_join: signer={}, candidate={}",
            env::signer_account_id(),
            candidate
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates,
                join_votes,
                ..
            }) => {
                let candidate_info = candidates
                    .get(&candidate)
                    .ok_or(VoteError::JoinNotCandidate)?;
                let voted = join_votes.entry(candidate.clone());
                voted.insert(voter);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.insert(candidate, candidate_info.clone().into());
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
                        old_epoch: *epoch,
                        old_participants: participants.clone(),
                        new_participants,
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        finished_votes: HashSet::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    #[handle_result]
    pub fn vote_leave(&mut self, kick: AccountId) -> Result<bool, Error> {
        log!(
            "vote_leave: signer={}, kick={}",
            env::signer_account_id(),
            kick
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                leave_votes,
                ..
            }) => {
                if !participants.contains_key(&kick) {
                    return Err(VoteError::KickNotParticipant.into());
                }
                if participants.len() <= *threshold {
                    return Err(VoteError::ParticipantsBelowThreshold.into());
                }
                let voted = leave_votes.entry(kick.clone());
                voted.insert(voter);
                if voted.len() >= *threshold {
                    let mut new_participants = participants.clone();
                    new_participants.remove(&kick);
                    *protocol_state = ProtocolContractState::Resharing(ResharingContractState {
                        old_epoch: *epoch,
                        old_participants: participants.clone(),
                        new_participants,
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        finished_votes: HashSet::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    #[handle_result]
    pub fn vote_pk(&mut self, public_key: PublicKey) -> Result<bool, Error> {
        log!(
            "vote_pk: signer={}, public_key={:?}",
            env::signer_account_id(),
            public_key
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Initializing(InitializingContractState {
                candidates,
                threshold,
                pk_votes,
            }) => {
                let voted = pk_votes.entry(public_key.clone());
                voted.insert(voter);
                if voted.len() >= *threshold {
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: 0,
                        participants: candidates.clone().into(),
                        threshold: *threshold,
                        public_key,
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ProtocolContractState::Running(state) if state.public_key == public_key => Ok(true),
            ProtocolContractState::Resharing(state) if state.public_key == public_key => Ok(true),
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    #[handle_result]
    pub fn vote_reshared(&mut self, epoch: u64) -> Result<bool, Error> {
        log!(
            "vote_reshared: signer={}, epoch={}",
            env::signer_account_id(),
            epoch
        );
        let voter = self.voter()?;
        let protocol_state = self.mutable_state();
        match protocol_state {
            ProtocolContractState::Resharing(ResharingContractState {
                old_epoch,
                old_participants: _,
                new_participants,
                threshold,
                public_key,
                finished_votes,
            }) => {
                if *old_epoch + 1 != epoch {
                    return Err(InvalidState::EpochMismatch.into());
                }
                finished_votes.insert(voter);
                if finished_votes.len() >= *threshold {
                    *protocol_state = ProtocolContractState::Running(RunningContractState {
                        epoch: *old_epoch + 1,
                        participants: new_participants.clone(),
                        threshold: *threshold,
                        public_key: public_key.clone(),
                        candidates: Candidates::new(),
                        join_votes: Votes::new(),
                        leave_votes: Votes::new(),
                    });
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ProtocolContractState::Running(state) => {
                if state.epoch == epoch {
                    Ok(true)
                } else {
                    Err(InvalidState::UnexpectedProtocolState.message("Running: invalid epoch"))
                }
            }
            _ => Err(InvalidState::UnexpectedProtocolState.message(protocol_state.name())),
        }
    }

    /// Propose an update to the contract. [`Update`] are all the possible updates that can be proposed.
    ///
    /// returns Some(id) if the proposal was successful, None otherwise
    #[payable]
    #[handle_result]
    pub fn propose_update(
        &mut self,
        #[serializer(borsh)] args: ProposeUpdateArgs,
    ) -> Result<UpdateId, Error> {
        // Only voters can propose updates:
        let proposer = self.voter()?;

        let attached = env::attached_deposit();
        let required = ProposedUpdates::required_deposit(&args.code, &args.config);
        if attached < required {
            return Err(InvalidParameters::InsufficientDeposit.message(format!(
                "Attached {}, Required {}",
                attached.as_yoctonear(),
                required.as_yoctonear(),
            )));
        }

        let Some(id) = self.proposed_updates().propose(args.code, args.config) else {
            return Err(ConversionError::DataConversion
                .message("Cannot propose update due to incorrect parameters."));
        };

        log!(
            "propose_update: signer={}, id={:?}",
            env::signer_account_id(),
            id,
        );

        // Refund the difference if the propser attached more than required.
        if let Some(diff) = attached.checked_sub(required) {
            if diff > NearToken::from_yoctonear(0) {
                Promise::new(proposer).transfer(diff);
            }
        }

        Ok(id)
    }

    /// Vote for a proposed update given the [`UpdateId`] of the update.
    ///
    /// Returns Ok(true) if the amount of voters surpassed the threshold and the update was executed.
    /// Returns Ok(false) if the amount of voters did not surpass the threshold. Returns Err if the update
    /// was not found or if the voter is not a participant in the protocol.
    #[handle_result]
    pub fn vote_update(&mut self, id: UpdateId) -> Result<bool, Error> {
        log!(
            "vote_update: signer={}, id={:?}",
            env::signer_account_id(),
            id,
        );
        let threshold = self.threshold()?;
        let voter = self.voter()?;
        let Some(votes) = self.proposed_updates().vote(&id, voter) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        // Not enough votes, wait for more.
        if votes.len() < threshold {
            return Ok(false);
        }

        let Some(_promise) = self.proposed_updates().do_update(&id, UPDATE_CONFIG_GAS) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        Ok(true)
    }
}

// Contract developer helper API
#[cfg(not(feature = "legacy"))]
#[near_bindgen]
impl VersionedMpcContract {
    #[handle_result]
    #[init]
    pub fn init(
        threshold: usize,
        candidates: BTreeMap<AccountId, CandidateInfo>,
        init_config: Option<InitConfigV1>,
    ) -> Result<Self, Error> {
        log!(
            "init: signer={}, threshold={}, candidates={}, init_config={:?}",
            env::signer_account_id(),
            threshold,
            serde_json::to_string(&candidates).unwrap(),
            init_config,
        );

        if threshold > candidates.len() {
            return Err(InitError::ThresholdTooHigh.into());
        }

        Ok(Self::V1(MpcContractV1::init(
            threshold,
            candidates,
            init_config,
        )))
    }

    // This function can be used to transfer the MPC network to a new contract.
    #[private]
    #[init]
    #[handle_result]
    pub fn init_running(
        epoch: u64,
        participants: Participants,
        threshold: usize,
        public_key: PublicKey,
        init_config: Option<InitConfigV1>,
    ) -> Result<Self, Error> {
        log!(
            "init_running: signer={}, epoch={}, participants={}, threshold={}, public_key={:?}, init_config={:?}",
            env::signer_account_id(),
            epoch,
            serde_json::to_string(&participants).unwrap(),
            threshold,
            public_key,
            init_config,
        );

        if threshold > participants.len() {
            return Err(InitError::ThresholdTooHigh.into());
        }

        Ok(Self::V1(MpcContractV1 {
            config: ConfigV1::from(init_config),
            protocol_state: ProtocolContractState::Running(RunningContractState {
                epoch,
                participants,
                threshold,
                public_key,
                candidates: Candidates::new(),
                join_votes: Votes::new(),
                leave_votes: Votes::new(),
            }),
            request_by_block_height: Vector::new(StorageKey::RequestsByTimestamp),
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            proposed_updates: ProposedUpdates::default(),
        }))
    }

    /// This will be called internally by the contract to migrate the state when a new contract
    /// is deployed. This function should be changed every time state is changed to do the proper
    /// migrate flow.
    ///
    /// If nothing is changed, then this function will just return the current state. If it fails
    /// to read the state, then it will return an error.
    #[private]
    #[init(ignore_state)]
    #[handle_result]
    pub fn migrate() -> Result<Self, Error> {
        let old: VersionedMpcContract =
            env::state_read().ok_or(InvalidState::ContractStateIsMissing)?;
        match old {
            VersionedMpcContract::V0(mpc_contract_v0) => {
                Ok(VersionedMpcContract::V1(MpcContractV1 {
                    config: ConfigV1::default(),
                    protocol_state: mpc_contract_v0.protocol_state,
                    pending_requests: mpc_contract_v0.pending_requests,
                    request_by_block_height: Vector::new(StorageKey::RequestsByTimestamp),
                    proposed_updates: ProposedUpdates::default(),
                }))
            }
            VersionedMpcContract::V1(_) => Ok(old),
        }
    }

    pub fn state(&self) -> &ProtocolContractState {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.protocol_state,
            Self::V1(mpc_contract) => &mpc_contract.protocol_state,
        }
    }

    pub fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        match self {
            Self::V0(mpc_contract) => mpc_contract.get_pending_request(request),
            Self::V1(mpc_contract) => mpc_contract.get_pending_request(request),
        }
    }

    pub fn config(&self) -> &ConfigV1 {
        match self {
            Self::V0(_) => panic!("Deprecated, use V1"),
            Self::V1(mpc_contract) => &mpc_contract.config,
        }
    }

    // contract version
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }
    /// **DEPRECATED**: Better use `return_signature_and_clean_state_on_success`
    #[private]
    #[handle_result]
    pub fn return_signature_on_finish(
        &mut self,
        #[callback_unwrap] signature: SignatureResult<SignatureResponse, SignaturePromiseError>,
    ) -> Result<SignatureResponse, Error> {
        if let Self::V1(_) = self {
            log!("This function is deprecated and shall only be called to handle signature requests submitted to legacy V0 contract");
        }
        match signature {
            SignatureResult::Ok(signature) => {
                log!("Signature is ready.");
                Ok(signature)
            }
            SignatureResult::Err(_) => Err(SignError::Timeout.into()),
        }
    }

    /// DEPRECATED this function can be removed after update to V1
    fn refund_on_fail(request: &ContractSignatureRequest) {
        let amount = request.deposit;
        let to = request.requester.clone();
        log!("refund {amount} to {to} due to fail");
        Promise::new(to).transfer(amount);
    }

    fn refund_on_success(request: &ContractSignatureRequest) {
        let deposit = request.deposit;
        let required = request.required_deposit;
        if let Some(diff) = deposit.checked_sub(required) {
            if diff > NearToken::from_yoctonear(0) {
                let to = request.requester.clone();
                log!("refund more than required deposit {diff} to {to}");
                Promise::new(to).transfer(diff);
            }
        }
    }

    /// Upon success, removes the signature from state and returns it.
    /// Returns an Error if the signature timed out.
    /// Note that timed out signatures will need to be cleaned up from the state by a different function.
    #[private]
    #[handle_result]
    pub fn return_signature_and_clean_state_on_success(
        &mut self,
        contract_signature_request: ContractSignatureRequest,
        #[callback_result] signature: Result<SignatureResponse, PromiseError>,
    ) -> Result<SignatureResponse, Error> {
        match self {
            Self::V0(_) => {
                panic!("not supposed to be called");
            }
            Self::V1(mpc_contract) => match signature {
                Ok(signature) => {
                    log!("Signature is ready.");
                    mpc_contract
                        .pending_requests
                        .remove(&contract_signature_request.request);
                    Ok(signature)
                }
                Err(_) => Err(SignError::Timeout.into()),
            },
        }
    }

    /// **DEPRECATED** use `return_signature_and_clean_state_on_success` instead
    /// This function removes the signature request from the contract state and:
    /// V0: executes any refunds and returns the Signature Result / an error
    /// V1: panics
    #[private]
    #[handle_result]
    pub fn clear_state_on_finish(
        &mut self,
        contract_signature_request: ContractSignatureRequest,
        #[callback_result] signature: Result<SignatureResponse, PromiseError>,
    ) -> Result<SignatureResult<SignatureResponse, SignaturePromiseError>, Error> {
        let result = match self {
            Self::V0(mpc_contract) => {
                mpc_contract.remove_request(contract_signature_request.request.clone())
            }
            Self::V1(mpc_contract) => {
                log!("This function is deprecated and shall only be called to handle signature requests submitted to V0 contract");
                match mpc_contract
                    .pending_requests
                    .remove(&contract_signature_request.request)
                {
                    Some(_) => Ok(()),
                    None => Err(InvalidParameters::RequestNotFound.into()),
                }
            }
        };
        if result.is_err() {
            // refund must happen in clear_state_on_finish, because regardless of this success or fail
            // the promise created by clear_state_on_finish is executed, because of callback_unwrap and
            // promise_then. but if `return_signature_on_finish` fail (returns error), the promise created
            // by it won't execute.
            Self::refund_on_fail(&contract_signature_request);
            result?;
        }

        match signature {
            Ok(signature) => {
                Self::refund_on_success(&contract_signature_request);
                Ok(SignatureResult::Ok(signature))
            }
            Err(_) => {
                Self::refund_on_fail(&contract_signature_request);
                Ok(SignatureResult::Err(SignaturePromiseError::Failed))
            }
        }
    }

    #[private]
    pub fn update_config(&mut self, config: ConfigV1) {
        match self {
            Self::V0(_) => {
                panic!("not implemented");
            }
            Self::V1(mpc_contract) => {
                mpc_contract.config = config;
            }
        }
    }

    fn mutable_state(&mut self) -> &mut ProtocolContractState {
        match self {
            Self::V0(ref mut mpc_contract) => &mut mpc_contract.protocol_state,
            Self::V1(ref mut mpc_contract) => &mut mpc_contract.protocol_state,
        }
    }

    fn request_already_exists(&self, request: &SignatureRequest) -> bool {
        match self {
            Self::V0(mpc_contract) => mpc_contract.pending_requests.contains_key(request),
            Self::V1(mpc_contract) => mpc_contract.pending_requests.contains_key(request),
        }
    }

    fn threshold(&self) -> Result<usize, Error> {
        match self {
            Self::V0(contract) => contract.protocol_state.threshold(),
            Self::V1(contract) => contract.protocol_state.threshold(),
        }
    }

    fn proposed_updates(&mut self) -> &mut ProposedUpdates {
        match self {
            Self::V0(contract) => &mut contract.proposed_updates,
            Self::V1(contract) => &mut contract.proposed_updates,
        }
    }
    /// Get our own account id as a voter. Check to see if we are a participant in the protocol.
    /// If we are not a participant, return an error.
    fn voter(&self) -> Result<AccountId, Error> {
        let voter = env::signer_account_id();
        match self {
            Self::V0(contract) => contract.protocol_state.is_participant(voter),
            Self::V1(contract) => contract.protocol_state.is_participant(voter),
        }
    }
}
