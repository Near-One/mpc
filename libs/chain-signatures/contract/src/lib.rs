pub mod config;
pub mod errors;
pub mod primitives;
pub mod state;
pub mod update;
use config::{ConfigV1, ConfigV2, InitConfigV1, InitConfigV2};
use crypto_shared::{
    derive_epsilon, derive_key, kdf::check_ec_signature, near_public_key_to_affine_point,
    types::SignatureResponse, ScalarExt as _,
};
use errors::{
    ConversionError, InitError, InvalidParameters, InvalidState, PublicKeyError, RespondError,
    SignError, VersionError,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Scalar;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::store::Vector;
use near_sdk::{
    env, log, near_bindgen, AccountId, CryptoHash, Gas, GasWeight, NearToken, Promise,
    PromiseError, PublicKey,
};
use primitives::{StorageKey, YieldIndex};
use state::key_state::{DKState, KeyEventId, KeyStateProposal};
use state::participants::{CandidateInfo, Candidates, Participants};
use state::protocol_state_v2::{
    InitializingContractStateV2, ProtocolContractStateV2, ResharingContractStateV2,
    RunningContractStateV2,
};
use state::signature::{ContractSignatureRequest, SignRequest, SignatureRequest};
use state::votes::{KeyStateVotes, PkVotes, Votes};
use std::cmp;
use std::collections::BTreeMap;

use crate::config::Config;
use crate::errors::Error;
use crate::update::{ProposeUpdateArgs, ProposedUpdates, UpdateId};
pub use state::protocol_state::{
    InitializingContractState, ProtocolContractState, ResharingContractState, RunningContractState,
};
const GAS_FOR_SIGN_CALL: Gas = Gas::from_tgas(10);

// Register used to receive data id from `promise_await_data`.
const DATA_ID_REGISTER: u64 = 0;

// Prepaid gas for a `return_signature_and_clean_state_on_success` call
const RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS: Gas = Gas::from_tgas(5);

// Prepaid gas for a `update_config` call
const UPDATE_CONFIG_GAS: Gas = Gas::from_tgas(5);

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub enum VersionedMpcContract {
    V0(MpcContract),
    V1(MpcContractV1),
    V2(MpcContractV2),
}

impl Default for VersionedMpcContract {
    fn default() -> Self {
        env::panic_str("Calling default not allowed.");
    }
}
use near_sdk::near;
#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct MpcContractV2 {
    protocol_state: ProtocolContractStateV2,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_by_block_height: Vector<(u64, SignatureRequest)>,
    proposed_updates: ProposedUpdates,
    config: ConfigV2,
}

impl MpcContractV2 {
    fn remove_timed_out_requests(&mut self, max_num_to_remove: u32) -> u32 {
        _remove_timed_out_requests(
            &mut self.pending_requests,
            &mut self.request_by_block_height,
            max_num_to_remove,
            self.config.request_timeout_blocks,
        )
    }
    fn add_request(&mut self, request: &SignatureRequest, data_id: CryptoHash) {
        self.request_by_block_height
            .push((env::block_height(), request.clone()));
        self.pending_requests
            .insert(request, &YieldIndex { data_id });
        // todo: improve this logic.
        // If a user submits a request at t0 and submits the same request at t1 > t0,
        // then the request might get removed from the state when cleaning up t0.
    }
    fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        self.pending_requests.get(request)
    }

    pub fn init(proposed_key_state: KeyStateProposal, init_config: Option<InitConfigV2>) -> Self {
        log!(
            "init: proposed_key_state={:?}, init_config={:?}",
            proposed_key_state,
            init_config,
        );

        MpcContractV2 {
            config: ConfigV2::from(init_config),
            protocol_state: ProtocolContractStateV2::Initializing(InitializingContractStateV2 {
                proposed_key_state,
                current_keygen_instance: None,
            }),
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            request_by_block_height: Vector::new(StorageKey::RequestsByTimestamp),
            proposed_updates: ProposedUpdates::default(),
        }
    }
    pub fn start_keygen_instance(&mut self) -> Result<(), Error> {
        match &mut self.protocol_state {
            ProtocolContractStateV2::Initializing(initializing) => {
                initializing.start_keygen_instance(self.config.reshare_timeout_blocks)
            }
            _ => Err(InvalidState::ProtocolStateNotResharing.into()),
        }
    }
    pub fn start_reshare_instance(&mut self, new_epoch_id: u64) -> Result<(), Error> {
        match &mut self.protocol_state {
            ProtocolContractStateV2::Resharing(resharing) => {
                resharing.start_reshare_instance(new_epoch_id, self.config.reshare_timeout_blocks)
            }
            _ => Err(InvalidState::ProtocolStateNotResharing.into()),
        }
    }
    pub fn conclude_reshare_instance(
        &mut self,
        key_event_id: KeyEventId,
    ) -> Result<Option<RunningContractStateV2>, Error> {
        let running = match &mut self.protocol_state {
            ProtocolContractStateV2::Resharing(resharing) => {
                resharing.vote_reshared(key_event_id, self.config.reshare_timeout_blocks)?
            }
            _ => {
                return Err(InvalidState::ProtocolStateNotResharing.into());
            }
        };
        if running {
            match &self.protocol_state {
                ProtocolContractStateV2::Resharing(resharing) => {
                    return Ok(Some(RunningContractStateV2::from(resharing)));
                }
                _ => {
                    return Err(InvalidState::ProtocolStateNotResharing.into());
                }
            }
        }
        Ok(None)
    }
    pub fn conclude_keygen_instance(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
    ) -> Result<Option<RunningContractStateV2>, Error> {
        let running = match &mut self.protocol_state {
            ProtocolContractStateV2::Initializing(initializing) => initializing.vote_keygen(
                key_event_id,
                public_key.clone(),
                self.config.reshare_timeout_blocks,
            )?,
            _ => {
                return Err(InvalidState::ProtocolStateNotResharing.into());
            }
        };
        if running {
            match &self.protocol_state {
                ProtocolContractStateV2::Initializing(state) => {
                    return Ok(Some(RunningContractStateV2 {
                        key_state: DKState::from((
                            &state.proposed_key_state,
                            &public_key,
                            &state.current_keygen_instance.as_ref().unwrap().key_event_id,
                        )),
                        key_state_votes: KeyStateVotes::default(),
                    }));
                }
                _ => {
                    return Err(InvalidState::ProtocolStateNotResharing.into());
                }
            }
        }
        Ok(None)
    }
}

/* Deprecated V1 Code */
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContractV1 {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_by_block_height: Vector<(u64, SignatureRequest)>,
    proposed_updates: ProposedUpdates,
    config: ConfigV1,
}

fn _remove_timed_out_requests(
    pending_requests: &mut LookupMap<SignatureRequest, YieldIndex>,
    request_by_block_height: &mut Vector<(u64, SignatureRequest)>,
    max_num_to_remove: u32,
    request_timeout_blocks: u64,
) -> u32 {
    let min_pending_request_height =
        cmp::max(env::block_height(), request_timeout_blocks) - request_timeout_blocks;
    let mut i = 0;
    for x in request_by_block_height.iter() {
        if (min_pending_request_height <= x.0) || (i > max_num_to_remove) {
            break;
        }
        pending_requests.remove(&x.1);
        i += 1;
    }
    request_by_block_height.drain(..i);
    cmp::max(i, 1) - 1
}

impl MpcContractV1 {
    fn remove_timed_out_requests(&mut self, max_num_to_remove: u32) -> u32 {
        _remove_timed_out_requests(
            &mut self.pending_requests,
            &mut self.request_by_block_height,
            max_num_to_remove,
            self.config.request_timeout_blocks,
        )
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

/* Deprecated V0 */
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_counter: u32,
    proposed_updates: ProposedUpdates,
    config: Config,
}
impl MpcContract {
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

fn valid_signature_request(
    max_key_version: u32,
    request: &SignRequest,
) -> Result<SignatureRequest, Error> {
    // It's important we fail here because the MPC nodes will fail in an identical way.
    // This allows users to get the error message
    let payload = match Scalar::from_bytes(request.payload) {
        Some(payload) => payload,
        None => {
            return Err(InvalidParameters::MalformedPayload
                .message("Payload hash cannot be convereted to Scalar"));
        }
    };

    if request.key_version > max_key_version {
        return Err(SignError::UnsupportedKeyVersion.into());
    }

    // Make sure sign call will not run out of gas doing yield/resume logic
    if env::prepaid_gas() < GAS_FOR_SIGN_CALL {
        return Err(InvalidParameters::InsufficientGas.message(format!(
            "Provided: {}, required: {}",
            env::prepaid_gas(),
            GAS_FOR_SIGN_CALL
        )));
    }

    let predecessor = env::predecessor_account_id();
    // Check deposit and refund if required
    let deposit = env::attached_deposit();
    match deposit.checked_sub(NearToken::from_yoctonear(1)) {
        None => {
            return Err(InvalidParameters::InsufficientDeposit.message(format!(
                "Require a deposit of 1 yoctonear, found: {}",
                deposit.as_yoctonear(),
            )));
        }
        Some(diff) => {
            if diff > NearToken::from_yoctonear(0) {
                log!("refund excess deposit {diff} to {predecessor}");
                Promise::new(predecessor.clone()).transfer(diff);
            }
        }
    }

    Ok(SignatureRequest::new(payload, &predecessor, &request.path))
}
// User contract API
#[near_bindgen]
impl VersionedMpcContract {
    pub fn remove_timed_out_requests(&mut self, max_num_to_remove: Option<u32>) -> u32 {
        match self {
            Self::V0(_) => 0,
            Self::V1(mpc_contract) => mpc_contract.remove_timed_out_requests(
                max_num_to_remove.unwrap_or(mpc_contract.config.max_num_requests_to_remove),
            ),
            Self::V2(mpc_contract) => mpc_contract.remove_timed_out_requests(
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
        log!(
            "sign: predecessor={:?}, request={:?}",
            env::predecessor_account_id(),
            request
        );
        // ensure the signer sent a valid signature request
        let request = match valid_signature_request(self.latest_key_version(), &request) {
            Err(err) => env::panic_str(&err.to_string()),
            Ok(request) => request,
        };

        let Self::V2(mpc_contract) = self else {
            env::panic_str(&VersionError::Deprecated.to_string());
        };
        // Remove timed out requests
        mpc_contract.remove_timed_out_requests(mpc_contract.config.max_num_requests_to_remove);

        // Check if the request already exists.
        if mpc_contract.pending_requests.contains_key(&request) {
            env::panic_str(&SignError::PayloadCollision.to_string());
        }

        env::log_str(&serde_json::to_string(&near_sdk::env::random_seed_array()).unwrap());

        let promise_index = env::promise_yield_create(
            "return_signature_and_clean_state_on_success_v2",
            &serde_json::to_vec(&(&request,)).unwrap(),
            RETURN_SIGNATURE_AND_CLEAN_STATE_ON_SUCCESS_CALL_GAS,
            GasWeight(0),
            DATA_ID_REGISTER,
        );

        // Store the request in the contract's local state
        let return_sig_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("read_register failed")
            .try_into()
            .expect("conversion to CryptoHash failed");
        mpc_contract.add_request(&request, return_sig_id);

        env::promise_return(promise_index);
    }

    /// This is the root public key combined from all the public keys of the participants.
    #[handle_result]
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        match self {
            Self::V0(_) | Self::V1(_) => env::panic_str("deprecated"),
            Self::V2(mpc_contract) => match &mpc_contract.protocol_state {
                ProtocolContractStateV2::Running(state) => Ok(state.key_state.public_key.clone()),
                ProtocolContractStateV2::Resharing(state) => {
                    Ok(state.current_state.key_state.public_key.clone())
                }
                _ => Err(InvalidState::ProtocolStateNotRunningNorResharing.into()),
            },
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
}

// Node API
#[near_bindgen]
impl VersionedMpcContract {
    #[handle_result]
    pub fn respond(
        &mut self,
        request: SignatureRequest,
        response: SignatureResponse,
    ) -> Result<(), Error> {
        let signer = env::signer_account_id();
        log!(
            "respond: signer={}, request={:?} big_r={:?} s={:?}",
            &signer,
            &request,
            &response.big_r,
            &response.s
        );
        let ProtocolContractStateV2::Running(_) = self.mutable_state() else {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        };
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
                    mpc_contract
                        .remove_timed_out_requests(mpc_contract.config.max_num_requests_to_remove);
                }
                Self::V2(mpc_contract) => {
                    mpc_contract
                        .remove_timed_out_requests(mpc_contract.config.max_num_requests_to_remove);
                }
            }
            // Finally, resolve the promise. This will have no effect if the request already timed.
            env::promise_yield_resume(&data_id, &serde_json::to_vec(&response).unwrap());
            Ok(())
        } else {
            Err(InvalidParameters::RequestNotFound.into())
        }
    }

    #[handle_result]
    pub fn propose_new_key_state(
        &mut self,
        proposed_key_state: KeyStateProposal,
    ) -> Result<bool, Error> {
        log!(
            "propose_new_key_state: signer={}, proposed_key_state={:?}",
            env::signer_account_id(),
            proposed_key_state,
        );
        match self {
            Self::V0(_) | Self::V1(_) => {
                env::panic_str("deprecated");
            }
            Self::V2(mpc_contract) => {
                let enter = match &mut mpc_contract.protocol_state {
                    ProtocolContractStateV2::Running(state) => {
                        state.vote_key_state_proposal(&proposed_key_state)?
                    }
                    ProtocolContractStateV2::Resharing(state) => {
                        state.vote_key_state_proposal(&proposed_key_state)?
                    }
                    _ => {
                        env::panic_str("unsupported");
                    }
                };
                if enter {
                    let next_state = match &mpc_contract.protocol_state {
                        ProtocolContractStateV2::Running(state) => {
                            ResharingContractStateV2::from((state, &proposed_key_state))
                        }
                        ProtocolContractStateV2::Resharing(state) => {
                            ResharingContractStateV2::from((state, &proposed_key_state))
                        }
                        _ => {
                            env::panic_str("unexpected");
                        }
                    };
                    // todo add log messages
                    mpc_contract.protocol_state = ProtocolContractStateV2::Resharing(next_state);
                    return Ok(true);
                }
            }
        };
        Ok(false)
    }

    #[handle_result]
    pub fn start_keygen_instance(&mut self) -> Result<(), Error> {
        log!("start_keygen_instance: signer={}", env::signer_account_id(),);
        match self {
            Self::V0(_) | Self::V1(_) => {
                Err(InvalidState::UnexpectedProtocolState.message("expected V2"))
            }
            Self::V2(contract_state) => contract_state.start_keygen_instance(),
        }
    }
    #[handle_result]
    pub fn complete_keygen_instance(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
    ) -> Result<bool, Error> {
        log!(
            "complete_keygen_instance: signer={}, resharing_id={:?}",
            env::signer_account_id(),
            key_event_id,
        );
        match self {
            Self::V0(_) | Self::V1(_) => {
                Err(InvalidState::UnexpectedProtocolState.message("expected V2"))
            }
            Self::V2(contract_state) => {
                if let Some(running) =
                    contract_state.conclude_keygen_instance(key_event_id, public_key)?
                {
                    contract_state.protocol_state = ProtocolContractStateV2::Running(running);
                }
                Ok(false)
            }
        }
    }
    #[handle_result]
    pub fn start_reshare_instance(&mut self, new_epoch_id: u64) -> Result<(), Error> {
        log!(
            "start_reshare_instance: signer={}, new_epoch_id={}",
            env::signer_account_id(),
            new_epoch_id,
        );
        match self {
            Self::V0(_) | Self::V1(_) => {
                Err(InvalidState::UnexpectedProtocolState.message("expected V2"))
            }
            Self::V2(contract_state) => contract_state.start_reshare_instance(new_epoch_id),
        }
    }

    #[handle_result]
    pub fn complete_reshare_instance(&mut self, key_event_id: KeyEventId) -> Result<bool, Error> {
        log!(
            "complete_reshare_instance: signer={}, resharing_id={:?}",
            env::signer_account_id(),
            key_event_id,
        );
        match self {
            Self::V0(_) | Self::V1(_) => {
                Err(InvalidState::UnexpectedProtocolState.message("expected V2"))
            }
            Self::V2(contract_state) => {
                if let Some(running) = contract_state.conclude_reshare_instance(key_event_id)? {
                    contract_state.protocol_state = ProtocolContractStateV2::Running(running);
                }
                Ok(false)
            }
        }
    }

    #[payable]
    #[handle_result]
    pub fn propose_update(
        &mut self,
        #[serializer(borsh)] args: ProposeUpdateArgs,
    ) -> Result<UpdateId, Error> {
        // Only voters can propose updates:
        let proposer = self.voter_or_panic();

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
        let voter = self.voter_or_panic();
        let threshold = match &self {
            Self::V0(_) | Self::V1(_) => env::panic_str("deprecated"),
            Self::V2(mpc_contract) => match &mpc_contract.protocol_state {
                ProtocolContractStateV2::Initializing(state) => {
                    state.proposed_key_state.proposed_threshold()
                }
                ProtocolContractStateV2::Running(state) => state.key_state.threshold(),
                ProtocolContractStateV2::Resharing(state) => {
                    state.current_state.key_state.threshold()
                }
                ProtocolContractStateV2::NotInitialized => {
                    return Err(InvalidState::UnexpectedProtocolState.into());
                }
            },
        };
        let Some(votes) = self.proposed_updates().vote(&id, voter) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        // Not enough votes, wait for more.
        if (votes.len() as u64) < threshold.value() {
            return Ok(false);
        }

        let Some(_promise) = self.proposed_updates().do_update(&id, UPDATE_CONFIG_GAS) else {
            return Err(InvalidParameters::UpdateNotFound.into());
        };

        Ok(true)
    }
}

// Contract developer helper API
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
                Ok(VersionedMpcContract::V2(MpcContractV2 {
                    config: ConfigV2::default(), //todo
                    protocol_state: (&mpc_contract_v0.protocol_state).into(),
                    pending_requests: mpc_contract_v0.pending_requests,
                    request_by_block_height: Vector::new(StorageKey::RequestsByTimestamp),
                    proposed_updates: ProposedUpdates::default(),
                }))
            }
            VersionedMpcContract::V1(mpc_contract_v1) => {
                Ok(VersionedMpcContract::V2(MpcContractV2 {
                    config: ConfigV2::from(&mpc_contract_v1.config),
                    protocol_state: (&mpc_contract_v1.protocol_state).into(),
                    pending_requests: mpc_contract_v1.pending_requests,
                    request_by_block_height: Vector::new(StorageKey::RequestsByTimestamp),
                    proposed_updates: ProposedUpdates::default(),
                }))
            }
            VersionedMpcContract::V2(_) => Ok(old),
        }
    }

    pub fn state(&self) -> &ProtocolContractStateV2 {
        match self {
            Self::V0(_) | Self::V1(_) => env::panic_str("deprecated"),
            Self::V2(mpc_contract) => &mpc_contract.protocol_state,
        }
    }

    pub fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        match self {
            Self::V0(mpc_contract) => mpc_contract.get_pending_request(request),
            Self::V1(mpc_contract) => mpc_contract.get_pending_request(request),
            Self::V2(mpc_contract) => mpc_contract.get_pending_request(request),
        }
    }

    pub fn config(&self) -> &ConfigV2 {
        match self {
            Self::V0(_) | Self::V1(_) => panic!("Deprecated, use V2"),
            Self::V2(mpc_contract) => &mpc_contract.config,
        }
    }

    // contract version
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// **DEPRECATED after V2** Upon success, removes the signature from state and returns it.
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
            Self::V0(_) | Self::V2(_) => {
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

    /// Upon success, removes the signature from state and returns it.
    /// Returns an Error if the signature timed out.
    /// Note that timed out signatures will need to be cleaned up from the state by a different function.
    #[private]
    #[handle_result] // question: is this bad? should we remove this?
    pub fn return_signature_and_clean_state_on_success_v2(
        &mut self,
        request: SignatureRequest,
        #[callback_result] signature: Result<SignatureResponse, PromiseError>,
    ) -> Result<SignatureResponse, Error> {
        let Self::V2(mpc_contract) = self else {
            return Err(VersionError::VersionMismatch.into());
        };
        match signature {
            Ok(signature) => {
                log!("Signature is ready.");
                mpc_contract.pending_requests.remove(&request);
                Ok(signature)
            }
            Err(_) => Err(SignError::Timeout.into()),
        }
    }

    #[private]
    pub fn update_config(&mut self, config: ConfigV2) {
        let Self::V2(mpc_contract) = self else {
            env::panic_str(&VersionError::VersionMismatch.to_string());
        };
        mpc_contract.config = config;
    }

    fn mutable_state(&mut self) -> &mut ProtocolContractStateV2 {
        match self {
            Self::V0(_) | Self::V1(_) => env::panic_str("deprecated"),
            Self::V2(ref mut mpc_contract) => &mut mpc_contract.protocol_state,
        }
    }

    fn proposed_updates(&mut self) -> &mut ProposedUpdates {
        match self {
            Self::V0(contract) => &mut contract.proposed_updates,
            Self::V1(contract) => &mut contract.proposed_updates,
            Self::V2(contract) => &mut contract.proposed_updates,
        }
    }
    /// Get our own account id as a voter.
    /// If we are not a participant, panic.
    fn voter_or_panic(&self) -> AccountId {
        let voter = env::signer_account_id();
        match self {
            Self::V0(_) | Self::V1(_) => env::panic_str("deprecated"),
            Self::V2(contract) => match contract.protocol_state.is_participant(voter) {
                Ok(voter) => voter,
                Err(err) => {
                    env::panic_str(format!("not a voter, {:?}", err).as_str());
                }
            },
        }
    }
}
