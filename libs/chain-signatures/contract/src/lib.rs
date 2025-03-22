pub mod config;
pub mod crypto_shared;
pub mod errors;
pub mod legacy_contract_state;
pub mod primitives;
pub mod state;
pub mod storage_keys;
pub mod update;

use crate::errors::Error;
use crate::update::{ProposeUpdateArgs, ProposedUpdates, UpdateId};
use config::{Config, InitConfig};
use crypto_shared::{
    derive_key, derive_tweak, kdf::check_ec_signature, near_public_key_to_affine_point,
    types::SignatureResponse, ScalarExt as _,
};
use errors::{
    ConversionError, DomainError, InvalidParameters, InvalidState, PublicKeyError, RespondError,
    SignError,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::near;
use near_sdk::store::{LookupMap, Vector};
use near_sdk::{
    env, log, near_bindgen, AccountId, BlockHeight, CryptoHash, Gas, GasWeight, NearToken, Promise,
    PromiseError, PublicKey,
};
use primitives::domain::{DomainConfig, DomainId, DomainRegistry, SignatureScheme};
use primitives::key_state::{EpochId, KeyEventId, Keyset};
use primitives::signature::{PayloadHash, SignRequest, SignatureRequest, Tweak, YieldIndex};
use primitives::thresholds::{Threshold, ThresholdParameters};
use state::running::RunningContractState;
use state::ProtocolContractState;
use std::cmp;
use storage_keys::StorageKey;

//Gas requised for a sign request
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
}

impl Default for VersionedMpcContract {
    fn default() -> Self {
        env::panic_str("Calling default not allowed.");
    }
}

#[near(serializers=[borsh])]
#[derive(Debug)]
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_by_block_height: Vector<(u64, SignatureRequest)>,
    proposed_updates: ProposedUpdates,
    config: Config,
}

impl MpcContract {
    fn public_key(&self, domain_id: DomainId) -> Result<PublicKey, Error> {
        self.protocol_state.public_key(domain_id)
    }

    fn threshold(&self) -> Result<Threshold, Error> {
        self.protocol_state.threshold()
    }

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
            .insert(request.clone(), YieldIndex { data_id });
        // todo: improve this logic.
        // If a user submits a request at t0 and submits the same request at t1 > t0,
        // then the request might get removed from the state when cleaning up t0.
    }

    fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        self.pending_requests.get(request).cloned()
    }

    pub fn init(parameters: ThresholdParameters, init_config: Option<InitConfig>) -> Self {
        log!(
            "init: parameters={:?}, init_config={:?}",
            parameters,
            init_config,
        );
        parameters.validate().unwrap();

        MpcContract {
            config: Config::from(init_config),
            protocol_state: ProtocolContractState::Running(RunningContractState::new(
                DomainRegistry::default(),
                Keyset::new(EpochId::new(0), Vec::new()),
                parameters,
            )),
            pending_requests: LookupMap::new(StorageKey::PendingRequests),
            request_by_block_height: Vector::new(StorageKey::RequestsByTimestamp),
            proposed_updates: ProposedUpdates::default(),
        }
    }

    pub fn start_keygen_instance(&mut self) -> Result<(), Error> {
        self.protocol_state
            .start_keygen_instance(self.config.event_max_idle_blocks)
    }

    pub fn start_reshare_instance(&mut self) -> Result<(), Error> {
        self.protocol_state
            .start_reshare_instance(self.config.event_max_idle_blocks)
    }

    pub fn vote_reshared(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        if let Some(new_state) = self.protocol_state.vote_reshared(key_event_id)? {
            self.protocol_state = new_state;
        }
        Ok(())
    }

    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        if let Some(new_state) = self.protocol_state.vote_pk(key_event_id, public_key)? {
            self.protocol_state = new_state;
        }
        Ok(())
    }

    pub fn vote_cancel_keygen(&mut self) -> Result<(), Error> {
        if let Some(new_state) = self.protocol_state.vote_cancel_keygen()? {
            self.protocol_state = new_state;
        }
        Ok(())
    }

    pub fn vote_new_parameters(&mut self, proposal: &ThresholdParameters) -> Result<(), Error> {
        if let Some(new_state) = self.protocol_state.vote_new_parameters(proposal)? {
            self.protocol_state = new_state;
        }
        Ok(())
    }

    pub fn vote_add_domains(&mut self, domains: Vec<DomainConfig>) -> Result<(), Error> {
        if let Some(new_state) = self.protocol_state.vote_add_domains(domains)? {
            self.protocol_state = new_state;
        }
        Ok(())
    }
}

// User contract API
#[near_bindgen]
impl VersionedMpcContract {
    pub fn remove_timed_out_requests(&mut self, max_num_to_remove: Option<u32>) -> u32 {
        match self {
            Self::V0(mpc_contract) => mpc_contract.remove_timed_out_requests(
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
        // It's important we fail here because the MPC nodes will fail in an identical way.
        // This allows users to get the error message
        if k256::Scalar::from_bytes(request.payload.as_bytes()).is_none() {
            env::panic_str(
                &InvalidParameters::MalformedPayload
                    .message("Payload hash cannot be convereted to Scalar")
                    .to_string(),
            );
        };

        if request.key_version > self.latest_key_version(None) {
            env::panic_str(&SignError::UnsupportedKeyVersion.to_string());
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

        let predecessor = env::predecessor_account_id();
        // Check deposit and refund if required
        let deposit = env::attached_deposit();
        match deposit.checked_sub(NearToken::from_yoctonear(1)) {
            None => {
                env::panic_str(
                    &InvalidParameters::InsufficientDeposit
                        .message(format!(
                            "Require a deposit of 1 yoctonear, found: {}",
                            deposit.as_yoctonear(),
                        ))
                        .to_string(),
                );
            }
            Some(diff) => {
                if diff > NearToken::from_yoctonear(0) {
                    log!("refund excess deposit {diff} to {predecessor}");
                    Promise::new(predecessor.clone()).transfer(diff);
                }
            }
        }

        let request = SignatureRequest::new(request.payload, &predecessor, &request.path);

        let Self::V0(mpc_contract) = self;
        // Remove timed out requests
        mpc_contract.remove_timed_out_requests(mpc_contract.config.max_num_requests_to_remove);

        // Check if the request already exists.
        if mpc_contract.pending_requests.contains_key(&request) {
            env::panic_str(&SignError::PayloadCollision.to_string());
        }

        env::log_str(&serde_json::to_string(&near_sdk::env::random_seed_array()).unwrap());

        let promise_index = env::promise_yield_create(
            "return_signature_and_clean_state_on_success",
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
    /// The domain parameter specifies which domain we're querying the public key for;
    /// the default is the first domain.
    #[handle_result]
    pub fn public_key(&self, domain: Option<DomainId>) -> Result<PublicKey, Error> {
        let domain = domain.unwrap_or_else(DomainId::legacy_ecdsa_id);
        match self {
            Self::V0(mpc_contract) => mpc_contract.public_key(domain),
        }
    }

    /// This is the derived public key of the caller given path and predecessor
    /// if predecessor is not provided, it will be the caller of the contract.
    ///
    /// The domain parameter specifies which domain we're deriving the public key for;
    /// the default is the first domain.
    #[handle_result]
    pub fn derived_public_key(
        &self,
        path: String,
        predecessor: Option<AccountId>,
        domain: Option<DomainId>,
    ) -> Result<PublicKey, Error> {
        let predecessor = predecessor.unwrap_or_else(env::predecessor_account_id);
        let tweak = derive_tweak(&predecessor, &path);
        let derived_public_key = derive_key(
            near_public_key_to_affine_point(self.public_key(domain)?),
            &tweak,
        );
        let encoded_point = derived_public_key.to_encoded_point(false);
        let slice: &[u8] = &encoded_point.as_bytes()[1..65];
        let mut data: Vec<u8> = vec![near_sdk::CurveType::SECP256K1 as u8];
        data.extend(slice.to_vec());
        PublicKey::try_from(data).map_err(|_| PublicKeyError::DerivedKeyConversionFailed.into())
    }

    /// Key versions refer new versions of the root key that we may choose to generate on cohort changes
    /// Older key versions will always work but newer key versions were never held by older signers
    /// Newer key versions may also add new security features, like only existing within a secure enclave.
    /// The signature_scheme parameter specifies which signature scheme we're querying the latest version
    /// for. The default is Secp256k1. The default is **NOT** to query across all signature schemes.
    pub fn latest_key_version(&self, signature_scheme: Option<SignatureScheme>) -> u32 {
        self.state()
            .most_recent_domain_for_signature_scheme(
                signature_scheme.unwrap_or(SignatureScheme::Secp256k1),
            )
            .unwrap()
            .0 as u32
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
        if !self.state().is_running() {
            return Err(InvalidState::ProtocolStateNotRunning.into());
        }
        // generate the expected public key
        let pk = self.public_key(None)?;
        let expected_public_key = derive_key(near_public_key_to_affine_point(pk), &request.tweak);

        // Check the signature is correct
        if check_ec_signature(
            &expected_public_key,
            &response.big_r.affine_point,
            &response.s.scalar,
            &request.payload_hash,
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
                Self::V0(mpc_contract) => {
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

    /// Propose a new set of parameters (participants and threshold) for the MPC network.
    /// If a threshold number of votes are reached on the exact same proposal, this will transition
    /// the contract into the Resharing state.
    #[handle_result]
    pub fn vote_new_parameters(&mut self, proposal: ThresholdParameters) -> Result<(), Error> {
        log!(
            "vote_new_parameters: signer={}, proposal={:?}",
            env::signer_account_id(),
            proposal,
        );
        match self {
            Self::V0(mpc_contract) => mpc_contract.vote_new_parameters(&proposal),
        }
    }

    /// Propose adding a new set of domains for the MPC network.
    /// If a threshold number of votes are reached on the exact same proposal, this will transition
    /// the contract into the Initializing state to generate keys for the new domains.
    ///
    /// The specified list of domains must have increasing and contiguous IDs, and the first ID
    /// must be the same as the `next_domain_id` returned by state().
    #[handle_result]
    pub fn vote_add_domains(&mut self, domains: Vec<DomainConfig>) -> Result<(), Error> {
        log!(
            "vote_add_domains: signer={}, domains={:?}",
            env::signer_account_id(),
            domains,
        );
        match self {
            Self::V0(mpc_contract) => mpc_contract.vote_add_domains(domains),
        }
    }

    /// Starts a new attempt to generate a key for the current domain.
    /// This only succeeds if the signer is the leader (the participant with the lowest ID).
    #[handle_result]
    pub fn start_keygen_instance(&mut self) -> Result<(), Error> {
        log!("start_keygen_instance: signer={}", env::signer_account_id(),);
        match self {
            Self::V0(contract_state) => contract_state.start_keygen_instance(),
        }
    }

    /// Casts a vote for `public_key` for the attempt identified by `key_event_id`.
    ///
    /// The effect of this method is either:
    ///  - Returns error (which aborts with no changes), if there is no active key generation
    ///    attempt (including if the attempt timed out), if the signer is not a participant,
    ///    or if the key_event_id corresponds to a different domain, different epoch, or different
    ///    attempt from the current key generation attempt.
    ///  - Returns Ok(()), with one of the following changes:
    ///    - A vote has been collected but we don't have enough votes yet.
    ///    - This vote is for a public key that disagrees from an earlier voted public key, causing
    ///      the attempt to abort; another call to `start` is then necessary.
    ///    - Everyone has now voted for the same public key; the state transitions into generating a
    ///      key for the next domain.
    ///    - Same as the last case, except that all domains have a generated key now, and the state
    ///      transitions into Running with the newly generated keys.
    #[handle_result]
    pub fn vote_pk(
        &mut self,
        key_event_id: KeyEventId,
        public_key: PublicKey,
    ) -> Result<(), Error> {
        log!(
            "vote_pk: signer={}, key_event_id={:?}, public_key={:?}",
            env::signer_account_id(),
            key_event_id,
            public_key,
        );
        match self {
            Self::V0(contract_state) => contract_state.vote_pk(key_event_id, public_key),
        }
    }

    /// Starts a new attempt to reshare the key for the current domain.
    /// This only succeeds if the signer is the leader (the participant with the lowest ID).
    #[handle_result]
    pub fn start_reshare_instance(&mut self) -> Result<(), Error> {
        log!(
            "start_reshare_instance: signer={}",
            env::signer_account_id()
        );
        match self {
            Self::V0(contract_state) => contract_state.start_reshare_instance(),
        }
    }

    /// Casts a vote for the successful resharing of the attempt identified by `key_event_id`.
    ///
    /// The effect of this method is either:
    ///  - Returns error (which aborts with no changes), if there is no active key resharing
    ///    attempt (including if the attempt timed out), if the signer is not a participant,
    ///    or if the key_event_id corresponds to a different domain, different epoch, or different
    ///    attempt from the current key resharing attempt.
    ///  - Returns Ok(()), with one of the following changes:
    ///    - A vote has been collected but we don't have enough votes yet.
    ///    - Everyone has now voted; the state transitions into resharing the key for the next
    ///      domain.
    ///    - Same as the last case, except that all domains' keys have been reshared now, and the
    ///      state transitions into Running with the newly reshared keys.
    #[handle_result]
    pub fn vote_reshared(&mut self, key_event_id: KeyEventId) -> Result<(), Error> {
        log!(
            "vote_reshared: signer={}, resharing_id={:?}",
            env::signer_account_id(),
            key_event_id,
        );
        match self {
            Self::V0(contract_state) => contract_state.vote_reshared(key_event_id),
        }
    }

    /// Casts a vote to cancel key generation. Any keys that have already been generated
    /// are kept and we transition into Running state; remaining domains are permanently deleted.
    /// Deleted domain IDs cannot be reused again in future calls to vote_add_domains.
    #[handle_result]
    pub fn vote_cancel_keygen(&mut self) -> Result<(), Error> {
        log!("vote_cancel_keygen: signer={}", env::signer_account_id());
        match self {
            Self::V0(contract_state) => contract_state.vote_cancel_keygen(),
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
            Self::V0(mpc_contract) => mpc_contract.threshold()?,
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
        parameters: ThresholdParameters,
        init_config: Option<InitConfig>,
    ) -> Result<Self, Error> {
        log!(
            "init: signer={}, parameters={:?}, init_config={:?}",
            env::signer_account_id(),
            parameters,
            init_config,
        );
        parameters.validate()?;

        Ok(Self::V0(MpcContract::init(parameters, init_config)))
    }

    // This function can be used to transfer the MPC network to a new contract.
    #[private]
    #[init]
    #[handle_result]
    pub fn init_running(
        domains: Vec<DomainConfig>,
        next_domain_id: u64,
        keyset: Keyset,
        parameters: ThresholdParameters,
        init_config: Option<InitConfig>,
    ) -> Result<Self, Error> {
        log!(
            "init_running: signer={}, domains={:?}, keyset={:?}, parameters={:?}, init_config={:?}",
            env::signer_account_id(),
            domains,
            keyset,
            parameters,
            init_config,
        );
        parameters.validate()?;
        let domains = DomainRegistry::from_raw_validated(domains, next_domain_id)?;

        // Check that the domains match exactly those in the keyset.
        let domain_ids_from_domains = domains.domains().iter().map(|d| d.id).collect::<Vec<_>>();
        let domain_ids_from_keyset = keyset
            .domains
            .iter()
            .map(|k| k.domain_id)
            .collect::<Vec<_>>();
        if domain_ids_from_domains != domain_ids_from_keyset {
            return Err(DomainError::DomainsMismatch.into());
        }

        Ok(Self::V0(MpcContract {
            config: Config::from(init_config),
            protocol_state: ProtocolContractState::Running(RunningContractState::new(
                domains, keyset, parameters,
            )),
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
        if let Some(legacy_contract_state::VersionedMpcContract::V1(state)) =
            env::state_read::<legacy_contract_state::VersionedMpcContract>()
        {
            // migrate config
            let mut config = Config::default();
            config.request_timeout_blocks = state.config.request_timeout_blocks;
            config.max_num_requests_to_remove = state.config.max_num_requests_to_remove;
            // migrate signature requests:
            let mut request_by_block_height: Vector<(BlockHeight, SignatureRequest)> =
                Vector::new(StorageKey::RequestsByTimestamp);
            let mut pending_requests: LookupMap<SignatureRequest, YieldIndex> =
                LookupMap::new(StorageKey::PendingRequests);
            for (created, request) in &state.request_by_block_height {
                // check if request is still valid:
                if created + config.request_timeout_blocks > env::block_height() {
                    // check if request is still pending:
                    if let Some(data_id) = state.pending_requests.get(request) {
                        let data_id = YieldIndex {
                            data_id: data_id.data_id,
                        };

                        let tweak = Tweak::new(request.tweak.scalar.to_bytes().into());
                        let payload_hash =
                            PayloadHash::new(request.payload_hash.scalar.to_bytes().into());

                        let request = SignatureRequest {
                            payload_hash,
                            tweak,
                        };

                        request_by_block_height.push((*created, request.clone()));
                        pending_requests.insert(request, data_id);
                    }
                }
            }
            return Ok(VersionedMpcContract::V0(MpcContract {
                config,
                protocol_state: (&state.protocol_state).into(),
                pending_requests,
                request_by_block_height,
                proposed_updates: ProposedUpdates::default(),
            }));
        }
        if let Some(v2_contract) = env::state_read::<VersionedMpcContract>() {
            return Ok(v2_contract);
        }
        Err(InvalidState::ContractStateIsMissing.into())
    }

    pub fn state(&self) -> &ProtocolContractState {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.protocol_state,
        }
    }

    pub fn get_pending_request(&self, request: &SignatureRequest) -> Option<YieldIndex> {
        match self {
            Self::V0(mpc_contract) => mpc_contract.get_pending_request(request),
        }
    }

    pub fn config(&self) -> &Config {
        match self {
            Self::V0(mpc_contract) => &mpc_contract.config,
        }
    }

    // contract version
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Upon success, removes the signature from state and returns it.
    /// Returns an Error if the signature timed out.
    /// Note that timed out signatures will need to be cleaned up from the state by a different function.
    ///
    /// Note: compared to V0 and V1, the argument types for this function are changed (simply
    /// `SignatureRequest` now, no longer `ContractSignatureRequest`).
    /// This should be fine, because the callback result is passed by the `respond`
    /// function, which is part of V2. Only very few signatures are expected to break, namely if:
    /// Block N:
    /// 1. response submitted, triggers `return_signature_and_clean_state_on_success` with
    ///    `ContractSignatureRequest`
    /// 2. contract code updated
    /// Block N+1:
    /// 1. any calls to the contract get rejected
    /// 2. migration function called
    /// 3. `return_signature_and_clean_state_on_success` fails with `ContractSignatureRequest`
    ///    argument.
    #[private]
    #[handle_result]
    pub fn return_signature_and_clean_state_on_success(
        &mut self,
        request: SignatureRequest, // this change here should actually be ok.
        #[callback_result] signature: Result<SignatureResponse, PromiseError>,
    ) -> Result<SignatureResponse, Error> {
        let Self::V0(mpc_contract) = self;
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
    pub fn update_config(&mut self, config: Config) {
        let Self::V0(mpc_contract) = self;
        mpc_contract.config = config;
    }

    fn proposed_updates(&mut self) -> &mut ProposedUpdates {
        match self {
            Self::V0(contract) => &mut contract.proposed_updates,
        }
    }
    /// Get our own account id as a voter.
    /// If we are not a participant, panic.
    fn voter_or_panic(&self) -> AccountId {
        let voter = env::signer_account_id();
        match self {
            Self::V0(contract) => match contract.protocol_state.authenticate_update_vote() {
                Ok(_) => voter,
                Err(err) => {
                    env::panic_str(format!("not a voter, {:?}", err).as_str());
                }
            },
        }
    }
}
