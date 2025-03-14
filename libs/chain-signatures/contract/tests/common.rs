use crypto_shared::kdf::{check_ec_signature, derive_secret_key};
use crypto_shared::{
    derive_epsilon, derive_key, ScalarExt as _, SerializableAffinePoint, SerializableScalar,
    SignatureResponse,
};
use digest::{Digest, FixedOutput};
use ecdsa::signature::Verifier;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::point::DecompressPoint as _;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, FieldBytes, Scalar, Secp256k1};
use mpc_contract::config::InitConfig;
use mpc_contract::primitives::key_state::{
    AttemptId, DKState, EpochId, KeyEventId, KeyStateProposal,
};
use mpc_contract::primitives::participants::{ParticipantInfo, Participants};
use mpc_contract::primitives::signature::{SignRequest, SignatureRequest};
use mpc_contract::primitives::thresholds::{DKGThreshold, Threshold, ThresholdParameters};
use mpc_contract::update::UpdateId;
use near_sdk::log;
use near_workspaces::network::Sandbox;
use near_workspaces::types::{AccountId, NearToken};
use near_workspaces::{Account, Contract, Worker};
use signature::DigestSigner;
use std::str::FromStr;

pub const CONTRACT_FILE_PATH: &str = "../target/wasm32-unknown-unknown/release/mpc_contract.wasm";
pub const INVALID_CONTRACT: &str = "../res/mpc_test_contract.wasm";
pub const PARTICIPANT_LEN: usize = 3;

pub fn candidates(names: Option<Vec<AccountId>>) -> Participants {
    let mut participants: Participants = Participants::new();
    let names = names.unwrap_or_else(|| {
        vec![
            "alice.near".parse().unwrap(),
            "bob.near".parse().unwrap(),
            "caesar.near".parse().unwrap(),
        ]
    });

    for account_id in names {
        let _ = participants.insert(
            account_id.clone(),
            ParticipantInfo {
                url: "127.0.0.1".into(),
                cipher_pk: [0; 32],
                sign_pk: near_sdk::PublicKey::from_str(
                    "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae",
                )
                .unwrap(),
            },
        );
    }
    participants
}
/// Create `amount` accounts and return them along with the candidate info.
pub async fn accounts(worker: &Worker<Sandbox>) -> (Vec<Account>, Participants) {
    let mut accounts = Vec::with_capacity(PARTICIPANT_LEN);
    for _ in 0..PARTICIPANT_LEN {
        log!("attempting to create account");
        let account = worker.dev_create_account().await.unwrap();
        log!("created account");
        accounts.push(account);
    }
    let candidates = candidates(Some(accounts.iter().map(|a| a.id().clone()).collect()));
    (accounts, candidates)
}

pub async fn init() -> (Worker<Sandbox>, Contract) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let wasm = std::fs::read(CONTRACT_FILE_PATH).unwrap();
    let contract = worker.dev_deploy(&wasm).await.unwrap();
    (worker, contract)
}
pub async fn contruct_valid_key_state_proposal(participants: &Participants) -> KeyStateProposal {
    let threshold = ((participants.count() as f64) * 0.6).ceil() as u64;
    let threshold = Threshold::new(threshold);
    let threshold_parameters = ThresholdParameters::new(participants.clone(), threshold).unwrap();
    let key_event_threshold = DKGThreshold::new(threshold_parameters.participants().count());
    KeyStateProposal::new(threshold_parameters, key_event_threshold).unwrap()
}
pub async fn init_with_candidates(
    pk: Option<near_crypto::PublicKey>,
) -> (Worker<Sandbox>, Contract, Vec<Account>) {
    let (worker, contract) = init().await;
    let (accounts, participants) = accounts(&worker).await;
    let threshold = ((participants.count() as f64) * 0.6).ceil() as u64;
    let threshold = Threshold::new(threshold);
    let threshold_parameters = ThresholdParameters::new(participants, threshold).unwrap();
    let init = if let Some(pk) = pk {
        let pk: near_sdk::PublicKey = near_sdk::PublicKey::from_str(&format!("{}", pk)).unwrap();
        let dk_state = DKState::new(
            pk,
            KeyEventId::new(EpochId::new(5), AttemptId::new()),
            threshold_parameters,
        )
        .unwrap();
        contract
            .call("init_running")
            .args_json(serde_json::json!({
                "key_state": dk_state,
                "init_config": None::<InitConfig>,
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap()
    } else {
        let key_event_threshold = DKGThreshold::new(threshold_parameters.participants().count());
        let key_state_proposal =
            KeyStateProposal::new(threshold_parameters, key_event_threshold).unwrap();
        contract
            .call("init")
            .args_json(serde_json::json!({
                "key_state_proposal": key_state_proposal,
                "init_config": None::<InitConfig>,
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap()
    };
    dbg!(init);
    (worker, contract, accounts)
}

pub async fn init_env() -> (Worker<Sandbox>, Contract, Vec<Account>, k256::SecretKey) {
    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk = sk.public_key();
    let (worker, contract, accounts) =
        init_with_candidates(Some(near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &pk.as_affine().to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        )))
        .await;

    (worker, contract, accounts, sk)
}

/// Process the message, creating the same hash with type of Digest, Scalar, and [u8; 32]
pub async fn process_message(msg: &str) -> (impl Digest, k256::Scalar, [u8; 32]) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();
    let scalar_hash =
        <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            &bytes,
        );

    let payload_hash: [u8; 32] = bytes.into();
    (digest, scalar_hash, payload_hash)
}

pub async fn create_response(
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    sk: &k256::SecretKey,
) -> ([u8; 32], SignatureRequest, SignatureResponse) {
    let (digest, scalar_hash, payload_hash) = process_message(msg).await;
    let pk = sk.public_key();

    let epsilon = derive_epsilon(predecessor_id, path);
    let derived_sk = derive_secret_key(sk, epsilon);
    let derived_pk = derive_key(pk.into(), epsilon);
    let signing_key = k256::ecdsa::SigningKey::from(&derived_sk);
    let verifying_key =
        k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());

    let (signature, _): (ecdsa::Signature<Secp256k1>, _) =
        signing_key.try_sign_digest(digest).unwrap();
    verifying_key.verify(msg.as_bytes(), &signature).unwrap();

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();
    let payload_hash_s = Scalar::from_bytes(payload_hash).unwrap();
    let respond_req = SignatureRequest::new(payload_hash_s, predecessor_id, path);
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    let s: k256::Scalar = *s.as_ref();

    let recovery_id = if check_ec_signature(&derived_pk, &big_r, &s, scalar_hash, 0).is_ok() {
        0
    } else if check_ec_signature(&derived_pk, &big_r, &s, scalar_hash, 1).is_ok() {
        1
    } else {
        panic!("unable to use recovery id of 0 or 1");
    };

    let respond_resp = SignatureResponse {
        big_r: SerializableAffinePoint {
            affine_point: big_r,
        },
        s: SerializableScalar { scalar: s },
        recovery_id,
    };

    (payload_hash, respond_req, respond_resp)
}

pub async fn sign_and_validate(
    request: &SignRequest,
    respond: Option<(&SignatureRequest, &SignatureResponse)>,
    contract: &Contract,
) -> anyhow::Result<()> {
    let status = contract
        .call("sign")
        .args_json(serde_json::json!({
            "request": request,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .max_gas()
        .transact_async()
        .await?;
    dbg!(&status);

    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    if let Some((respond_req, respond_resp)) = respond {
        // Call `respond` as if we are the MPC network itself.
        let respond = contract
            .call("respond")
            .args_json(serde_json::json!({
                "request": respond_req,
                "response": respond_resp
            }))
            .max_gas()
            .transact()
            .await?;
        dbg!(&respond);
    }

    let execution = status.await?;
    dbg!(&execution);
    let execution = execution.into_result()?;

    // Finally wait the result:
    let returned_resp: SignatureResponse = execution.json()?;
    if let Some((_, respond_resp)) = respond {
        assert_eq!(
            &returned_resp, respond_resp,
            "Returned signature request does not match"
        );
    }

    Ok(())
}

pub async fn vote_update_till_completion(
    contract: &Contract,
    accounts: &[Account],
    proposal_id: &UpdateId,
) {
    for voter in accounts {
        let execution = voter
            .call(contract.id(), "vote_update")
            .args_json(serde_json::json!({
                "id": proposal_id,
            }))
            .max_gas()
            .transact()
            .await
            .unwrap();

        // Met the threshold, voting completed.
        if execution.is_failure() {
            break;
        }
    }
}
