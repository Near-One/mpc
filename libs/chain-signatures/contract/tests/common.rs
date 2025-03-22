use digest::{Digest, FixedOutput};
use ecdsa::signature::Verifier;
use k256::{
    elliptic_curve::{point::DecompressPoint as _, sec1::ToEncodedPoint},
    AffinePoint, FieldBytes, Scalar, Secp256k1, SecretKey,
};
use mpc_contract::{
    config::InitConfig,
    crypto_shared::{
        derive_key, derive_tweak, kdf::check_ec_signature, ScalarExt, SerializableAffinePoint,
        SerializableScalar, SignatureResponse,
    },
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantInfo, Participants},
        signature::{PayloadHash, SignRequest, SignatureRequest, Tweak},
        thresholds::{Threshold, ThresholdParameters},
    },
    update::UpdateId,
};
use near_crypto::KeyType;
use near_sdk::log;
use near_workspaces::{
    network::Sandbox,
    result::ExecutionFinalResult,
    types::{AccountId, NearToken},
    Account, Contract, Worker,
};
use signature::DigestSigner;
use std::str::FromStr;

pub const CONTRACT_FILE_PATH: &str = "../target/wasm32-unknown-unknown/release/mpc_contract.wasm";
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

pub async fn init_with_candidates(
    pks: Vec<near_crypto::PublicKey>,
) -> (Worker<Sandbox>, Contract, Vec<Account>) {
    let (worker, contract) = init().await;
    let (accounts, participants) = accounts(&worker).await;
    let threshold = ((participants.len() as f64) * 0.6).ceil() as u64;
    let threshold = Threshold::new(threshold);
    let threshold_parameters = ThresholdParameters::new(participants, threshold).unwrap();
    let init = if !pks.is_empty() {
        let mut keys = Vec::new();
        let mut domains = Vec::new();
        for pk in pks {
            let domain_id = DomainId(domains.len() as u64 * 2);
            domains.push(DomainConfig {
                id: domain_id,
                scheme: match pk.key_type() {
                    KeyType::ED25519 => SignatureScheme::Ed25519,
                    KeyType::SECP256K1 => SignatureScheme::Secp256k1,
                },
            });

            let pk = near_sdk::PublicKey::from_str(&format!("{}", pk)).unwrap();
            let key = KeyForDomain {
                attempt: AttemptId::new(),
                domain_id,
                key: pk,
            };
            keys.push(key);
        }
        let keyset = Keyset::new(EpochId::new(5), keys);
        contract
            .call("init_running")
            .args_json(serde_json::json!({
                "domains": domains,
                "next_domain_id": domains.len() as u64 * 2,
                "keyset": keyset,
                "parameters": threshold_parameters,
            }))
            .transact()
            .await
            .unwrap()
            .into_result()
            .unwrap()
    } else {
        contract
            .call("init")
            .args_json(serde_json::json!({
                "parameters": threshold_parameters,
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

pub async fn init_env_secp256k1(
    num_domains: usize,
) -> (
    Worker<Sandbox>,
    Contract,
    Vec<Account>,
    Vec<k256::SecretKey>,
) {
    let mut public_keys = Vec::new();
    let mut secret_keys = Vec::new();
    for _ in 0..num_domains {
        // TODO: Also add some ed25519 keys.
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk = sk.public_key();
        public_keys.push(near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &pk.as_affine().to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        ));
        secret_keys.push(sk);
    }
    let (worker, contract, accounts) = init_with_candidates(public_keys).await;

    (worker, contract, accounts, secret_keys)
}

/// Process the message, creating the same hash with type of [`Digest`] and [`PayloadHash`]
pub async fn process_message(msg: &str) -> (impl Digest, PayloadHash) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();

    let payload_hash = PayloadHash::new(bytes.into());
    (digest, payload_hash)
}

pub fn derive_secret_key(secret_key: &SecretKey, tweak: &Tweak) -> SecretKey {
    let tweak = Scalar::from_non_biased(tweak.as_bytes());
    SecretKey::new((tweak + secret_key.to_nonzero_scalar().as_ref()).into())
}

pub async fn create_response(
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    sk: &k256::SecretKey,
) -> (PayloadHash, SignatureRequest, SignatureResponse) {
    let (digest, payload_hash) = process_message(msg).await;
    let pk = sk.public_key();

    let tweak = derive_tweak(predecessor_id, path);
    let derived_sk = derive_secret_key(sk, &tweak);
    let derived_pk = derive_key(pk.into(), &tweak);
    let signing_key = k256::ecdsa::SigningKey::from(&derived_sk);
    let verifying_key =
        k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());

    let (signature, _): (ecdsa::Signature<Secp256k1>, _) =
        signing_key.try_sign_digest(digest).unwrap();
    verifying_key.verify(msg.as_bytes(), &signature).unwrap();

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();
    let respond_req = SignatureRequest::new(payload_hash.clone(), predecessor_id, path);
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    let s: k256::Scalar = *s.as_ref();

    let recovery_id = if check_ec_signature(&derived_pk, &big_r, &s, &payload_hash, 0).is_ok() {
        0
    } else if check_ec_signature(&derived_pk, &big_r, &s, &payload_hash, 1).is_ok() {
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

pub fn check_call_success(result: ExecutionFinalResult) {
    assert!(
        result.is_success(),
        "execution should have succeeded: {result:#?}"
    );
}
