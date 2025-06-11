use cait_sith::eddsa::KeygenOutput;
use digest::{Digest, FixedOutput};
use ecdsa::signature::Verifier;
use frost_ed25519::{keys::SigningShare, Ed25519Group, Group, VerifyingKey};
use fs2::FileExt;
use k256::{
    elliptic_curve::{point::DecompressPoint as _, sec1::ToEncodedPoint, PrimeField},
    AffinePoint, FieldBytes, Scalar, Secp256k1, SecretKey,
};
use mpc_contract::{
    config::InitConfig,
    crypto_shared::{
        derive_key_secp256k1, derive_tweak, ed25519_types, k256_types, kdf::check_ec_signature,
        SerializableScalar, SignatureResponse,
    },
    primitives::{
        domain::{DomainConfig, DomainId, SignatureScheme},
        key_state::{AttemptId, EpochId, KeyForDomain, Keyset},
        participants::{ParticipantInfo, Participants},
        signature::{Bytes, SignatureRequest, Tweak},
        thresholds::{Threshold, ThresholdParameters},
    },
    update::UpdateId,
};
use mpc_contract::{
    crypto_shared::k256_types::SerializableAffinePoint,
    primitives::signature::{Payload, SignRequestArgs},
};
use near_crypto::KeyType;
use near_sdk::log;
use near_workspaces::{
    network::Sandbox,
    result::ExecutionFinalResult,
    types::{AccountId, NearToken},
    Account, Contract, Worker,
};
use serde::{Deserialize, Serialize};
//use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use sha2::Sha256;
use signature::DigestSigner;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::Path,
    process::Command,
    str::FromStr,
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};

pub const CONTRACT_FILE_PATH: &str =
    "../../../target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm";
pub const PARTICIPANT_LEN: usize = 3;
// pub const PROJECT_ROOT_DIRECTORY: &str =

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
pub async fn gen_accounts(worker: &Worker<Sandbox>, amount: usize) -> (Vec<Account>, Participants) {
    let mut accounts = Vec::with_capacity(amount);
    for _ in 0..amount {
        log!("attempting to create account");
        let account = worker.dev_create_account().await.unwrap();
        log!("created account");
        accounts.push(account);
    }
    let candidates = candidates(Some(accounts.iter().map(|a| a.id().clone()).collect()));
    (accounts, candidates)
}

static CONTRACT: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Debug, Serialize, Deserialize)]
struct BuildLock {
    timestamp: u64,
}

impl BuildLock {
    fn new() -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// checks if self is younger than 3 seconds
    fn expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp) > 4
    }
}

pub fn current_contract() -> &'static Vec<u8> {
    CONTRACT.get_or_init(|| {
        let pkg_dir = Path::new(env!("CARGO_MANIFEST_DIR")); // this should point to
                                                             // libs/chain-signatures/contract
        let project_dir = pkg_dir.join("../../../"); // pointing to libs/chain-signatures

        let wasm_path =
            project_dir.join("target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm");

        println!("wasm path: {:?}", wasm_path);

        // get lock-file:
        let lock_path = project_dir.join(".contract.itest.build.lock");
        let mut lockfile = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("Failed to open lockfile");
        lockfile
            .lock_exclusive()
            .expect("Failed to lock build file");

        // check if we need to re-build
        let do_build = match lockfile.metadata().unwrap().len() {
            0 => true,
            _ => {
                let mut buf = String::new();
                lockfile.read_to_string(&mut buf).unwrap();
                match serde_json::from_str::<BuildLock>(&buf) {
                    Ok(build_lock) => build_lock.expired(),
                    _ => true,
                }
            }
        };

        if do_build {
            let status = Command::new("cargo")
                .args([
                    "build",
                    "--package=mpc-contract",
                    "--profile=release-contract",
                    "--target=wasm32-unknown-unknown",
                ])
                .current_dir(&project_dir)
                .status()
                .expect("Failed to run cargo build");

            assert!(status.success(), "cargo build failed");

            let status = Command::new("wasm-opt")
                .args([
                    "-Oz",
                    "-o",
                    wasm_path.to_str().unwrap(),
                    wasm_path.to_str().unwrap(),
                ])
                .current_dir(project_dir)
                .status()
                .expect("Failed to run wasm-opt");

            assert!(status.success(), "wasm-opt failed");
            lockfile.set_len(0).unwrap();
            lockfile
                .write_all(serde_json::to_string(&BuildLock::new()).unwrap().as_bytes())
                .expect("Failed to write timestamp to lockfile");
        }

        std::fs::read(CONTRACT_FILE_PATH).unwrap()
    })
}

pub async fn init() -> (Worker<Sandbox>, Contract) {
    let worker = near_workspaces::sandbox().await.unwrap();
    let wasm = &current_contract();
    let contract = worker.dev_deploy(wasm).await.unwrap();
    (worker, contract)
}

pub async fn init_with_candidates(
    pks: Vec<near_crypto::PublicKey>,
) -> (Worker<Sandbox>, Contract, Vec<Account>) {
    let (worker, contract) = init().await;
    let (accounts, participants) = gen_accounts(&worker, PARTICIPANT_LEN).await;
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

            let near_publick_key = near_sdk::PublicKey::from_str(&format!("{}", pk)).unwrap();
            let public_key_extended = near_publick_key.try_into().unwrap();

            let key = KeyForDomain {
                attempt: AttemptId::new(),
                domain_id,
                key: public_key_extended,
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

pub async fn init_env_ed25519(
    num_domains: usize,
) -> (Worker<Sandbox>, Contract, Vec<Account>, Vec<KeygenOutput>) {
    let mut public_keys = Vec::new();
    let mut secret_keys = Vec::new();
    for _ in 0..num_domains {
        let scalar = curve25519_dalek::Scalar::random(&mut OsRng);
        let private_share = SigningShare::new(scalar);
        let public_key_element = Ed25519Group::generator() * scalar;
        let public_key = VerifyingKey::new(public_key_element);

        let keygen_output = KeygenOutput {
            private_share,
            public_key,
        };

        public_keys.push(near_crypto::PublicKey::ED25519(
            near_crypto::ED25519PublicKey::from(public_key.to_element().compress().to_bytes()),
        ));

        secret_keys.push(keygen_output);
    }
    let (worker, contract, accounts) = init_with_candidates(public_keys).await;

    (worker, contract, accounts, secret_keys)
}

/// Process the message, creating the same hash with type of [`Digest`] and [`Payload`]
pub async fn process_message(msg: &str) -> (impl Digest, Payload) {
    let msg = msg.as_bytes();
    let digest = <k256::Secp256k1 as ecdsa::hazmat::DigestPrimitive>::Digest::new_with_prefix(msg);
    let bytes: FieldBytes = digest.clone().finalize_fixed();

    let payload_hash = Payload::from_legacy_ecdsa(bytes.into());
    (digest, payload_hash)
}

pub fn derive_secret_key_secp256k1(secret_key: &k256::SecretKey, tweak: &Tweak) -> k256::SecretKey {
    let tweak = Scalar::from_repr(tweak.as_bytes().into()).unwrap();
    SecretKey::new((tweak + secret_key.to_nonzero_scalar().as_ref()).into())
}

pub fn derive_secret_key_ed25519(secret_key: &KeygenOutput, tweak: &Tweak) -> KeygenOutput {
    let tweak = curve25519_dalek::Scalar::from_bytes_mod_order(tweak.as_bytes());
    let private_share = SigningShare::new(secret_key.private_share.to_scalar() + tweak);
    let public_key =
        VerifyingKey::new(secret_key.public_key.to_element() + Ed25519Group::generator() * tweak);

    KeygenOutput {
        private_share,
        public_key,
    }
}

pub async fn create_response(
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    sk: &k256::SecretKey,
) -> (Payload, SignatureRequest, SignatureResponse) {
    let (digest, payload) = process_message(msg).await;
    let pk = sk.public_key();

    let tweak = derive_tweak(predecessor_id, path);
    let derived_sk = derive_secret_key_secp256k1(sk, &tweak);
    let derived_pk = derive_key_secp256k1(&pk.into(), &tweak).unwrap();
    let signing_key = k256::ecdsa::SigningKey::from(&derived_sk);
    let verifying_key =
        k256::ecdsa::VerifyingKey::from(&k256::PublicKey::from_affine(derived_pk).unwrap());

    let (signature, _): (ecdsa::Signature<Secp256k1>, _) =
        signing_key.try_sign_digest(digest).unwrap();
    verifying_key.verify(msg.as_bytes(), &signature).unwrap();

    let s = signature.s();
    let (r_bytes, _s_bytes) = signature.split_bytes();
    let respond_req = SignatureRequest::new(DomainId(0), payload.clone(), predecessor_id, path);
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    let s: k256::Scalar = *s.as_ref();

    let recovery_id = if check_ec_signature(&derived_pk, &big_r, &s, payload.as_ecdsa().unwrap(), 0)
        .is_ok()
    {
        0
    } else if check_ec_signature(&derived_pk, &big_r, &s, payload.as_ecdsa().unwrap(), 1).is_ok() {
        1
    } else {
        panic!("unable to use recovery id of 0 or 1");
    };

    let respond_resp = SignatureResponse::Secp256k1(k256_types::Signature {
        big_r: SerializableAffinePoint {
            affine_point: big_r,
        },
        s: SerializableScalar { scalar: s },
        recovery_id,
    });

    (payload, respond_req, respond_resp)
}

pub async fn create_response_ed25519(
    predecessor_id: &AccountId,
    msg: &str,
    path: &str,
    signing_key: &KeygenOutput,
) -> (Payload, SignatureRequest, SignatureResponse) {
    let tweak = derive_tweak(predecessor_id, path);
    let derived_signing_key = derive_secret_key_ed25519(signing_key, &tweak);

    let payload: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(msg);
        hasher.clone().finalize().into()
    };

    let derived_signing_key =
        frost_ed25519::SigningKey::from_scalar(derived_signing_key.private_share.to_scalar())
            .unwrap();

    let signature = derived_signing_key
        .sign(OsRng, &payload)
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();

    let bytes = Bytes::new(payload.into()).unwrap();
    let payload = Payload::Eddsa(bytes);

    let respond_req = SignatureRequest::new(DomainId(0), payload.clone(), predecessor_id, path);

    let signature_response = SignatureResponse::Ed25519 {
        signature: ed25519_types::Signature::new(signature),
    };

    (payload, respond_req, signature_response)
}

pub async fn sign_and_validate(
    request: &SignRequestArgs,
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

        dbg!(&execution);

        let update_occurred: bool = execution.json().expect("Vote cast was unsuccessful");

        if update_occurred {
            return;
        }
    }
    panic!("Update didn't occurred")
}

pub fn check_call_success(result: ExecutionFinalResult) {
    assert!(
        result.is_success(),
        "execution should have succeeded: {result:#?}"
    );
}
