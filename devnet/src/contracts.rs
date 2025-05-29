use std::collections::BTreeMap;

use mpc_contract::primitives::{
    domain::{DomainConfig, SignatureScheme},
    signature::{Bytes, Payload, SignRequestArgs},
};
use near_primitives::action::Action;
use near_sdk::AccountId;
use rand::RngCore;
use serde::Serialize;

#[derive(Serialize)]
struct ParallelSignArgsV2 {
    target_contract: AccountId,
    ecdsa_calls_by_domain: BTreeMap<u64, u64>,
    eddsa_calls_by_domain: BTreeMap<u64, u64>,
    seed: u64,
}

pub fn make_action(method: &str, args: &[u8], tgas: u64, deposit: u128) -> Action {
    Action::FunctionCall(Box::new(near_primitives::action::FunctionCallAction {
        method_name: method.to_string(),
        args: args.to_vec(),
        gas: tgas * 1_000_000_000_000,
        deposit,
    }))
}

pub fn make_payload(scheme: SignatureScheme) -> Payload {
    match scheme {
        SignatureScheme::Secp256k1 => {
            Payload::Ecdsa(Bytes::new(rand::random::<[u8; 32]>().to_vec()).unwrap())
        }
        SignatureScheme::Ed25519 => {
            let len = rand::random_range(32..=1232);
            let mut payload = vec![0; len];
            rand::rng().fill_bytes(&mut payload);
            Payload::Eddsa(Bytes::new(payload).unwrap())
        }
    }
}

//#[derive(Clone)]
//pub struct ParallelSignContract {
//    pub account_id: AccountId,
//    pub mpc_contract: AccountId,
//}

#[derive(Clone)]
pub struct ActionCall {
    pub receiver_id: AccountId,
    pub actions: Vec<Action>,
}

pub fn make_parallel_sign_calls_args(
    domain_config: DomainConfig,
    mpc_contract: AccountId,
    signatures_per_contract_call: u64,
) -> Vec<u8> {
    let mut ecdsa_calls_by_domain = BTreeMap::new();
    let mut eddsa_calls_by_domain = BTreeMap::new();
    match domain_config.scheme {
        SignatureScheme::Secp256k1 => {
            ecdsa_calls_by_domain.insert(domain_config.id.0, signatures_per_contract_call);
        }
        SignatureScheme::Ed25519 => {
            eddsa_calls_by_domain.insert(domain_config.id.0, signatures_per_contract_call);
        }
    }
    serde_json::to_vec(&ParallelSignArgsV2 {
        target_contract: mpc_contract,
        ecdsa_calls_by_domain,
        eddsa_calls_by_domain,
        seed: rand::random(),
    })
    .unwrap()
}

pub fn make_parallel_sign_call_action(
    parallel_sign_contract: AccountId,
    mpc_contract: AccountId,
    domain_config: DomainConfig,
    signatures_per_contract_call: u64,
) -> ActionCall {
    ActionCall {
        receiver_id: parallel_sign_contract,
        actions: vec![make_action(
            "make_parallel_sign_calls",
            &make_parallel_sign_calls_args(
                domain_config,
                mpc_contract,
                signatures_per_contract_call,
            ),
            300,
            1,
        )],
    }
}
//impl ParallelSignContract {
//    pub fn make_parallel_sign_call_action(
//        &self,
//        domain_config: DomainConfig,
//        signatures_per_contract_call: u64,
//    ) -> ActionCall {
//        ActionCall {
//            receiver_id: self.account_id.clone(),
//            actions: vec![make_action(
//                "make_parallel_sign_calls",
//                &make_parallel_sign_calls_args(
//                    domain_config,
//                    self.mpc_contract.clone(),
//                    signatures_per_contract_call,
//                ),
//                300,
//                1,
//            )],
//        }
//    }
//}

#[derive(Serialize)]
pub struct SignArgsV1 {
    pub request: legacy_mpc_contract::primitives::SignRequest,
}

#[derive(Serialize)]
pub struct SignArgsV2 {
    pub request: SignRequestArgs,
}

//pub struct MpcContract {
//    pub account: AccountId,
//}

pub fn make_sign_action(mpc_contract: AccountId, domain_config: DomainConfig) -> ActionCall {
    ActionCall {
        receiver_id: mpc_contract,
        actions: vec![make_action(
            "sign",
            &serde_json::to_vec(&SignArgsV2 {
                request: SignRequestArgs {
                    domain_id: Some(domain_config.id),
                    path: "".to_string(),
                    payload_v2: Some(make_payload(domain_config.scheme)),
                    ..Default::default()
                },
            })
            .unwrap(),
            300,
            1,
        )],
    }
}

pub fn make_legacy_sign_action(mpc_contract: AccountId) -> ActionCall {
    ActionCall {
        receiver_id: mpc_contract,
        actions: vec![make_action(
            "sign",
            &serde_json::to_vec(&SignArgsV1 {
                request: legacy_mpc_contract::primitives::SignRequest {
                    key_version: 0,
                    path: "".to_string(),
                    payload: rand::random(),
                },
            })
            .unwrap(),
            300,
            1,
        )],
    }
}
//impl MpcContract {
//    pub fn make_sign_action(&self, domain_config: DomainConfig) -> ActionCall {
//        ActionCall {
//            receiver_id: self.account.clone(),
//            actions: vec![make_action(
//                "sign",
//                &serde_json::to_vec(&SignArgsV2 {
//                    request: SignRequestArgs {
//                        domain_id: Some(domain_config.id),
//                        path: "".to_string(),
//                        payload_v2: Some(make_payload(domain_config.scheme)),
//                        ..Default::default()
//                    },
//                })
//                .unwrap(),
//                300,
//                1,
//            )],
//        }
//    }
//
//    pub fn make_legacy_sign_action(&self) -> ActionCall {
//        ActionCall {
//            receiver_id: self.account.clone(),
//            actions: vec![make_action(
//                "sign",
//                &serde_json::to_vec(&SignArgsV1 {
//                    request: legacy_mpc_contract::primitives::SignRequest {
//                        key_version: 0,
//                        path: "".to_string(),
//                        payload: rand::random(),
//                    },
//                })
//                .unwrap(),
//                300,
//                1,
//            )],
//        }
//    }
//}
