use lazy_static::lazy_static;

lazy_static! {
    pub static ref MPC_NUM_TRIPLES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_triples_generated",
            "Number of triples generated (including both owned and not owned)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_TRIPLES_AVAILABLE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_triples_available",
            "Number of triples generated that we own, and not yet used"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_PRESIGNATURES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_presignatures_generated",
            "Number of presignatures generated (including both owned and not owned)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_PRESIGNATURES_AVAILABLE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_available",
            "Number of presignatures generated that we own, and not yet used"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_ECDSA_SIGNATURES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_ecdsa_signatures_generated",
            "Number of signatures generated (initiated by either us or someone else)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_EDDSA_SIGNATURES_GENERATED_COORDINATOR: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_eddsa_signatures_generated_coordinator",
            "Number of signatures generated (initiated by either us or someone else)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_EDDSA_SIGNATURES_GENERATED_PASSIVE: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_eddsa_signatures_generated_passive",
            "Number of signatures generated (initiated by either us or someone else)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_INDEXER_NUM_RECEIPT_EXECUTION_OUTCOMES: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_indexer_num_receipt_execution_outcomes",
            "Number of receipt execution outcomes processed by the near indexer"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_REQUESTS_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_requests",
            "Number of signatures requests indexed"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_REQUESTS_LEADER: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!(
            "mpc_num_signature_requests_leader",
            "Number of signatures requests for which this node is the leader",
            &["result"],
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_SENT: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_responses_sent",
            "Number of signature responses sent by this node. Note that transactions can still be
             rejected later when they arrive at the chunk producer, and we wouldn't know of that."
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_FAILED_TO_SEND_IMMEDIATELY: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_responses_failed_to_send_immediately",
            "Number of signature responses sent by this node, where the sending failed immediately
             at the local node. Note that transactions can still be rejected later when they arrive
             at the chunk producer, and we wouldn't know of that."
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_INDEXER_LATEST_BLOCK_HEIGHT: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_indexer_latest_block_height",
            "Latest block height processed by the near indexer"
        )
        .unwrap();
}
