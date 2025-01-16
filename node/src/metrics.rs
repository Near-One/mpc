use lazy_static::lazy_static;
use near_o11y::metrics::exponential_buckets;

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
    pub static ref MPC_NUM_SIGNATURES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signatures_generated",
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
    pub static ref MPC_SIGN_COMPUTATION_LATENCY: prometheus::Histogram =
        prometheus::register_histogram!(
            "mpc_signature_computation_latency",
            "Time elapsed between the leader initiating a signature computation
             and obtaining a full signature",
            exponential_buckets(0.1, 2.0, 10).unwrap(),
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
    pub static ref MPC_SIGN_REQUEST_TO_RESPONSE_LATENCY: prometheus::Histogram =
        prometheus::register_histogram!(
            "mpc_signature_request_to_response_latency",
            "Latency from the block containing the signature request to the
             block containing the signature response",
            exponential_buckets(0.5, 2.0, 10).unwrap(),
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_TIMED_OUT: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_responses_timed_out",
            "Number of times the node sent a response and failed to observe it
             on-chain before timing out",
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_ABANDONED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_responses_abandoned",
            "Number of responses which we constructed successfully but failed to
             submit and observe on-chain within the retry limit",
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

lazy_static! {
    pub static ref MPC_ACCESS_KEY_NONCE: prometheus::IntGauge = prometheus::register_int_gauge!(
        "mpc_access_key_nonce",
        "Latest observed nonce among transactions submitted using
             the node's access key for its near account",
    )
    .unwrap();
}
