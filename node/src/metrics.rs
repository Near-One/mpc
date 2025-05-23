use lazy_static::lazy_static;

lazy_static! {
    pub static ref MPC_NODE_VERSION: prometheus::IntGaugeVec =
        prometheus::register_int_gauge_vec!(
            "mpc_node_version",
            "Version of the MPC node",
            &["version"],
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_TRIPLES_GENERATED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_triples_generated",
            "Number of triples generated (including both owned and not owned)"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_TRIPLES_GENERATION_TIME_ELAPSED: prometheus::Histogram =
        near_o11y::metrics::try_create_histogram(
            "near_mpc_triples_generation_time_elapsed",
            "Time take to generate a batch of triples",
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_PRE_SIGNATURE_TIME_ELAPSED: prometheus::Histogram =
        near_o11y::metrics::try_create_histogram(
            "near_mpc_pre_signature_time_elapsed",
            "Time take to generate a pre signature",
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_SIGNATURE_TIME_ELAPSED: prometheus::Histogram =
        near_o11y::metrics::try_create_histogram(
            "near_mpc_signature_time_elapsed",
            "Time take to generate a signature",
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
    pub static ref MPC_OWNED_NUM_TRIPLES_ONLINE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_triples_online",
            "Number of triples generated that we own, and not yet used,
                for which the participant set is confirmed alive"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_TRIPLES_WITH_OFFLINE_PARTICIPANT: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_triples_with_offline_participant",
            "Number of triples generated that we own, and not yet used,
                for which some participant is offline",
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
    pub static ref MPC_OWNED_NUM_PRESIGNATURES_ONLINE: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_online",
            "Number of presignatures generated that we own, and not yet used,
                for which the participant set is confirmed alive"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OWNED_NUM_PRESIGNATURES_WITH_OFFLINE_PARTICIPANT: prometheus::IntGauge =
        prometheus::register_int_gauge!(
            "mpc_owned_num_presignatures_with_offline_participant",
            "Number of presignatures generated that we own, and not yet used,
                for which some participant is offline",
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
            "mpc_num_signature_requests_indexed",
            "Number of signatures requests seen by the indexer"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGN_RESPONSES_INDEXED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_signature_responses_indexed",
            "Number of signatures responses seen by the indexer"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_SIGNATURE_COMPUTATIONS_LED: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!(
            "mpc_num_signature_computations_led",
            "Number of signature computations that this node led",
            &["result"],
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_PASSIVE_SIGN_REQUESTS_RECEIVED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_passive_signature_requests_received",
            "Number of passive signature requests received from mpc peers"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_NUM_PASSIVE_SIGN_REQUESTS_LOOKUP_SUCCEEDED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "mpc_num_passive_signature_requests_lookup_succeeded",
            "Number of passive signature requests successfully looked up in local DB"
        )
        .unwrap();
}

lazy_static! {
    pub static ref MPC_OUTGOING_TRANSACTION_OUTCOMES: prometheus::IntCounterVec =
        prometheus::register_int_counter_vec!(
            "mpc_outgoing_transaction_outcomes",
            "Number of transactions sent by this node, by type and outcome",
            &["type", "outcome"],
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

lazy_static! {
    pub static ref MPC_CURRENT_JOB_STATE: prometheus::IntGaugeVec =
        prometheus::register_int_gauge_vec!(
            "mpc_current_job_state",
            "Current state of the top-level MPC job",
            &["state"],
        )
        .unwrap();
}

lazy_static! {
    pub static ref SIGN_REQUEST_CHANNEL_FAILED: prometheus::IntCounter =
        prometheus::register_int_counter!(
            "sign_request_channel_failed",
            "failed to send on channel in sign_request_channel",
        )
        .unwrap();
}

lazy_static! {
    pub static ref NETWORK_LIVE_CONNECTIONS: prometheus::IntGaugeVec =
        prometheus::register_int_gauge_vec!(
            "mpc_network_live_connections",
            "Current state of the mesh network connections",
            &["my_participant_id", "peer_participant_id"],
        )
        .unwrap();
}
