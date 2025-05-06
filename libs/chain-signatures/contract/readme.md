# MPC Contract

This folder contains the code for the **MPC Contract**, which is deployed on the NEAR blockchain.

The contract aims to reflect the current state of the MPC-Network and allows users to submit signature requests via the `sign` [endpoint](#user-api).

**Benchmarks:**

| Contract | avg. receipts | avg. gas [Tgas]   |
| -------- | ------------- | ----------------- |
| V0       | 8             | 11.30479597562405 |
| V1       | 4             | 6.131075775468398 |
| V2       | tbd           | tbd               |

**Migration Considerations:** Migration from `V1` to `V2` will not affect how **users** interact with the contract, but
will require the **MPC nodes** to switch to the newer compatible version at the same time.

### State and Lifecycle

The contract state tracks pending signature requests, the current configuration of the contract as well as any updates to the contract that are proposed by Participants of the MPC-Network via the `update` [endpoint](#participants-api).

```Rust
pub struct MpcContract {
    protocol_state: ProtocolContractState,
    pending_requests: LookupMap<SignatureRequest, YieldIndex>,
    request_by_block_height: Vector<(u64, SignatureRequest)>,
    proposed_updates: ProposedUpdates,
    config: Config,
}
```

The **Protocol State** of the contract should reflect the state of the MPC-Network:
```mermaid
stateDiagram-v2
    direction LR
    [*] --> NotInitialized : deploy
    NotInitialized --> Running : init
    Running --> Initializing : vote_add_domains
    Running --> Resharing : vote_new_parameters
    Initializing --> Running : vote_pk
    Initializing --> Running : vote_cancel_keygen
    Resharing --> Running : vote_reshared
    Resharing --> Resharing : vote_new_parameters
```

### Contract API
#### User API

| Function                                                                                     | Behavior                                                                                                 | Return Value               | Gas requirement | Effective Gas Cost |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- | -------------------------- | --------------- | ------------------ |
| `sign(request: SignRequestArgs)`                                                             | Submits a signature request to the contract. Requires a deposit of 1 yoctonear. Re-submitting the same request before the original request timed out or has been responded to may cause both requests to fail. | deferred to promise        | `10 Tgas`       | `~6 Tgas`          |
| `public_key(domain: Option<DomainId>)`                                                       | Read-only function; returns the public key used for the given domain (defaulting to first).              | `Result<PublicKey, Error>` |                 |                    |
| `derived_public_key(path: String, predecessor: Option<AccountId>, domain: Option<DomainId>)` | Generates a derived public key for a given path and account, for the given domain (defaulting to first). | `Result<PublicKey, Error>` |                 |                    |

#### SignRequestArgs (Latest version)
The sign request takes the following arguments:
* `path` (String): the derivation path.
* `payload_v2`: either `{"Ecdsa": "<hex encoded 32 bytes>"}` or `{"Eddsa": "<hex encoded between 32 and 1232 bytes>"}`
* `domain_id` (integer): the domain ID that identifies the key and signature scheme to use for signing.

#### SignRequestArgs (Legacy version for backwards compatibility with V1)
* The legacy argument `payload` can be used in place of `payload_v2`; the format for that is an array of 32 integer bytes. This argument can only be used
  to pass in an ECDSA payload.
* The legacy argument `key_version` can be used in place of `domain_id` and means the same thing.

#### Participants API
These functions require the caller to be a participant or candidate.

| Function                                                                            | Behavior                                                                                                                                                                                                                                | Return Value              | Gas Requirement | Effective Gas Cost |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | --------------- | ------------------ |
| `respond(request: SignatureRequest, response: SignatureResponse)`                   | Processes a response to a signature request, verifying its validity and ensuring proper state cleanup.                                                                                                                                  | `Result<(), Error>`       | 10Tgas          | ~6Tgas             |
| `vote_add_domains(domains: Vec<DomainConfig>)`                                      | Votes to add new domains (new keys) to the MPC network; newly proposed domain IDs must start from next_domain_id and be contiguous.                                                                                                     | `Result<(), Error>`       | TBD             | TBD                |
| `vote_new_parameters(prospective_epoch_id: EpochId, proposal: ThresholdParameters)` | Votes to change the set of participants as well as the new threshold for the network. (Prospective epoch ID must be 1 plus current)                                                                                                     | `Result<(), Error>`       | TBD             | TBD                |
| `vote_code_hash(code_hash: CodeHash)`                                               | Votes to add new whitelisted TEE Docker image code hashes.                                                                                                                                                                              | `Result<(), Error>`       | TBD             | TBD                |
| `start_keygen_instance(key_event_id: KeyEventId)`                                   | For Initializing state only. Starts a new attempt to generate a key (key_event_id must be the expected one)                                                                                                                             | `Result<(), Error>`       | TBD             | TBD                |
| `start_resharing_instance(key_event_id: KeyEventId)`                                | For Resharing state only. Starts a new attempt to reshare a key (key_event_id must be the expected one)                                                                                                                                 | `Result<(), Error>`       | TBD             | TBD                |
| `vote_pk(key_event_id: KeyEventId, public_key: PublicKey)`                          | For Initializing state only. Votes for the public key for the given generation attempt; if enough votes are collected, transitions to the next domain to generate a key for, or if all domains are completed, transitions into Running. | `Result<(), Error>`       | TBD             | TBD                |
| `vote_reshared(key_event_id: KeyEventId)`                                           | For Resharing state only. Votes for the success of the given resharing attempt; if enough votes are collected, transitions to the next domain to reshare for, or if all domains are completed, transitions into Running.                | `Result<(), Error>`       | TBD             | TBD                |
| `vote_cancel_keygen(next_domain_id: u64)`                                           | For Initializing state only. Votes to cancel the key generation (identified by the next_domain_id) and revert to the Running state.                                                                                                     | `Result<(), Error>`       | TBD             | TBD                |
| `propose_update(args: ProposeUpdateArgs)`                                           | Proposes an update to the contract, requiring an attached deposit.                                                                                                                                                                      | `Result<UpdateId, Error>` | TBD             | TBD                |
| `vote_update(id: UpdateId)`                                                         | Votes on a proposed update. If the threshold is met, the update is executed.                                                                                                                                                            | `Result<bool, Error>`     | TBD             | TBD                |


#### Developer API

| Function                                                                   | Behavior                                                                                                                                                                                                                                 | Return Value             | Gas Requirement | Effective Gas Cost |
| -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | --------------- | ------------------ |
| `init(parameters: ThresholdParameters, init_config: Option<InitConfigV1>)` | Initializes the contract with a threshold, candidate participants, and config values. Can only be called once. This sets the contract state to `Running` with zero domains. vote_add_domains can be called to initialize key generation. | `Result<Self, Error>`    | TBD             | TBD                |
| `state()`                                                                  | Returns the current state of the contract.                                                                                                                                                                                               | `&ProtocolContractState` | TBD             | TBD                |
| `get_pending_request(request: &SignatureRequest)`                          | Retrieves pending signature requests.                                                                                                                                                                                                    | `Option<YieldIndex>`     | TBD             | TBD                |
| `config()`                                                                 | Returns the contract configuration.                                                                                                                                                                                                      | `&ConfigV1`              | TBD             | TBD                |
| `version()`                                                                | Returns the contract version.                                                                                                                                                                                                            | `String`                 | TBD             | TBD                |
| `update_config(config: ConfigV1)`                                          | Updates the contract configuration for `V1`.                                                                                                                                                                                             | `()`                     | TBD             | TBD                |


## Development
Run tests with `cargo nextest run`. This includes the integration tests, for which it is necessary to compile the contract first:
```
cargo build --release --target=wasm32-unknown-unknown
wasm-opt -Oz -o target/wasm32-unknown-unknown/release/mpc_contract.wasm target/wasm32-unknown-unknown/release/mpc_contract.wasm
```
Note that due to the Rust compiler version used in this project and a lack of compatibility with the runtime version used in near-workspaces,
we need to use wasm-opt to strip the contract of unused features. Otherwise the contract cannot be deserialized by near-workspaces runtime.
