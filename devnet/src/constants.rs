pub const ONE_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// Below this minimum balance we consider an account to be possibly unusable.
pub const MINIMUM_BALANCE_TO_REMAIN_IN_ACCOUNTS: u128 = ONE_NEAR / 10;
/// When we need to refill an account (during an update operation), we will not
/// refill it if it's more than this percent of the desired balance. That way, we don't
/// end up topping up accounts all the time with tiny amounts.
pub const PERCENT_OF_ORIGINAL_BALANCE_BELOW_WHICH_TO_REFILL: u128 = 70;

/// The default docker image to deploy the node with.
pub const DEFAULT_MPC_DOCKER_IMAGE: &str = "nearone/mpc-node-gcp:testnet-release";
/// The default parallel signing contract path to test with.
pub const DEFAULT_PARALLEL_SIGN_CONTRACT_PATH: &str =
    "../pytest/tests/test_contracts/parallel/res/contract.wasm";
/// Address of the mpc contract on testnet
pub const TESTNET_CONTRACT_ACCOUNT_ID: &str = "v1.signer-prod.testnet";
