use crate::types::load_config;

#[derive(clap::Parser)]
pub enum Cli {
    /// Manage MPC networks
    Mpc(MpcNetworkCmd),
    /// Manage loadtest setups
    Loadtest(LoadtestCmd),
}

impl Cli {
    pub async fn run(self) {
        let config = load_config().await;
        match self {
            Cli::Mpc(cmd) => {
                let name = cmd.name;
                match cmd.subcmd {
                    MpcNetworkSubCmd::New(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::Update(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DeployContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::RemoveContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::ViewContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::Join(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::VoteJoin(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::VoteLeave(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DeployInfra(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DeployNomad(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    MpcNetworkSubCmd::DestroyInfra(cmd) => {
                        cmd.run(&name, config).await;
                    }
                }
            }
            Cli::Loadtest(cmd) => {
                let name = cmd.name;
                match cmd.subcmd {
                    LoadtestSubCmd::New(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::Update(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::DeployParallelSignContract(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::Run(cmd) => {
                        cmd.run(&name, config).await;
                    }
                    LoadtestSubCmd::DrainExpiredRequests(cmd) => {
                        cmd.run(&name, config).await;
                    }
                }
            }
        }
    }
}

#[derive(clap::Parser)]
pub struct MpcNetworkCmd {
    /// A friendly name of the MPC network; use a unique name in the team.
    pub name: String,
    #[clap(subcommand)]
    pub subcmd: MpcNetworkSubCmd,
}

#[derive(clap::Parser)]
pub enum MpcNetworkSubCmd {
    /// Create a new MPC network.
    New(NewMpcNetworkCmd),
    /// Update the parameters of an existing MPC network, including refilling accounts.
    Update(UpdateMpcNetworkCmd),
    /// Deploy the MPC contract, initializing it to a number of participants.
    DeployContract(MpcDeployContractCmd),
    /// Remove the MPC contract from the local state, so a fresh one can be deployed.
    RemoveContract(RemoveContractCmd),
    /// View the contract state.
    ViewContract(MpcViewContractCmd),
    /// Send a join() transaction to the contract to propose adding a participant.
    Join(MpcJoinCmd),
    /// Send vote_join() transactions to the contract to vote on adding a participant.
    VoteJoin(MpcVoteJoinCmd),
    /// Send vote_leave() transactions to the contract to vote on removing a participant.
    VoteLeave(MpcVoteLeaveCmd),
    /// Deploy the GCP nodes with Terraform to host Nomad jobs to run this network.
    DeployInfra(MpcTerraformDeployInfraCmd),
    /// Deploy the Nomad jobs to run this network.
    DeployNomad(MpcTerraformDeployNomadCmd),
    /// Destroy the GCP nodes previously deployed.
    DestroyInfra(MpcTerraformDestroyInfraCmd),
}

#[derive(clap::Parser)]
pub struct LoadtestCmd {
    /// A friendly name of the loadtest setup.
    pub name: String,
    #[clap(subcommand)]
    pub subcmd: LoadtestSubCmd,
}

#[derive(clap::Parser)]
pub enum LoadtestSubCmd {
    /// Creates a new loadtest setup.
    New(NewLoadtestCmd),
    /// Refills accounts in the loadtest setup, and optionally create more accounts or keys.
    Update(UpdateLoadtestCmd),
    /// Deploy the parallel signature request contract for sending load faster.
    DeployParallelSignContract(DeployParallelSignContractCmd),
    /// Send load to an MPC network.
    Run(RunLoadtestCmd),
    /// Drain expired requests in bulk from the MPC contract in order to free up account storage.
    DrainExpiredRequests(DrainExpiredRequestsCmd),
}

#[derive(clap::Parser)]
pub struct NewMpcNetworkCmd {
    /// Number of participants that will participant in the network at some point. This can be
    /// increased later, but it's recommended to pick the highest number you intend to use,
    /// because initializing new machines is slow.
    #[clap(long)]
    pub num_participants: usize,
    /// The threshold to initialize the contract with.
    #[clap(long)]
    pub threshold: usize,
    /// The amount of NEAR to give to each MPC account. This is NOT the account that will be used
    /// to send signature responses, so you do NOT need to give a lot to these accounts.
    #[clap(long, default_value = "1")]
    pub near_per_account: u128,
    /// Number of additional access keys per participant to add for the responding account.
    #[clap(long)]
    pub num_responding_access_keys: usize,
    /// The amount of NEAR to give to each responding account. This is the account that will be used
    /// to send signature responses, so depending on the number of access keys, you may want to give
    /// higher amounts here.
    #[clap(long, default_value = "1")]
    pub near_per_responding_account: u128,
}

#[derive(clap::Parser)]
pub struct UpdateMpcNetworkCmd {
    #[clap(long)]
    pub num_participants: Option<usize>,
    #[clap(long)]
    pub threshold: Option<usize>,
    #[clap(long)]
    pub near_per_account: Option<u128>,
    #[clap(long)]
    pub num_responding_access_keys: Option<usize>,
    #[clap(long)]
    pub near_per_responding_account: Option<u128>,
}

#[derive(clap::Parser)]
pub struct MpcDeployContractCmd {
    /// File path that contains the contract code.
    #[clap(
        long,
        default_value = "../libs/chain-signatures/compiled-contracts/v1.0.1.wasm"
    )]
    pub path: String,
    /// The number of participants to initialize with; the participants will be from 0 to
    /// init_participants-1.
    #[clap(long)]
    pub init_participants: usize,
    /// The number of NEAR to deposit into the contract account, for storage deposit.
    #[clap(long, default_value = "20")]
    pub deposit_near: u128,
    /// Maximum number of requests to remove per signature request; reduce this to
    /// optimize gas cost for signature requests.
    #[clap(long)]
    pub max_requests_to_remove: Option<u32>,
}

#[derive(clap::Parser)]
pub struct RemoveContractCmd {}

#[derive(clap::Parser)]
pub struct MpcViewContractCmd {}

#[derive(clap::Parser)]
pub struct MpcJoinCmd {
    /// The index of the participant that proposes to join the network.
    pub account_index: usize,
}

#[derive(clap::Parser)]
pub struct MpcVoteJoinCmd {
    /// The index of the participant that is joining the network.
    pub for_account_index: usize,
    /// The indices of the voters; leave empty to vote from every other participant.
    #[clap(long, value_delimiter = ',')]
    pub voters: Vec<usize>,
}

#[derive(clap::Parser)]
pub struct MpcVoteLeaveCmd {
    /// The index of the participant that is leaving the network.
    pub for_account_index: usize,
    /// The indices of the voters; leave empty to vote from every other participant.
    #[clap(long, value_delimiter = ',')]
    pub voters: Vec<usize>,
}

#[derive(clap::Parser)]
pub struct MpcTerraformDeployInfraCmd {
    /// If true, deletes the keyshares from the GCP secrets manager. This is useful if you wish to
    /// deploy a new contract and need to re-generate the key.
    #[clap(long)]
    pub reset_keyshares: bool,
}

#[derive(clap::Parser)]
pub struct MpcTerraformDeployNomadCmd {
    /// If true, shuts down the nodes and deletes the database.
    #[clap(long)]
    pub shutdown_and_reset_db: bool,
    /// Overrides the docker image to use for MPC nodes.
    #[clap(long)]
    pub docker_image: Option<String>,
}

#[derive(clap::Parser)]
pub struct MpcTerraformDestroyInfraCmd {}

#[derive(clap::Parser)]
pub struct NewLoadtestCmd {
    /// The number of accounts to create for the loadtest setup.
    /// It is recommended to just use 1 account. You can use more if you want to test functionality
    /// of handling multiple accounts. However, the number of access keys is what matters, not the
    /// number of accounts.
    #[clap(long)]
    pub num_accounts: usize,
    /// Number of access keys to add per account. This is the number of parallel requests that can
    /// be issued at once.
    #[clap(long)]
    pub keys_per_account: usize,
    /// Amount of NEAR to give to each account. This should be chosen based on how much gas is
    /// expected to be used for concurrently running requests. For example, if you were going to
    /// send 300Tgas transactions with 100 access keys, and each transaction is going to take 5
    /// blocks, then there is a concurrency of 500 transactions. Then you'll need however many
    /// NEAR to cover 150Pgas of compute. Or, just reduce the gas limit you use to something much
    /// lower.
    #[clap(long)]
    pub near_per_account: u128,
}

#[derive(clap::Parser)]
pub struct UpdateLoadtestCmd {
    #[clap(long)]
    pub num_accounts: Option<usize>,
    #[clap(long)]
    pub keys_per_account: Option<usize>,
    #[clap(long)]
    pub near_per_account: Option<u128>,
}

#[derive(clap::Parser)]
pub struct DeployParallelSignContractCmd {
    /// File path that contains the parallel signature request contract code.
    #[clap(
        long,
        default_value = "../pytest/tests/test_contracts/parallel/res/contract.wasm"
    )]
    pub path: String,
    #[clap(long, default_value = "2")]
    pub deposit_near: u128,
}

#[derive(clap::Parser)]
pub struct RunLoadtestCmd {
    /// The name of the MPC network to run the loadtest against.
    #[clap(long)]
    pub mpc_network: String,
    /// The QPS to send. The loadtest framework will try to send this many
    /// signature requests per second.
    #[clap(long)]
    pub qps: usize,
    /// The number of signatures to send per parallel-signature contract call.
    /// This will be divided into the QPS, so you don't need to change the QPS flag.
    #[clap(long)]
    pub signatures_per_contract_call: Option<usize>,
}

#[derive(clap::Parser)]
pub struct DrainExpiredRequestsCmd {
    #[clap(long)]
    pub mpc_network: String,
    /// QPS to send the drain requests with. This does not need to be very high.
    /// The draining will stop as soon as any request comes back with 0 drained.
    #[clap(long, default_value = "1")]
    pub qps: usize,
}
