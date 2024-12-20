use clap::Parser;
use mpc_node::cli;
use mpc_node::tracing::init_logging;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = cli::Cli::parse();
    cli.run().await
}
