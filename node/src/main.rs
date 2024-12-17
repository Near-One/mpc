use clap::Parser;
use tracing::init_logging;

mod assets;
mod background;
mod cli;
mod config;
mod db;
mod hkdf;
mod indexer;
mod key_generation;
mod metrics;
mod mpc_client;
mod network;
mod p2p;
mod primitives;
mod protocol;
mod sign;
mod sign_request;
#[cfg(test)]
mod tests;
mod tracing;
mod tracking;
mod triple;
mod web;
mod validation;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = cli::Cli::parse();
    cli.run().await
}
