use clap::Parser;
use cli::Cli;

mod account;
mod cli;
mod constants;
mod contracts;
mod devnet;
mod funding;
mod loadtest;
mod mpc;
mod queries;
mod rpc;
mod terraform;
mod tx;
mod types;

#[tokio::main]
async fn main() {
    Cli::parse().run().await;
}
