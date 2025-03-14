use clap::Parser;
use cli::Cli;

mod account;
mod cli;
mod constants;
mod devnet;
mod funding;
mod loadtest;
mod mpc;
mod rpc;
mod terraform;
mod types;

#[tokio::main]
async fn main() {
    Cli::parse().run().await;
}
