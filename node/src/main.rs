use clap::Parser;
use tracing::init_logging;

mod assets;
#[cfg(test)]
mod async_testing;
mod background;
mod cli;
mod config;
mod coordinator;
mod db;
mod indexer;
mod key_events;
mod keyshare;
mod metrics;
mod mpc_client;
mod network;
mod p2p;
mod primitives;
mod protocol;
mod protocol_version;
mod providers;
mod runtime;
mod sign_request;
pub mod signing;
#[cfg(test)]
mod tests;
mod tracing;
mod tracking;
mod web;

fn main() -> anyhow::Result<()> {
    init_logging();
    // Set the version metric
    metrics::MPC_NODE_VERSION.with_label_values(&[env!("CARGO_PKG_VERSION")]).set(1);
    futures::executor::block_on(cli::Cli::parse().run())
}
