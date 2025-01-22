use clap::Parser;
use tracing::init_logging;

mod assets;
#[cfg(test)]
mod async_testing;
mod background;
mod cli;
mod config;
mod db;
mod hkdf;
mod indexer;
mod key_generation;
mod keyshare;
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
#[cfg(not(test))]
mod web;
mod web_common;
#[cfg(test)]
mod web_test;

fn main() -> anyhow::Result<()> {
    init_logging();
    futures::executor::block_on(cli::Cli::parse().run())
}
