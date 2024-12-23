// Used to migrate key from old rust mpc to new ones.
// The only difference is in the size of AES key that is used in encrypting the share on disk.

use std::env;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use anyhow::{Context, Result};
use clap::Parser;
use dotenv_parser::parse_dotenv;
use mpc_node::key_generation::{save_root_keyshare, RootKeyshareData};
use near_sdk::base64::prelude::BASE64_STANDARD;
use near_sdk::base64::Engine;
use near_sdk::serde_json;
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Debug, Parser)]
pub struct Cli {
    #[clap(long)]
    path_to_private_share: PathBuf,
    #[clap(long)]
    aes_key: String,
}

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

async fn load_old_share(aes_key: &[u8], filename_of_private_share: String) -> Result<RootKeyshareData> {
    let mut file = File::open(format!("/app/data/{filename_of_private_share}")).await?;
    let mut b64 = Vec::new();
    file.read_to_end(&mut b64).await?;

    let raw_data = BASE64_STANDARD.decode(b64).expect("Expected valid b64 string");
    let initialization_vector = &raw_data[0..16];
    let cypher_text = &raw_data[16..];
    let plain_text = Aes256CbcDec::new_from_slices(aes_key, initialization_vector)
        .expect("Couldn't initialize aes decoder")
        .decrypt_padded_vec_mut::<Pkcs7>(cypher_text)
        .expect("Couldn't decrypt a message");

    let data: RootKeyshareData = serde_json::from_slice(&plain_text)?;

    Ok(data)
}

async fn get_new_aes_key() -> String {
    let mut local_config_env = File::open("/app/data/local-config.env").await.unwrap();
    let mut source = String::new();
    local_config_env.read_to_string(&mut source).await.unwrap();

    let envs = parse_dotenv(source.as_str()).unwrap();
    let aes_key = envs.get("MPC_SECRET_STORE_KEY").expect("MPC_SECRET_STORE_KEY not found in config");

    aes_key.clone()
}

#[tokio::main]
async fn main() -> Result<()> {
    let filename_of_private_share = env::args().nth(1).expect("Usage: program <filename_of_private_share> <old_aes_key>");
    let aes_key = env::args().nth(2).expect("Usage: program <path_to_private_share> <old_aes_key>");

    let old_aes_key = hex::decode(aes_key).expect("Couldn't decode old aes key from hex");
    let share = load_old_share(old_aes_key.as_slice(), filename_of_private_share).await?;
    let new_aes_key = hex::decode(get_new_aes_key().await).context("Couldn't decode new aes key from hex")?;
    let new_aes_key = <[u8; 16]>::try_from(new_aes_key).unwrap();

    save_root_keyshare(&PathBuf::from("/app/data/"), new_aes_key, &share)?;

    println!("Key successfully migrated");

    Ok(())
}