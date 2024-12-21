// Used to generate public/private config parts to deploy an mpc-node.

use std::env;
use std::fs::File;
use std::io::Write;
use rand::{random, Rng};
use anyhow::Result;
use mpc_node::p2p::generate_keypair;
use mpc_node::config::{ParticipantId, ParticipantInfo};

fn generate_aes_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    rand::thread_rng().fill(&mut key);
    key
}

fn generate_random_u32() -> u32 {
    let random_number: u32 = random();
    random_number
}


fn main() -> Result<()> {
    let ip_address = env::args().nth(1).expect("Usage: program <IP_ADDRESS>");

    let (secret_key, public_key) = generate_keypair()?;
    let secret_key = near_crypto::SecretKey::ED25519(secret_key.clone());
    let public_key = near_crypto::PublicKey::ED25519(public_key.clone());
    let near_account_id = generate_random_u32();
    let aes_key = hex::encode(generate_aes_key());

    {
        let mut local_config = File::create("local-config.env")?;
        writeln!(local_config, "MPC_HOME_DIR: /app/data")?;
        writeln!(local_config, "RUST_BACKTRACE: full")?;
        writeln!(local_config, "RUST_LOG: info")?;

        writeln!(local_config, "MPC_P2P_PRIVATE_KEY={}", secret_key)?;
        writeln!(local_config, "MPC_NEAR_ACCOUNT_ID={}", near_account_id)?;
        writeln!(local_config, "MPC_SECRET_STORE_KEY={}", aes_key)?;
        writeln!(local_config, "MPC_P2P_IP_ADDRESS={}", ip_address)?;

        println!("Private data saved to local-config.env (DO NOT SHARE IT)")
    }

    {
        let public_part = ParticipantInfo {
            id: ParticipantId::from_raw(near_account_id),
            p2p_public_key: public_key,
            address: ip_address,
            port: 10000,
            near_account_id: near_account_id.to_string().parse()?,
        };
        let mut public_part_file = File::create("public-part.yaml")?;
        let yaml_data = serde_yaml::to_string(&public_part)?;
        public_part_file.write_all(yaml_data.as_bytes())?;

        println!("Public data saved to public-part.yaml (SHARE IT)");
    }
    Ok(())
}
