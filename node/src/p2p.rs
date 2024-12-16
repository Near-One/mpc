use crate::config::{MpcConfig, ParticipantInfo, ParticipantsConfig};
use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
use crate::primitives::{MpcMessage, MpcPeerMessage, ParticipantId};
use crate::tracking::{self, AutoAbortTask, AutoAbortTaskCollection};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use borsh::BorshDeserialize;
use near_crypto::ED25519SecretKey;
use near_sdk::AccountId;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::quic::Suite;
use rustls::server::danger::ClientCertVerifier;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinSet;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// Implements MeshNetworkTransportSender for sending messages over a QUIC-based
/// mesh network.
pub struct QuicMeshSender {
    my_id: ParticipantId,
    participants: Vec<ParticipantId>,
    connections: HashMap<ParticipantId, Arc<PersistentConnection>>,
}

/// Implements MeshNetworkTransportReceiver.
pub struct QuicMeshReceiver {
    receiver: Receiver<MpcPeerMessage>,
    _incoming_connections_task: AutoAbortTask<()>,
}

/// Maps public keys to participant IDs. Used to identify incoming connections.
#[derive(Default)]
struct ParticipantIdentities {
    key_to_participant_id: HashMap<near_crypto::PublicKey, ParticipantId>,
}

/// A always-allowing client certificate verifier for the QUIC TLS layer.
/// Note that in general, verifying the certificate simply means that the
/// other party's public key has been correctly signed by a certificate
/// authority. In this case, we don't need that, because we already know
/// the exact public key we're expecting from each peer. So don't bother
/// verifying the certificate itself.
#[derive(Debug)]
struct DummyClientCertVerifier;

impl ClientCertVerifier for DummyClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// A retrying connection that will automatically reconnect if the QUIC
/// connection is broken.
struct PersistentConnection {
    target_participant_id: ParticipantId,
    // Current connection and version. The connection is an Option because it
    // can be None if the connection was never established. It is a Weak
    // because the connection is owned by the loop-to-connect task (see the
    // `new` method) and when the connection is closed it is dropped. The
    // version is incremented every time the connection is re-established.
    current: tokio::sync::watch::Receiver<Option<(usize, Weak<quinn::Connection>)>>,
    // Atomic to quickly read whether a connection is alive. It's faster than
    // checking the current connection.
    is_alive: Arc<AtomicBool>,
    // The task that loops to connect to the target. When `PersistentConnection`
    // is dropped, this task is aborted. The task owns any active connection,
    // so dropping it also frees any connection currently alive.
    _task: AutoAbortTask<()>,
}

impl PersistentConnection {
    const CONNECTION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

    /// Returns a new QUIC stream, establishing a new connection if necessary.
    /// The stream itself can still fail after returning if the connection
    /// drops while the stream is used; but if the connection is already known
    /// to have failed before the stream is opened, this will re-establish the
    /// connection first.
    async fn new_stream(&self, expected_version: usize) -> anyhow::Result<quinn::SendStream> {
        let Some(conn) = self.current.borrow().clone() else {
            anyhow::bail!(
                "Connection to {} was never established",
                self.target_participant_id
            );
        };

        let (version, conn) = conn;
        if version != expected_version {
            anyhow::bail!(
                "Connection to {} is not the original connection expected",
                self.target_participant_id
            );
        }
        let Some(conn) = conn.upgrade() else {
            anyhow::bail!("Connection to {} was dropped", self.target_participant_id);
        };
        let stream = conn.open_uni().await?;
        Ok(stream)
    }

    pub fn new(
        endpoint: Endpoint,
        my_id: ParticipantId,
        target_address: String,
        target_participant_id: ParticipantId,
        participant_identities: Arc<ParticipantIdentities>,
    ) -> anyhow::Result<PersistentConnection> {
        let (current_sender, current_receiver) = tokio::sync::watch::channel(None);
        let is_alive = Arc::new(AtomicBool::new(false));
        let is_alive_clone = is_alive.clone();
        let task = tracking::spawn(
            &format!("Persistent connection to {}", target_participant_id),
            async move {
                async fn connect(
                    endpoint: &Endpoint,
                    target_address: &str,
                    target_participant_id: ParticipantId,
                    participant_identities: &ParticipantIdentities,
                ) -> anyhow::Result<Connection> {
                    let socket_addr = target_address.to_socket_addrs()?.next().unwrap();
                    let conn = endpoint.connect(socket_addr, "dummy")?.await?;

                    let participant_id = verify_peer_identity(&conn, participant_identities)?;
                    if participant_id != target_participant_id {
                        anyhow::bail!("Unexpected peer identity");
                    }
                    Ok(conn)
                }

                let mut connection_version = 1;
                loop {
                    let new_conn = match connect(
                        &endpoint,
                        &target_address,
                        target_participant_id,
                        &participant_identities,
                    )
                    .await
                    {
                        Ok(new_conn) => {
                            tracing::info!("Connected to {}, me {}", target_participant_id, my_id);
                            new_conn
                        }
                        Err(e) => {
                            tracing::info!(
                                "Could not connect to {}, retrying: {}, me {}",
                                target_participant_id,
                                e,
                                my_id
                            );
                            // Don't immediately retry, to avoid spamming the network with
                            // connection attempts.
                            tokio::time::sleep(Self::CONNECTION_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    let new_conn = Arc::new(new_conn);
                    if current_sender
                        .send(Some((connection_version, Arc::downgrade(&new_conn))))
                        .is_err()
                    {
                        break;
                    }
                    connection_version += 1;
                    is_alive_clone.store(true, Ordering::Relaxed);
                    new_conn.closed().await;
                    is_alive_clone.store(false, Ordering::Relaxed);
                }
            },
        );
        Ok(PersistentConnection {
            target_participant_id,
            current: current_receiver,
            is_alive,
            _task: task,
        })
    }
}

/// We hardcode a dummy private key used for signing certificates. This is
/// fine because we're not relying on a certificate authority to verify
/// public keys; rather the public keys come from the contract on chain.
/// Still, TLS requires us to have signed certificates, so this is just to
/// satisfy the TLS protocol.
const DUMMY_ISSUER_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MFECAQEwBQYDK2VwBCIEIGkMPQEb0GXxgFXbgojLebmHnCUpS3QYqJrYcfyFqHtW
gSEAAbdC8KDpDZPqZalKndJm2N6EXn+cNxIb2gRa21P5mcs=
-----END PRIVATE KEY-----";

const PKCS8_HEADER: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

const PKCS8_MIDDLE: [u8; 3] = [0x81, 0x21, 0x00];

/// Converts an ED25519 secret key to a keypair that can be used in TLS.
fn raw_ed25519_secret_key_to_keypair(
    key: &near_crypto::ED25519SecretKey,
) -> anyhow::Result<rcgen::KeyPair> {
    let mut pkcs8_encoded = Vec::with_capacity(16 + 32 + 3 + 32);
    pkcs8_encoded.extend_from_slice(&PKCS8_HEADER);
    pkcs8_encoded.extend_from_slice(&key.0[..32]);
    pkcs8_encoded.extend_from_slice(&PKCS8_MIDDLE);
    pkcs8_encoded.extend_from_slice(&key.0[32..]);
    let private_key = PrivatePkcs8KeyDer::from(pkcs8_encoded.as_slice());
    let keypair = rcgen::KeyPair::try_from(&private_key)?;
    Ok(keypair)
}

/// Converts a keypair to an ED25519 secret key, asserting that it is the
/// exact kind of keypair we expect.
fn keypair_to_raw_ed25519_secret_key(
    keypair: &rcgen::KeyPair,
) -> anyhow::Result<near_crypto::ED25519SecretKey> {
    let pkcs8_encoded = keypair.serialize_der();
    if pkcs8_encoded.len() != 16 + 32 + 3 + 32 {
        anyhow::bail!("Invalid PKCS8 length");
    }
    if pkcs8_encoded[..16] != PKCS8_HEADER {
        anyhow::bail!("Invalid PKCS8 header");
    }
    if pkcs8_encoded[16 + 32..16 + 32 + 3] != PKCS8_MIDDLE {
        anyhow::bail!("Invalid PKCS8 middle");
    }

    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&pkcs8_encoded[16..16 + 32]);
    key[32..].copy_from_slice(&pkcs8_encoded[16 + 32 + 3..]);

    Ok(near_crypto::ED25519SecretKey(key))
}

/// Configures the quinn library to properly perform TLS handshakes.
fn configure_quinn(
    p2p_private_key: &near_crypto::ED25519SecretKey,
) -> anyhow::Result<(ServerConfig, ClientConfig)> {
    // The issuer is a dummy certificate authority that every node trusts.
    let issuer_signer = rcgen::KeyPair::from_pem(DUMMY_ISSUER_PRIVATE_KEY)?;
    let issuer_cert =
        rcgen::CertificateParams::new(vec!["root".to_string()])?.self_signed(&issuer_signer)?;

    // This is the keypair that is secret to this node, used in P2P handshakes.
    let p2p_key = raw_ed25519_secret_key_to_keypair(p2p_private_key)?;
    let p2p_key_der =
        rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(p2p_key.serialize_der()));

    let p2p_cert = rcgen::CertificateParams::new(vec!["dummy".to_string()])?.signed_by(
        &p2p_key,
        &issuer_cert,
        &issuer_signer,
    )?;

    // Use a single trusted issuer.
    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add(issuer_cert.der().clone())?;

    // As the server, we do not verify the client's certificate, but we still need
    // a custom verifier or else the certificate will not even be propagated to us
    // when we handle the connection. Later we'll check that the client provided a
    // valid public key in the certificate.
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(DummyClientCertVerifier))
        .with_single_cert(vec![p2p_cert.der().clone()], p2p_key_der.clone_key())?;
    // As a client, we verify that the server has a valid certificate signed by the
    // dummy issuer (this is required by rustls). When making the connection we also
    // check that the server has the right public key.
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_client_auth_cert(vec![p2p_cert.der().clone()], p2p_key_der.clone_key())?;

    let server_suite = initial_suite_from_provider(server_config.crypto_provider())
        .ok_or_else(|| anyhow!("No supported cipher suite found in server config"))?;
    let client_suite = initial_suite_from_provider(client_config.crypto_provider())
        .ok_or_else(|| anyhow!("No supported cipher suite found in client config"))?;

    let server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::with_initial(
        server_config.into(),
        server_suite,
    )?));
    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::with_initial(
        client_config.into(),
        client_suite,
    )?));
    Ok((server_config, client_config))
}

/// I don't understand this function but it's copied from the quinn code to satisfy the quinn API.
fn initial_suite_from_provider(provider: &Arc<rustls::crypto::CryptoProvider>) -> Option<Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                Some(suite.quic_suite())
            }
            _ => None,
        })
        .flatten()
}

/// Creates a mesh network using QUIC for communication.
pub async fn new_quic_mesh_network(
    config: &MpcConfig,
    p2p_private_key: &near_crypto::ED25519SecretKey,
) -> Result<(
    impl MeshNetworkTransportSender,
    impl MeshNetworkTransportReceiver,
)> {
    let (server_config, client_config) = configure_quinn(p2p_private_key)?;

    let my_port = config
        .participants
        .participants
        .iter()
        .find(|participant| participant.id == config.my_participant_id)
        .map(|participant| participant.port)
        .ok_or_else(|| anyhow!("My ID not found in participants"))?;

    // Create server and client endpoints.
    let server = Endpoint::server(
        server_config,
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), my_port),
    )?;

    let mut client = Endpoint::client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))?;
    client.set_default_client_config(client_config);

    // Prepare participant data.
    let mut participant_ids = Vec::new();
    let mut participant_identities = ParticipantIdentities::default();
    let mut connections = HashMap::new();
    for participant in &config.participants.participants {
        participant_ids.push(participant.id);
        participant_identities
            .key_to_participant_id
            .insert(participant.p2p_public_key.clone(), participant.id);
    }
    let participant_identities = Arc::new(participant_identities);
    for participant in &config.participants.participants {
        if participant.id == config.my_participant_id {
            continue;
        }
        connections.insert(
            participant.id,
            Arc::new(PersistentConnection::new(
                client.clone(),
                config.my_participant_id,
                format!("{}:{}", participant.address, participant.port),
                participant.id,
                participant_identities.clone(),
            )?),
        );
    }

    // TODO: what should the channel size be? What's our flow control strategy in general?
    let (message_sender, message_receiver) = mpsc::channel(1000000);
    let endpoint_for_listener = server.clone();

    let incoming_connections_task = tracking::spawn("Handle incoming connections", async move {
        let mut tasks = AutoAbortTaskCollection::new();
        while let Some(conn) = endpoint_for_listener.accept().await {
            let message_sender = message_sender.clone();
            let participant_identities = participant_identities.clone();
            tasks.spawn_checked("Handle connection", async move {
                if let Ok(connection) = conn.await {
                    let verified_participant_id =
                        verify_peer_identity(&connection, &participant_identities)?;
                    tracking::set_progress(&format!("Connection from {}", verified_participant_id));

                    loop {
                        let stream = connection.accept_uni().await?;
                        tracing::debug!("Accepted stream from {}", verified_participant_id);
                        let message_sender = message_sender.clone();
                        // Don't track this, or else it is too spammy.
                        tokio::spawn(handle_incoming_stream(
                            verified_participant_id,
                            stream,
                            message_sender,
                        ));
                    }
                }
                anyhow::Ok(())
            });
        }
    });

    let sender = QuicMeshSender {
        my_id: config.my_participant_id,
        participants: participant_ids,
        connections,
    };

    let receiver = QuicMeshReceiver {
        receiver: message_receiver,
        _incoming_connections_task: incoming_connections_task,
    };

    Ok((sender, receiver))
}

fn verify_peer_identity(
    conn: &Connection,
    participant_identities: &ParticipantIdentities,
) -> anyhow::Result<ParticipantId> {
    let Some(identity) = conn.peer_identity() else {
        anyhow::bail!("Connection without peer identity");
    };
    let Ok(certs) = identity.downcast::<Vec<CertificateDer<'static>>>() else {
        anyhow::bail!("Connection with unexpected peer identity type");
    };
    if certs.len() != 1 {
        anyhow::bail!("Connection with unexpected number of certificates");
    };
    let Ok(cert) = X509Certificate::from_der(&certs[0]) else {
        anyhow::bail!("Connection with invalid certificate");
    };
    let Ok(public_key) = cert.1.public_key().parsed() else {
        anyhow::bail!("Connection with invalid public key");
    };
    // The library doesn't recognize ED25519 keys, but that's fine, we'll compare the raw
    // bytes directly.
    let PublicKey::Unknown(public_key_data) = public_key else {
        anyhow::bail!(
            "Connection with unexpected public key type: {:?}",
            public_key
        );
    };
    let public_key = near_crypto::ED25519PublicKey(
        public_key_data
            .try_into()
            .context("Connection with public key of unexpected length")?,
    );
    let Some(peer_id) = participant_identities
        .key_to_participant_id
        .get(&near_crypto::PublicKey::ED25519(public_key))
    else {
        anyhow::bail!("Connection with unknown public key");
    };
    Ok(*peer_id)
}

/// For now, each stream handles exactly one MpcMessage. This reads the message
/// and sends it to the message_sender.
async fn handle_incoming_stream(
    peer_id: ParticipantId,
    mut recv: quinn::RecvStream,
    message_sender: Sender<MpcPeerMessage>,
) -> Result<()> {
    let mut msg_len_buf = [0u8; 4];
    recv.read_exact(&mut msg_len_buf).await?;
    let msg_len = u32::from_be_bytes(msg_len_buf) as usize;

    let mut msg_buf = vec![0u8; msg_len];
    recv.read_exact(&mut msg_buf).await?;

    let peer_message = MpcPeerMessage {
        from: peer_id,
        message: MpcMessage::try_from_slice(&msg_buf)?,
    };

    message_sender.send(peer_message).await?;
    Ok(())
}

#[async_trait]
impl MeshNetworkTransportSender for QuicMeshSender {
    fn my_participant_id(&self) -> ParticipantId {
        self.my_id
    }

    fn all_participant_ids(&self) -> Vec<ParticipantId> {
        self.participants.clone()
    }

    fn connection_version(&self, participant_id: ParticipantId) -> usize {
        self.connections
            .get(&participant_id)
            .map(|conn| conn.current.borrow().clone().map(|(v, _)| v).unwrap_or(0))
            .unwrap_or(0)
    }

    async fn send(
        &self,
        recipient_id: ParticipantId,
        message: MpcMessage,
        connection_version: usize,
    ) -> Result<()> {
        // For now, every message opens a new stream. This is totally fine
        // for performance, but it does mean messages may not arrive in order.
        let mut stream = self
            .connections
            .get(&recipient_id)
            .ok_or_else(|| anyhow!("Recipient not found"))?
            .new_stream(connection_version)
            .await?;

        let msg = borsh::to_vec(&message)?;
        stream.write_all(&(msg.len() as u32).to_be_bytes()).await?;
        stream.write_all(&msg).await?;
        stream.finish()?;

        Ok(())
    }

    async fn wait_for_ready(&self, threshold: usize) -> anyhow::Result<()> {
        assert!(threshold - 1 <= self.connections.len());
        let mut join_set = JoinSet::new();
        for (participant_id, conn) in &self.connections {
            let participant_id = *participant_id;
            let my_id = self.my_id;
            let conn = conn.clone();
            join_set.spawn(async move {
                let mut receiver = conn.current.clone();
                while receiver
                    .borrow()
                    .clone()
                    .is_none_or(|(_, weak)| weak.upgrade().is_none())
                {
                    tracing::info!("Waiting for connection to {}, me {}", participant_id, my_id);
                    receiver.changed().await?;
                }
                tracing::info!("Connected to {}, me {}", participant_id, my_id);
                anyhow::Ok(())
            });
        }
        for _ in 1..threshold {
            join_set.join_next().await.unwrap()??;
        }
        Ok(())
    }

    fn all_alive_participant_ids(&self) -> Vec<ParticipantId> {
        let mut ids: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, conn)| conn.is_alive.load(Ordering::Relaxed))
            .map(|(p, _)| *p)
            .chain([self.my_id])
            .collect();
        // Make it stable for testing.
        ids.sort();
        ids
    }
}

#[async_trait]
impl MeshNetworkTransportReceiver for QuicMeshReceiver {
    async fn receive(&mut self) -> Result<MpcPeerMessage> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("Channel closed"))
    }
}

/// Generates an ED25519 keypair, returning the pem-encoded private key and the
/// hex-encoded public key.
pub fn generate_keypair() -> Result<(near_crypto::ED25519SecretKey, near_crypto::ED25519PublicKey)>
{
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    Ok((
        keypair_to_raw_ed25519_secret_key(&key_pair)?,
        near_crypto::ED25519PublicKey(key_pair.public_key_raw().try_into().unwrap()),
    ))
}

pub fn generate_test_p2p_configs(
    participant_accounts: &[AccountId],
    threshold: usize,
    // this is a hack to make sure that when tests run in parallel, they don't
    // collide on the same port.
    seed: u16,
) -> anyhow::Result<Vec<(MpcConfig, ED25519SecretKey)>> {
    let mut participants = Vec::new();
    let mut keypairs = Vec::new();
    for (i, participant_account) in participant_accounts.iter().enumerate() {
        let (p2p_private_key, p2p_public_key) = generate_keypair()?;
        participants.push(ParticipantInfo {
            id: ParticipantId::from_raw(rand::random()),
            address: "127.0.0.1".to_string(),
            port: 10000 + seed * 1000 + i as u16,
            p2p_public_key: near_crypto::PublicKey::ED25519(p2p_public_key.clone()),
            near_account_id: participant_account.clone(),
        });
        keypairs.push((p2p_private_key, p2p_public_key));
    }

    let mut configs = Vec::new();
    for (i, keypair) in keypairs.into_iter().enumerate() {
        let participants = ParticipantsConfig {
            threshold: threshold as u32,
            participants: participants.clone(),
        };

        let mpc_config = MpcConfig {
            my_participant_id: participants.participants[i].id,
            participants,
        };
        configs.push((mpc_config, keypair.0));
    }

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
    use crate::p2p::{keypair_to_raw_ed25519_secret_key, raw_ed25519_secret_key_to_keypair};
    use crate::primitives::{MpcMessage, ParticipantId};
    use crate::tracing::init_logging;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use serial_test::serial;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_pkcs8_ed25519_encoding() {
        let (private_key, _) = super::generate_keypair().unwrap();
        let keypair = raw_ed25519_secret_key_to_keypair(&private_key).unwrap();
        let private_key2 = keypair_to_raw_ed25519_secret_key(&keypair).unwrap();
        assert_eq!(private_key, private_key2);
    }

    #[tokio::test]
    #[serial]
    async fn test_basic_quic_mesh_network() {
        init_logging();
        let configs = super::generate_test_p2p_configs(
            &["test0".parse().unwrap(), "test1".parse().unwrap()],
            2,
            0,
        )
        .unwrap();
        let participant0 = configs[0].0.my_participant_id;
        let participant1 = configs[1].0.my_participant_id;

        start_root_task_with_periodic_dump(async move {
            let (sender0, mut receiver0) =
                super::new_quic_mesh_network(&configs[0].0, &configs[0].1)
                    .await
                    .unwrap();
            let (sender1, mut receiver1) =
                super::new_quic_mesh_network(&configs[1].0, &configs[1].1)
                    .await
                    .unwrap();

            sender0.wait_for_ready(2).await.unwrap();
            sender1.wait_for_ready(2).await.unwrap();

            for _ in 0..100 {
                sender0
                    .send(
                        participant1,
                        MpcMessage {
                            data: vec![vec![1, 2, 3]],
                            task_id: crate::primitives::MpcTaskId::KeyGeneration,
                            participants: vec![],
                        },
                        1,
                    )
                    .await
                    .unwrap();
                let msg = receiver1.receive().await.unwrap();
                assert_eq!(msg.from, participant0);
                assert_eq!(msg.message.data, vec![vec![1, 2, 3]]);

                sender1
                    .send(
                        participant0,
                        MpcMessage {
                            data: vec![vec![4, 5, 6]],
                            task_id: crate::primitives::MpcTaskId::KeyGeneration,
                            participants: vec![],
                        },
                        1,
                    )
                    .await
                    .unwrap();

                let msg = receiver0.receive().await.unwrap();
                assert_eq!(msg.from, participant1);
                assert_eq!(msg.message.data, vec![vec![4, 5, 6]]);
            }
        })
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_wait_for_ready() {
        init_logging();
        let mut configs = super::generate_test_p2p_configs(
            &[
                "test0".parse().unwrap(),
                "test1".parse().unwrap(),
                "test2".parse().unwrap(),
                "test3".parse().unwrap(),
            ],
            4,
            1,
        )
        .unwrap();
        // Make node 3 use the wrong address for the 0th node. All connections should work
        // except from 3 to 0.
        configs[3].0.participants.participants[0].address = "169.254.1.1".to_owned();
        start_root_task_with_periodic_dump(async move {
            let (sender0, _receiver0) = super::new_quic_mesh_network(&configs[0].0, &configs[0].1)
                .await
                .unwrap();
            let (sender1, receiver1) = super::new_quic_mesh_network(&configs[1].0, &configs[1].1)
                .await
                .unwrap();
            let (sender2, _receiver2) = super::new_quic_mesh_network(&configs[2].0, &configs[2].1)
                .await
                .unwrap();
            let (sender3, _receiver3) = super::new_quic_mesh_network(&configs[3].0, &configs[3].1)
                .await
                .unwrap();

            sender0.wait_for_ready(4).await.unwrap();
            sender1.wait_for_ready(4).await.unwrap();
            sender2.wait_for_ready(4).await.unwrap();
            // Node 3 should not be able to connect to node 0, so if we wait for 4,
            // it should fail.
            assert!(timeout(Duration::from_secs(1), sender3.wait_for_ready(4))
                .await
                .is_err());

            // But if we wait for 3, it should succeed.
            sender3.wait_for_ready(3).await.unwrap();

            let ids: Vec<_> = configs[0]
                .0
                .participants
                .participants
                .iter()
                .map(|p| p.id)
                .collect();
            assert_eq!(sender0.all_alive_participant_ids(), sorted(&ids));
            assert_eq!(sender1.all_alive_participant_ids(), sorted(&ids));
            assert_eq!(sender2.all_alive_participant_ids(), sorted(&ids));
            assert_eq!(
                sender3.all_alive_participant_ids(),
                sorted(&[ids[1], ids[2], ids[3]]),
            );

            // Disconnect node 1. Other nodes should notice the change.
            drop((sender1, receiver1));
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert_eq!(
                sender0.all_alive_participant_ids(),
                sorted(&[ids[0], ids[2], ids[3]])
            );
            assert_eq!(
                sender2.all_alive_participant_ids(),
                sorted(&[ids[0], ids[2], ids[3]])
            );
            assert_eq!(
                sender3.all_alive_participant_ids(),
                sorted(&[ids[2], ids[3]])
            );

            // Reconnect node 1. Other nodes should re-establish the connections.
            let (sender1, _receiver1) = super::new_quic_mesh_network(&configs[1].0, &configs[1].1)
                .await
                .unwrap();
            sender0.wait_for_ready(4).await.unwrap();
            sender1.wait_for_ready(4).await.unwrap();
            sender2.wait_for_ready(4).await.unwrap();
            sender3.wait_for_ready(3).await.unwrap();
            assert_eq!(sender0.all_alive_participant_ids(), sorted(&ids));
            assert_eq!(sender1.all_alive_participant_ids(), sorted(&ids));
            assert_eq!(sender2.all_alive_participant_ids(), sorted(&ids));
            assert_eq!(
                sender3.all_alive_participant_ids(),
                sorted(&[ids[1], ids[2], ids[3]]),
            );
        })
        .await;
    }

    fn sorted(ids: &[ParticipantId]) -> Vec<ParticipantId> {
        let mut ids = ids.to_vec();
        ids.sort();
        ids
    }
}
