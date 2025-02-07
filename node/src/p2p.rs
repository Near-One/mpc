use crate::config::MpcConfig;
use crate::metrics;
use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
use crate::primitives::{MpcMessage, MpcPeerMessage, ParticipantId};
use crate::tracking::{self, AutoAbortTask, AutoAbortTaskCollection};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use borsh::BorshDeserialize;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, CommonState, ServerConfig};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, UnboundedSender};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use x509_parser::prelude::{FromDer, X509Certificate};
use x509_parser::public_key::PublicKey;

/// Implements MeshNetworkTransportSender for sending messages over a TLS-based
/// mesh network.
pub struct TlsMeshSender {
    my_id: ParticipantId,
    participants: Vec<ParticipantId>,
    connections: HashMap<ParticipantId, Arc<PersistentConnection>>,
    connectivities: Arc<HashMap<ParticipantId, ConnectivityIndicator>>,
}

/// Implements MeshNetworkTransportReceiver.
pub struct TlsMeshReceiver {
    receiver: Receiver<MpcPeerMessage>,
    _incoming_connections_task: AutoAbortTask<()>,
}

/// Maps public keys to participant IDs. Used to identify incoming connections.
#[derive(Default)]
struct ParticipantIdentities {
    key_to_participant_id: HashMap<near_crypto::PublicKey, ParticipantId>,
}

/// A always-allowing client certificate verifier for the TLS layer.
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

/// A retrying connection that will automatically reconnect if the TCP
/// connection is broken.
struct PersistentConnection {
    target_participant_id: ParticipantId,
    // Current connection and version. The connection is an Option because it
    // can be None if the connection was never established. It is a Weak
    // because the connection is owned by the loop-to-connect task (see the
    // `new` method) and when the connection is closed it is dropped. The
    // version is incremented every time the connection is re-established.
    current: tokio::sync::watch::Receiver<Option<(usize, Weak<TlsConnection>)>>,
    // The task that loops to connect to the target. When `PersistentConnection`
    // is dropped, this task is aborted. The task owns any active connection,
    // so dropping it also frees any connection currently alive.
    _task: AutoAbortTask<()>,
}

/// State for a single TLS/TCP connection to one participant. We only ever send
/// messages through this connection, so there is nothing to handle receiving.
/// Dropping this struct will automatically close the connection.
struct TlsConnection {
    /// Used to send messages via the connection.
    sender: UnboundedSender<Packet>,
    /// Task that reads messages from the channel (other side of `sender`) and
    /// sends it over the TLS connection. This task owns the connection, so
    /// dropping it closes the connection.
    _sender_task: AutoAbortTask<()>,
    /// Task that periodically sends a Ping message to the other side. It does
    /// not expect a Pong, it simply keeps the connection alive (so we can
    /// quickly detect if the connection is broken).
    _keepalive_task: AutoAbortTask<()>,
    /// This is cancelled when the connection is closed. Used to wait for the
    /// connection to close.
    closed: CancellationToken,
}

/// Simple structure to cancel the CancellationToken when dropped.
struct DropToCancel(CancellationToken);

impl Drop for DropToCancel {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Either a Ping or a data packet.
enum Packet {
    Ping,
    Data(Vec<u8>),
}

impl TlsConnection {
    /// Makes a TLS/TCP connection to the given address, authenticating the
    /// other side as the given participant.
    async fn new(
        client_config: Arc<ClientConfig>,
        target_address: &str,
        target_participant_id: ParticipantId,
        participant_identities: &ParticipantIdentities,
    ) -> anyhow::Result<TlsConnection> {
        let conn = TcpStream::connect(target_address)
            .await
            .context("TCP connect")?;
        let mut tls_conn = tokio_rustls::TlsConnector::from(client_config)
            .connect("dummy".try_into().unwrap(), conn)
            .await
            .context("TLS connect")?;

        let peer_id = verify_peer_identity(tls_conn.get_ref().1, participant_identities)
            .context("Verify server identity")?;
        if peer_id != target_participant_id {
            anyhow::bail!(
                "Incorrect peer identity, expected {}, authenticated {}",
                target_participant_id,
                peer_id
            );
        }

        let (sender, mut receiver) = mpsc::unbounded_channel::<Packet>();
        let closed = CancellationToken::new();
        let closed_clone = closed.clone();
        let sender_task = tracking::spawn_checked(
            &format!("TLS connection to {}", target_participant_id),
            async move {
                let _drop_to_cancel = DropToCancel(closed_clone);
                let mut sent_bytes: u64 = 0;
                loop {
                    tokio::select! {
                        data = receiver.recv() => {
                            let Some(data) = data else {
                                break;
                            };
                            match data {
                                Packet::Ping => {
                                    tls_conn.write_u8(0).await?;
                                    sent_bytes += 1;
                                }
                                Packet::Data(vec) => {
                                    tls_conn.write_u8(1).await?;
                                    tls_conn.write_u32(vec.len() as u32).await?;
                                    tls_conn.write_all(&vec).await?;
                                    sent_bytes += 5 + vec.len() as u64;
                                }
                            }
                            tracking::set_progress(&format!("Sent {} bytes", sent_bytes));
                        }
                        _ = tls_conn.read_u8() => {
                            // We do not expect any data from the other side. However,
                            // selecting on it will quickly return error if the connection
                            // is broken before we have data to send. That way we can
                            // immediately quit the loop as soon as the connection is broken
                            // (so we can reconnect).
                            break;
                        }
                    }
                }
                anyhow::Ok(())
            },
        );
        let sender_clone = sender.clone();
        let keepalive_task = tracking::spawn(
            &format!("TCP keepalive for {}", target_participant_id),
            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    if sender_clone.send(Packet::Ping).is_err() {
                        // The receiver side will be dropped when the sender task is
                        // dropped (i.e. connection is closed).
                        break;
                    }
                }
            },
        );
        Ok(TlsConnection {
            sender,
            _sender_task: sender_task,
            _keepalive_task: keepalive_task,
            closed,
        })
    }

    async fn wait_for_close(&self) {
        self.closed.cancelled().await;
    }

    fn send(&self, data: Vec<u8>) -> anyhow::Result<()> {
        self.sender.send(Packet::Data(data))?;
        Ok(())
    }
}

impl PersistentConnection {
    const CONNECTION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

    /// Sends a message over the connection. If the connection was reset, fail.
    async fn send_message(&self, expected_version: usize, msg: Vec<u8>) -> anyhow::Result<()> {
        let (expected_version, version, conn) = if expected_version == 0 {
            // This means that the connection was never established when the computation
            // started. This is possible when someone else initiated the computation,
            // before we've got a chance to establish an outgoing connection to the
            // involved participants yet. So in this case, we shall wait for a connection.
            let current_conn = self.current.borrow().clone();
            match current_conn {
                Some((version, conn)) => (1, version, conn),
                None => {
                    let (version, conn) = self
                        .current
                        .clone()
                        .wait_for(|conn| conn.is_some())
                        .await?
                        .clone()
                        .unwrap();
                    (1, version, conn)
                }
            }
        } else {
            match self.current.borrow().clone() {
                Some((version, conn)) => (expected_version, version, conn),
                None => {
                    anyhow::bail!(
                        "Programming error: Connection to {} is missing",
                        self.target_participant_id
                    );
                }
            }
        };

        if version != expected_version {
            anyhow::bail!(
                "Connection to {} is not the original connection expected",
                self.target_participant_id
            );
        }
        let Some(conn) = conn.upgrade() else {
            anyhow::bail!("Connection to {} was dropped", self.target_participant_id);
        };
        conn.send(msg)?;
        Ok(())
    }

    pub fn new(
        client_config: Arc<ClientConfig>,
        my_id: ParticipantId,
        target_address: String,
        target_participant_id: ParticipantId,
        participant_identities: Arc<ParticipantIdentities>,
        connectivity_indicator: ConnectivityIndicator,
    ) -> anyhow::Result<PersistentConnection> {
        let (current_sender, current_receiver) = tokio::sync::watch::channel(None);

        let task = tracking::spawn(
            &format!("Persistent connection to {}", target_participant_id),
            async move {
                let mut connection_version = 1;
                loop {
                    let new_conn = match TlsConnection::new(
                        client_config.clone(),
                        &target_address,
                        target_participant_id,
                        &participant_identities,
                    )
                    .await
                    {
                        Ok(new_conn) => {
                            tracing::info!(
                                "Outgoing {} --> {} connected",
                                my_id,
                                target_participant_id
                            );
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
                    let _indicator_guard = connectivity_indicator.mark_connected_outgoing();
                    new_conn.wait_for_close().await;
                }
            },
        );
        Ok(PersistentConnection {
            target_participant_id,
            current: current_receiver,
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

/// Configures TLS server and client to properly perform TLS handshakes.
/// On the server side it expects a client to provide a certificate that
/// presents a public key that matches one of the participants in the MPC
/// network. On the client side it expects the server to present a
/// certificate that presents a public key that matches the expected participant
/// being connected to.
fn configure_tls(
    p2p_private_key: &near_crypto::ED25519SecretKey,
) -> anyhow::Result<(Arc<ServerConfig>, Arc<ClientConfig>)> {
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

    Ok((server_config.into(), client_config.into()))
}

/// Creates a mesh network using TLS over TCP for communication.
pub async fn new_tls_mesh_network(
    config: &MpcConfig,
    p2p_private_key: &near_crypto::ED25519SecretKey,
) -> anyhow::Result<(
    impl MeshNetworkTransportSender,
    impl MeshNetworkTransportReceiver,
)> {
    let (server_config, client_config) = configure_tls(p2p_private_key)?;

    let my_port = config
        .participants
        .participants
        .iter()
        .find(|participant| participant.id == config.my_participant_id)
        .map(|participant| participant.port)
        .ok_or_else(|| anyhow!("My ID not found in participants"))?;

    // Prepare participant data.
    let mut participant_identities = ParticipantIdentities::default();
    let mut connections = HashMap::new();
    let mut connectivities = HashMap::new();
    for participant in &config.participants.participants {
        if participant.id == config.my_participant_id {
            continue;
        }
        participant_identities
            .key_to_participant_id
            .insert(participant.p2p_public_key.clone(), participant.id);
        connectivities.insert(participant.id, ConnectivityIndicator::new());
    }
    let connectivities = Arc::new(connectivities);
    let participant_identities = Arc::new(participant_identities);
    for participant in &config.participants.participants {
        if participant.id == config.my_participant_id {
            continue;
        }
        connections.insert(
            participant.id,
            Arc::new(PersistentConnection::new(
                client_config.clone(),
                config.my_participant_id,
                format!("{}:{}", participant.address, participant.port),
                participant.id,
                participant_identities.clone(),
                connectivities.get(&participant.id).unwrap().clone(),
            )?),
        );
    }

    let tls_acceptor = TlsAcceptor::from(server_config);

    // TODO: what should the channel size be? What's our flow control strategy in general?
    let (message_sender, message_receiver) = mpsc::channel(1000000);
    // let endpoint_for_listener = server.clone();
    let tcp_listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(0, 0, 0, 0),
        my_port,
    )))
    .await
    .context("TCP bind")?;

    let connectivities_clone = connectivities.clone();
    let my_id = config.my_participant_id;
    let incoming_connections_task = tracking::spawn("Handle incoming connections", async move {
        let mut tasks = AutoAbortTaskCollection::new();
        while let Ok((tcp_stream, _)) = tcp_listener.accept().await {
            let message_sender = message_sender.clone();
            let participant_identities = participant_identities.clone();
            let tls_acceptor = tls_acceptor.clone();
            let connectivities = connectivities_clone.clone();
            tasks.spawn_checked::<_, ()>("Handle connection", async move {
                let mut stream = tls_acceptor.accept(tcp_stream).await?;
                let peer_id = verify_peer_identity(stream.get_ref().1, &participant_identities)?;
                tracking::set_progress(&format!("Authenticated as {}", peer_id));
                tracing::info!("Incoming {} <-- {} connected", my_id, peer_id);
                let _indicator_guard = connectivities
                    .get(&peer_id)
                    .unwrap()
                    .mark_connected_incoming();
                let mut received_bytes: u64 = 0;
                loop {
                    let tag = stream.read_u8().await?;
                    match tag {
                        0 => {
                            // Ping
                            received_bytes += 1;
                        }
                        1 => {
                            let mut len_buf = [0u8; 4];
                            stream.read_exact(&mut len_buf).await?;
                            let len = u32::from_be_bytes(len_buf) as usize;
                            let mut buf = vec![0u8; len];
                            stream.read_exact(&mut buf).await?;
                            let message = MpcPeerMessage {
                                from: peer_id,
                                message: MpcMessage::try_from_slice(&buf)?,
                            };
                            message_sender.send(message).await?;
                            received_bytes += 5 + len as u64;
                        }
                        _ => {
                            anyhow::bail!("Invalid tag");
                        }
                    }
                    tracking::set_progress(&format!(
                        "Received {} bytes from {}",
                        received_bytes, peer_id
                    ));
                }
            });
        }
    });

    let sender = TlsMeshSender {
        my_id: config.my_participant_id,
        participants: config
            .participants
            .participants
            .iter()
            .map(|p| p.id)
            .collect(),
        connections,
        connectivities,
    };

    let receiver = TlsMeshReceiver {
        receiver: message_receiver,
        _incoming_connections_task: incoming_connections_task,
    };

    Ok((sender, receiver))
}

fn verify_peer_identity(
    conn: &CommonState,
    participant_identities: &ParticipantIdentities,
) -> anyhow::Result<ParticipantId> {
    let Some(certs) = conn.peer_certificates() else {
        anyhow::bail!("Connection without peer identity");
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

/// Struct to track bidirectional connectivity between two nodes.
/// A node has one ConnectivityIndicator for each other node in the network.
#[derive(Clone)]
struct ConnectivityIndicator {
    /// A packed integer; the high 32 bits represents the number of incoming
    /// connections currently active from the other node, and the low 32 bits
    /// represents the number of outgoing connections currently active to the
    /// other node. The latter is expected to never exceed 1.
    ///
    /// By looking at this integer we can determine if both directions are
    /// connected.
    connected: Arc<AtomicU64>,
    /// This is used to implement `wait_for_both_connected` by allowing the
    /// waiter to asynchronously wait for the atomic to change.
    notify: Arc<tokio::sync::Notify>,
}

struct DropToDisconnectOutgoing(ConnectivityIndicator);
impl Drop for DropToDisconnectOutgoing {
    fn drop(&mut self) {
        self.0.connected.fetch_sub(1, Ordering::Relaxed);
        self.0.notify.notify_waiters();
    }
}

struct DropToDisconnectIncoming(ConnectivityIndicator);
impl Drop for DropToDisconnectIncoming {
    fn drop(&mut self) {
        self.0
            .connected
            .fetch_sub(ConnectivityIndicator::INCOMING_COUNT, Ordering::Relaxed);
        self.0.notify.notify_waiters();
    }
}

impl ConnectivityIndicator {
    const INCOMING_COUNT: u64 = 1 << 32;

    fn new() -> Self {
        Self {
            connected: Arc::new(AtomicU64::new(0)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn mark_connected_outgoing(&self) -> DropToDisconnectOutgoing {
        self.connected.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
        DropToDisconnectOutgoing(self.clone())
    }

    fn mark_connected_incoming(&self) -> DropToDisconnectIncoming {
        self.connected
            .fetch_add(Self::INCOMING_COUNT, Ordering::Relaxed);
        self.notify.notify_waiters();
        DropToDisconnectIncoming(self.clone())
    }

    fn is_connected_both_ways(&self) -> bool {
        let flag = self.connected.load(Ordering::Relaxed);
        flag >= Self::INCOMING_COUNT && flag & (Self::INCOMING_COUNT - 1) >= 1
    }

    /// Only returns when both directions are connected.
    /// This should not be used by two tasks concurrently.
    async fn wait_for_both_connected(&self) {
        loop {
            if self.is_connected_both_ways() {
                return;
            }
            // Should not be used concurrently from multiple tasks, because this
            // notification pattern can miss notifications if there are two waiters.
            self.notify.notified().await;
        }
    }
}

#[async_trait]
impl MeshNetworkTransportSender for TlsMeshSender {
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
    ) -> anyhow::Result<()> {
        self.connections
            .get(&recipient_id)
            .ok_or_else(|| anyhow!("Recipient not found"))?
            .send_message(connection_version, borsh::to_vec(&message)?)
            .await?;
        Ok(())
    }

    async fn wait_for_ready(&self, threshold: usize) -> anyhow::Result<()> {
        assert!(threshold - 1 <= self.connections.len());
        let mut join_set = JoinSet::new();
        for (participant_id, indicator) in &*self.connectivities {
            let participant_id = *participant_id;
            let my_id = self.my_id;
            let indicator = indicator.clone();
            join_set.spawn(async move {
                indicator.wait_for_both_connected().await;
                tracing::info!("Bidrectional {} <--> {} connected", my_id, participant_id);
                anyhow::Ok(())
            });
        }
        for _ in 1..threshold {
            join_set.join_next().await.unwrap()??;
        }
        Ok(())
    }

    fn all_alive_participant_ids(&self) -> Vec<ParticipantId> {
        let mut ids = self
            .connectivities
            .iter()
            .filter(|(_, indicator)| indicator.is_connected_both_ways())
            .map(|(id, _)| *id)
            .chain([self.my_id])
            .collect::<Vec<_>>();
        ids.sort();
        ids
    }

    fn emit_metrics(&self) {
        let my_participant_id = self.my_participant_id();
        let live_participants: HashSet<ParticipantId> =
            self.all_alive_participant_ids().into_iter().collect();

        metrics::NETWORK_LIVE_CONNECTIONS.reset();

        for id in self.all_participant_ids() {
            let is_live_participant = live_participants.contains(&id);
            metrics::NETWORK_LIVE_CONNECTIONS
                .with_label_values(&[&my_participant_id.to_string(), &id.to_string()])
                .set(is_live_participant.into());
        }
    }
}

#[async_trait]
impl MeshNetworkTransportReceiver for TlsMeshReceiver {
    async fn receive(&mut self) -> anyhow::Result<MpcPeerMessage> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| anyhow!("Channel closed"))
    }
}

pub mod testing {
    use super::{PKCS8_HEADER, PKCS8_MIDDLE};
    use crate::config::{MpcConfig, ParticipantInfo, ParticipantsConfig};
    use crate::primitives::ParticipantId;
    use near_crypto::ED25519SecretKey;
    use near_sdk::AccountId;

    /// A unique seed for each integration test to avoid port conflicts during testing.
    #[derive(Copy, Clone)]
    pub struct PortSeed(u16);

    impl PortSeed {
        pub fn p2p_port(&self, node_index: usize) -> u16 {
            (10000_usize + self.0 as usize * 100 + node_index)
                .try_into()
                .unwrap()
        }

        pub fn web_port(&self, node_index: usize) -> u16 {
            (20000_usize + self.0 as usize * 100 + node_index)
                .try_into()
                .unwrap()
        }

        pub const CLI_FOR_PYTEST: Self = Self(0);
    }

    #[cfg(test)]
    impl PortSeed {
        // Each place that passes a PortSeed in should define a unique one here.
        pub const P2P_BASIC_TEST: Self = Self(1);
        pub const P2P_WAIT_FOR_READY_TEST: Self = Self(2);
        pub const BASIC_CLUSTER_TEST: Self = Self(3);
        pub const FAULTY_CLUSTER_TEST: Self = Self(4);
        pub const KEY_RESHARING_SIMPLE_TEST: Self = Self(5);
        pub const KEY_RESHARING_MULTISTAGE_TEST: Self = Self(6);
        pub const KEY_RESHARING_SIGNATURE_BUFFERING_TEST: Self = Self(7);
    }

    /// Converts a keypair to an ED25519 secret key, asserting that it is the
    /// exact kind of keypair we expect.
    pub fn keypair_to_raw_ed25519_secret_key(
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

    /// Generates an ED25519 keypair, returning the pem-encoded private key and the
    /// hex-encoded public key.
    pub fn generate_keypair(
    ) -> anyhow::Result<(near_crypto::ED25519SecretKey, near_crypto::ED25519PublicKey)> {
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
        port_seed: PortSeed,
    ) -> anyhow::Result<Vec<(MpcConfig, ED25519SecretKey)>> {
        let mut participants = Vec::new();
        let mut keypairs = Vec::new();
        for (i, participant_account) in participant_accounts.iter().enumerate() {
            let (p2p_private_key, p2p_public_key) = generate_keypair()?;
            participants.push(ParticipantInfo {
                id: ParticipantId::from_raw(rand::random()),
                address: "127.0.0.1".to_string(),
                port: port_seed.p2p_port(i),
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
}

#[cfg(test)]
mod tests {
    use crate::network::{MeshNetworkTransportReceiver, MeshNetworkTransportSender};
    use crate::p2p::raw_ed25519_secret_key_to_keypair;
    use crate::p2p::testing::{
        generate_keypair, generate_test_p2p_configs, keypair_to_raw_ed25519_secret_key, PortSeed,
    };
    use crate::primitives::{MpcMessage, ParticipantId};
    use crate::tracing::init_logging;
    use crate::tracking::testing::start_root_task_with_periodic_dump;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_pkcs8_ed25519_encoding() {
        let (private_key, _) = generate_keypair().unwrap();
        let keypair = raw_ed25519_secret_key_to_keypair(&private_key).unwrap();
        let private_key2 = keypair_to_raw_ed25519_secret_key(&keypair).unwrap();
        assert_eq!(private_key, private_key2);
    }

    #[tokio::test]
    async fn test_basic_tls_mesh_network() {
        init_logging();
        let configs = generate_test_p2p_configs(
            &["test0".parse().unwrap(), "test1".parse().unwrap()],
            2,
            PortSeed::P2P_BASIC_TEST,
        )
        .unwrap();
        let participant0 = configs[0].0.my_participant_id;
        let participant1 = configs[1].0.my_participant_id;

        start_root_task_with_periodic_dump(async move {
            let (sender0, mut receiver0) =
                super::new_tls_mesh_network(&configs[0].0, &configs[0].1)
                    .await
                    .unwrap();
            let (sender1, mut receiver1) =
                super::new_tls_mesh_network(&configs[1].0, &configs[1].1)
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
    async fn test_wait_for_ready() {
        init_logging();
        let mut configs = generate_test_p2p_configs(
            &[
                "test0".parse().unwrap(),
                "test1".parse().unwrap(),
                "test2".parse().unwrap(),
                "test3".parse().unwrap(),
            ],
            4,
            PortSeed::P2P_WAIT_FOR_READY_TEST,
        )
        .unwrap();
        // Make node 3 use the wrong address for the 0th node. All connections should work
        // except from 3 to 0.
        configs[3].0.participants.participants[0].address = "169.254.1.1".to_owned();
        start_root_task_with_periodic_dump(async move {
            let (sender0, _receiver0) = super::new_tls_mesh_network(&configs[0].0, &configs[0].1)
                .await
                .unwrap();
            let (sender1, receiver1) = super::new_tls_mesh_network(&configs[1].0, &configs[1].1)
                .await
                .unwrap();
            let (sender2, _receiver2) = super::new_tls_mesh_network(&configs[2].0, &configs[2].1)
                .await
                .unwrap();
            let (sender3, _receiver3) = super::new_tls_mesh_network(&configs[3].0, &configs[3].1)
                .await
                .unwrap();

            sender1.wait_for_ready(4).await.unwrap();
            sender2.wait_for_ready(4).await.unwrap();
            // Node 3 should not be able to connect to node 0, so if we wait for 4,
            // it should fail. This goes both ways (3 to 0 and 0 to 3).
            assert!(timeout(Duration::from_secs(1), sender0.wait_for_ready(4))
                .await
                .is_err());
            assert!(timeout(Duration::from_secs(1), sender3.wait_for_ready(4))
                .await
                .is_err());

            // But if we wait for 3, it should succeed.
            sender0.wait_for_ready(3).await.unwrap();
            sender3.wait_for_ready(3).await.unwrap();

            let ids: Vec<_> = configs[0]
                .0
                .participants
                .participants
                .iter()
                .map(|p| p.id)
                .collect();
            assert_eq!(
                sender0.all_alive_participant_ids(),
                sorted(&[ids[0], ids[1], ids[2]]),
            );
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
                sorted(&[ids[0], ids[2]])
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
            let (sender1, _receiver1) = super::new_tls_mesh_network(&configs[1].0, &configs[1].1)
                .await
                .unwrap();
            sender0.wait_for_ready(3).await.unwrap();
            sender1.wait_for_ready(4).await.unwrap();
            sender2.wait_for_ready(4).await.unwrap();
            sender3.wait_for_ready(3).await.unwrap();
            assert_eq!(
                sender0.all_alive_participant_ids(),
                sorted(&[ids[0], ids[1], ids[2]]),
            );
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
