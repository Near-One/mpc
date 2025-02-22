use crate::primitives::ParticipantId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

/// Represents a version of a bidirectional connection with another node.
/// This allows us to detect if the connection was reset or dropped in either
/// direction, the lack of which would guarantee that messages are not lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectionVersion {
    pub outgoing: usize,
    pub incoming: usize,
}

/// A connection object along with a version number.
///
/// The expectation is that every time we make a new connection, the version
/// would be incremented.
///
/// The connection may be dropped, in which case this represents a *pending*
/// connection of the *next* version. For example, initially the version is 0
/// and the weak ptr points to nothing. So version() returns 1, meaning that
/// when to send or receive anything, we would wait until the first connection
/// is established.
pub struct ConnectionWithVersion<T: Send + Sync + 'static> {
    pub connection: Weak<T>,
    version: usize,
}

impl<T: Send + Sync + 'static> Clone for ConnectionWithVersion<T> {
    fn clone(&self) -> Self {
        Self {
            connection: self.connection.clone(),
            version: self.version,
        }
    }
}

impl<T: Send + Sync + 'static> ConnectionWithVersion<T> {
    pub fn version(&self) -> usize {
        if self.connection.upgrade().is_some() {
            self.version
        } else {
            self.version + 1
        }
    }

    pub fn is_connected(&self) -> bool {
        self.connection.upgrade().is_some()
    }
}

/// Struct to track bidirectional connectivity between two nodes.
/// A node has one NodeConnectivity for each other node in the network.
pub struct NodeConnectivity<I: Send + Sync + 'static, O: Send + Sync + 'static> {
    outgoing_sender: tokio::sync::watch::Sender<ConnectionWithVersion<I>>,
    outgoing_receiver: tokio::sync::watch::Receiver<ConnectionWithVersion<I>>,
    incoming_sender: tokio::sync::watch::Sender<ConnectionWithVersion<O>>,
    incoming_receiver: tokio::sync::watch::Receiver<ConnectionWithVersion<O>>,
    outgoing_version: AtomicUsize,
    incoming_version: AtomicUsize,
}

impl<I: Send + Sync + 'static, O: Send + Sync + 'static> NodeConnectivity<I, O> {
    pub fn new() -> Self {
        let (outgoing_sender, outgoing_receiver) =
            tokio::sync::watch::channel(ConnectionWithVersion {
                connection: Weak::new(),
                version: 0,
            });
        let (incoming_sender, incoming_receiver) =
            tokio::sync::watch::channel(ConnectionWithVersion {
                connection: Weak::new(),
                version: 0,
            });
        Self {
            outgoing_sender,
            outgoing_receiver,
            incoming_sender,
            incoming_receiver,
            outgoing_version: AtomicUsize::new(0),
            incoming_version: AtomicUsize::new(0),
        }
    }

    /// Sets a new outgoing connection and increments the version by 1.
    /// The caller needs to drop the connection object when the network
    /// connection is dropped.
    pub fn set_outgoing_connection(&self, conn: &Arc<I>) {
        let version = self.outgoing_version.fetch_add(1, Ordering::Relaxed) + 1;
        self.outgoing_sender
            .send(ConnectionWithVersion {
                connection: Arc::downgrade(conn),
                version,
            })
            .unwrap(); // can't fail: we keep the receiver
    }

    /// Sets a new incoming connection and increments the version by 1.
    /// The caller needs to drop the connection object when the network
    /// connection is dropped.
    ///
    /// Unlike outgoing connections, it's possible for multiple incoming
    /// connections to be active for a given node, as we don't control how
    /// they make outgoing connections to us. However, for the purpose of
    /// tracking connectivity and connection resets, we logically assume that
    /// as soon as this is called, the old connection is considered dropped.
    pub fn set_incoming_connection(&self, conn: &Arc<O>) {
        let version = self.incoming_version.fetch_add(1, Ordering::Relaxed) + 1;
        self.incoming_sender
            .send(ConnectionWithVersion {
                connection: Arc::downgrade(conn),
                version,
            })
            .unwrap(); // can't fail: we keep the receiver
    }

    /// The current ConnectionVersion.
    pub fn connection_version(&self) -> ConnectionVersion {
        let outgoing = self.outgoing_receiver.borrow();
        let incoming = self.incoming_receiver.borrow();

        ConnectionVersion {
            outgoing: outgoing.version(),
            incoming: incoming.version(),
        }
    }

    pub fn is_bidirectionally_connected(&self) -> bool {
        let outgoing = self.outgoing_receiver.borrow();
        let incoming = self.incoming_receiver.borrow();
        outgoing.is_connected() && incoming.is_connected()
    }

    /// Given the result of a previous call to `connection_version()`, determine
    /// if the network connection in either direction may have been interrupted
    /// since that call. If this returns false, then all messages sent in the
    /// meantime have been sent on the same connection.
    pub fn was_connection_interrupted(&self, version: ConnectionVersion) -> bool {
        let outgoing = self.outgoing_receiver.borrow();
        let incoming = self.incoming_receiver.borrow();
        outgoing.version() != version.outgoing || incoming.version() != version.incoming
    }

    /// Returns the current outgoing connection, without caring about what connection
    /// version it has. Returns None if there is no current connection.
    ///
    /// This is used for sending best-effort update messages.
    pub fn any_outgoing_connection(&self) -> Option<Arc<I>> {
        let current = self.outgoing_receiver.borrow();
        current.connection.upgrade()
    }

    /// Returns the outgoing connection, asserting that it is the expected version.
    /// The difference between this and wait_for_outgoing_connection is that this
    /// method assumes that the original connection (corresponding to the passed-in
    /// version) was already established.
    pub fn outgoing_connection_asserting(
        &self,
        expected: ConnectionVersion,
    ) -> anyhow::Result<Arc<I>> {
        let current = self.outgoing_receiver.borrow().clone();
        if current.version != expected.outgoing {
            anyhow::bail!(
                "Connection was reset (expected version {} but got {})",
                expected.outgoing,
                current.version
            );
        }
        let Some(conn) = current.connection.upgrade() else {
            anyhow::bail!("Connection was dropped");
        };
        Ok(conn)
    }
}

#[async_trait::async_trait]
pub trait NodeConnectivityInterface: Send + Sync + 'static {
    fn connection_version(&self) -> ConnectionVersion;
    fn was_connection_interrupted(&self, version: ConnectionVersion) -> bool;
    async fn wait_for_connection(&self, version: ConnectionVersion) -> anyhow::Result<()>;
    fn is_bidirectionally_connected(&self) -> bool;
}

#[async_trait::async_trait]
impl<I, O> NodeConnectivityInterface for NodeConnectivity<I, O>
where
    I: Send + Sync + 'static,
    O: Send + Sync + 'static,
{
    fn connection_version(&self) -> ConnectionVersion {
        NodeConnectivity::connection_version(self)
    }

    fn was_connection_interrupted(&self, version: ConnectionVersion) -> bool {
        NodeConnectivity::was_connection_interrupted(self, version)
    }

    async fn wait_for_connection(&self, version: ConnectionVersion) -> anyhow::Result<()> {
        let outgoing_receiver = {
            let outgoing = self.outgoing_receiver.borrow();
            if outgoing.version < version.outgoing {
                Some(self.outgoing_receiver.clone())
            } else {
                None
            }
        };
        let incoming_receiver = {
            let incoming = self.incoming_receiver.borrow();
            if incoming.version < version.incoming {
                Some(self.incoming_receiver.clone())
            } else {
                None
            }
        };
        if let Some(mut receiver) = outgoing_receiver {
            receiver
                .wait_for(|item| item.version >= version.outgoing)
                .await?;
        }
        if let Some(mut receiver) = incoming_receiver {
            receiver
                .wait_for(|item| item.version >= version.incoming)
                .await?;
        }
        Ok(())
    }

    fn is_bidirectionally_connected(&self) -> bool {
        NodeConnectivity::is_bidirectionally_connected(self)
    }
}

/// Convenient collection of multiple NodeConnectivity objects.
pub struct AllNodeConnectivities<I: Send + Sync + 'static, O: Send + Sync + 'static> {
    connectivities: HashMap<ParticipantId, Arc<NodeConnectivity<I, O>>>,
}

impl<I: Send + Sync + 'static, O: Send + Sync + 'static> AllNodeConnectivities<I, O> {
    pub fn new(my_participant_id: ParticipantId, all_participant_ids: &[ParticipantId]) -> Self {
        let mut connectivities = HashMap::new();
        for p in all_participant_ids {
            if *p == my_participant_id {
                continue;
            }
            connectivities.insert(*p, Arc::new(NodeConnectivity::new()));
        }
        Self { connectivities }
    }

    /// Waits for `threshold` number of connections (a freebie is included for the node itself)
    /// to be bidirectionally established at the same time.
    pub async fn wait_for_ready(&self, threshold: usize) {
        let mut receivers = self
            .connectivities
            .values()
            .map(|c| (c.outgoing_receiver.clone(), c.incoming_receiver.clone()))
            .collect::<Vec<_>>();
        loop {
            let mut connected_count = 0;
            for (outgoing_receiver, incoming_receiver) in &receivers {
                let outgoing = outgoing_receiver.borrow();
                let incoming = incoming_receiver.borrow();
                if outgoing.is_connected() && incoming.is_connected() {
                    connected_count += 1;
                }
            }
            if connected_count + 1 >= threshold {
                break;
            }

            let update_futs = receivers
                .iter_mut()
                .map(|(outgoing_receiver, incoming_receiver)| {
                    futures::future::select(
                        Box::pin(outgoing_receiver.changed()),
                        Box::pin(incoming_receiver.changed()),
                    )
                })
                .collect::<Vec<_>>();
            futures::future::select_all(update_futs).await;
        }
    }

    pub fn get(&self, p: ParticipantId) -> anyhow::Result<Arc<NodeConnectivity<I, O>>> {
        self.connectivities
            .get(&p)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("No such participant {}", p))
    }
}

#[cfg(test)]
mod tests {
    use crate::async_testing::{run_future_once, MaybeReady};
    use crate::network::conn::{AllNodeConnectivities, ConnectionVersion, NodeConnectivity};
    use crate::primitives::ParticipantId;
    use futures::FutureExt;
    use std::sync::Arc;

    #[test]
    fn test_connection_version() {
        use super::*;
        let conn = ConnectionWithVersion {
            connection: Weak::<()>::new(),
            version: 0,
        };
        assert_eq!(conn.version(), 1);
        assert!(!conn.is_connected());

        let arc = Arc::new(0);
        let conn = ConnectionWithVersion {
            connection: Arc::downgrade(&arc),
            version: 2,
        };
        assert_eq!(conn.version(), 2);
        assert!(conn.is_connected());
    }

    fn ver(outgoing: usize, incoming: usize) -> ConnectionVersion {
        ConnectionVersion { outgoing, incoming }
    }

    #[test]
    fn test_connectivity() {
        let connectivity = NodeConnectivity::<usize, usize>::new();
        assert_eq!(connectivity.connection_version(), ver(1, 1));
        assert!(!connectivity.is_bidirectionally_connected());
        assert!(!connectivity.was_connection_interrupted(ver(1, 1)));

        let conn = Arc::new(0);
        connectivity.set_outgoing_connection(&conn);
        assert_eq!(connectivity.connection_version(), ver(1, 1));
        assert!(!connectivity.is_bidirectionally_connected());
        assert!(!connectivity.was_connection_interrupted(ver(1, 1)));

        let conn2 = Arc::new(0);
        connectivity.set_incoming_connection(&conn2);
        assert_eq!(connectivity.connection_version(), ver(1, 1));
        assert!(connectivity.is_bidirectionally_connected());
        assert!(!connectivity.was_connection_interrupted(ver(1, 1)));

        drop(conn);
        assert_eq!(connectivity.connection_version(), ver(2, 1));
        assert!(!connectivity.is_bidirectionally_connected());
        assert!(connectivity.was_connection_interrupted(ver(1, 1)));
        assert!(!connectivity.was_connection_interrupted(ver(2, 1)));

        let conn3 = Arc::new(0);
        connectivity.set_incoming_connection(&conn3);
        assert_eq!(connectivity.connection_version(), ver(2, 2));
        assert!(!connectivity.is_bidirectionally_connected());
        assert!(connectivity.was_connection_interrupted(ver(2, 1)));
        assert!(!connectivity.was_connection_interrupted(ver(2, 2)));

        drop(conn2);
        assert_eq!(connectivity.connection_version(), ver(2, 2));

        let conn4 = Arc::new(0);
        connectivity.set_outgoing_connection(&conn4);
        assert_eq!(connectivity.connection_version(), ver(2, 2));
        assert!(connectivity.is_bidirectionally_connected());
        assert!(connectivity.was_connection_interrupted(ver(1, 2)));
        assert!(!connectivity.was_connection_interrupted(ver(2, 2)));
    }

    #[tokio::test]
    async fn test_wait_for_ready() {
        let id0 = ParticipantId::from_raw(1);
        let id1 = ParticipantId::from_raw(2);
        let id2 = ParticipantId::from_raw(3);
        let connectivity = AllNodeConnectivities::<usize, usize>::new(id1, &[id0, id1, id2]);

        let conn10 = Arc::new(0);
        let conn01 = Arc::new(0);

        connectivity
            .get(id0)
            .unwrap()
            .set_outgoing_connection(&conn10);
        connectivity
            .get(id0)
            .unwrap()
            .set_incoming_connection(&conn01);

        assert_eq!(connectivity.wait_for_ready(2).now_or_never(), Some(()));

        let fut = connectivity.wait_for_ready(3);
        let MaybeReady::Future(fut) = run_future_once(fut) else {
            panic!("wait_for_ready(3) should not be ready yet");
        };

        let conn12 = Arc::new(0);
        let conn21 = Arc::new(0);

        connectivity
            .get(id2)
            .unwrap()
            .set_outgoing_connection(&conn12);
        connectivity
            .get(id2)
            .unwrap()
            .set_incoming_connection(&conn21);

        assert_eq!(fut.now_or_never(), Some(()));
    }
}
