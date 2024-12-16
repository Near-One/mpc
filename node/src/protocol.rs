use crate::primitives::{BatchedMessages, ParticipantId};
use crate::tracking;
use crate::{network::NetworkTaskChannel, tracking::TaskHandle};
use cait_sith::protocol::{Action, Protocol};
use futures::TryFutureExt;
use std::collections::{BTreeMap, HashMap};
use std::sync::{atomic::AtomicUsize, Arc};
use tokio::sync::mpsc;

/// Runs any cait-sith protocol, returning the result. Exports tracking progress
/// describing how many messages are sent and received to each participant.
pub async fn run_protocol<T>(
    name: &'static str,
    mut channel: NetworkTaskChannel,
    me: ParticipantId,
    mut protocol: impl Protocol<Output = T>,
) -> anyhow::Result<T> {
    let counters = Arc::new(MessageCounters::new(
        name.to_string(),
        &channel.participants,
    ));
    let mut queue_senders: HashMap<ParticipantId, mpsc::UnboundedSender<BatchedMessages>> =
        HashMap::new();
    let mut queue_receivers: HashMap<ParticipantId, mpsc::UnboundedReceiver<BatchedMessages>> =
        HashMap::new();

    for p in &channel.participants {
        let (send, recv) = mpsc::unbounded_channel();
        queue_senders.insert(*p, send);
        queue_receivers.insert(*p, recv);
    }

    // We split the protocol into two tasks: one dedicated to sending messages, and one dedicated
    // to computation and receiving messages. There are two reasons for this:
    //  - If we just used a loop to poke the protocol, and send messages whenever the protocol asks
    //    us to, then we can run into a situation where the protocol is asking us to send 1000
    //    messages to participant 1, but because of bandwidth limitations, the sending blocks on
    //    waiting for enough outgoing buffer to hold the messages. Even though the protocol, at this
    //    moment, may have more messages to send to other participants, we don't get a chance to
    //    send any of that until we've sent all 1000 messages to participant 1. This is very
    //    inefficient, so instead we put messages into queues, indexed by the recipient, and have
    //    a parallel task for each recipient that sends the messages.
    //  - We need the sending task to be a separate spawn from the computation task because while
    //    we're computing, we would not be able to cooperatively run any other tasks, and that can
    //    unnecessarily block sending. It is OK to have the receiving side blocked by computation,
    //    because on the receiving side, the network channel already provides us with a buffer
    //    dedicated to our task.
    let sending_handle = {
        let counters = counters.clone();
        let sender = channel.sender();
        let participants = channel.participants.clone();
        tracking::spawn_checked("send messages", async move {
            // One future for each recipient. For the same recipient it is OK to send messages
            // serially, but for multiple recipients we want them to not block each other.
            // These futures are IO-bound, so we don't have to spawn them separately.
            let futures = queue_receivers
                .into_iter()
                .map(move |(participant_id, mut receiver)| {
                    let sender = sender.clone();
                    let counters = counters.clone();
                    let participants = participants.clone();
                    async move {
                        while let Some(messages) = receiver.recv().await {
                            let num_messages = messages.len();
                            sender(participant_id, messages, participants.clone()).await?;
                            counters.sent(participant_id, num_messages);
                        }
                        anyhow::Ok(())
                    }
                });
            futures::future::try_join_all(futures).await?;
            anyhow::Ok(())
        })
        .map_err(anyhow::Error::from)
    };

    let participants = channel.participants.clone();
    let computation_handle = async move {
        loop {
            let mut messages_to_send: HashMap<ParticipantId, _> = HashMap::new();
            let done = loop {
                match protocol.poke()? {
                    Action::Wait => break None,
                    Action::SendMany(vec) => {
                        for participant in &participants {
                            if participant == &me {
                                continue;
                            }
                            messages_to_send
                                .entry(*participant)
                                .or_insert(Vec::new())
                                .push(vec.clone());
                        }
                    }
                    Action::SendPrivate(participant, vec) => {
                        messages_to_send
                            .entry(From::from(participant))
                            .or_insert(Vec::new())
                            .push(vec.clone());
                    }
                    Action::Return(result) => {
                        // Warning: we cannot return immediately!! There may be some important
                        // messages to send to others to enable others to complete their computation.
                        break Some(result);
                    }
                }
            };

            // Batch-send the messages. This is a useful optimization as cait-sith tends to ask us
            // to send many messages at once to the same recipient.
            // TODO(#21): maybe we can fix the cait-sith protocol to not ask us to send so many
            // messages in the first place.
            for (p, messages) in messages_to_send.into_iter() {
                if messages.is_empty() {
                    continue;
                }
                counters.queue_send(p, messages.len());
                // There's a chance this sending can fail, because the sending task can return early
                // if the connection to some other participant is broken. In that case, the
                // computation task should also just fail.
                queue_senders.get(&p).unwrap().send(messages)?;
            }

            if let Some(result) = done {
                return anyhow::Ok(result);
            }

            counters.set_receiving();

            let msg = channel.receive().await?;
            counters.received(msg.from, msg.message.data.len());

            for one_msg in msg.message.data {
                protocol.message(msg.from.into(), one_msg);
            }
        }
    };
    let (computation_result, _) = futures::try_join!(computation_handle, sending_handle)?;
    Ok(computation_result)
}

/// Debugging counters to be used to export progress for tracking::set_progress, while
/// the computation is happening.
struct MessageCounters {
    name: String,
    task: Arc<TaskHandle>,
    counters: BTreeMap<ParticipantId, PerParticipantCounters>,
    current_action: AtomicUsize, // 1 = receiving, 0 = computing
}

struct PerParticipantCounters {
    sent: AtomicUsize,
    in_flight: AtomicUsize,
    received: AtomicUsize,
}

impl MessageCounters {
    pub fn new(name: String, participants: &[ParticipantId]) -> Self {
        Self {
            name,
            task: tracking::current_task(),
            counters: participants
                .iter()
                .map(|p| {
                    (
                        *p,
                        PerParticipantCounters {
                            sent: AtomicUsize::new(0),
                            in_flight: AtomicUsize::new(0),
                            received: AtomicUsize::new(0),
                        },
                    )
                })
                .collect(),
            current_action: AtomicUsize::new(0),
        }
    }

    pub fn queue_send(&self, participant: ParticipantId, num_messages: usize) {
        self.counters
            .get(&participant)
            .unwrap()
            .in_flight
            .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    pub fn sent(&self, participant: ParticipantId, num_messages: usize) {
        let counters = self.counters.get(&participant).unwrap();
        counters
            .sent
            .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        counters
            .in_flight
            .fetch_sub(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    pub fn received(&self, participant: ParticipantId, num_messages: usize) {
        self.counters
            .get(&participant)
            .unwrap()
            .received
            .fetch_add(num_messages, std::sync::atomic::Ordering::Relaxed);
        self.current_action
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn set_receiving(&self) {
        self.current_action
            .store(1, std::sync::atomic::Ordering::Relaxed);
        self.report_progress();
    }

    fn report_progress(&self) {
        self.task.set_progress(&format!(
            "{}: parties: {:?}, sent {:?} (inflight [{:?}]), received [{:?}] ({})",
            self.name,
            self.counters.keys().collect::<Vec<_>>(),
            self.counters
                .values()
                .map(|c| c.sent.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.counters
                .values()
                .map(|c| c.in_flight.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            self.counters
                .values()
                .map(|c| c.received.load(std::sync::atomic::Ordering::Relaxed))
                .collect::<Vec<_>>(),
            if self
                .current_action
                .load(std::sync::atomic::Ordering::Relaxed)
                == 1
            {
                "receiving"
            } else {
                "computing"
            },
        ));
    }
}
