// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Status Research & Development GmbH

use std::{collections::HashSet, fs, time::Duration};

use anyhow::{Context, bail, ensure};
use futures::StreamExt;
use libp2p::{
    PeerId, noise,
    swarm::{ConnectionId, SwarmEvent},
    tcp, yamux,
};
use waggle::{
    behaviour::{Behaviour, Event},
    config::Config,
    shard::{Action, Error, Metadata, Shard},
};

const RUST: u8 = b'R';
const NIM: u8 = b'N';

fn topic(index: u8) -> Vec<u8> {
    vec![0, 255, index]
}

#[derive(Clone, Debug)]
struct TestMetadata(Vec<u8>);

impl Metadata for TestMetadata {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn update(&mut self, data: &[u8]) -> Result<bool, Error> {
        let changed = self.0 != data;
        self.0 = data.to_vec();
        Ok(changed)
    }
}

struct TestShard {
    id: Vec<u8>,
    metadata: Vec<u8>,
    pieces: Option<Vec<u8>>,
}

impl Shard for TestShard {
    fn object_id(&self) -> Vec<u8> {
        self.id.clone()
    }

    fn metadata(&self) -> Box<dyn Metadata> {
        Box::new(TestMetadata(self.metadata.clone()))
    }

    fn action_from_metadata(
        &self,
        _: PeerId,
        _: ConnectionId,
        _: Option<&[u8]>,
    ) -> Result<Action, Error> {
        Ok(Action {
            need: false,
            send: self.pieces.clone().map(|body| (body, self.metadata())),
        })
    }
}

fn fixture(index: u8, case: u8) -> TestShard {
    TestShard {
        id: vec![RUST, index, case],
        metadata: if case == 2 { vec![] } else { vec![0, 255, 1] },
        pieces: match case {
            0 => None,
            1 => Some((0..=255).collect()),
            2 => Some(vec![]),
            _ => unreachable!(),
        },
    }
}

async fn listen(address_file: &str, topics: &[u8]) -> anyhow::Result<libp2p::Swarm<Behaviour>> {
    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| Behaviour::new(Config::default()))?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    for &index in topics {
        ensure!(
            swarm.behaviour_mut().subscribe(topic(index)),
            "failed to subscribe to topic {index}"
        );
    }
    swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                let temporary = format!("{address_file}.tmp");
                fs::write(
                    &temporary,
                    format!("{address}/p2p/{}", swarm.local_peer_id()),
                )?;
                fs::rename(&temporary, address_file)?;
                return Ok(swarm);
            }
            SwarmEvent::ListenerError { error, .. } => bail!("listener error: {error}"),
            SwarmEvent::ListenerClosed {
                addresses, reason, ..
            } => {
                bail!("listener closed for {addresses:?}: {reason:?}")
            }
            event => eprintln!("waiting for listen address: {event:?}"),
        }
    }
}

async fn next_event(swarm: &mut libp2p::Swarm<Behaviour>) -> anyhow::Result<SwarmEvent<Event>> {
    match swarm.select_next_some().await {
        SwarmEvent::Behaviour(Event::InvalidData { reason, .. }) => bail!("invalid data: {reason}"),
        SwarmEvent::Behaviour(Event::FullQueue(peer)) => bail!("send queue full for {peer}"),
        event => Ok(event),
    }
}

async fn run(address_file: &str) -> anyhow::Result<()> {
    let mut swarm = listen(address_file, &[0, 1]).await?;
    let mut subscriptions = HashSet::new();
    let mut received = HashSet::new();
    let mut remote = None;
    loop {
        match next_event(&mut swarm).await? {
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic_id }) => {
                ensure!(
                    remote.is_none_or(|peer| peer == peer_id),
                    "unexpected subscriber"
                );
                remote = Some(peer_id);
                let index = *topic_id.last().context("empty topic")?;
                ensure!(
                    index < 2 && topic_id == topic(index),
                    "wrong subscription topic"
                );
                ensure!(subscriptions.insert(index), "duplicate subscription");
                for case in 0..3 {
                    swarm
                        .behaviour_mut()
                        .publish(topic_id.clone(), fixture(index, case))?;
                }
            }
            SwarmEvent::Behaviour(Event::Received {
                peer_id,
                topic_id,
                received: msg,
            }) => {
                ensure!(Some(peer_id) == remote, "unexpected sender");
                if msg.object_id == [NIM, 255] {
                    ensure!(received.len() == 6, "ack before all Nim messages");
                    ensure!(
                        topic_id == topic(0)
                            && msg.metadata.is_none()
                            && msg.pieces == Some(vec![1]),
                        "invalid final ack"
                    );
                    println!(
                        "Rust verified 6 Nim messages across 2 topics and the final acknowledgement"
                    );
                    return Ok(());
                }
                ensure!(
                    msg.object_id.len() == 3 && msg.object_id[0] == NIM,
                    "invalid object ID"
                );
                let (index, case) = (msg.object_id[1], msg.object_id[2]);
                ensure!(
                    index < 2 && case < 3 && topic_id == topic(index),
                    "wrong topic or case"
                );
                let expected = fixture(index, case);
                let metadata = if case == 1 {
                    None
                } else {
                    Some(expected.metadata)
                };
                ensure!(
                    msg.metadata == metadata && msg.pieces == expected.pieces,
                    "Nim message content mismatch"
                );
                ensure!(received.insert((index, case)), "duplicate Nim message");
                if received.len() == 6 {
                    swarm.behaviour_mut().publish(
                        topic(0),
                        TestShard {
                            id: vec![RUST, 255],
                            metadata: vec![],
                            pieces: Some(vec![1]),
                        },
                    )?;
                }
            }
            SwarmEvent::ConnectionClosed { cause, .. } => {
                bail!("connection closed before final ack: {cause:?}")
            }
            event => eprintln!("unhandled wire event: {event:?}"),
        }
    }
}

#[derive(Clone, Debug)]
struct BitMetadata(u8);

impl Metadata for BitMetadata {
    fn as_slice(&self) -> &[u8] {
        std::slice::from_ref(&self.0)
    }
    fn update(&mut self, data: &[u8]) -> Result<bool, Error> {
        if data.len() != 1 || data[0] > 7 {
            return Err(Error::InvalidFormat);
        }
        let next = self.0 | data[0];
        let changed = next != self.0;
        self.0 = next;
        Ok(changed)
    }
}

struct BitShard {
    id: Vec<u8>,
    have: u8,
}

impl Shard for BitShard {
    fn object_id(&self) -> Vec<u8> {
        self.id.clone()
    }
    fn metadata(&self) -> Box<dyn Metadata> {
        Box::new(BitMetadata(self.have))
    }
    fn action_from_metadata(
        &self,
        _: PeerId,
        _: ConnectionId,
        metadata: Option<&[u8]>,
    ) -> Result<Action, Error> {
        let remote = match metadata {
            None => 0,
            Some(data) if data.len() == 1 && data[0] <= 7 => data[0],
            _ => return Err(Error::InvalidFormat),
        };
        let missing = self.have & !remote;
        Ok(Action {
            need: remote & !self.have != 0,
            send: (missing != 0).then(|| {
                (
                    vec![missing],
                    Box::new(BitMetadata(remote | missing)) as Box<dyn Metadata>,
                )
            }),
        })
    }
}

async fn reconcile(address_file: &str) -> anyhow::Result<()> {
    let mut swarm = listen(address_file, &[1]).await?;
    let mut have = 2;
    let mut deliveries = 0;
    let mut remote = None;
    loop {
        match next_event(&mut swarm).await? {
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic_id }) => {
                ensure!(
                    remote.is_none() && topic_id == topic(1),
                    "unexpected subscription"
                );
                remote = Some(peer_id);
                swarm
                    .behaviour_mut()
                    .publish(topic(1), BitShard { id: vec![1], have })?;
            }
            SwarmEvent::Behaviour(Event::Received {
                peer_id,
                topic_id,
                received: msg,
            }) => {
                ensure!(
                    remote == Some(peer_id) && topic_id == topic(1),
                    "unexpected sender or topic"
                );
                if msg.object_id == [NIM, 255] {
                    ensure!(have == 3 && deliveries == 1, "incomplete reconstruction");
                    ensure!(
                        msg.metadata == Some(vec![3]) && msg.pieces == Some(vec![3]),
                        "invalid final ack"
                    );
                    println!(
                        "Rust reconciled complementary pieces with Nim; duplicate payload suppressed"
                    );
                    return Ok(());
                }
                ensure!(msg.object_id == [1], "invalid object ID");
                if let Some(body) = msg.pieces {
                    ensure!(body == [1], "expected only the missing piece");
                    deliveries += 1;
                    ensure!(deliveries == 1, "duplicate application delivery");
                    have |= body[0];
                    swarm
                        .behaviour_mut()
                        .publish(topic(1), BitShard { id: vec![1], have })?;
                    swarm.behaviour_mut().publish(
                        topic(1),
                        BitShard {
                            id: vec![RUST, 255],
                            have,
                        },
                    )?;
                }
            }
            SwarmEvent::ConnectionClosed { cause, .. } => bail!("early close: {cause:?}"),
            event => eprintln!("unhandled reconcile event: {event:?}"),
        }
    }
}

async fn topology(address_file: &str) -> anyhow::Result<()> {
    let mut swarm = listen(address_file, &[0, 1]).await?;
    let mut have = 2;
    let mut data_subscribers = HashSet::new();
    let mut control_subscribers = HashSet::new();
    let mut started = false;
    let mut ready = HashSet::new();
    let mut acknowledgements = HashSet::new();

    loop {
        match next_event(&mut swarm).await? {
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic_id }) => {
                ensure!(topic_id == topic(0) || topic_id == topic(1), "wrong topic");
                if topic_id == topic(0) {
                    control_subscribers.insert(peer_id);
                } else {
                    ensure!(data_subscribers.insert(peer_id), "duplicate subscription");
                    ensure!(data_subscribers.len() <= 2, "too many peers");
                }

                if !started && data_subscribers.len() == 2 && control_subscribers.len() == 2 {
                    started = true;
                    swarm
                        .behaviour_mut()
                        .publish(topic(1), BitShard { id: vec![1], have })?;
                    swarm.behaviour_mut().publish(
                        topic(0),
                        TestShard {
                            id: vec![RUST, 1],
                            metadata: vec![],
                            pieces: Some(vec![1]),
                        },
                    )?;
                }
            }
            SwarmEvent::Behaviour(Event::Unsubscribed { peer_id, topic_id }) => {
                if topic_id == topic(1) {
                    data_subscribers.remove(&peer_id);
                }
            }
            SwarmEvent::Behaviour(Event::Received {
                peer_id,
                topic_id,
                received: msg,
            }) => {
                if topic_id == topic(0) {
                    ensure!(
                        have == 7 && msg.pieces == Some(vec![7]),
                        "premature confirmation"
                    );
                    ensure!(
                        msg.object_id.len() >= 2
                            && msg.object_id[0] == NIM
                            && [1, 4].contains(&msg.object_id[1]),
                        "invalid control object"
                    );
                    if msg.object_id.len() == 2 {
                        ensure!(ready.insert(peer_id), "duplicate ready");
                        if ready.len() == 2 {
                            swarm.behaviour_mut().publish(
                                topic(0),
                                TestShard {
                                    id: vec![RUST, 255],
                                    metadata: vec![],
                                    pieces: Some(vec![7]),
                                },
                            )?;
                        }
                    } else {
                        ensure!(
                            msg.object_id.len() == 3 && msg.object_id[2] == 255 && ready.len() == 2,
                            "invalid final ack"
                        );
                        ensure!(acknowledgements.insert(peer_id), "duplicate ack");
                        if acknowledgements.len() == 2 {
                            println!(
                                "Rust relayed complementary pieces between two Nim peers; all three reconstructed 7"
                            );
                            return Ok(());
                        }
                    }
                } else {
                    ensure!(
                        topic_id == topic(1) && msg.object_id == [1],
                        "unexpected data"
                    );
                    if let Some(body) = msg.pieces {
                        ensure!(
                            body.len() == 1 && body[0] <= 7 && body[0] & !have != 0,
                            "duplicate or invalid pieces"
                        );
                        have |= body[0];
                        swarm
                            .behaviour_mut()
                            .publish(topic(1), BitShard { id: vec![1], have })?;
                    }
                }
            }
            SwarmEvent::ConnectionClosed { .. } => bail!("unexpected disconnect"),
            event => eprintln!("unhandled topology event: {event:?}"),
        }
    }
}

async fn lifecycle(address_file: &str) -> anyhow::Result<()> {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Phase {
        AwaitingSubscription,
        Initial,
        Resubscribed,
        Reconnected,
    }

    let mut swarm = listen(address_file, &[0, 1]).await?;
    let mut data_subscribers = HashSet::new();
    let mut phase = Phase::AwaitingSubscription;
    let mut unsubscribed = false;
    let mut closed = false;
    let mut identity = None;

    loop {
        match next_event(&mut swarm).await? {
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic_id }) => {
                ensure!(topic_id == topic(0) || topic_id == topic(1), "wrong topic");
                if topic_id == topic(1) {
                    ensure!(data_subscribers.insert(peer_id), "duplicate subscription");
                    ensure!(
                        identity.is_none_or(|id| id == peer_id),
                        "identity changed on reconnect"
                    );
                    identity = Some(peer_id);
                    phase = match phase {
                        Phase::AwaitingSubscription => Phase::Initial,
                        Phase::Initial => {
                            ensure!(unsubscribed, "resubscribed before close");
                            Phase::Resubscribed
                        }
                        Phase::Resubscribed => {
                            ensure!(closed, "expected a new connection");
                            Phase::Reconnected
                        }
                        Phase::Reconnected => bail!("too many subscriptions"),
                    };
                    swarm.behaviour_mut().publish(
                        topic(1),
                        TestShard {
                            id: vec![1],
                            metadata: vec![phase as u8],
                            pieces: Some(vec![phase as u8]),
                        },
                    )?;
                }
            }
            SwarmEvent::Behaviour(Event::Unsubscribed { peer_id, topic_id }) => {
                if topic_id == topic(1) {
                    ensure!(Some(peer_id) == identity, "unexpected unsubscribe sender");
                    data_subscribers.remove(&peer_id);
                    if phase == Phase::Initial {
                        ensure!(!unsubscribed, "duplicate unsubscribe");
                        unsubscribed = true;
                        swarm.behaviour_mut().publish(
                            topic(0),
                            TestShard {
                                id: vec![RUST, 0],
                                metadata: vec![],
                                pieces: Some(vec![1]),
                            },
                        )?;
                    }
                }
            }
            SwarmEvent::Behaviour(Event::Received {
                peer_id,
                topic_id,
                received: msg,
            }) => {
                ensure!(Some(peer_id) == identity, "unexpected sender");
                ensure!(topic_id == topic(0), "unexpected data");
                if msg.object_id == [NIM, 0] {
                    ensure!(
                        phase == Phase::Initial && msg.pieces == Some(vec![1]),
                        "invalid close probe"
                    );
                    // Probe only while the subscription closure is still unobserved.
                    if !unsubscribed {
                        swarm.behaviour_mut().publish(
                            topic(1),
                            TestShard {
                                id: vec![RUST, 0],
                                metadata: vec![],
                                pieces: Some(vec![]),
                            },
                        )?;
                    }
                    continue;
                }
                ensure!(
                    phase == Phase::Reconnected && closed && unsubscribed,
                    "lifecycle incomplete: sender={peer_id}, identity={identity:?}, phase={phase:?}, closed={closed}, unsubscribed={unsubscribed}"
                );
                ensure!(
                    msg.object_id == [NIM, 255] && msg.pieces == Some(vec![3]),
                    "invalid ack"
                );
                println!(
                    "Rust verified unsubscribe/resubscribe and reconnect with the same Nim identity"
                );
                return Ok(());
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                ensure!(
                    phase == Phase::Resubscribed && Some(peer_id) == identity && !closed,
                    "unexpected disconnect: peer={peer_id}, identity={identity:?}, phase={phase:?}, closed={closed}, unsubscribed={unsubscribed}, cause={cause:?}"
                );
                closed = true;
                data_subscribers.remove(&peer_id);
            }
            _ => {}
        }
    }
}

async fn pressure(address_file: &str) -> anyhow::Result<()> {
    let mut swarm = listen(address_file, &[0, 1]).await?;
    let mut data_subscribers = HashSet::new();
    let mut control_subscribers = HashSet::new();
    let mut started = false;
    let mut phase = 0u8;
    let mut remote = None;

    loop {
        match next_event(&mut swarm).await? {
            SwarmEvent::Behaviour(Event::Subscribed { peer_id, topic_id }) => {
                ensure!(
                    remote.is_none_or(|peer| peer == peer_id),
                    "unexpected subscriber"
                );
                remote = Some(peer_id);
                ensure!(topic_id == topic(0) || topic_id == topic(1), "wrong topic");
                if topic_id == topic(0) {
                    control_subscribers.insert(peer_id);
                } else {
                    ensure!(data_subscribers.insert(peer_id), "duplicate subscription");
                }

                if !started && data_subscribers.len() == 1 && control_subscribers.len() == 1 {
                    started = true;
                    swarm.behaviour_mut().publish(
                        topic(0),
                        TestShard {
                            id: vec![RUST, 0],
                            metadata: vec![],
                            pieces: Some(vec![0]),
                        },
                    )?;
                }
            }
            SwarmEvent::Behaviour(Event::Unsubscribed { peer_id, topic_id }) => {
                if topic_id == topic(1) {
                    data_subscribers.remove(&peer_id);
                }
            }
            SwarmEvent::Behaviour(Event::Received {
                peer_id,
                topic_id,
                received: msg,
            }) => {
                ensure!(Some(peer_id) == remote, "unexpected sender");
                if topic_id == topic(0) {
                    ensure!(
                        phase == 2 && msg.object_id == [NIM, 255] && msg.pieces == Some(vec![2]),
                        "invalid pressure ack"
                    );
                    println!(
                        "Rust verified both payloads after Nim queue saturation and unchanged-snapshot retry"
                    );
                    return Ok(());
                }

                ensure!(
                    started
                        && phase < 2
                        && topic_id == topic(1)
                        && msg.object_id == [phase + 1]
                        && msg.metadata == Some(vec![1])
                        && msg.pieces == Some(vec![1]),
                    "invalid pressure payload or duplicate"
                );
                phase += 1;
                swarm.behaviour_mut().publish(
                    topic(0),
                    TestShard {
                        id: vec![RUST, phase],
                        metadata: vec![],
                        pieces: Some(vec![phase]),
                    },
                )?;
            }
            SwarmEvent::ConnectionClosed { .. } => bail!("unexpected disconnect"),
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: waggle-interop-peer <address-file>")?;
    let mode = std::env::args().nth(2);
    let scenario = async {
        match mode.as_deref() {
            None => run(&path).await,
            Some("reconcile") => reconcile(&path).await,
            Some("topology") => topology(&path).await,
            Some("lifecycle") => lifecycle(&path).await,
            Some("pressure") => pressure(&path).await,
            Some(scenario) => bail!("unknown scenario: {scenario}"),
        }
    };
    tokio::time::timeout(Duration::from_secs(60), scenario)
        .await
        .context("Waggle scenario did not complete within 60 seconds")??;
    Ok(())
}
