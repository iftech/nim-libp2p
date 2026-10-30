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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("usage: waggle-interop-peer <address-file>")?;
    let mode = std::env::args().nth(2);
    let scenario = async {
        match mode.as_deref() {
            None => run(&path).await,

            Some(scenario) => bail!("unknown scenario: {scenario}"),
        }
    };
    tokio::time::timeout(Duration::from_secs(60), scenario)
        .await
        .context("Waggle scenario did not complete within 60 seconds")??;
    Ok(())
}
