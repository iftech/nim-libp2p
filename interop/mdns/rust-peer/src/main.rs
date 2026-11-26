// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) Status Research & Development GmbH

use futures::StreamExt;
use libp2p::{
    SwarmBuilder, identify, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
    tcp, yamux,
};
use std::{collections::HashMap, error::Error, time::Duration};

#[derive(NetworkBehaviour)]
struct Behaviour {
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            Ok::<_, Box<dyn Error + Send + Sync>>(Behaviour {
                mdns: mdns::tokio::Behaviour::new(
                    mdns::Config {
                        query_interval: Duration::from_secs(5),
                        ..Default::default()
                    },
                    key.public().to_peer_id(),
                )?,
                identify: identify::Behaviour::new(identify::Config::new(
                    "/ipfs/0.1.0".into(),
                    key.public(),
                )),
            })
        })?
        .with_swarm_config(|config| config.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    eprintln!("Rust mDNS peer {}", swarm.local_peer_id());
    tokio::time::timeout(Duration::from_secs(70), async {
        let mut unidentified_dials = HashMap::new();
        let mut nim_peer = None;
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                    for (peer_id, address) in peers {
                        eprintln!("Discovered {peer_id} at {address}");
                        if nim_peer.is_none() {
                            let opts = DialOpts::from(address.clone());
                            let connection_id = opts.connection_id();
                            match swarm.dial(opts) {
                                Ok(()) => {
                                    unidentified_dials.insert(connection_id, (peer_id, address));
                                }
                                Err(error) => {
                                    eprintln!("Failed to dial {peer_id} at {address}: {error:#}");
                                }
                            }
                        }
                    }
                }
                SwarmEvent::OutgoingConnectionError {
                    connection_id,
                    peer_id,
                    error,
                } => {
                    if let Some((peer_id, address)) = unidentified_dials.remove(&connection_id) {
                        eprintln!("Failed to connect to {peer_id} at {address}: {error:#}");
                    } else {
                        eprintln!("Outgoing connection {connection_id} to {peer_id:?} failed: {error}");
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                    connection_id,
                    peer_id,
                    info,
                    ..
                })) => {
                    let discovered = unidentified_dials.remove(&connection_id).is_some();
                    if discovered && nim_peer.is_none() && info.agent_version == "nim-libp2p" {
                        eprintln!("Discovered Nim peer {peer_id}");
                        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
                        nim_peer = Some(peer_id);
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => eprintln!("Listening on {address}"),
                SwarmEvent::ConnectionClosed {
                    connection_id,
                    peer_id,
                    num_established,
                    cause,
                    ..
                } => {
                    let dial = unidentified_dials.remove(&connection_id);
                    if Some(peer_id) == nim_peer {
                        if let Some(error) = cause {
                            eprintln!("Connection to Nim peer {peer_id} closed: {error}");
                        }
                        if num_established == 0 {
                            // CI uses Nim's exit status to verify discovery in the other direction.
                            return Ok::<(), anyhow::Error>(());
                        }
                    } else if let Some((_, address)) = dial {
                        let reason = cause.map_or_else(
                            || "no error reported".into(),
                            |error| error.to_string(),
                        );
                        anyhow::bail!("Connection to {peer_id} at {address} closed before Identify completed: {reason}");
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("mDNS interop peer timed out"))?
}
