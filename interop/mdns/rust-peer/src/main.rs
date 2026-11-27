// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) Status Research & Development GmbH

use futures::StreamExt;
use libp2p::{
    PeerId, Swarm, SwarmBuilder, identify, mdns, noise,
    swarm::{ConnectionError, ConnectionId, NetworkBehaviour, SwarmEvent, dial_opts::DialOpts},
    tcp, yamux,
};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    io,
    time::Duration,
};

#[derive(NetworkBehaviour)]
struct Behaviour {
    mdns: mdns::tokio::Behaviour,
    identify: identify::Behaviour,
}

fn dial_discovered_peer(
    swarm: &mut Swarm<Behaviour>,
    peer_id: PeerId,
    dialed_peers: &mut HashSet<PeerId>,
    unidentified_dials: &mut HashMap<ConnectionId, PeerId>,
) {
    if dialed_peers.contains(&peer_id) {
        return;
    }
    eprintln!("Dialing mDNS peer {peer_id}");
    // The mDNS behaviour supplies the peer's cached addresses.
    let opts = DialOpts::peer_id(peer_id).build();
    let connection_id = opts.connection_id();
    match swarm.dial(opts) {
        Ok(()) => {
            dialed_peers.insert(peer_id);
            unidentified_dials.insert(connection_id, peer_id);
        }
        Err(error) => eprintln!("Failed to dial {peer_id}: {error:#}"),
    }
}

fn check_connection_close(error: ConnectionError) -> Result<(), ConnectionError> {
    let ConnectionError::IO(error) = error else {
        return Err(error);
    };
    let error = match error.downcast::<yamux::Error>() {
        Ok(error) => io::Error::from(error),
        Err(error) => return Err(ConnectionError::IO(error)),
    };
    // Yamux reports remote GOAWAY and EOF as Closed.
    match error.get_ref().and_then(|source| source.downcast_ref()) {
        Some(yamux_wire::ConnectionError::Closed) => Ok(()),
        _ => Err(ConnectionError::IO(error)),
    }
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
        let mut dialed_peers = HashSet::new();
        let mut nim_peer = None;
        let mut retry = tokio::time::interval(Duration::from_secs(5));
        loop {
            let event = tokio::select! {
                event = swarm.select_next_some() => event,
                _ = retry.tick(), if nim_peer.is_none() => {
                    // Cache refreshes do not necessarily emit another Discovered event.
                    let candidates: HashSet<_> =
                        swarm.behaviour().mdns.discovered_nodes().copied().collect();
                    for peer_id in candidates {
                        dial_discovered_peer(
                            &mut swarm,
                            peer_id,
                            &mut dialed_peers,
                            &mut unidentified_dials,
                        );
                    }
                    continue;
                }
            };
            match event {
                SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Discovered(peers)))
                    if nim_peer.is_none() =>
                {
                    for (peer_id, _) in peers {
                        dial_discovered_peer(
                            &mut swarm,
                            peer_id,
                            &mut dialed_peers,
                            &mut unidentified_dials,
                        );
                    }
                }
                SwarmEvent::OutgoingConnectionError {
                    connection_id,
                    peer_id,
                    error,
                } => {
                    let dial = unidentified_dials.remove(&connection_id);
                    if let Some(peer_id) = dial {
                        dialed_peers.remove(&peer_id);
                    }
                    let peer_id = dial.or(peer_id);
                    eprintln!("Outgoing connection {connection_id} to {peer_id:?} failed: {error:#}");
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
                            check_connection_close(error).map_err(|error| {
                                anyhow::anyhow!("Connection to Nim peer {peer_id} closed: {error}")
                            })?;
                        }
                        if num_established == 0 {
                            // CI uses Nim's exit status to verify discovery in the other direction.
                            return Ok::<(), anyhow::Error>(());
                        }
                    } else if let Some(peer_id) = dial {
                        dialed_peers.remove(&peer_id);
                        let reason = cause.map_or_else(
                            || "no error reported".into(),
                            |error| error.to_string(),
                        );
                        eprintln!("Connection to {peer_id} closed before Identify completed: {reason}");
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("mDNS interop peer timed out"))?
}
