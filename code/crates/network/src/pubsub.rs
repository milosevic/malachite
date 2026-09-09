// Quint Studio oracle: value rendering for the instrumentation below.
#[allow(unused_imports)]
use quint_oracle::ToLogged as _;

use bytes::Bytes;
use libp2p::swarm;

use crate::behaviour::Behaviour;
use crate::{Channel, ChannelNames, PeerIdExt, PubSubProtocol};

pub fn subscribe(
    swarm: &mut swarm::Swarm<Behaviour>,
    protocol: PubSubProtocol,
    channels: &[Channel],
    channel_names: &ChannelNames,
) -> Result<(), eyre::Report> {
    let quint_node = if quint_oracle::enabled() {
        crate::quint_ids::node(swarm.local_peer_id())
    } else {
        String::new()
    };

    match protocol {
        PubSubProtocol::GossipSub => {
            if let Some(gossipsub) = swarm.behaviour_mut().gossipsub.as_mut() {
                for channel in channels {
                    gossipsub.subscribe(&channel.to_gossipsub_topic(channel_names))?;
                }
            } else {
    if quint_oracle::enabled() {
        let node = quint_node.as_str();
        let logged: std::collections::BTreeSet<String> =
            channels.iter().map(|c| format!("{c:?}")).collect();
        quint_oracle::Event::builder(quint_oracle::current_test(), "pubsubsubscribe")
            .argument("node", node, Some("NODES"))
            .argument(
                "protocol",
                match protocol {
                    PubSubProtocol::GossipSub => "GossipSub",
                    PubSubProtocol::Broadcast => "Broadcast",
                },
                None,
            )
            .argument("channels", logged, Some("CHANNEL_SETS"))
        .argument("outcome", "rejected", None)
            .scope("p2p-network")
            .send();
    }
                return Err(eyre::eyre!("GossipSub not enabled"));
            }
        }
        PubSubProtocol::Broadcast => {
            if let Some(broadcast) = swarm.behaviour_mut().broadcast.as_mut() {
                for channel in channels {
                    broadcast.subscribe(channel.to_broadcast_topic(channel_names));
                }
            } else {
    if quint_oracle::enabled() {
        let node = quint_node.as_str();
        let logged: std::collections::BTreeSet<String> =
            channels.iter().map(|c| format!("{c:?}")).collect();
        quint_oracle::Event::builder(quint_oracle::current_test(), "pubsubsubscribe")
            .argument("node", node, Some("NODES"))
            .argument(
                "protocol",
                match protocol {
                    PubSubProtocol::GossipSub => "GossipSub",
                    PubSubProtocol::Broadcast => "Broadcast",
                },
                None,
            )
            .argument("channels", logged, Some("CHANNEL_SETS"))
        .argument("outcome", "rejected", None)
            .scope("p2p-network")
            .send();
    }
                return Err(eyre::eyre!("Broadcast not enabled"));
            }
        }
    }

    if quint_oracle::enabled() {
        let node = quint_node.as_str();
        let logged: std::collections::BTreeSet<String> =
            channels.iter().map(|c| format!("{c:?}")).collect();
        quint_oracle::Event::builder(quint_oracle::current_test(), "pubsubsubscribe")
            .argument("node", node, Some("NODES"))
            .argument(
                "protocol",
                match protocol {
                    PubSubProtocol::GossipSub => "GossipSub",
                    PubSubProtocol::Broadcast => "Broadcast",
                },
                None,
            )
            .argument("channels", logged, Some("CHANNEL_SETS"))
            .scope("p2p-network")
            .send();
    }

    Ok(())
}

pub fn publish(
    swarm: &mut swarm::Swarm<Behaviour>,
    protocol: PubSubProtocol,
    channel: Channel,
    channel_names: &ChannelNames,
    data: Bytes,
) -> Result<(), eyre::Report> {
    let data_size = data.len();

    let quint_node = if quint_oracle::enabled() {
        crate::quint_ids::node(swarm.local_peer_id())
    } else {
        String::new()
    };

    match protocol {
        PubSubProtocol::GossipSub => {
            if let Some(gossipsub) = swarm.behaviour_mut().gossipsub.as_mut() {
                if let Err(e) = gossipsub.publish(channel.to_gossipsub_topic(channel_names), data) {
                    if quint_oracle::enabled() {
        let node = quint_node.as_str();
        quint_oracle::Event::builder(quint_oracle::current_test(), "pubsubpublish")
            .argument("node", node, Some("NODES"))
            .argument(
                "protocol",
                match protocol {
                    PubSubProtocol::GossipSub => "GossipSub",
                    PubSubProtocol::Broadcast => "Broadcast",
                },
                None,
            )
            .argument("channel", format!("{channel:?}"), Some("CHANNELS"))
            .argument("data_size", data_size as i64, Some("DATA_SIZES"))
            .argument("outcome", "rejected", None)
            .scope("p2p-network")
            .send();
    }
                    return Err(e.into());
                }
            } else {
                if quint_oracle::enabled() {
        let node = quint_node.as_str();
        quint_oracle::Event::builder(quint_oracle::current_test(), "pubsubpublish")
            .argument("node", node, Some("NODES"))
            .argument(
                "protocol",
                match protocol {
                    PubSubProtocol::GossipSub => "GossipSub",
                    PubSubProtocol::Broadcast => "Broadcast",
                },
                None,
            )
            .argument("channel", format!("{channel:?}"), Some("CHANNELS"))
            .argument("data_size", data_size as i64, Some("DATA_SIZES"))
            .argument("outcome", "rejected", None)
            .scope("p2p-network")
            .send();
    }
                return Err(eyre::eyre!("GossipSub not enabled"));
            }
        }
        PubSubProtocol::Broadcast => {
            if let Some(broadcast) = swarm.behaviour_mut().broadcast.as_mut() {
                broadcast.broadcast(&channel.to_broadcast_topic(channel_names), data);
            } else {
                if quint_oracle::enabled() {
        let node = quint_node.as_str();
        quint_oracle::Event::builder(quint_oracle::current_test(), "pubsubpublish")
            .argument("node", node, Some("NODES"))
            .argument(
                "protocol",
                match protocol {
                    PubSubProtocol::GossipSub => "GossipSub",
                    PubSubProtocol::Broadcast => "Broadcast",
                },
                None,
            )
            .argument("channel", format!("{channel:?}"), Some("CHANNELS"))
            .argument("data_size", data_size as i64, Some("DATA_SIZES"))
            .argument("outcome", "rejected", None)
            .scope("p2p-network")
            .send();
    }
                return Err(eyre::eyre!("Broadcast not enabled"));
            }
        }
    }

    if quint_oracle::enabled() {
        let node = quint_node.as_str();
        quint_oracle::Event::builder(quint_oracle::current_test(), "pubsubpublish")
            .argument("node", node, Some("NODES"))
            .argument(
                "protocol",
                match protocol {
                    PubSubProtocol::GossipSub => "GossipSub",
                    PubSubProtocol::Broadcast => "Broadcast",
                },
                None,
            )
            .argument("channel", format!("{channel:?}"), Some("CHANNELS"))
            .argument("data_size", data_size as i64, Some("DATA_SIZES"))
            .scope("p2p-network")
            .send();
    }

    Ok(())
}

/// Get the mesh peers for a specific channel
pub fn get_mesh_peers(
    swarm: &swarm::Swarm<Behaviour>,
    channel: Channel,
    channel_names: &ChannelNames,
) -> Vec<crate::PeerId> {
    if let Some(gossipsub) = swarm.behaviour().gossipsub.as_ref() {
        let topic = channel.to_gossipsub_topic(channel_names);
        let topic_hash = topic.hash();
        gossipsub
            .mesh_peers(&topic_hash)
            .map(crate::PeerId::from_libp2p)
            .collect()
    } else {
        Vec::new()
    }
}
