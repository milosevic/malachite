//! Utility functions for spawning the actor system and connecting it to the application.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use eyre::{eyre, Result};
use tokio::task::JoinHandle;
use tracing::Span;

use malachitebft_engine::consensus::{Consensus, ConsensusCodec, ConsensusParams, ConsensusRef};
use malachitebft_engine::host::HostRef;
use malachitebft_engine::network::{Network, NetworkRef};
use malachitebft_engine::node::{Node, NodeRef};
use malachitebft_engine::sync::{Params as SyncParams, Sync, SyncCodec, SyncMsg, SyncRef};
use malachitebft_engine::util::events::TxEvent;
use malachitebft_engine::util::output_port::OutputPort;
use malachitebft_engine::wal::{Wal, WalCodec, WalRef};
use malachitebft_network::{
    ChannelNames, Config as NetworkConfig, DiscoveryConfig, GossipSubConfig, NetworkIdentity,
};
use malachitebft_signing::{Signer, Verifier};
use malachitebft_sync as sync;

use crate::config::{ConsensusConfig, ValueSyncConfig};
use crate::metrics::{Metrics, SharedRegistry};
use crate::types::core::{ConsensusProtocol, Context};
use crate::types::ValuePayload;

/// Whether this node can run the protocol the operator selected.
///
/// `ConsensusParams::classic` is still the only constructor, because the consensus actor
/// drives the classic round state machine and vote keeper; the fast driver exists
/// (`core-driver/src/fast/`) but is not wired into that actor yet. So `fast` is a
/// configuration the node understands and **refuses**, rather than one it silently
/// downgrades to classic — a node that quietly ran the wrong protocol would disagree with
/// its peers at the first quorum, and the operator would be left diagnosing a stalled
/// network instead of reading a configuration error.
///
/// Depends only on the configuration file, so callers should run it **before spawning any
/// actor**: there is no reason to open a WAL or a network listener for a node that cannot
/// start. [`spawn_consensus_actor`] calls it too, for embedders that bypass the builder.
///
/// TODO: two things must land in the same change that removes this refusal.
///
/// 1. The protocol is a per-node field for a property that is network-wide and fixed at
///    genesis — nothing here cross-validates it against the rest of the validator set.
/// 2. Fast proposals must be routed through the same membership check the classic path
///    uses (`core-consensus/src/handle/proposal.rs`, `validator_set.get_by_address`)
///    before they reach the driver. The fast driver's `FreshProposals` store, like the
///    classic `ProposalKeeper`, is bounded only because something upstream rejects
///    non-members first; handing it raw gossip would make it grow without limit.
pub fn check_consensus_protocol(cfg: &ConsensusConfig) -> Result<()> {
    match cfg.protocol {
        ConsensusProtocol::Classic => Ok(()),
        ConsensusProtocol::Fast => Err(fast_is_not_wired_in()),
    }
}

/// The consensus parameters for the protocol the operator selected.
///
/// **This is where the guarantee lives**, not in [`check_consensus_protocol`]. The match
/// is exhaustive over [`ConsensusProtocol`] and only the `Classic` arm can produce a
/// `Params`, so there is no way to build consensus parameters without having answered the
/// protocol question — deleting the refusal stops the crate compiling rather than silently
/// starting a classic node under `protocol = "fast"`.
///
/// [`check_consensus_protocol`] answers the same question earlier, before any actor is
/// spawned. That call is a fail-fast convenience; this one cannot be skipped.
fn consensus_params_for<Ctx>(
    cfg: &ConsensusConfig,
    address: Ctx::Address,
    value_payload: ValuePayload,
) -> Result<ConsensusParams<Ctx>>
where
    Ctx: Context,
{
    match cfg.protocol {
        ConsensusProtocol::Classic => {
            Ok(ConsensusParams::classic(address, value_payload, cfg.enabled))
        }
        ConsensusProtocol::Fast => Err(fast_is_not_wired_in()),
    }
}

/// One message for both refusals, so they cannot drift apart.
fn fast_is_not_wired_in() -> eyre::Report {
    eyre!(
        "consensus.protocol = \"fast\" is not yet supported by this node: the Fast \
         Tendermint driver is implemented but not wired into the consensus actor. \
         Set consensus.protocol = \"classic\" (the default) to start."
    )
}

/// Spawn the [`Node`] supervisor.
///
/// Spawned **first**, before any children, so its [`NodeRef`] can be threaded
/// into actors that signal safety-critical failures (the WAL worker thread and
/// the Consensus actor). Children link to it after they are spawned.
pub async fn spawn_node_actor(metrics: Metrics) -> Result<(NodeRef, JoinHandle<()>)> {
    let node = Node::new(metrics, tracing::Span::current());
    let (actor_ref, handle) = node.spawn().await?;
    Ok((actor_ref, handle))
}

pub async fn spawn_network_actor<Ctx, Codec>(
    consensus_cfg: &ConsensusConfig,
    value_sync_cfg: &ValueSyncConfig,
    identity: NetworkIdentity,
    registry: &SharedRegistry,
    codec: Codec,
) -> Result<NetworkRef<Ctx>>
where
    Ctx: Context,
    Codec: ConsensusCodec<Ctx>,
    Codec: SyncCodec<Ctx>,
{
    consensus_cfg
        .p2p
        .channel_names
        .validate()
        .map_err(|e| eyre!("Invalid P2P channel names: {e}"))?;

    let config = make_network_config(consensus_cfg, value_sync_cfg);

    Network::spawn(identity, config, registry.clone(), codec, Span::current())
        .await
        .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub async fn spawn_consensus_actor<Ctx>(
    ctx: Ctx,
    address: Ctx::Address,
    cfg: ConsensusConfig,
    verifier: Box<dyn Verifier<Ctx>>,
    signer: Option<Box<dyn Signer<Ctx>>>,
    network: NetworkRef<Ctx>,
    host: HostRef<Ctx>,
    wal: WalRef<Ctx>,
    sync: Arc<OutputPort<SyncMsg<Ctx>>>,
    metrics: Metrics,
    tx_event: TxEvent<Ctx>,
    node: NodeRef,
) -> Result<ConsensusRef<Ctx>>
where
    Ctx: Context,
{
    use crate::config;

    let value_payload = match cfg.value_payload {
        config::ValuePayload::ProposalOnly => ValuePayload::ProposalOnly,
        config::ValuePayload::ProposalAndParts => ValuePayload::ProposalAndParts,
    };

    // Honour the operator's protocol selection. `ConsensusParams::classic` is still the
    // only constructor, because the consensus actor drives the classic round state machine
    // and vote keeper; the fast driver exists (`core-driver/src/fast/`) but is not wired
    // into this actor yet. So `fast` is a configuration the node understands and refuses,
    // rather than one it silently downgrades to classic — a node that quietly ran the
    // wrong protocol would disagree with its peers at the first quorum, and the operator
    // would see a stalled network rather than a configuration error.
    let consensus_params = consensus_params_for::<Ctx>(&cfg, address, value_payload)?;

    Consensus::spawn(
        ctx,
        consensus_params,
        cfg,
        verifier,
        signer,
        network,
        host,
        wal,
        sync,
        metrics,
        tx_event,
        node,
        Span::current(),
    )
    .await
    .map_err(Into::into)
}

pub async fn spawn_wal_actor<Ctx, Codec>(
    ctx: &Ctx,
    codec: Codec,
    path: &Path,
    registry: &SharedRegistry,
    node: NodeRef,
) -> Result<WalRef<Ctx>>
where
    Ctx: Context,
    Codec: WalCodec<Ctx>,
{
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
    }

    Wal::spawn(
        ctx,
        codec,
        path.to_owned(),
        registry.clone(),
        Span::current(),
        node,
    )
    .await
    .map_err(Into::into)
}

pub async fn spawn_sync_actor<Ctx, Codec>(
    ctx: Ctx,
    network: NetworkRef<Ctx>,
    host: HostRef<Ctx>,
    consensus: ConsensusRef<Ctx>,
    sync_codec: Codec,
    config: &ValueSyncConfig,
    registry: &SharedRegistry,
) -> Result<Option<SyncRef<Ctx>>>
where
    Ctx: Context,
    Codec: SyncCodec<Ctx>,
{
    if !config.enabled {
        return Ok(None);
    }

    if config.enabled && config.batch_size == 0 {
        return Err(eyre!("Value sync batch size cannot be zero"));
    }

    let params = SyncParams {
        status_update_interval: config.status_update_interval,
        request_timeout: config.request_timeout,
    };

    let scoring_strategy = match config.scoring_strategy {
        malachitebft_config::ScoringStrategy::Ema => sync::scoring::Strategy::Ema,
    };

    let sync_config = sync::Config {
        enabled: config.enabled,
        max_request_size: config.max_request_size.as_u64() as usize,
        max_response_size: config.max_response_size.as_u64() as usize,
        request_timeout: config.request_timeout,
        parallel_requests: config.parallel_requests,
        scoring_strategy,
        inactive_threshold: (!config.inactive_threshold.is_zero())
            .then_some(config.inactive_threshold),
        batch_size: config.batch_size,
    };

    let metrics = sync::Metrics::register(registry, params.status_update_interval);

    let actor_ref = Sync::spawn(
        ctx,
        network,
        host,
        consensus,
        params,
        sync_codec,
        sync_config,
        metrics,
        Span::current(),
    )
    .await?;

    Ok(Some(actor_ref))
}

fn make_network_config(cfg: &ConsensusConfig, value_sync_cfg: &ValueSyncConfig) -> NetworkConfig {
    use malachitebft_config as config;
    use malachitebft_network as network;

    NetworkConfig {
        listen_addr: cfg.p2p.listen_addr.clone(),
        persistent_peers: cfg.p2p.persistent_peers.clone(),
        persistent_peers_only: cfg.p2p.persistent_peers_only,
        discovery: DiscoveryConfig {
            enabled: cfg.p2p.discovery.enabled,
            persistent_peers_only: cfg.p2p.persistent_peers_only,
            bootstrap_protocol: match cfg.p2p.discovery.bootstrap_protocol {
                config::BootstrapProtocol::Kademlia => network::BootstrapProtocol::Kademlia,
                config::BootstrapProtocol::Full => network::BootstrapProtocol::Full,
            },
            selector: match cfg.p2p.discovery.selector {
                config::Selector::Kademlia => network::Selector::Kademlia,
                config::Selector::Random => network::Selector::Random,
            },
            num_outbound_peers: cfg.p2p.discovery.num_outbound_peers,
            num_inbound_peers: cfg.p2p.discovery.num_inbound_peers,
            max_connections_per_ip: cfg.p2p.discovery.max_connections_per_ip,
            ip_throttle_duration: cfg.p2p.discovery.ip_throttle_duration,
            max_connections_per_peer: cfg.p2p.discovery.max_connections_per_peer,
            ephemeral_connection_timeout: cfg.p2p.discovery.ephemeral_connection_timeout,
            dial_max_retries: cfg.p2p.discovery.dial_max_retries,
            request_max_retries: cfg.p2p.discovery.request_max_retries,
            connect_request_max_retries: cfg.p2p.discovery.connect_request_max_retries,
            max_peers_per_response: cfg.p2p.discovery.max_peers_per_response,
        },
        idle_connection_timeout: Duration::from_secs(15 * 60),
        transport: network::TransportProtocol::from_multiaddr(&cfg.p2p.listen_addr).unwrap_or_else(
            || {
                panic!(
                    "No valid transport protocol found in listen address: {}",
                    cfg.p2p.listen_addr
                )
            },
        ),
        pubsub_protocol: match cfg.p2p.protocol {
            config::PubSubProtocol::GossipSub(_) => network::PubSubProtocol::GossipSub,
            config::PubSubProtocol::Broadcast => network::PubSubProtocol::Broadcast,
        },
        gossipsub: match cfg.p2p.protocol {
            config::PubSubProtocol::GossipSub(config) => GossipSubConfig {
                mesh_n: config.mesh_n(),
                mesh_n_high: config.mesh_n_high(),
                mesh_n_low: config.mesh_n_low(),
                mesh_outbound_min: config.mesh_outbound_min(),
                enable_peer_scoring: config.enable_peer_scoring(),
                enable_explicit_peering: config.enable_explicit_peering(),
                enable_flood_publish: config.enable_flood_publish(),
            },
            config::PubSubProtocol::Broadcast => GossipSubConfig::default(),
        },
        channel_names: ChannelNames {
            consensus: cfg.p2p.channel_names.consensus.clone(),
            proposal_parts: cfg.p2p.channel_names.proposal_parts.clone(),
            sync: cfg.p2p.channel_names.sync.clone(),
            liveness: cfg.p2p.channel_names.liveness.clone(),
        },
        rpc_max_size: cfg.p2p.rpc_max_size.as_u64() as usize,
        pubsub_max_size: cfg.p2p.pubsub_max_size.as_u64() as usize,
        enable_consensus: cfg.enabled,
        enable_sync: value_sync_cfg.enabled,
        protocol_names: network::ProtocolNames {
            consensus: cfg.p2p.protocol_names.consensus.clone(),
            discovery_kad: cfg.p2p.protocol_names.discovery_kad.clone(),
            discovery_regres: cfg.p2p.protocol_names.discovery_regres.clone(),
            sync: cfg.p2p.protocol_names.sync.clone(),
            validator_proof: cfg.p2p.protocol_names.validator_proof.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConsensusConfig;
    use malachitebft_config::DiscoveryConfig as SerdeDiscoveryConfig;
    use malachitebft_network::DiscoveryConfig as RuntimeDiscoveryConfig;

    /// The classic path must keep starting exactly as it did before the field existed.
    #[test]
    fn the_default_protocol_is_accepted() {
        assert!(check_consensus_protocol(&ConsensusConfig::default()).is_ok());
    }

    /// The whole "no silent downgrade" guarantee is this one refusal, so it is pinned
    /// rather than left to the match arm.
    #[test]
    fn the_fast_protocol_is_refused_rather_than_downgraded() {
        let cfg = ConsensusConfig {
            protocol: ConsensusProtocol::Fast,
            ..ConsensusConfig::default()
        };
        let err = check_consensus_protocol(&cfg)
            .expect_err("fast must not be accepted while the driver is unwired");
        let msg = err.to_string();
        assert!(msg.contains("not yet supported"), "got {msg}");
        assert!(msg.contains("classic"), "the error must name the value that works: {msg}");
    }

    /// The refusal that cannot be bypassed: `spawn_consensus_actor` has no other way to
    /// obtain a `Params`, so this arm is what actually prevents a classic node starting
    /// under `protocol = "fast"`. `check_consensus_protocol` only answers it earlier.
    #[test]
    fn consensus_params_cannot_be_built_for_an_unsupported_protocol() {
        use malachitebft_test::{Address, TestContext};

        let addr = Address::new([0; 20]);
        let classic = ConsensusConfig::default();
        assert!(
            consensus_params_for::<TestContext>(&classic, addr, ValuePayload::ProposalOnly).is_ok(),
            "classic must still build its params"
        );

        let fast = ConsensusConfig {
            protocol: ConsensusProtocol::Fast,
            ..ConsensusConfig::default()
        };
        let err = consensus_params_for::<TestContext>(&fast, addr, ValuePayload::ProposalOnly)
            .map(|_| ())
            .expect_err("fast must not yield params while the driver is unwired");
        assert!(err.to_string().contains("not yet supported"), "got {err}");
    }

    /// The serde-deserialized default in `malachitebft-config` and the runtime
    /// default in `malachitebft-discovery` are defined independently. Pin them
    /// so a change in one without the other is caught immediately.
    #[test]
    fn ip_throttle_duration_default_matches_across_crates() {
        assert_eq!(
            RuntimeDiscoveryConfig::default().ip_throttle_duration,
            SerdeDiscoveryConfig::default().ip_throttle_duration,
        );
    }
}
