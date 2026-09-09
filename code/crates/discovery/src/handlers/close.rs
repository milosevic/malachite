use libp2p::{swarm::ConnectionId, PeerId, Swarm};
use tracing::{debug, warn};

use crate::{Discovery, DiscoveryClient, State};

impl<C> Discovery<C>
where
    C: DiscoveryClient,
{
    pub fn can_close(&mut self) -> bool {
        self.state == State::Idle && self.controller.close.can_perform()
    }

    fn should_close(&self, peer_id: PeerId, connection_id: ConnectionId) -> bool {
        // Only close ephemeral connections (i.e not inbound/outbound connections)
        // NOTE: a inbound or outbound connection can still be closed if it is not
        // part of the active connections to the peer. This is possible due to the
        // limit of the number of connections per peer.
        (!self.outbound_peers.contains_key(&peer_id) && !self.inbound_peers.contains(&peer_id))
            || self
                .active_connections
                .get(&peer_id)
                .is_none_or(|connection_ids| !connection_ids.contains(&connection_id))
    }

    pub fn close_connection(
        &mut self,
        swarm: &mut Swarm<C>,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) {
        if !self.should_close(peer_id, connection_id) {
            crate::oracle::close_connection(&peer_id, &connection_id, true);
            return;
        }

        crate::oracle::close_connection(&peer_id, &connection_id, false);

        debug!("Closing connection {connection_id} to peer {peer_id}");
        // Close the connection even if it is not active
        swarm.close_connection(connection_id);
    }

    pub fn handle_closed_connection(
        &mut self,
        swarm: &mut Swarm<C>,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) {
        // Logged on entry: the handler has no guard, and the cleanup below emits
        // the nested rate-limiter / dial-history events that must follow it.
        crate::oracle::handle_closed_connection(&peer_id, &connection_id);

        let was_last_connection = !swarm.is_connected(&peer_id);

        self.connections.remove(&connection_id);

        let remove_active_peer =
            if let Some(connection_ids) = self.active_connections.get_mut(&peer_id) {
                if connection_ids.contains(&connection_id) {
                    warn!("Removing active connection {connection_id} to peer {peer_id}");
                    connection_ids.retain(|id| id != &connection_id);
                } else {
                    warn!("Non-established connection {connection_id} to peer {peer_id} closed");
                }

                connection_ids.is_empty()
            } else {
                false
            };

        if remove_active_peer {
            self.active_connections.remove(&peer_id);
        }

        // In case the connection was closed before identifying the peer
        self.controller.dial.remove_in_progress(&connection_id);

        if self.outbound_peers.contains_key(&peer_id) {
            warn!("Outbound connection {connection_id} to peer {peer_id} closed");

            if was_last_connection {
                warn!("Last connection to peer {peer_id} closed, removing from outbound peers");

                self.outbound_peers.remove(&peer_id);
            }

            if self.is_enabled() {
                self.repair_outbound_peers(swarm);
            }
        } else if self.inbound_peers.contains(&peer_id) {
            warn!("Inbound connection {connection_id} to peer {peer_id} closed");

            if was_last_connection {
                warn!("Last connection to peer {peer_id} closed, removing from inbound peers");

                self.inbound_peers.remove(&peer_id);
            }
        }

        // Clean up discovered peers when all connections are closed
        if was_last_connection {
            self.cleanup_peer_on_disconnect(peer_id);
        }

        self.update_discovery_metrics();
    }

    /// Clean up peer state and dial history when the last connection to a peer is closed
    fn cleanup_peer_on_disconnect(&mut self, peer_id: PeerId) {
        let peer_info = self.discovered_peers.remove(&peer_id);

        // Remove signed peer record (no longer connected, record may be stale)
        self.signed_peer_records.remove(&peer_id);

        // Clear rate limiter state for this peer
        self.rate_limiter.remove_peer(&peer_id);

        // Clear connect_request done_on to allow re-upgrading the peer on reconnection
        self.controller.connect_request.remove_done_on(&peer_id);

        // Find and reset the bootstrap node peer_id to allow re-identification
        // This handles the case where a bootstrap node restarts with a different peer_id
        for bootstrap_node in self.bootstrap_nodes.iter_mut() {
            if bootstrap_node.0 == Some(peer_id) {
                warn!(
                    "Resetting bootstrap node peer_id {} to allow re-identification",
                    peer_id
                );
                bootstrap_node.0 = None; // Reset to None so it can be re-identified
                self.controller
                    .dial_clear_done_for_peer(peer_id, &bootstrap_node.1);
                return;
            }
        }

        // Handle non-bootstrap peers when discovery is disabled
        if !self.is_enabled() {
            let addrs = peer_info.map(|info| info.listen_addrs).unwrap_or_default();
            self.controller.dial_clear_done_for_peer(peer_id, &addrs);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use libp2p::core::ConnectedPoint;
    use libp2p::futures::StreamExt;
    use libp2p::kad::{Addresses, KBucketKey, KBucketRef, RoutingUpdate};
    use libp2p::request_response::{OutboundRequestId, ResponseChannel};
    use libp2p::swarm::{dummy, ConnectionId, SwarmEvent};
    use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};
    use malachitebft_metrics::Registry;

    use crate::{
        config::Config, ConnectionDirection, ConnectionInfo, Discovery, DiscoveryClient, Request,
        Response,
    };

    impl DiscoveryClient for dummy::Behaviour {
        fn add_address(&mut self, _peer: &PeerId, _address: Multiaddr) -> RoutingUpdate {
            unreachable!()
        }

        fn kbuckets(
            &mut self,
        ) -> impl Iterator<Item = KBucketRef<'_, KBucketKey<PeerId>, Addresses>> {
            std::iter::empty()
        }

        fn send_request(&mut self, _peer_id: &PeerId, _req: Request) -> OutboundRequestId {
            unreachable!()
        }

        fn send_response(
            &mut self,
            _ch: ResponseChannel<Response>,
            _rs: Response,
        ) -> Result<(), Response> {
            unreachable!()
        }
    }

    fn build_swarm() -> Swarm<dummy::Behaviour> {
        SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("tcp transport")
            .with_behaviour(|_| dummy::Behaviour)
            .expect("dummy behaviour")
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build()
    }

    async fn wait_listen_addr(swarm: &mut Swarm<dummy::Behaviour>) -> Multiaddr {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                return address;
            }
        }
    }

    #[tokio::test]
    async fn closing_identified_connection_keeps_peer_state_while_another_connection_remains() {
        let mut local_swarm = build_swarm();
        let mut remote_swarm = build_swarm();
        let remote_peer_id = *remote_swarm.local_peer_id();

        remote_swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let remote_addr = wait_listen_addr(&mut remote_swarm).await;
        local_swarm.dial(remote_addr.clone()).unwrap();

        let remaining_connection_id = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = local_swarm.select_next_some() => {
                        if let SwarmEvent::ConnectionEstablished { peer_id, connection_id, .. } = event {
                            assert_eq!(peer_id, remote_peer_id);
                            break connection_id;
                        }
                    }
                    _ = remote_swarm.select_next_some() => {}
                }
            }
        })
        .await
        .expect("timed out waiting for connection");

        let bootstrap_addr: Multiaddr = "/ip4/127.0.0.1/tcp/26000".parse().unwrap();
        let mut registry = Registry::default();
        let mut discovery = Discovery::<dummy::Behaviour>::new(
            Config::new(false),
            vec![bootstrap_addr.clone()],
            &mut registry,
        );
        discovery.bootstrap_nodes[0].0 = Some(remote_peer_id);

        let closed_connection_id = ConnectionId::new_unchecked(usize::MAX);
        discovery
            .active_connections
            .insert(remote_peer_id, vec![closed_connection_id]);
        discovery.connections.insert(
            closed_connection_id,
            ConnectionInfo {
                direction: ConnectionDirection::Outbound,
                remote_addr: bootstrap_addr.clone(),
            },
        );
        discovery.connections.insert(
            remaining_connection_id,
            ConnectionInfo {
                direction: ConnectionDirection::Outbound,
                remote_addr,
            },
        );

        discovery.handle_closed_connection(&mut local_swarm, remote_peer_id, closed_connection_id);

        assert_eq!(
            discovery.get_peer_id_for_addr(&bootstrap_addr),
            Some(remote_peer_id)
        );
        assert!(!discovery.connections.contains_key(&closed_connection_id));
        assert!(discovery.connections.contains_key(&remaining_connection_id));
        assert!(!discovery.active_connections.contains_key(&remote_peer_id));

        assert!(local_swarm.close_connection(remaining_connection_id));
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = local_swarm.select_next_some() => {
                        if matches!(event, SwarmEvent::ConnectionClosed { connection_id, .. } if connection_id == remaining_connection_id) {
                            break;
                        }
                    }
                    _ = remote_swarm.select_next_some() => {}
                }
            }
        })
        .await
        .expect("timed out waiting for connection to close");

        discovery.handle_closed_connection(
            &mut local_swarm,
            remote_peer_id,
            remaining_connection_id,
        );

        assert_eq!(discovery.get_peer_id_for_addr(&bootstrap_addr), None);
        assert!(!discovery.connections.contains_key(&remaining_connection_id));
    }

    /// reproduces the violated property `rate_limit_admits_at_most_max_per_window`
    /// — fails on current code.
    ///
    /// The limiter's stated guarantee is at most `max_requests_per_window`
    /// peers requests served per peer per `rate_window` (6 per 60s by default,
    /// `DiscoveryRateLimiter::default`). But `remove_peer` clears the peer's
    /// request window while deliberately keeping its violations
    /// (rate_limiter.rs:198-206), and `cleanup_peer_on_disconnect` calls it on
    /// every last-connection close. So a peer that exhausts its budget, drops
    /// the connection and immediately reconnects gets a fresh budget inside the
    /// same 60-second window.
    ///
    /// Everything here runs under default production settings. The requests are
    /// counted through `DiscoveryRateLimiter::check_request`, exactly the call
    /// `check_rate_limit` makes (handlers/peers_request.rs:38) — the handler
    /// itself needs a `ResponseChannel` only the swarm can mint — while the
    /// window reset is driven through the real public entry point the swarm
    /// calls on `SwarmEvent::ConnectionClosed`.
    #[tokio::test]
    #[ignore]
    async fn rate_limit_window_survives_a_peer_reconnect() {
        let mut swarm = build_swarm();
        let mut registry = Registry::default();
        let bootstrap_addr: Multiaddr = "/ip4/127.0.0.1/tcp/26000".parse().unwrap();
        let mut discovery = Discovery::<dummy::Behaviour>::new(
            Config::default(),
            vec![bootstrap_addr],
            &mut registry,
        );

        let peer_id = PeerId::random();
        let peer_addr: Multiaddr = "/ip4/203.0.113.9/tcp/41337".parse().unwrap();
        let max_per_window = discovery.rate_limiter.max_requests_per_window();

        // The peer connects inbound.
        let first_connection = ConnectionId::new_unchecked(1);
        discovery.handle_connection(
            &mut swarm,
            peer_id,
            first_connection,
            ConnectedPoint::Listener {
                local_addr: "/ip4/10.0.0.1/tcp/26656".parse().unwrap(),
                send_back_addr: peer_addr.clone(),
            },
        );

        // It spends its whole budget and is then rate limited.
        let mut served = 0;
        while discovery.rate_limiter.check_request(&peer_id).is_allowed() {
            served += 1;
            assert!(served <= max_per_window, "budget exceeded before the reconnect");
        }
        assert_eq!(served, max_per_window);

        // It drops the connection: the swarm reports it closed, which is where
        // discovery cleans up the peer's rate limiter state.
        discovery.handle_closed_connection(&mut swarm, peer_id, first_connection);

        // It reconnects at once and keeps asking, still well inside the window.
        let second_connection = ConnectionId::new_unchecked(2);
        discovery.handle_connection(
            &mut swarm,
            peer_id,
            second_connection,
            ConnectedPoint::Listener {
                local_addr: "/ip4/10.0.0.1/tcp/26656".parse().unwrap(),
                send_back_addr: peer_addr,
            },
        );

        while discovery.rate_limiter.check_request(&peer_id).is_allowed() {
            served += 1;
            if served > max_per_window * 4 {
                break;
            }
        }

        assert!(
            served <= max_per_window,
            "{served} peers requests were served to {peer_id} within one {:?} window, \
             but the limiter promises at most {max_per_window}: reconnecting clears \
             the request window",
            discovery.rate_limiter.rate_window()
        );
    }
}
