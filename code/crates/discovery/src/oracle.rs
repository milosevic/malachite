//! Quint Studio oracle instrumentation for the `peer-discovery` component.
//!
//! Every helper here is a no-op unless the crate is built with the
//! `quint-oracle-enabled` feature, which is off by default — a production build
//! compiles neither the oracle client nor any of this module's bodies.
//!
//! The Quint model (`quint-specs/peer-discovery.qnt`) works over small integer
//! peer ids and address ids, so the live `PeerId`/`Multiaddr` values are
//! projected onto per-test indices: peers become 1, 2, 3… and addresses 10, 20,
//! 30… in first-seen order. The registries are thread-local, which is also the
//! per-test scope (the Rust test harness gives each test its own thread).

#[cfg(feature = "quint-oracle-enabled")]
mod imp {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::time::Duration;

    use libp2p::{Multiaddr, PeerId};

    use crate::dial::DialData;

    const SCOPE: &str = "peer-discovery";

    thread_local! {
        static PEER_IX: RefCell<HashMap<PeerId, i64>> = RefCell::new(HashMap::new());
        static ADDR_IX: RefCell<HashMap<Multiaddr, i64>> = RefCell::new(HashMap::new());
        static LAST_EVENT: RefCell<Option<std::time::Instant>> = const { RefCell::new(None) };
        static CONN_IX: RefCell<HashMap<libp2p::swarm::ConnectionId, i64>> =
            RefCell::new(HashMap::new());
        static REQ_IX: RefCell<HashMap<String, i64>> = RefCell::new(HashMap::new());
    }

    /// The rate limiter's decisions depend on elapsed wall-clock time, which the
    /// model tracks as a logical clock in millisecond units. Emit one
    /// `clock_tick` whenever at least a millisecond passed since the previous
    /// logged event, so replay sees the same window/expiry boundaries the code
    /// crossed. Must be called before the event it precedes.
    fn tick(now: std::time::Instant) {
        let elapsed_ms = LAST_EVENT.with(|last| {
            let previous = last.borrow_mut().replace(now);
            previous.map(|previous| now.duration_since(previous).as_millis())
        });

        if elapsed_ms.is_some_and(|ms| ms >= 1) {
            quint_oracle::Event::builder(quint_oracle::current_test(), "clock_tick")
                .argument("amount", 1_i64, None)
                .scope(SCOPE)
                .send();
        }
    }

    /// The model's peer id for this `PeerId`: 1, 2, 3… in first-seen order.
    pub fn peer_ix(peer: &PeerId) -> i64 {
        PEER_IX.with(|m| {
            let mut m = m.borrow_mut();
            let next = m.len() as i64 + 1;
            *m.entry(*peer).or_insert(next)
        })
    }

    /// The model's address id for this `Multiaddr`: 10, 20, 30… in first-seen order.
    pub fn addr_ix(addr: &Multiaddr) -> i64 {
        ADDR_IX.with(|m| {
            let mut m = m.borrow_mut();
            let next = (m.len() as i64 + 1) * 10;
            *m.entry(addr.clone()).or_insert(next)
        })
    }

    fn dial_data_value(dial_data: &DialData) -> quint_oracle::Value {
        let addrs: std::collections::BTreeSet<quint_oracle::Value> = dial_data
            .listen_addrs()
            .iter()
            .map(|addr| quint_oracle::ToLogged::to_logged(&addr_ix(addr)))
            .collect();

        quint_oracle::record([
            (
                "peer_id",
                quint_oracle::ToLogged::to_logged(
                    // 0 is the model's NO_PEER
                    &dial_data.peer_id().map(|p| peer_ix(&p)).unwrap_or(0),
                ),
            ),
            ("listen_addrs", quint_oracle::ToLogged::to_logged(&addrs)),
            (
                "retry",
                quint_oracle::ToLogged::to_logged(&(dial_data.retry.count() as i64)),
            ),
            (
                "is_bootstrap",
                quint_oracle::ToLogged::to_logged(&dial_data.is_bootstrap()),
            ),
        ])
    }

    /// `DiscoveryRateLimiter::new`
    pub fn rate_limiter_new(
        rate_window: Duration,
        max_requests_per_window: u32,
        max_violations: u32,
        violation_expiry: Duration,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "DiscoveryRateLimiternew")
            .argument("max_requests", max_requests_per_window as i64, None)
            .argument("max_violations", max_violations as i64, None)
            .argument("rate_window", rate_window.as_millis().max(1) as i64, None)
            .argument(
                "violation_expiry",
                violation_expiry.as_millis().max(1) as i64,
                None,
            )
            .scope(SCOPE)
            .send();
    }

    /// `DiscoveryRateLimiter::check_request` — the incoming peers request the
    /// model handles in `handle_peers_request`.
    pub fn check_request(peer: &PeerId) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "check_request")
            .argument("peer", peer_ix(peer), None)
            .scope(SCOPE)
            .send();
    }

    /// `DiscoveryRateLimiter::remove_peer`
    pub fn rate_limiter_remove_peer(peer: &PeerId) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(
            quint_oracle::current_test(),
            "DiscoveryRateLimiterremove_peer",
        )
        .argument("peer_id", peer_ix(peer), None)
        .scope(SCOPE)
        .send();
    }

    /// `Controller::dial_register_done_on`
    pub fn dial_register_done_on(dial_data: &DialData, register_addrs: bool) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(
            quint_oracle::current_test(),
            "Controllerdial_register_done_on",
        )
        .argument("dial_data", dial_data_value(dial_data), None)
        .argument("register_addrs", register_addrs, None)
        .scope(SCOPE)
        .send();
    }

    /// `Controller::dial_clear_done_for_peer`
    pub fn dial_clear_done_for_peer(peer: &PeerId, listen_addrs: &[Multiaddr]) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        let addrs: std::collections::BTreeSet<quint_oracle::Value> = listen_addrs
            .iter()
            .map(|addr| quint_oracle::ToLogged::to_logged(&addr_ix(addr)))
            .collect();

        quint_oracle::Event::builder(
            quint_oracle::current_test(),
            "Controllerdial_clear_done_for_peer",
        )
        .argument("peer_id", peer_ix(peer), None)
        .argument("addrs", addrs, None)
        .scope(SCOPE)
        .send();
    }

    /// The model's connection id for this `ConnectionId`: 1, 2, 3… in first-seen order.
    pub fn conn_ix(conn: &libp2p::swarm::ConnectionId) -> i64 {
        CONN_IX.with(|m| {
            let mut m = m.borrow_mut();
            let next = m.len() as i64 + 1;
            *m.entry(*conn).or_insert(next)
        })
    }

    /// The model's request id for this outbound request: 1, 2, 3… in first-seen order.
    pub fn req_ix(request_id: &libp2p::request_response::OutboundRequestId) -> i64 {
        REQ_IX.with(|m| {
            let mut m = m.borrow_mut();
            let key = format!("{request_id:?}");
            let next = m.len() as i64 + 1;
            *m.entry(key).or_insert(next)
        })
    }

    fn addr_set(addrs: impl IntoIterator<Item = Multiaddr>) -> std::collections::BTreeSet<quint_oracle::Value> {
        addrs
            .into_iter()
            .map(|addr| quint_oracle::ToLogged::to_logged(&addr_ix(&addr)))
            .collect()
    }

    /// `Action::add_to_queue` on the DIAL queue — the model's `Actionadd_to_queue`
    /// (controller.rs:45-63). Logged at the dial-specific call sites only.
    pub fn dial_add_to_queue(dial_data: &DialData, delay: Option<Duration>) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "Actionadd_to_queue")
            .argument("value", dial_data_value(dial_data), None)
            .argument(
                "delay",
                delay.map(|d| d.as_millis() as i64).unwrap_or(0),
                None,
            )
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::dial_peer` (handlers/dial.rs:39-86). `connection_id` is `None`
    /// on the branches that drop the queue entry without dialing; `rejected`
    /// tags the `should_dial` guard rejection.
    pub fn dial_peer(connection_id: Option<&libp2p::swarm::ConnectionId>, rejected: bool) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        let cid = connection_id.map(conn_ix).unwrap_or(0);
        let mut event = quint_oracle::Event::builder(quint_oracle::current_test(), "dial_peer")
            .argument("connection_id", cid, Some("CONNS"));
        if rejected {
            event = event.argument("outcome", "rejected", None);
        }
        event.scope(SCOPE).send();
    }

    /// `Discovery::handle_connection` (handlers/dial.rs:88-152)
    pub fn handle_connection(peer: &PeerId, conn: &libp2p::swarm::ConnectionId, inbound: bool) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_connection")
            .argument("peer_id", peer_ix(peer), Some("PEERS"))
            .argument("connection_id", conn_ix(conn), Some("CONNS"))
            .argument("inbound", inbound, None)
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::handle_failed_connection` (handlers/dial.rs:154-222)
    pub fn handle_failed_connection(conn: &libp2p::swarm::ConnectionId, fatal: bool) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_failed_connection")
            .argument("connection_id", conn_ix(conn), Some("CONNS"))
            .argument("fatal", fatal, None)
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::handle_new_peer` (handlers/identify.rs:125-305). `rejected`
    /// tags the identify-interval and persistent-peers-only early returns, which
    /// the model guards rather than models.
    pub fn handle_new_peer(
        conn: &libp2p::swarm::ConnectionId,
        listen_addrs: &[Multiaddr],
        rejected: bool,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        let mut event = quint_oracle::Event::builder(quint_oracle::current_test(), "handle_new_peer")
            .argument("connection_id", conn_ix(conn), Some("CONNS"))
            .argument(
                "listen_addrs",
                addr_set(listen_addrs.iter().cloned()),
                Some("ADDRS"),
            );
        if rejected {
            event = event.argument("outcome", "rejected", None);
        }
        event.scope(SCOPE).send();
    }

    /// `Discovery::close_connection` (handlers/close.rs:26-39)
    pub fn close_connection(
        peer: &PeerId,
        conn: &libp2p::swarm::ConnectionId,
        rejected: bool,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        let mut event =
            quint_oracle::Event::builder(quint_oracle::current_test(), "close_connection")
                .argument("peer_id", peer_ix(peer), Some("PEERS"))
                .argument("connection_id", conn_ix(conn), Some("CONNS"));
        if rejected {
            event = event.argument("outcome", "rejected", None);
        }
        event.scope(SCOPE).send();
    }

    /// `Discovery::handle_closed_connection` (handlers/close.rs:41-99). Logged on
    /// entry: the handler has no guard, and its own cleanup emits the nested
    /// `remove_peer` / `dial_clear_done_for_peer` events which must follow it.
    pub fn handle_closed_connection(peer: &PeerId, conn: &libp2p::swarm::ConnectionId) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_closed_connection")
            .argument("peer_id", peer_ix(peer), Some("PEERS"))
            .argument("connection_id", conn_ix(conn), Some("CONNS"))
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::peers_request_peer` (handlers/peers_request.rs:74-102)
    pub fn peers_request_peer(
        request_id: Option<&libp2p::request_response::OutboundRequestId>,
        rejected: bool,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        let mut event =
            quint_oracle::Event::builder(quint_oracle::current_test(), "peers_request_peer")
                .argument(
                    "request_id",
                    request_id.map(req_ix).unwrap_or(0),
                    Some("REQ_IDS"),
                );
        if rejected {
            event = event.argument("outcome", "rejected", None);
        }
        event.scope(SCOPE).send();
    }

    /// `Discovery::handle_peers_response` (handlers/peers_request.rs:167-181) —
    /// the outer handler only clears the in-progress request; each verified
    /// record is dialed through `add_to_dial_queue`, which logs its own
    /// register + queue events.
    pub fn handle_peers_response(request_id: &libp2p::request_response::OutboundRequestId) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_peers_response")
            .argument("request_id", req_ix(request_id), Some("REQ_IDS"))
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::handle_failed_peers_request` (handlers/peers_request.rs:183-212)
    pub fn handle_failed_peers_request(
        request_id: &libp2p::request_response::OutboundRequestId,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_failed_peers_request")
            .argument("request_id", req_ix(request_id), Some("REQ_IDS"))
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::connect_request_peer` (handlers/connect_request.rs:30-57)
    pub fn connect_request_peer(
        request_id: Option<&libp2p::request_response::OutboundRequestId>,
        rejected: bool,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        let mut event =
            quint_oracle::Event::builder(quint_oracle::current_test(), "connect_request_peer")
                .argument(
                    "request_id",
                    request_id.map(req_ix).unwrap_or(0),
                    Some("REQ_IDS"),
                );
        if rejected {
            event = event.argument("outcome", "rejected", None);
        }
        event.scope(SCOPE).send();
    }

    /// `Discovery::handle_connect_request` (handlers/connect_request.rs:59-97)
    pub fn handle_connect_request(peer: &PeerId) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_connect_request")
            .argument("peer", peer_ix(peer), Some("PEERS"))
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::handle_connect_response` (handlers/connect_request.rs:99-135)
    pub fn handle_connect_response(
        request_id: &libp2p::request_response::OutboundRequestId,
        accepted: bool,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_connect_response")
            .argument("request_id", req_ix(request_id), Some("REQ_IDS"))
            .argument("accepted", accepted, None)
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::handle_failed_connect_request` (handlers/connect_request.rs:145-175)
    pub fn handle_failed_connect_request(
        request_id: &libp2p::request_response::OutboundRequestId,
    ) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(
            quint_oracle::current_test(),
            "handle_failed_connect_request",
        )
        .argument("request_id", req_ix(request_id), Some("REQ_IDS"))
        .scope(SCOPE)
        .send();
    }

    /// `Discovery::adjust_peers` / `select_outbound_peers`
    /// (handlers/peers_management.rs:12-83). `candidate` is `None` when the
    /// selector returned no candidate at all — the model's selection-short branch.
    pub fn adjust_peers(candidate: Option<&PeerId>) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "adjust_peers")
            .argument(
                "candidate",
                candidate.map(peer_ix).unwrap_or(0),
                Some("PEERS"),
            )
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::repair_outbound_peers`, the inbound-upgrade branch
    /// (handlers/peers_management.rs:93-112)
    pub fn repair_outbound_peers(peer: &PeerId) {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "repair_outbound_peers")
            .argument("peer", peer_ix(peer), Some("PEERS"))
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::handle_successful_bootstrap` (handlers/bootstrap.rs:10-45)
    pub fn handle_successful_bootstrap() {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_successful_bootstrap")
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::handle_failed_bootstrap` (handlers/bootstrap.rs:47-51)
    pub fn handle_failed_bootstrap() {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "handle_failed_bootstrap")
            .scope(SCOPE)
            .send();
    }

    /// `Discovery::make_extension_step`, the branch that completes the extension
    /// and returns to Idle (handlers/extension.rs:90-92)
    pub fn make_extension_step() {
        if !quint_oracle::enabled() {
            return;
        }
        tick(std::time::Instant::now());
        quint_oracle::Event::builder(quint_oracle::current_test(), "make_extension_step")
            .scope(SCOPE)
            .send();
    }

}

#[cfg(not(feature = "quint-oracle-enabled"))]
mod imp {
    use std::time::Duration;

    use libp2p::{Multiaddr, PeerId};

    use crate::dial::DialData;

    #[inline(always)]
    pub fn rate_limiter_new(_: Duration, _: u32, _: u32, _: Duration) {}
    #[inline(always)]
    pub fn check_request(_: &PeerId) {}
    #[inline(always)]
    pub fn rate_limiter_remove_peer(_: &PeerId) {}
    #[inline(always)]
    pub fn dial_register_done_on(_: &DialData, _: bool) {}
    #[inline(always)]
    pub fn dial_clear_done_for_peer(_: &PeerId, _: &[Multiaddr]) {}
    #[inline(always)]
    pub fn dial_add_to_queue(_: &DialData, _: Option<Duration>) {}
    #[inline(always)]
    pub fn dial_peer(_: Option<&libp2p::swarm::ConnectionId>, _: bool) {}
    #[inline(always)]
    pub fn handle_connection(_: &PeerId, _: &libp2p::swarm::ConnectionId, _: bool) {}
    #[inline(always)]
    pub fn handle_failed_connection(_: &libp2p::swarm::ConnectionId, _: bool) {}
    #[inline(always)]
    pub fn handle_new_peer(_: &libp2p::swarm::ConnectionId, _: &[Multiaddr], _: bool) {}
    #[inline(always)]
    pub fn close_connection(_: &PeerId, _: &libp2p::swarm::ConnectionId, _: bool) {}
    #[inline(always)]
    pub fn handle_closed_connection(_: &PeerId, _: &libp2p::swarm::ConnectionId) {}
    #[inline(always)]
    pub fn peers_request_peer(
        _: Option<&libp2p::request_response::OutboundRequestId>,
        _: bool,
    ) {
    }
    #[inline(always)]
    pub fn handle_peers_response(_: &libp2p::request_response::OutboundRequestId) {}
    #[inline(always)]
    pub fn handle_failed_peers_request(_: &libp2p::request_response::OutboundRequestId) {}
    #[inline(always)]
    pub fn connect_request_peer(
        _: Option<&libp2p::request_response::OutboundRequestId>,
        _: bool,
    ) {
    }
    #[inline(always)]
    pub fn handle_connect_request(_: &PeerId) {}
    #[inline(always)]
    pub fn handle_connect_response(_: &libp2p::request_response::OutboundRequestId, _: bool) {}
    #[inline(always)]
    pub fn handle_failed_connect_request(_: &libp2p::request_response::OutboundRequestId) {}
    #[inline(always)]
    pub fn adjust_peers(_: Option<&PeerId>) {}
    #[inline(always)]
    pub fn repair_outbound_peers(_: &PeerId) {}
    #[inline(always)]
    pub fn handle_successful_bootstrap() {}
    #[inline(always)]
    pub fn handle_failed_bootstrap() {}
    #[inline(always)]
    pub fn make_extension_step() {}
}

pub(crate) use imp::*;
