//! Per-test identity projection for the Quint Studio oracle.
//!
//! The `p2p-network` model works over small named identities ("n1", "p1", "c1",
//! "A1", …) while the code deals in random `PeerId`s, libp2p `ConnectionId`s and
//! real multiaddrs. Every logged identity is therefore projected onto an index
//! assigned in first-seen order. The registries are thread-local, which is also
//! the per-test scope: the Rust test harness gives each test its own thread, and
//! a `#[tokio::test]` drives its network task on that same thread.
//!
//! This module only renames values — it makes no oracle calls of its own beyond
//! building the `Addr` record the spec declares.

use std::cell::RefCell;
use std::collections::HashMap;

use libp2p::swarm::ConnectionId;
use libp2p::{Multiaddr, PeerId};

thread_local! {
    static NODE_IX: RefCell<HashMap<PeerId, usize>> = RefCell::new(HashMap::new());
    static PEER_IX: RefCell<HashMap<PeerId, usize>> = RefCell::new(HashMap::new());
    static CONN_IX: RefCell<HashMap<ConnectionId, usize>> = RefCell::new(HashMap::new());
    static BASE_IX: RefCell<HashMap<Multiaddr, usize>> = RefCell::new(HashMap::new());
    static IP_IX: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    static LIMITER_IX: RefCell<usize> = const { RefCell::new(0) };
    /// Consensus addresses and consensus public keys share one index space, so a
    /// validator is named by a single number: "ca3" always pairs with "k3".
    static VALIDATOR_IX: RefCell<(HashMap<String, usize>, HashMap<Vec<u8>, usize>, usize)> =
        RefCell::new((HashMap::new(), HashMap::new(), 0));
}

fn ix<K: std::hash::Hash + Eq + Clone>(
    registry: &'static std::thread::LocalKey<RefCell<HashMap<K, usize>>>,
    key: &K,
) -> usize {
    registry.with(|m| {
        let mut m = m.borrow_mut();
        let next = m.len() + 1;
        *m.entry(key.clone()).or_insert(next)
    })
}

/// The model's `NodeId` for a swarm's own peer id: "n1", "n2", ….
pub(crate) fn node(peer: &PeerId) -> String {
    format!("n{}", ix(&NODE_IX, peer))
}

/// The model's `NodeId` for one `ip_limits::Behaviour` instance, which carries no
/// peer id of its own: "l1", "l2", ….
pub(crate) fn limiter_node() -> String {
    LIMITER_IX.with(|c| {
        let mut c = c.borrow_mut();
        *c += 1;
        format!("l{}", *c)
    })
}

/// The model's `PeerId` for a remote peer: "p1", "p2", ….
pub(crate) fn peer(peer: &PeerId) -> String {
    format!("p{}", ix(&PEER_IX, peer))
}

/// The model's `ConnId`: "c1", "c2", ….
pub(crate) fn conn(connection_id: ConnectionId) -> String {
    format!("c{}", ix(&CONN_IX, &connection_id))
}

/// The model's `Ip`: "i1", "i2", ….
pub(crate) fn ip_name(ip: &std::net::IpAddr) -> String {
    format!("i{}", ix(&IP_IX, &ip.to_string()))
}

/// The model's consensus address for a validator: "ca1", "ca2", …. When the
/// validator's public key is known it is registered under the same index.
pub(crate) fn cons_addr(address: &str, public_key: Option<&[u8]>) -> String {
    format!("ca{}", validator_ix(Some(address), public_key))
}

/// The model's consensus public key: "k1", "k2", …, sharing the index space of
/// the consensus address of the same validator.
pub(crate) fn public_key(key: &[u8]) -> String {
    format!("k{}", validator_ix(None, Some(key)))
}

fn validator_ix(address: Option<&str>, key: Option<&[u8]>) -> usize {
    VALIDATOR_IX.with(|cell| {
        let (addrs, keys, next) = &mut *cell.borrow_mut();
        let found = address
            .and_then(|a| addrs.get(a).copied())
            .or_else(|| key.and_then(|k| keys.get(k).copied()));
        let assigned = match found {
            Some(existing) => existing,
            None => {
                *next += 1;
                *next
            }
        };
        if let Some(a) = address {
            addrs.entry(a.to_string()).or_insert(assigned);
        }
        if let Some(k) = key {
            keys.entry(k.to_vec()).or_insert(assigned);
        }
        assigned
    })
}

/// The model's `Addr` record: the three facts the component derives from a
/// multiaddr, each projected onto its own index space.
pub(crate) fn addr(address: &Multiaddr) -> quint_oracle::Value {
    use quint_oracle::ToLogged as _;

    let base = malachitebft_discovery::util::strip_peer_id_from_multiaddr(address);
    let base_name = format!("A{}", ix(&BASE_IX, &base));

    let ip = match crate::ip_limits::extract_ip(address) {
        Some(ip) => ip_name(&ip),
        None => String::new(),
    };

    let peer_name = address
        .iter()
        .find_map(|p| match p {
            libp2p::multiaddr::Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .map(|id| peer(&id))
        .unwrap_or_default();

    quint_oracle::record([
        ("base", base_name.to_logged()),
        ("ip", ip.to_logged()),
        ("peer", peer_name.to_logged()),
    ])
}
