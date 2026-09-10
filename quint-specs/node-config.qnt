// Node Configuration — the TOML-deserializable node / P2P / discovery / gossipsub /
// timeout configuration, its defaults and lenient deserializers, the Prometheus
// registry wrapper, and the PeerId type.
//
// Code:
//   code/crates/config/src/lib.rs:80    ChannelNames::validate (empty / duplicate)
//   code/crates/config/src/lib.rs:145   P2pConfig::default (rpc 10 MiB, pubsub 4 MiB)
//   code/crates/config/src/lib.rs:219   DiscoveryConfig::default
//   code/crates/config/src/lib.rs:429   GossipSubConfig::new -> adjust()
//   code/crates/config/src/lib.rs:453   GossipSubConfig::adjust (the clamping rules)
//   code/crates/config/src/utils.rs:4   bool_from_anything (lenient TOML bool)
//   code/crates/core-types/src/timeouts.rs:95  LinearTimeouts::duration_for
//   code/crates/metrics/src/registry.rs SharedRegistry::new / with_moniker / export
//   code/crates/metrics/src/metrics.rs:160     Metrics::register
//   code/crates/peer/src/lib.rs:76      PeerId::from_bytes / from_multihash / to_bytes
//
// GRANULARITY: single instance. Configuration is per-process; the modeled state is
// one node's configuration plus its metrics registry and the peer ids it parses.
//
// The message-size limits and the timeout values configured here are the bounds other
// layers enforce, so the enforcement side is modeled too (network_publish_pubsub /
// network_send_rpc / timeout_duration_for) — that is the only way a property can say
// the configured bound is the bound actually applied.

module node_config_core {
  import basicSpells.* from "./spells/basicSpells"

  // ---------------------------------------------------------------- types

  /// GossipSub mesh parameters (config/src/lib.rs:389-417). Sizes are peer counts.
  type Mesh = {
    mesh_n: int,
    mesh_n_high: int,
    mesh_n_low: int,
    mesh_outbound_min: int,
    peer_scoring: bool,
    explicit_peering: bool,
    flood_publish: bool,
  }

  /// GossipSub / broadcast channel names (config/src/lib.rs:39-47).
  type Channels = { consensus: str, proposal_parts: str, sync: str, liveness: str }

  /// ChannelNames::validate outcomes (config/src/lib.rs:62-77).
  type Verdict = VOk | VEmpty(str) | VDuplicate(str)

  /// DiscoveryConfig (config/src/lib.rs:163-217), only the numeric limits.
  type Discovery = {
    enabled: bool,
    num_outbound_peers: int,
    num_inbound_peers: int,
    max_connections_per_ip: int,
    max_peers_per_response: int,
    dial_max_retries: int,
  }

  /// LinearTimeouts (core-types/src/timeouts.rs:35-66), in milliseconds.
  type Timeouts = {
    propose: int,
    propose_delta: int,
    prevote: int,
    prevote_delta: int,
    precommit: int,
    precommit_delta: int,
    rebroadcast: int,
    max_timeout: int,
  }

  /// Outcome of `bool_from_anything` (config/src/utils.rs:4-37).
  type ParseOutcome = PNative(bool) | PString(bool) | PError(str)

  /// The byte encoding of a peer id: a multihash code plus its digest.
  /// `well_formed` stands for `Multihash::from_bytes` succeeding at all.
  type PeerBytes = { code: int, digest_len: int, digest: int, well_formed: bool }

  /// An accepted PeerId, carrying the bytes it was parsed from so a
  /// round-trip property can compare a recomputation against the source.
  type Peer = { code: int, digest_len: int, digest: int, source: PeerBytes }

  type State = {
    // --- the configuration itself
    gossip: Mesh,
    channels: Channels,
    channel_verdict: Option[Verdict],
    discovery: Discovery,
    timeouts: Timeouts,
    persistent_peers: Set[int],
    persistent_peers_only: bool,
    pubsub_max_size: int,
    rpc_max_size: int,

    // --- the metrics registry (metrics/src/registry.rs)
    registry_created: bool,
    registry_moniker: Option[str],
    registered_metrics: List[str],
    registry_exported: bool,

    // --- peer ids (peer/src/lib.rs)
    peers: int -> Peer,
    next_peer: int,
    peer_reject: Option[str],
    roundtrips_checked: Set[int],
    roundtrip_failed: bool,

    // --- ghosts: silent behaviours that leave no visible trace
    // Latched when adjust() evaluates `mesh_n_low - 1` with mesh_n_low == 0,
    // which underflows in the real `usize` arithmetic.
    adjust_underflow: bool,
    // Latched when adjust() recomputed each of the four mesh fields.
    defaulted_mesh_n: bool,
    raised_mesh_n_high: bool,
    recomputed_mesh_n_low: bool,
    recomputed_mesh_outbound_min: bool,
    kept_mesh_outbound_min: bool,
    // The last outcome of the lenient bool deserializer.
    bool_parse: Option[ParseOutcome],
    // Message sizes the network layer actually let through, per transport.
    accepted_pubsub_sizes: Set[int],
    accepted_rpc_sizes: Set[int],
    rejected_oversized_pubsub: bool,
    rejected_oversized_rpc: bool,
    // Durations produced by duration_for, and whether any hit the cap.
    computed_timeouts: Set[int],
    timeout_clamped: bool,
    // True while nothing but defaults has been applied.
    only_defaults: bool,
  }

  // ------------------------------------------------------------ constants

  /// Message sizes are in MiB, the unit the code's ByteSize defaults use.
  pure val DEFAULT_PUBSUB_MAX_SIZE: int = 4
  pure val DEFAULT_RPC_MAX_SIZE: int = 10

  /// A full proposal part never fits below this; a pubsub limit under it
  /// silently makes consensus values undeliverable.
  pure val MIN_PROPOSAL_SIZE: int = 1
  /// The largest message the libp2p transport can actually carry.
  pure val TRANSPORT_MAX_SIZE: int = 16

  /// PeerId multihash codes (peer/src/lib.rs:52-53).
  pure val MULTIHASH_IDENTITY_CODE: int = 0
  pure val MULTIHASH_SHA256_CODE: int = 18
  /// peer/src/lib.rs:50
  pure val MAX_INLINE_KEY_LENGTH: int = 42

  pure val DEFAULT_MESH: Mesh = {
    mesh_n: 6, mesh_n_high: 12, mesh_n_low: 4, mesh_outbound_min: 2,
    peer_scoring: false, explicit_peering: false, flood_publish: true,
  }

  pure val DEFAULT_CHANNELS: Channels =
    { consensus: "/consensus", proposal_parts: "/proposal_parts",
      sync: "/sync", liveness: "/liveness" }

  pure val DEFAULT_DISCOVERY: Discovery = {
    enabled: false, num_outbound_peers: 50, num_inbound_peers: 50,
    max_connections_per_ip: 5, max_peers_per_response: 100, dial_max_retries: 5,
  }

  pure val DEFAULT_TIMEOUTS: Timeouts = {
    propose: 3000, propose_delta: 500, prevote: 1000, prevote_delta: 500,
    precommit: 1000, precommit_delta: 500, rebroadcast: 5000, max_timeout: 60000,
  }

  /// The metric names Metrics::register installs under one prefix
  /// (metrics/src/metrics.rs:160+) — a representative subset.
  /// The fully-qualified metric names, prefix included: `with_prefix` composes the
  /// name at registration time, and Quint has no string operators.
  pure val METRIC_NAMES: List[str] = List(
    "malachitebft_core_consensus_consensus_time",
    "malachitebft_core_consensus_time_per_block",
    "malachitebft_core_consensus_time_per_step",
    "malachitebft_core_consensus_height",
    "malachitebft_core_consensus_round",
  )

  // -------------------------------------------------------------- domains
  // Deliberately include boundary and invalid values: every guard conjunct
  // below has to be falsifiable within its domain.

  /// Raw gossipsub configurations as they arrive from TOML, before adjust().
  pure val MESH_RAWS: Set[Mesh] = Set(
    // the shipped default
    DEFAULT_MESH,
    // everything omitted from TOML — serde fills zeros, adjust() must repair them
    { mesh_n: 0, mesh_n_high: 0, mesh_n_low: 0, mesh_outbound_min: 0,
      peer_scoring: false, explicit_peering: false, flood_publish: true },
    // everything omitted, with the lenient bool having turned peer scoring on
    { mesh_n: 0, mesh_n_high: 0, mesh_n_low: 0, mesh_outbound_min: 0,
      peer_scoring: true, explicit_peering: false, flood_publish: true },
    // mesh_n = 1: mesh_n_low becomes 1*2/3 = 0, and adjust() then evaluates
    // `mesh_n_low - 1` on a usize
    { mesh_n: 1, mesh_n_high: 0, mesh_n_low: 0, mesh_outbound_min: 0,
      peer_scoring: true, explicit_peering: false, flood_publish: true },
    // mesh_n = 2: the fallback yields mesh_outbound_min == mesh_n_low
    { mesh_n: 2, mesh_n_high: 1, mesh_n_low: 1, mesh_outbound_min: 0,
      peer_scoring: false, explicit_peering: true, flood_publish: false },
    // inconsistent high/low that adjust() has to override
    { mesh_n: 8, mesh_n_high: 4, mesh_n_low: 9, mesh_outbound_min: 7,
      peer_scoring: true, explicit_peering: true, flood_publish: true },
    // fully consistent values adjust() must leave alone
    { mesh_n: 10, mesh_n_high: 20, mesh_n_low: 6, mesh_outbound_min: 4,
      peer_scoring: false, explicit_peering: false, flood_publish: true },
  )

  /// Every ChannelNames value `validate` is called with: the default, each of the
  /// four single-empty variants, and each of the six duplicate pairs
  /// (config/src/lib.rs:1191-1303), plus fully custom distinct names.
  pure val CHANNEL_SETS: Set[Channels] = Set(
    DEFAULT_CHANNELS,
    // one empty name, one per field
    { ...DEFAULT_CHANNELS, consensus: "" },
    { ...DEFAULT_CHANNELS, proposal_parts: "" },
    { ...DEFAULT_CHANNELS, sync: "" },
    { ...DEFAULT_CHANNELS, liveness: "" },
    // two logical channels sharing one topic, one per pair
    { ...DEFAULT_CHANNELS, consensus: "/dup", proposal_parts: "/dup" },
    { ...DEFAULT_CHANNELS, consensus: "/dup", sync: "/dup" },
    { ...DEFAULT_CHANNELS, consensus: "/dup", liveness: "/dup" },
    { ...DEFAULT_CHANNELS, proposal_parts: "/dup", sync: "/dup" },
    { ...DEFAULT_CHANNELS, proposal_parts: "/dup", liveness: "/dup" },
    { ...DEFAULT_CHANNELS, sync: "/dup", liveness: "/dup" },
    // distinct custom names
    { consensus: "/c", proposal_parts: "/p", sync: "/s", liveness: "/l" },
    { consensus: "/custom/consensus/v2", proposal_parts: "/custom/proposal_parts/v2",
      sync: "/custom/sync/v2", liveness: "/custom/liveness/v2" },
    { consensus: "/app/consensus/v1", proposal_parts: "/app/proposal_parts/v1",
      sync: "/app/sync/v1", liveness: "/app/liveness/v1" },
  )

  pure val DISCOVERY_SETS: Set[Discovery] = Set(
    DEFAULT_DISCOVERY,
    { ...DEFAULT_DISCOVERY, enabled: true },
    // enabled but with limits of zero — nothing in this crate rejects it
    { ...DEFAULT_DISCOVERY, enabled: true, num_outbound_peers: 0, dial_max_retries: 0 },
    { ...DEFAULT_DISCOVERY, enabled: true, max_peers_per_response: 0, max_connections_per_ip: 0 },
  )

  pure val TIMEOUT_SETS: Set[Timeouts] = Set(
    DEFAULT_TIMEOUTS,
    // every timeout zero — accepted by serde, no cross-field validation exists
    { propose: 0, propose_delta: 0, prevote: 0, prevote_delta: 0,
      precommit: 0, precommit_delta: 0, rebroadcast: 0, max_timeout: 0 },
    // enormous deltas that reach the cap after a single round
    { ...DEFAULT_TIMEOUTS, propose_delta: 100000, prevote_delta: 100000 },
    // a cap below the base timeouts
    { ...DEFAULT_TIMEOUTS, max_timeout: 100 },
  )

  pure val SIZE_LIMITS: Set[int] = Set(0, 1, 4, 10, 16, 64)
  pure val MESSAGE_SIZES: Set[int] = Set(1, 4, 5, 10, 20)
  pure val PEER_SETS: Set[Set[int]] = Set(Set(), Set(1), Set(1, 2))
  pure val TIMEOUT_KINDS: Set[str] = Set("propose", "prevote", "precommit", "rebroadcast")
  /// -1 stands for the nil round: `duration_for` calls
  /// `timeout.round.as_u32().expect("Round must be defined")` on it
  /// (core-types/src/timeouts.rs:96), so the precondition is a real contract.
  pure val ROUNDS: Set[int] = Set(-1, 0, 1, 2, 200)

  /// Peer-id handles a caller can name, including ones never parsed.
  pure val PEER_HANDLES: Set[int] = 0.to(3)
  pure val MONIKERS: Set[str] = Set("node-1", "node-2")

  /// The strings `visit_str` can be handed, including one that is not a boolean.
  pure val BOOL_STRINGS: Set[str] = Set("true", "false", "yes")

  pure val PEER_BYTES: Set[PeerBytes] = Set(
    // sha256 digest — always accepted
    { code: MULTIHASH_SHA256_CODE, digest_len: 32, digest: 1, well_formed: true },
    // inline (identity) key within the inline limit
    { code: MULTIHASH_IDENTITY_CODE, digest_len: 32, digest: 2, well_formed: true },
    // inline key at the boundary
    { code: MULTIHASH_IDENTITY_CODE, digest_len: MAX_INLINE_KEY_LENGTH, digest: 3, well_formed: true },
    // inline key one past the boundary — rejected as an unsupported code
    { code: MULTIHASH_IDENTITY_CODE, digest_len: 43, digest: 4, well_formed: true },
    // a hash function that is not valid for peer ids
    { code: 17, digest_len: 20, digest: 5, well_formed: true },
    // bytes that are not a multihash at all
    { code: MULTIHASH_SHA256_CODE, digest_len: 32, digest: 6, well_formed: false },
  )

  // ------------------------------------------------- functional logic

  /// GossipSubConfig::adjust (config/src/lib.rs:453-479), mirrored exactly.
  pure def adjust(m: Mesh): Mesh = {
    val n = if (m.mesh_n == 0) 6 else m.mesh_n
    val nh = if (m.mesh_n_high == 0 or m.mesh_n_high < n) n * 2 else m.mesh_n_high
    val nl = if (m.mesh_n_low == 0 or m.mesh_n_low > n) n * 2 / 3 else m.mesh_n_low
    val om =
      if (m.mesh_outbound_min == 0 or m.mesh_outbound_min > n / 2 or m.mesh_outbound_min >= nl)
        max(1, min(n / 2, nl - 1))
      else m.mesh_outbound_min
    { ...m, mesh_n: n, mesh_n_high: nh, mesh_n_low: nl, mesh_outbound_min: om }
  }

  /// True when adjust() reaches `mesh_n_low - 1` with mesh_n_low == 0. Quint
  /// integers are unbounded, so the model computes -1 where the real `usize`
  /// subtraction underflows — this ghost records that the code got there.
  pure def adjust_underflows(m: Mesh): bool = {
    val n = if (m.mesh_n == 0) 6 else m.mesh_n
    val nl = if (m.mesh_n_low == 0 or m.mesh_n_low > n) n * 2 / 3 else m.mesh_n_low
    val recomputes =
      m.mesh_outbound_min == 0 or m.mesh_outbound_min > n / 2 or m.mesh_outbound_min >= nl
    recomputes and nl == 0
  }

  /// The four (field, name) entries ChannelNames::validate walks over.
  pure def channel_entries(c: Channels): List[(str, str)] =
    List(("consensus", c.consensus), ("proposal_parts", c.proposal_parts),
         ("sync", c.sync), ("liveness", c.liveness))

  /// ChannelNames::validate (config/src/lib.rs:80-107): empty names first,
  /// in field order, then the first duplicate pair.
  pure def validate_channels(c: Channels): Verdict = {
    val es = channel_entries(c)
    val empties = es.indices().filter(i => es.nth(i)._2 == "")
    if (empties != Set())
      VEmpty(es.nth(empties.fold(99, (a, i) => min(a, i)))._1)
    else {
      val dups = es.indices().filter(i =>
        es.indices().exists(j => j < i and es.nth(j)._2 == es.nth(i)._2))
      if (dups != Set())
        VDuplicate(es.nth(dups.fold(99, (a, i) => min(a, i)))._2)
      else VOk
    }
  }

  pure def channels_are_distinct_and_named(c: Channels): bool = {
    val es = channel_entries(c)
    and {
      es.indices().forall(i => es.nth(i)._2 != ""),
      es.indices().forall(i => es.indices().forall(j => i == j or es.nth(i)._2 != es.nth(j)._2)),
    }
  }

  /// BoolVisitor::visit_str (config/src/utils.rs:24-35): exactly "true"/"false"
  /// parse, anything else is a deserialization error the caller sees as Err.
  pure def parse_bool_str(s: str): ParseOutcome =
    if (s == "true") PString(true)
    else if (s == "false") PString(false)
    else PError(s)

  /// LinearTimeouts::duration_for (core-types/src/timeouts.rs:95-127), with the
  /// per-round extrapolation clamped to max_timeout.
  pure def duration_for(t: Timeouts, kind: str, rnd: int): int =
    if (kind == "propose") min(t.propose + t.propose_delta * rnd, t.max_timeout)
    else if (kind == "prevote") min(t.prevote + t.prevote_delta * rnd, t.max_timeout)
    else if (kind == "precommit") min(t.precommit + t.precommit_delta * rnd, t.max_timeout)
    else min(t.rebroadcast + (t.propose_delta + t.prevote_delta + t.precommit_delta) * rnd,
             t.max_timeout)

  /// PeerId::to_bytes (peer/src/lib.rs:110) — the multihash encoding of a peer id.
  pure def peer_to_bytes(p: Peer): PeerBytes =
    { code: p.code, digest_len: p.digest_len, digest: p.digest, well_formed: true }

  /// PeerId::from_multihash (peer/src/lib.rs:87-96): sha256 always, identity only
  /// while the inline key fits.
  pure def code_is_supported(b: PeerBytes): bool =
    or {
      b.code == MULTIHASH_SHA256_CODE,
      b.code == MULTIHASH_IDENTITY_CODE and b.digest_len <= MAX_INLINE_KEY_LENGTH,
    }

  pure def list_has_duplicate(l: List[str]): bool =
    l.indices().exists(i => l.indices().exists(j => j < i and l.nth(j) == l.nth(i)))

  /// A round-trip-clean placeholder, so looking up an absent peer handle is a
  /// defined operation and the `has(peer)` conjunct is the only thing gating
  /// the action.
  pure val MISSING_PEER: Peer = {
    code: MULTIHASH_SHA256_CODE, digest_len: 32, digest: 0,
    source: { code: MULTIHASH_SHA256_CODE, digest_len: 32, digest: 0, well_formed: true },
  }

  pure val initial_state: State = {
    gossip: DEFAULT_MESH,
    channels: DEFAULT_CHANNELS,
    channel_verdict: None,
    discovery: DEFAULT_DISCOVERY,
    timeouts: DEFAULT_TIMEOUTS,
    persistent_peers: Set(),
    persistent_peers_only: false,
    pubsub_max_size: DEFAULT_PUBSUB_MAX_SIZE,
    rpc_max_size: DEFAULT_RPC_MAX_SIZE,
    registry_created: false,
    registry_moniker: None,
    registered_metrics: List(),
    registry_exported: false,
    peers: Map(),
    next_peer: 0,
    peer_reject: None,
    roundtrips_checked: Set(),
    roundtrip_failed: false,
    adjust_underflow: false,
    defaulted_mesh_n: false,
    raised_mesh_n_high: false,
    recomputed_mesh_n_low: false,
    recomputed_mesh_outbound_min: false,
    kept_mesh_outbound_min: false,
    bool_parse: None,
    accepted_pubsub_sizes: Set(),
    accepted_rpc_sizes: Set(),
    rejected_oversized_pubsub: false,
    rejected_oversized_rpc: false,
    computed_timeouts: Set(),
    timeout_clamped: false,
    only_defaults: true,
  }
}

module node_config {
  import basicSpells.* from "./spells/basicSpells"
  import node_config_core.*

  var state: State

  action init = all {
    state' = initial_state,
  }

  // ------------------------------------------------------ configuration

  /// P2pConfig::default / DiscoveryConfig::default / GossipSubConfig::default
  /// (config/src/lib.rs:145-158, 219-239, 420-423) — reinstall the shipped
  /// defaults. Carries no arguments: the defaults are fixed in the code.
  action P2pConfigdefault: bool = all {
    state' = { ...initial_state,
               // the registry and the peer ids are not part of the config reset
               registry_created: state.registry_created,
               registry_moniker: state.registry_moniker,
               registered_metrics: state.registered_metrics,
               registry_exported: state.registry_exported,
               peers: state.peers,
               next_peer: state.next_peer,
               peer_reject: state.peer_reject,
               roundtrips_checked: state.roundtrips_checked,
               roundtrip_failed: state.roundtrip_failed,
               only_defaults: true },
  }

  /// GossipSubConfig::new (config/src/lib.rs:429-451) — installs the whole raw
  /// configuration and immediately runs adjust() over it. Baseline-establishing,
  /// so the entire payload is one parameter.
  action GossipSubConfignew(raw: Mesh): bool = {
    val n = if (raw.mesh_n == 0) 6 else raw.mesh_n
    val nl = if (raw.mesh_n_low == 0 or raw.mesh_n_low > n) n * 2 / 3 else raw.mesh_n_low
    all {
      state' = { ...state,
                 gossip: adjust(raw),
                 adjust_underflow: state.adjust_underflow or adjust_underflows(raw),
                 defaulted_mesh_n: state.defaulted_mesh_n or raw.mesh_n == 0,
                 raised_mesh_n_high:
                   state.raised_mesh_n_high or raw.mesh_n_high == 0 or raw.mesh_n_high < n,
                 recomputed_mesh_n_low:
                   state.recomputed_mesh_n_low or raw.mesh_n_low == 0 or raw.mesh_n_low > n,
                 recomputed_mesh_outbound_min:
                   state.recomputed_mesh_outbound_min or raw.mesh_outbound_min == 0
                     or raw.mesh_outbound_min > n / 2 or raw.mesh_outbound_min >= nl,
                 kept_mesh_outbound_min:
                   state.kept_mesh_outbound_min or (raw.mesh_outbound_min != 0
                     and raw.mesh_outbound_min <= n / 2 and raw.mesh_outbound_min < nl),
                 only_defaults: state.only_defaults and raw == DEFAULT_MESH },
    }
  }

  /// GossipSubConfig::adjust (config/src/lib.rs:453) — public, so a caller can
  /// re-run it on an already-adjusted configuration.
  action GossipSubConfigadjust: bool = all {
    state' = { ...state,
               gossip: adjust(state.gossip),
               adjust_underflow: state.adjust_underflow or adjust_underflows(state.gossip) },
  }

  /// The TOML deserializer installing ChannelNames (config/src/lib.rs:39-56).
  /// Nothing validates them at this point — validate() is a separate call.
  action ChannelNamesset(names: Channels): bool = all {
    state' = { ...state,
               channels: names,
               channel_verdict: None,
               only_defaults: state.only_defaults and names == DEFAULT_CHANNELS },
  }

  /// ChannelNames::validate (config/src/lib.rs:80-107) — a query on a
  /// ChannelNames value. It is called as a method, so the names it validates
  /// come with the call; the verdict is recorded so a property can recheck it.
  action ChannelNamesvalidate(names: Channels): bool = all {
    state' = { ...state,
               channels: names,
               channel_verdict: Some(validate_channels(names)),
               only_defaults: state.only_defaults and names == DEFAULT_CHANNELS },
  }

  /// BoolVisitor::visit_bool (config/src/utils.rs:18-23) — a native TOML boolean
  /// passes straight through. Used for gossipsub's enable_peer_scoring and the
  /// other lenient flags (config/src/lib.rs:535-549).
  action bool_from_anything_bool(value: bool): bool = all {
    state' = { ...state,
               bool_parse: Some(PNative(value)),
               gossip: { ...state.gossip, peer_scoring: value },
               only_defaults: false },
  }

  /// BoolVisitor::visit_str (config/src/utils.rs:24-35) — a quoted boolean. A
  /// string that is not a boolean is not a rejected transition: the visitor was
  /// entered and returned a deserialization error, which the model records.
  action bool_from_anything_str(value: str): bool = {
    val outcome = parse_bool_str(value)
    all {
      state' = { ...state,
                 bool_parse: Some(outcome),
                 gossip: match outcome {
                   | PString(b) => { ...state.gossip, peer_scoring: b }
                   | PNative(b) => { ...state.gossip, peer_scoring: b }
                   | PError(_) => state.gossip
                 },
                 only_defaults: false },
    }
  }

  /// The TOML deserializer installing P2pConfig's message-size limits
  /// (config/src/lib.rs:128-134). No bound is checked against the transport.
  action P2pConfigset_message_limits(pubsub_max_size: int, rpc_max_size: int): bool = all {
    state' = { ...state,
               pubsub_max_size: pubsub_max_size,
               rpc_max_size: rpc_max_size,
               only_defaults: state.only_defaults
                 and pubsub_max_size == DEFAULT_PUBSUB_MAX_SIZE
                 and rpc_max_size == DEFAULT_RPC_MAX_SIZE },
  }

  /// The TOML deserializer installing DiscoveryConfig (config/src/lib.rs:163-217).
  /// Every numeric field takes whatever the file says; nothing rejects a zero.
  action DiscoveryConfigset(discovery: Discovery): bool = all {
    state' = { ...state,
               discovery: discovery,
               only_defaults: state.only_defaults and discovery == DEFAULT_DISCOVERY },
  }

  /// The TOML deserializer installing the persistent-peer list and the
  /// persistent_peers_only switch (config/src/lib.rs:115-122).
  action P2pConfigset_persistent_peers(peers: Set[int], peers_only: bool): bool = all {
    state' = { ...state,
               persistent_peers: peers,
               persistent_peers_only: peers_only,
               only_defaults: state.only_defaults and peers == Set() and not(peers_only) },
  }

  /// The TOML deserializer installing the consensus timeouts
  /// (core-types/src/timeouts.rs:35-66). No cross-field validation exists.
  action TimeoutConfigset(timeouts: Timeouts): bool = all {
    state' = { ...state,
               timeouts: timeouts,
               only_defaults: state.only_defaults and timeouts == DEFAULT_TIMEOUTS },
  }

  // ------------------------------- the layers that enforce those bounds

  /// LinearTimeouts::duration_for (core-types/src/timeouts.rs:95) — the value the
  /// consensus engine actually waits for, derived from the configured timeouts.
  action timeout_duration_for(kind: str, rnd: int): bool = {
    val d = duration_for(state.timeouts, kind, rnd)
    all {
      rnd >= 0,                                  // Round must be defined (timeouts.rs:96)
      state' = { ...state,
                 computed_timeouts: state.computed_timeouts.union(Set(d)),
                 timeout_clamped: state.timeout_clamped or d == state.timeouts.max_timeout },
    }
  }

  /// The gossipsub publish path enforcing pubsub_max_size
  /// (network/src/behaviour.rs:227) — the bound configured above.
  action network_publish_pubsub(msg_size: int): bool = all {
    state' =
      if (msg_size <= state.pubsub_max_size)
        { ...state, accepted_pubsub_sizes: state.accepted_pubsub_sizes.union(Set(msg_size)) }
      else
        { ...state, rejected_oversized_pubsub: true },
  }

  /// The sync RPC path enforcing rpc_max_size (network/src/behaviour.rs:255).
  action network_send_rpc(msg_size: int): bool = all {
    state' =
      if (msg_size <= state.rpc_max_size)
        { ...state, accepted_rpc_sizes: state.accepted_rpc_sizes.union(Set(msg_size)) }
      else
        { ...state, rejected_oversized_rpc: true },
  }

  // ------------------------------------------------------------ metrics

  /// SharedRegistry::new / global() / export (metrics/src/registry.rs:16, 60).
  /// Creating the registry starts it empty and with no moniker.
  action SharedRegistrynew__export: bool = all {
    state' = { ...state,
               registry_created: true,
               registry_moniker: None,
               registered_metrics: List(),
               registry_exported: false },
  }

  /// SharedRegistry::with_moniker (metrics/src/registry.rs:26) — the clone shares
  /// the same underlying registry and adds a `moniker` label to new sub-registries.
  action SharedRegistrywith_moniker(moniker: str): bool = all {
    state.registry_created,
    state' = { ...state, registry_moniker: Some(moniker) },
  }

  /// Metrics::register (metrics/src/metrics.rs:160) — registers the whole metric
  /// family under one prefix. Nothing here checks whether it already ran.
  action Metricsregister: bool = all {
    state.registry_created,
    state' = { ...state,
               registered_metrics:
                 METRIC_NAMES.foldl(state.registered_metrics, (acc, m) => acc.append(m)) },
  }

  /// metrics::export (metrics/src/registry.rs:60) — encodes the registry to text.
  action Registryexport: bool = all {
    state.registry_created,
    state' = { ...state, registry_exported: true },
  }

  // ----------------------------------------------------------- peer ids

  /// PeerId::from_bytes (peer/src/lib.rs:76) — decodes a multihash and then
  /// checks the code. Guarded: only well-formed bytes with a supported code
  /// become a PeerId; the two rejection causes are recorded separately.
  action PeerIdfrom_bytes(bytes: PeerBytes): bool = all {
    state' =
      if (not(bytes.well_formed))
        { ...state, peer_reject: Some("invalid multihash") }
      else if (not(code_is_supported(bytes)))
        { ...state, peer_reject: Some("unsupported multihash code") }
      else
        { ...state,
          peers: state.peers.put(state.next_peer,
                   { code: bytes.code, digest_len: bytes.digest_len,
                     digest: bytes.digest, source: bytes }),
          next_peer: state.next_peer + 1 },
  }

  /// PeerId::random (peer/src/lib.rs:104) — an identity multihash over 32 random
  /// bytes, built with `expect` rather than the from_multihash check.
  action PeerIdrandom: bool = {
    val bytes: PeerBytes = { code: MULTIHASH_IDENTITY_CODE, digest_len: 32,
                             digest: state.next_peer + 100, well_formed: true }
    all {
      state' = { ...state,
                 peers: state.peers.put(state.next_peer,
                          { code: bytes.code, digest_len: bytes.digest_len,
                            digest: bytes.digest, source: bytes }),
                 next_peer: state.next_peer + 1 },
    }
  }

  /// PeerId::to_bytes (peer/src/lib.rs:110) followed by a re-parse — the
  /// round-trip the serde impls rely on (peer/src/lib.rs:156-200).
  action PeerIdto_bytes(peer: int): bool = {
    val p = state.peers.getOrElse(peer, MISSING_PEER)
    val encoded = peer_to_bytes(p)
    all {
      state.peers.has(peer),
      state' = { ...state,
                 roundtrips_checked: state.roundtrips_checked.union(Set(peer)),
                 roundtrip_failed: state.roundtrip_failed
                   or not(code_is_supported(encoded))
                   or encoded != p.source },
    }
  }

  // --------------------------------------------------------------- step

  action step = any {
    P2pConfigdefault,
    { nondet raw = MESH_RAWS.oneOf()
      GossipSubConfignew(raw) },
    GossipSubConfigadjust,
    { nondet names = CHANNEL_SETS.oneOf()
      ChannelNamesset(names) },
    { nondet names = CHANNEL_SETS.oneOf()
      ChannelNamesvalidate(names) },
    { nondet value = Set(false, true).oneOf()
      bool_from_anything_bool(value) },
    { nondet value = BOOL_STRINGS.oneOf()
      bool_from_anything_str(value) },
    { nondet pubsub_max_size = SIZE_LIMITS.oneOf()
      nondet rpc_max_size = SIZE_LIMITS.oneOf()
      P2pConfigset_message_limits(pubsub_max_size, rpc_max_size) },
    { nondet discovery = DISCOVERY_SETS.oneOf()
      DiscoveryConfigset(discovery) },
    { nondet peers = PEER_SETS.oneOf()
      nondet peers_only = Set(false, true).oneOf()
      P2pConfigset_persistent_peers(peers, peers_only) },
    { nondet timeouts = TIMEOUT_SETS.oneOf()
      TimeoutConfigset(timeouts) },
    { nondet kind = TIMEOUT_KINDS.oneOf()
      nondet rnd = ROUNDS.oneOf()
      timeout_duration_for(kind, rnd) },
    { nondet msg_size = MESSAGE_SIZES.oneOf()
      network_publish_pubsub(msg_size) },
    { nondet msg_size = MESSAGE_SIZES.oneOf()
      network_send_rpc(msg_size) },
    SharedRegistrynew__export,
    { nondet moniker = MONIKERS.oneOf()
      SharedRegistrywith_moniker(moniker) },
    Metricsregister,
    Registryexport,
    { nondet bytes = PEER_BYTES.oneOf()
      PeerIdfrom_bytes(bytes) },
    PeerIdrandom,
    { nondet peer = PEER_HANDLES.oneOf()
      PeerIdto_bytes(peer) },
  }

  // -------------------------------------------------- correctness properties

  /// The gossipsub mesh parameters always satisfy the constraints their own
  /// documentation states: mesh_n_low <= mesh_n <= mesh_n_high, and
  /// mesh_outbound_min is at least 1, at most mesh_n / 2, and below mesh_n_low.
  val gossip_mesh_within_documented_bounds: bool = and {
    state.gossip.mesh_n > 0,
    state.gossip.mesh_n_high >= state.gossip.mesh_n,
    state.gossip.mesh_n_low <= state.gossip.mesh_n,
    state.gossip.mesh_outbound_min >= 1,
    state.gossip.mesh_outbound_min <= state.gossip.mesh_n / 2,
    state.gossip.mesh_outbound_min < state.gossip.mesh_n_low,
  }

  /// Adjusting a gossipsub configuration never subtracts one from a zero
  /// mesh_n_low, which would underflow the unsigned arithmetic and panic.
  val mesh_adjust_never_underflows: bool = not(state.adjust_underflow)

  /// The defaults alone are a complete, usable configuration: valid channel
  /// names, mesh parameters within their bounds, and a pubsub limit that can
  /// carry a proposal.
  val defaults_alone_are_a_valid_configuration: bool =
    state.only_defaults implies and {
      channels_are_distinct_and_named(state.channels),
      gossip_mesh_within_documented_bounds,
      state.pubsub_max_size >= MIN_PROPOSAL_SIZE,
      state.rpc_max_size >= MIN_PROPOSAL_SIZE,
    }

  /// Every message the network layer let through is within the size limit
  /// configured for its transport.
  val accepted_messages_within_configured_limits: bool = and {
    state.accepted_pubsub_sizes.forall(s => s <= state.pubsub_max_size),
    state.accepted_rpc_sizes.forall(s => s <= state.rpc_max_size),
  }

  /// The configured pubsub limit is large enough for a full proposal and no
  /// larger than the transport can carry.
  val pubsub_limit_is_carriable_and_sufficient: bool = and {
    state.pubsub_max_size >= MIN_PROPOSAL_SIZE,
    state.pubsub_max_size <= TRANSPORT_MAX_SIZE,
  }

  /// A node restricted to persistent peers has at least one persistent peer
  /// configured, so it can still connect to the network.
  val peers_only_mode_has_peers: bool =
    state.persistent_peers_only implies state.persistent_peers != Set()

  /// Enabled peer discovery has non-zero limits, so it can actually dial,
  /// request and accept peers.
  val enabled_discovery_has_workable_limits: bool =
    state.discovery.enabled implies and {
      state.discovery.num_outbound_peers > 0,
      state.discovery.max_connections_per_ip > 0,
      state.discovery.max_peers_per_response > 0,
      state.discovery.dial_max_retries > 0,
    }

  /// Every timeout the consensus engine derives from the configuration is
  /// positive and no greater than the configured cap.
  val computed_timeouts_are_positive_and_capped: bool =
    state.computed_timeouts.forall(d => d > 0 and d <= state.timeouts.max_timeout)

  /// A recorded channel-name verdict agrees with the names actually configured.
  val channel_verdict_matches_configured_names: bool =
    match state.channel_verdict {
      | None => true
      | Some(v) => match v {
          | VOk => channels_are_distinct_and_named(state.channels)
          | VEmpty(_) => not(channels_are_distinct_and_named(state.channels))
          | VDuplicate(name) =>
              channel_entries(state.channels).indices().filter(i =>
                channel_entries(state.channels).nth(i)._2 == name).size() > 1
        }
    }

  /// No metric name is registered twice in one registry, which would make the
  /// exported Prometheus output contain duplicate series.
  val metric_names_registered_at_most_once: bool =
    not(list_has_duplicate(state.registered_metrics))

  /// Every peer id re-encodes to exactly the bytes it was parsed from, and
  /// those bytes still parse back into a peer id.
  val peer_ids_round_trip_through_bytes: bool = and {
    not(state.roundtrip_failed),
    state.peers.keys().forall(i => {
      val p = state.peers.get(i)
      peer_to_bytes(p) == p.source and code_is_supported(peer_to_bytes(p))
    }),
  }

  /// Every stored peer id uses a multihash code valid for peer ids, with an
  /// inline key no longer than the inline limit.
  val stored_peer_ids_use_supported_codes: bool =
    state.peers.keys().forall(i => code_is_supported(peer_to_bytes(state.peers.get(i))))

  // ------------------------------------------------------- observations

  /// adjust() replaced a mesh_n of zero with the default of 6.
  val mesh_n_defaulted_from_zero: bool = state.defaulted_mesh_n

  /// adjust() raised mesh_n_high because it was zero or below mesh_n.
  val mesh_n_high_raised_to_twice_mesh_n: bool = state.raised_mesh_n_high

  /// adjust() recomputed mesh_n_low because it was zero or above mesh_n.
  val mesh_n_low_recomputed: bool = state.recomputed_mesh_n_low

  /// adjust() recomputed mesh_outbound_min from the fallback formula.
  val mesh_outbound_min_recomputed: bool = state.recomputed_mesh_outbound_min

  /// adjust() kept the configured mesh_outbound_min untouched.
  val mesh_outbound_min_kept_as_configured: bool = state.kept_mesh_outbound_min

  /// adjust() reached the `mesh_n_low - 1` subtraction with mesh_n_low at zero.
  val adjust_reached_zero_mesh_n_low: bool = state.adjust_underflow

  /// Channel-name validation accepted the configured names.
  val channel_names_validated_ok: bool = state.channel_verdict == Some(VOk)

  /// Channel-name validation rejected a name for being empty.
  val channel_name_rejected_as_empty: bool =
    match state.channel_verdict {
      | Some(v) => match v { | VEmpty(_) => true | _ => false }
      | None => false
    }

  /// Channel-name validation rejected two channels sharing one topic name.
  val channel_names_rejected_as_duplicate: bool =
    match state.channel_verdict {
      | Some(v) => match v { | VDuplicate(_) => true | _ => false }
      | None => false
    }

  /// The lenient bool deserializer read a native TOML boolean.
  val bool_parsed_from_native_bool: bool =
    match state.bool_parse {
      | Some(o) => match o { | PNative(_) => true | _ => false }
      | None => false
    }

  /// The lenient bool deserializer accepted a quoted "true"/"false" string.
  val bool_parsed_from_string: bool =
    match state.bool_parse {
      | Some(o) => match o { | PString(_) => true | _ => false }
      | None => false
    }

  /// The lenient bool deserializer rejected a string that is not a boolean.
  val bool_string_rejected: bool =
    match state.bool_parse {
      | Some(o) => match o { | PError(_) => true | _ => false }
      | None => false
    }

  /// A pubsub message was published at exactly the configured size limit.
  val pubsub_message_accepted_at_limit: bool =
    state.accepted_pubsub_sizes.contains(state.pubsub_max_size)

  /// A pubsub message was refused for exceeding pubsub_max_size.
  val pubsub_message_rejected_as_oversized: bool = state.rejected_oversized_pubsub

  /// A sync RPC message was refused for exceeding rpc_max_size.
  val rpc_message_rejected_as_oversized: bool = state.rejected_oversized_rpc

  /// A pubsub limit was configured below the size of a full proposal.
  val pubsub_limit_below_proposal_size: bool = state.pubsub_max_size < MIN_PROPOSAL_SIZE

  /// A pubsub limit was configured above what the transport can carry.
  val pubsub_limit_above_transport_capacity: bool = state.pubsub_max_size > TRANSPORT_MAX_SIZE

  /// persistent_peers_only was enabled with an empty persistent-peer list.
  val peers_only_enabled_with_no_peers: bool =
    state.persistent_peers_only and state.persistent_peers == Set()

  /// Discovery was enabled with a limit of zero on some dimension.
  val discovery_enabled_with_a_zero_limit: bool =
    state.discovery.enabled and or {
      state.discovery.num_outbound_peers == 0,
      state.discovery.max_connections_per_ip == 0,
      state.discovery.max_peers_per_response == 0,
      state.discovery.dial_max_retries == 0,
    }

  /// A derived timeout was clamped to max_timeout.
  val timeout_clamped_at_max: bool = state.timeout_clamped

  /// A derived timeout came out as zero, so the step expires immediately.
  val zero_timeout_computed: bool = state.computed_timeouts.contains(0)

  /// Two derived timeouts of different lengths were seen, so a timeout grew
  /// with the round number.
  val timeout_grew_with_round: bool = state.computed_timeouts.size() > 1

  /// The metrics registry was created without a moniker label.
  val registry_created_without_moniker: bool =
    state.registry_created and state.registry_moniker == None

  /// The metrics registry carries a moniker label.
  val registry_labelled_with_moniker: bool = state.registry_moniker != None

  /// The consensus metric family was registered.
  val metrics_registered_once: bool = state.registered_metrics != List()

  /// The consensus metric family was registered a second time into the same
  /// registry.
  val metric_registered_twice: bool = list_has_duplicate(state.registered_metrics)

  /// The registry was exported to Prometheus text.
  val registry_exported: bool = state.registry_exported

  /// A peer id was parsed from a sha256 multihash.
  val peer_id_accepted_with_sha256_code: bool =
    state.peers.keys().exists(i => state.peers.get(i).code == MULTIHASH_SHA256_CODE)

  /// A peer id was parsed from an inline (identity) public key.
  val peer_id_accepted_with_inline_identity_key: bool =
    state.peers.keys().exists(i => state.peers.get(i).code == MULTIHASH_IDENTITY_CODE)

  /// A peer id was accepted with an inline key at exactly the inline limit.
  val peer_id_accepted_at_inline_key_limit: bool =
    state.peers.keys().exists(i =>
      state.peers.get(i).code == MULTIHASH_IDENTITY_CODE
        and state.peers.get(i).digest_len == MAX_INLINE_KEY_LENGTH)

  /// Peer-id parsing rejected bytes that are not a valid multihash.
  val peer_id_rejected_as_malformed_multihash: bool =
    state.peer_reject == Some("invalid multihash")

  /// Peer-id parsing rejected a multihash code that is not valid for peer ids,
  /// including an inline key past the inline limit.
  val peer_id_rejected_for_unsupported_code: bool =
    state.peer_reject == Some("unsupported multihash code")

  /// A peer id was re-encoded to bytes and parsed back.
  val peer_id_round_tripped_through_bytes: bool = state.roundtrips_checked != Set()
}
