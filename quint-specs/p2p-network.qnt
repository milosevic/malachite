// P2P Network — libp2p swarm behaviour composition, gossipsub/broadcast pubsub,
// peer classification and scoring, prioritization/eviction, and per-IP inbound
// connection limits.
//
// Code:
//   code/crates/network/src/ip_limits.rs     (per-IP inbound limiter)
//   code/crates/network/src/state.rs         (peer state machine, prioritization)
//   code/crates/network/src/pubsub.rs        (subscribe / publish / mesh peers)
//   code/crates/network/src/peer_type.rs     (validator > persistent > full node)
//   code/crates/network/src/peer_scoring.rs  (application-specific scores)
//   code/crates/network/src/lib.rs:864       (peer_info teardown on full disconnect)
//
// GRANULARITY: fleet. The test map's `instances: "many"` rows (n3f0_pubsub_protocol,
// persistent_peers_only, persistent_peers, ip_limits) run several network nodes inside
// one process and each of them runs modeled operations, so the component's state is
// lifted to `NodeId -> LocalState`. Every action takes the `node` whose State it
// mutates; the wire stage logs that node's moniker as the `node` argument. The nodes
// are independent in this component — the code never lets one node's State read
// another's.

module p2p_network_core {
  import basicSpells.* from "./spells/basicSpells"

  type NodeId = str
  type PeerId = str
  /// A dialable address, carried as the three facts this component derives from a
  /// multiaddr: `base` is strip_peer_id_from_multiaddr, `ip` is ip_limits::extract_ip
  /// and `peer` is extract_peer_id_from_multiaddr. `""` means the multiaddr carries
  /// no such component. The code computes all three, so replay never has to parse.
  type Addr = { base: str, ip: Ip, peer: PeerId }
  type PubKey = str
  type ConsAddr = str
  type Ip = str
  type ConnId = str
  type Channel = str
  /// A pubsub payload, carried as the only fact the component reasons about: the
  /// encoded size checked against pubsub_max_size.
  type Data = { size: int }

  /// Connection direction as classified by the discovery layer. `Ephemeral` is
  /// discovery's third state, reported as `None` in PeerInfo.connection_direction.
  type Direction = Outbound | Inbound | Ephemeral

  /// PubSubProtocol (config): exactly one of the two pubsub behaviours is used.
  type Protocol = GossipSub | Broadcast

  /// ValidatorInfo (state.rs:29) — voting power is irrelevant to this component.
  type Validator = { address: ConsAddr, publicKey: PubKey }

  /// PeerInfo (state.rs:100). `peer_type` is flattened into its two flags, exactly
  /// as PeerType stores them; `primary_type_str` is derived (validator > persistent).
  type PeerInfo = {
    address: Addr,
    consensusAddress: Option[ConsAddr],
    consensusPublicKey: Option[PubKey],
    isValidator: bool,
    isPersistent: bool,
    direction: Option[Direction],
    score: int,
    topics: Set[Channel],
  }

  /// One entry of discovery.connections — what the component reads to learn the
  /// REAL remote address of a connection.
  type Conn = { peer: PeerId, remoteAddr: Addr }

  /// The whole startup payload of Behaviour::new_with_metrics + Config, carried as
  /// one parameter so replay pins the baseline with zero unguided picks.
  type Config = {
    maxConnectionsPerIp: int,
    numInboundPeers: int,
    persistentPeersOnly: bool,
    protocol: Protocol,
    gossipsubEnabled: bool,
    broadcastEnabled: bool,
    pubsubMaxSize: int,
    consensusAddress: ConsAddr,
  }

  type LocalState = {
    started: bool,
    config: Config,

    // ---- ip_limits::Behaviour ----
    connectionIps: ConnId -> Ip,
    connectionsPerIp: Ip -> int,

    // ---- State ----
    validatorSet: Set[Validator],
    localIsValidator: bool,
    persistentPeerAddrs: List[Addr],
    persistentPeerIds: Set[PeerId],
    peers: PeerId -> PeerInfo,
    pendingProofs: PeerId -> PubKey,
    subscribedChannels: Set[Channel],

    // ---- discovery-layer facts this component reads ----
    conns: ConnId -> Conn,
    directions: PeerId -> Direction,
    connected: Set[PeerId],

    // ---- ghosts: latches for behaviour that leaves no visible state trace ----
    published: Set[{ channel: Channel, data: Data }],
    publishedGossipsub: bool,
    publishedBroadcast: bool,
    deniedInbound: Set[ConnId],
    acceptedUntracked: Set[ConnId],
    untrackedOnClose: bool,
    untrackedOnListenFailure: bool,
    untrackedUnknown: bool,
    proofBuffered: Set[PeerId],
    pendingProofApplied: bool,
    proofPromotedValidator: bool,
    proofWithoutValidatorMatch: bool,
    promotedByUpdate: bool,
    demotedByUpdate: bool,
    localBecameValidator: bool,
    localLostValidator: bool,
    promotedWithoutEviction: bool,
    evicted: Set[PeerId],
    evictedHighValue: bool,
    evictionInverted: bool,
    prioritizationBlocked: bool,
    persistentAdded: bool,
    disconnected: Set[PeerId],
    removedWhileInboundKept: bool,
    staleIdRetained: bool,
    addressFromListenAddrs: bool,
    addressFallbackZero: bool,
    keptOutboundAddress: bool,
    peerStateCleaned: bool,
  }

  // ---------------------------------------------------------------- domains ----

  // Identities are projected onto these small per-test index spaces by the
  // instrumentation (`quint_ids` in the network crate): the local node of a
  // swarm becomes "n1", "n2", …; an `ip_limits::Behaviour` instance, which has
  // no peer id of its own, becomes "l1", "l2", …; remote peers "p1", "p2", …;
  // connections "c1", "c2", …; address bases "A1", "A2", …; IPs "i1", "i2", …;
  // consensus addresses "ca1", …; consensus public keys "k1", ….
  pure val SWARM_NODES: Set[NodeId] =
    Set("n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8")

  pure val LIMITER_NODES: Set[NodeId] =
    Set("l1", "l2", "l3", "l4", "l5", "l6", "l7", "l8")

  pure val NODES: Set[NodeId] = SWARM_NODES.union(LIMITER_NODES)

  pure val PEERS: Set[PeerId] =
    Set("p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8")

  pure val KEYS: Set[PubKey] =
    Set("k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10", "k11", "k12")

  /// Channel (channel.rs:27) — the model names channels by their variant.
  pure val CHANNELS: Set[Channel] = Set("Consensus", "Liveness", "ProposalParts", "Sync")

  pure val CONN_IDS: Set[ConnId] = Set(
    "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8",
    "c9", "c10", "c11", "c12", "c13", "c14", "c15", "c16")

  /// Encoded pubsub payload sizes, compared against the configured
  /// `pubsub_max_size`.
  pure val DATA_SIZES: Set[int] = 0.to(20000000)

  /// strip_peer_id_from_multiaddr — two addresses are the same persistent peer
  /// when their bases match.
  pure val ADDR_BASES: Set[str] = Set(
    "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12")

  /// ip_limits::extract_ip — `""` for an address with no ip4/ip6 component.
  pure val IP_SLOTS: Set[Ip] = Set("", "i1", "i2", "i3", "i4")

  /// extract_peer_id_from_multiaddr — `""` unless the address carries /p2p/.
  pure val PEER_SLOTS: Set[PeerId] = Set("").union(PEERS)

  pure val ADDRS: Set[Addr] =
    tuples(ADDR_BASES, IP_SLOTS, PEER_SLOTS).map(((b, i, p)) =>
      { base: b, ip: i, peer: p })

  /// The multiaddr the code falls back to when neither the connection nor
  /// identify offers an address (state.rs:466: "/ip4/0.0.0.0/tcp/0"). It is a
  /// real address, so it is projected like any other.
  pure val ZERO_ADDR: Addr = { base: "A0", ip: "", peer: "" }

  pure def hasIp(a: Addr): bool = a.ip != ""

  pure def hasPeerId(a: Addr): bool = a.peer != ""

  pure def baseOf(a: Addr): str = a.base

  /// Consensus addresses, paired one-to-one with the public key of the same
  /// validator by the instrumentation, so a validator is fully named by its index.
  pure val CONS_ADDRS: Set[ConsAddr] =
    Set("ca1", "ca2", "ca3", "ca4", "ca5", "ca6", "ca7", "ca8")

  pure val CONS_ADDR_SLOTS: Set[ConsAddr] = Set("").union(CONS_ADDRS)

  /// The validator sets consensus can hand down (process_validator_set_update payload).
  pure val ALL_VALIDATORS: Set[Validator] = Set(
    { address: "ca1", publicKey: "k1" },
    { address: "ca2", publicKey: "k2" },
    { address: "ca3", publicKey: "k3" },
    { address: "ca4", publicKey: "k4" },
    { address: "ca5", publicKey: "k5" },
    { address: "ca6", publicKey: "k6" },
    { address: "ca7", publicKey: "k7" },
    { address: "ca8", publicKey: "k8" },
  )

  pure val VALIDATOR_SETS: Set[Set[Validator]] = ALL_VALIDATORS.powerset()

  pure val CHANNEL_SETS: Set[Set[Channel]] = CHANNELS.powerset()

  /// Mesh snapshots gossipsub can report (update_peer_info payload).
  pure val MESH_VIEWS: Set[Channel -> Set[PeerId]] = Set(
    Map("Consensus" -> Set(), "Sync" -> Set()),
    Map("Consensus" -> Set("p1"), "Sync" -> Set()),
    Map("Consensus" -> Set("p1", "p2"), "Sync" -> Set("p1"))
  )

  /// Gossipsub-reported peer scores (absent = keep the current application score).
  pure val SCORE_VIEWS: Set[PeerId -> int] = Set(
    Map(),
    Map("p1" -> 4),
    Map("p1" -> 300, "p2" -> 4)
  )

  /// Identify's self-reported listen_addrs — the spoofing surface. Only the
  /// first entry is ever read, so the instrumentation logs at most one.
  pure val LISTEN_ADDR_LISTS: Set[List[Addr]] =
    Set(List()).union(ADDRS.map(a => List(a)))

  /// Config scalars, each picked on its own so replay pins them independently.
  /// `max_connections_per_ip` and `num_inbound_peers` are plain operator-set
  /// counts (the suite configures 1..200), so the domains are wide intervals.
  pure val CONN_LIMITS: Set[int] = 0.to(4096)

  pure val INBOUND_SLOTS: Set[int] = 0.to(4096)

  // ------------------------------------------------------- peer_scoring.rs ----

  pure val VALIDATOR_SCORE: int = 200
  pure val PERSISTENT_PEER_SCORE: int = 100
  pure val FULL_NODE_SCORE: int = 4

  /// peer_scoring::get_peer_score — validator wins over persistent.
  pure def peerScore(isValidator: bool, isPersistent: bool): int =
    if (isValidator) VALIDATOR_SCORE
    else if (isPersistent) PERSISTENT_PEER_SCORE
    else FULL_NODE_SCORE

  // -------------------------------------------------------------- configs ----

  pure val NULL_CONFIG: Config =
    { maxConnectionsPerIp: 0, numInboundPeers: 0,
      persistentPeersOnly: false, protocol: GossipSub, gossipsubEnabled: false,
      broadcastEnabled: false, pubsubMaxSize: 0, consensusAddress: "" }

  // --------------------------------------------------------- list helpers ----

  pure def listContains(l: List[Addr], x: Addr): bool =
    l.foldl(false, (acc, a) => acc or a == x)

  /// Vec::remove(position) — drops the FIRST occurrence only.
  pure def listRemoveFirst(l: List[Addr], x: Addr): List[Addr] =
    l.foldl({ out: List(), done: false }, (acc, a) =>
      if (not(acc.done) and a == x) { out: acc.out, done: true }
      else { out: acc.out.append(a), done: acc.done }).out

  // ------------------------------------------------------- initial states ----

  pure val unstarted: LocalState = {
    started: false, config: NULL_CONFIG,
    connectionIps: Map(), connectionsPerIp: Map(),
    validatorSet: Set(), localIsValidator: false,
    persistentPeerAddrs: List(), persistentPeerIds: Set(),
    peers: Map(), pendingProofs: Map(), subscribedChannels: Set(),
    conns: Map(), directions: Map(), connected: Set(),
    published: Set(), publishedGossipsub: false, publishedBroadcast: false,
    deniedInbound: Set(), acceptedUntracked: Set(),
    untrackedOnClose: false, untrackedOnListenFailure: false, untrackedUnknown: false,
    proofBuffered: Set(), pendingProofApplied: false,
    proofPromotedValidator: false, proofWithoutValidatorMatch: false,
    promotedByUpdate: false, demotedByUpdate: false,
    localBecameValidator: false, localLostValidator: false,
    promotedWithoutEviction: false, evicted: Set(), evictedHighValue: false,
    evictionInverted: false,
    prioritizationBlocked: false, persistentAdded: false,
    disconnected: Set(), removedWhileInboundKept: false, staleIdRetained: false,
    addressFromListenAddrs: false, addressFallbackZero: false,
    keptOutboundAddress: false, peerStateCleaned: false,
  }

  /// State::new + LocalNodeInfo construction (state.rs:324, lib.rs:386-418):
  /// persistent peer ids are seeded from the configured addresses that carry /p2p/.
  pure def baselineFrom(config: Config): LocalState = {
    ...unstarted,
    started: true,
    config: config,
  }

  /// One iteration of the constructor loop that seeds a configured persistent
  /// peer address (state.rs:334, ip_limits.rs:84): the address is recorded, and
  /// its /p2p/ identity, when it carries one, becomes a known persistent peer id.
  pure def applyConfigurePersistentPeer(s: LocalState, addr: Addr): LocalState =
    { ...s,
      persistentPeerAddrs: s.persistentPeerAddrs.append(addr),
      persistentPeerIds:
        if (hasPeerId(addr)) s.persistentPeerIds.union(Set(addr.peer))
        else s.persistentPeerIds }

  // --------------------------------------------------------- ip_limits.rs ----

  /// handle_pending_inbound_connection (ip_limits.rs:184-230). Four arms: an address
  /// with no IP component is accepted and NOT tracked, a tracked IP at the limit is
  /// denied, a non-persistent IP still inside its reconnect cooldown is denied, and
  /// otherwise the connection is counted immediately (before the handshake).
  pure def applyPendingInbound(
    s: LocalState, remote_addr: Addr, connection_id: ConnId, throttled: bool
  ): LocalState =
    if (not(hasIp(remote_addr)))
      { ...s, acceptedUntracked: s.acceptedUntracked.union(Set(connection_id)) }
    else {
      val ip = remote_addr.ip
      val count = s.connectionsPerIp.getOrElse(ip, 0)
      if (count >= s.config.maxConnectionsPerIp)
        { ...s, deniedInbound: s.deniedInbound.union(Set(connection_id)) }
      else if (throttled)
        // reconnect throttle (ip_limits.rs:206-224): the cooldown itself is wall
        // clock, so the code hands the model its own verdict for this attempt.
        s
      else
        { ...s,
          connectionIps: s.connectionIps.put(connection_id, ip),
          connectionsPerIp: s.connectionsPerIp.put(ip, count + 1) }
    }

  /// untrack_connection (ip_limits.rs:57-67). Unknown connection ids are ignored;
  /// the per-IP entry is dropped once its saturating count reaches zero.
  pure def applyUntrack(s: LocalState, connection_id: ConnId, onClose: bool): LocalState =
    if (not(s.connectionIps.has(connection_id)))
      { ...s, untrackedUnknown: true }
    else {
      val ip = s.connectionIps.get(connection_id)
      val c = s.connectionsPerIp.getOrElse(ip, 0)
      val newCount = if (c - 1 < 0) 0 else c - 1
      { ...s,
        connectionIps: s.connectionIps.mapRemove(connection_id),
        connectionsPerIp:
          if (newCount == 0) s.connectionsPerIp.mapRemove(ip)
          else s.connectionsPerIp.put(ip, newCount),
        untrackedOnClose: s.untrackedOnClose or onClose,
        untrackedOnListenFailure: s.untrackedOnListenFailure or not(onClose) }
    }

  // ------------------------------------------------ classification helpers ----

  /// ValidatorInfo::address_for_public_key over the whole set (state.rs:40).
  pure def validatorAddressFor(vset: Set[Validator], key: PubKey): Option[ConsAddr] =
    match vset.find(v => v.publicKey == key) {
      | None => None
      | Some(v) => Some(v.address)
    }

  /// is_persistent_peer_by_address (state.rs:363-382) — compares the REAL remote
  /// address of the connection against the configured persistent addresses. A
  /// connection discovery does not know about is never persistent.
  pure def isPersistentByAddress(s: LocalState, connection_id: ConnId): bool =
    if (not(s.conns.has(connection_id))) false
    else {
      val remoteBase = baseOf(s.conns.get(connection_id).remoteAddr)
      s.persistentPeerAddrs.foldl(false, (acc, pa) => acc or baseOf(pa) == remoteBase)
    }

  /// is_persistent_peer (state.rs:349-356).
  pure def isPersistentPeer(s: LocalState, peer_id: PeerId, connection_id: ConnId): bool =
    s.persistentPeerIds.contains(peer_id) or isPersistentByAddress(s, connection_id)

  /// PeerInfo.connection_direction: discovery's Ephemeral is recorded as None.
  pure def recordedDirection(s: LocalState, peer_id: PeerId): Option[Direction] =
    if (not(s.directions.has(peer_id))) None
    else {
      val d = s.directions.get(peer_id)
      if (d == Ephemeral) None else Some(d)
    }

  pure def isEphemeral(s: LocalState, peer_id: PeerId): bool =
    s.directions.has(peer_id) and s.directions.get(peer_id) == Ephemeral

  pure def inboundCount(s: LocalState): int =
    s.directions.keys().filter(p => s.directions.get(p) == Inbound).size()

  pure def hasInboundCapacity(s: LocalState): bool =
    inboundCount(s) < s.config.numInboundPeers

  /// find_lowest_priority_inbound_peer (state.rs:748-757): only non-validator,
  /// non-persistent inbound peers are candidates, lowest score wins. Rust breaks
  /// score ties by iteration order; the model breaks them by fold order.
  pure def lowestPriorityInbound(s: LocalState): Option[PeerId] = {
    val candidates = s.directions.keys().filter(p =>
      s.directions.get(p) == Inbound and s.peers.has(p)
        and not(s.peers.get(p).isValidator) and not(s.peers.get(p).isPersistent))
    val seed: Option[PeerId] = None
    candidates.fold(seed, (acc, p) =>
      match acc {
        | None => Some(p)
        | Some(q) => if (s.peers.get(p).score < s.peers.get(q).score) Some(p) else Some(q)
      })
  }

  // ---------------------------------------------------- State transitions ----

  /// record_verified_proof (state.rs:283-322). The signature was already verified
  /// outside this component. An unknown peer's proof is BUFFERED, not dropped.
  pure def applyRecordVerifiedProof(s: LocalState, peer_id: PeerId, public_key: PubKey): LocalState =
    if (not(s.peers.has(peer_id)))
      { ...s,
        pendingProofs: s.pendingProofs.put(peer_id, public_key),
        proofBuffered: s.proofBuffered.union(Set(peer_id)) }
    else {
      val peer = s.peers.get(peer_id)
      val validatorAddress = validatorAddressFor(s.validatorSet, public_key)
      val isValidator = validatorAddress != None
      { ...s,
        peers: s.peers.put(peer_id, { ...peer,
          consensusPublicKey: Some(public_key),
          consensusAddress: validatorAddress,
          isValidator: isValidator,
          score: peerScore(isValidator, peer.isPersistent) }),
        proofPromotedValidator: s.proofPromotedValidator or isValidator,
        proofWithoutValidatorMatch: s.proofWithoutValidatorMatch or not(isValidator) }
    }

  /// reclassify_peers (state.rs:216-268): only peers holding a stored proof are
  /// re-evaluated; consensus_address is set when in the set and cleared when not.
  pure def applyReclassifyPeers(s: LocalState): LocalState = {
    val newPeers = s.peers.keys().mapBy(p => {
      val peer = s.peers.get(p)
      match peer.consensusPublicKey {
        | None => peer
        | Some(key) => {
          val validatorAddress = validatorAddressFor(s.validatorSet, key)
          val isValidator = validatorAddress != None
          { ...peer, consensusAddress: validatorAddress, isValidator: isValidator,
                     score: peerScore(isValidator, peer.isPersistent) }
        }
      }
    })
    { ...s,
      peers: newPeers,
      promotedByUpdate: s.promotedByUpdate or
        s.peers.keys().exists(p => not(s.peers.get(p).isValidator) and newPeers.get(p).isValidator),
      demotedByUpdate: s.demotedByUpdate or
        s.peers.keys().exists(p => s.peers.get(p).isValidator and not(newPeers.get(p).isValidator)) }
  }

  /// reclassify_local_node (state.rs:191-212): the LOCAL node is matched by its
  /// configured consensus ADDRESS, not by a verified public key.
  pure def applyReclassifyLocalNode(s: LocalState): LocalState = {
    val nowValidator =
      s.config.consensusAddress != "" and
      s.validatorSet.exists(v => v.address == s.config.consensusAddress)
    { ...s,
      localIsValidator: nowValidator,
      localBecameValidator: s.localBecameValidator or (not(s.localIsValidator) and nowValidator),
      localLostValidator: s.localLostValidator or (s.localIsValidator and not(nowValidator)) }
  }

  /// process_validator_set_update (state.rs:178-189).
  pure def applyValidatorSetUpdate(s: LocalState, new_validators: Set[Validator]): LocalState =
    applyReclassifyPeers(applyReclassifyLocalNode({ ...s, validatorSet: new_validators }))

  /// try_prioritize_peer (state.rs:688-745): promote an ephemeral validator or
  /// persistent peer to inbound, evicting the lowest-scoring evictable inbound peer
  /// first when inbound slots are full. Returns without any change when no
  /// evictable peer exists.
  pure def applyTryPrioritize(s: LocalState, peer_id: PeerId): LocalState =
    if (not(s.peers.has(peer_id))) s
    else {
      val peer = s.peers.get(peer_id)
      if (not(peer.isValidator) and not(peer.isPersistent)) s
      else if (not(isEphemeral(s, peer_id))) s
      else {
        val roomy = hasInboundCapacity(s)
        val victim = if (roomy) None else lowestPriorityInbound(s)
        if (not(roomy) and victim == None)
          { ...s, prioritizationBlocked: true }
        else {
          val afterEvict =
            match victim {
              | None => { ...s, promotedWithoutEviction: true }
              | Some(e) =>
                { ...s,
                  directions: s.directions.mapRemove(e),
                  connected: s.connected.exclude(Set(e)),
                  evicted: s.evicted.union(Set(e)),
                  evictedHighValue: s.evictedHighValue or
                    (s.peers.has(e) and (s.peers.get(e).isValidator or s.peers.get(e).isPersistent)),
                  evictionInverted: s.evictionInverted or
                    (s.peers.has(e) and s.peers.get(e).score >= peer.score) }
            }
          { ...afterEvict,
            directions: afterEvict.directions.put(peer_id, Inbound),
            peers: afterEvict.peers.put(peer_id,
              { ...afterEvict.peers.get(peer_id), direction: Some(Inbound) }) }
        }
      }
    }

  /// update_peer (state.rs:428-528). The address comes from the connection's real
  /// remote address; identify's self-reported listen_addrs are only a fallback.
  pure def applyUpdatePeer(
    s: LocalState, peer_id: PeerId, connection_id: ConnId, listen_addrs: List[Addr]
  ): LocalState = {
    val isPersistent = isPersistentPeer(s, peer_id, connection_id)
    val s1 =
      if (isPersistent) { ...s, persistentPeerIds: s.persistentPeerIds.union(Set(peer_id)) }
      else s
    val fromConn = s.conns.has(connection_id)
    val address =
      if (fromConn) s.conns.get(connection_id).remoteAddr
      else if (listen_addrs.length() > 0) listen_addrs.head()
      else ZERO_ADDR
    val direction = recordedDirection(s, peer_id)
    val s2 = { ...s1,
      addressFromListenAddrs: s1.addressFromListenAddrs or (not(fromConn) and listen_addrs.length() > 0),
      addressFallbackZero: s1.addressFallbackZero or (not(fromConn) and listen_addrs.length() == 0) }
    if (s2.peers.has(peer_id)) {
      val existing = s2.peers.get(peer_id)
      val preferNew = direction == Some(Outbound) or existing.direction != Some(Outbound)
      val moved = if (preferNew) { ...existing, address: address, direction: direction } else existing
      { ...s2,
        peers: s2.peers.put(peer_id,
          { ...moved, isPersistent: isPersistent,
                      score: peerScore(moved.isValidator, isPersistent) }),
        keptOutboundAddress: s2.keptOutboundAddress or not(preferNew) }
    } else {
      val fresh = {
        address: address, consensusAddress: None, consensusPublicKey: None,
        isValidator: false, isPersistent: isPersistent, direction: direction,
        score: peerScore(false, isPersistent), topics: Set() }
      val s3 = { ...s2, peers: s2.peers.put(peer_id, fresh) }
      if (s3.pendingProofs.has(peer_id))
        applyRecordVerifiedProof(
          { ...s3, pendingProofs: s3.pendingProofs.mapRemove(peer_id), pendingProofApplied: true },
          peer_id, s3.pendingProofs.get(peer_id))
      else s3
    }
  }

  /// update_peer_persistent_status (state.rs:558-585) — flips the persistent flag
  /// and recomputes the gossipsub application score, preserving validator status.
  pure def setPersistentStatus(s: LocalState, peer_id: PeerId, isPersistent: bool): LocalState =
    if (not(s.peers.has(peer_id))) s
    else {
      val peer = s.peers.get(peer_id)
      { ...s, peers: s.peers.put(peer_id,
          { ...peer, isPersistent: isPersistent,
                     score: peerScore(peer.isValidator, isPersistent) }) }
    }

  /// add_persistent_peer (state.rs:588-632).
  pure def applyAddPersistentPeer(s: LocalState, addr: Addr): LocalState = {
    val s1 =
      if (not(hasPeerId(addr))) s
      else {
        val pid = addr.peer
        val withId = { ...s, persistentPeerIds: s.persistentPeerIds.union(Set(pid)) }
        applyTryPrioritize(setPersistentStatus(withId, pid, true), pid)
      }
    { ...s1,
      persistentPeerAddrs: s1.persistentPeerAddrs.append(addr),
      persistentAdded: true }
  }

  /// discovery.get_peer_id_for_addr — the peer id is only known once a connection
  /// to that address was actually established.
  pure def discoveryPeerIdForAddr(s: LocalState, addr: Addr): Option[PeerId] =
    match s.conns.keys().find(c => baseOf(s.conns.get(c).remoteAddr) == baseOf(addr)) {
      | None => None
      | Some(c) => Some(s.conns.get(c).peer)
    }

  /// remove_persistent_peer (state.rs:635-684). The persistent-peer ID set is only
  /// cleaned when discovery can resolve the address to a peer id.
  pure def applyRemovePersistentPeer(s: LocalState, addr: Addr): LocalState = {
    val s0 = { ...s, persistentPeerAddrs: listRemoveFirst(s.persistentPeerAddrs, addr) }
    match discoveryPeerIdForAddr(s0, addr) {
      | None =>
        { ...s0,
          staleIdRetained: s0.staleIdRetained or
            (hasPeerId(addr) and s0.persistentPeerIds.contains(addr.peer)) }
      | Some(pid) => {
        val s1 = setPersistentStatus(
          { ...s0, persistentPeerIds: s0.persistentPeerIds.exclude(Set(pid)) }, pid, false)
        val isInbound = s1.directions.has(pid) and s1.directions.get(pid) == Inbound
        val shouldDisconnect = s1.config.persistentPeersOnly or not(isInbound)
        if (s1.connected.contains(pid) and shouldDisconnect)
          { ...s1,
            connected: s1.connected.exclude(Set(pid)),
            disconnected: s1.disconnected.union(Set(pid)) }
        else
          { ...s1, removedWhileInboundKept: s1.removedWhileInboundKept or s1.connected.contains(pid) }
      }
    }
  }

  /// update_peer_info (state.rs:383-425): refresh mesh membership and, when
  /// gossipsub reports one, the peer's score.
  pure def applyUpdatePeerInfo(
    s: LocalState, mesh: Channel -> Set[PeerId], scores: PeerId -> int
  ): LocalState =
    { ...s, peers: s.peers.keys().mapBy(p => {
        val peer = s.peers.get(p)
        { ...peer,
          score: scores.getOrElse(p, peer.score),
          topics: mesh.keys().filter(c => mesh.get(c).contains(p)) }
      }) }

  /// The full-disconnect teardown at lib.rs:859-868: PeerInfo and any buffered proof
  /// are dropped. Note that persistent_peer_ids is deliberately NOT touched here.
  pure def applyPeerDisconnected(s: LocalState, peer_id: PeerId): LocalState =
    { ...s,
      peers: s.peers.mapRemove(peer_id),
      pendingProofs: s.pendingProofs.mapRemove(peer_id),
      directions: s.directions.mapRemove(peer_id),
      connected: s.connected.exclude(Set(peer_id)),
      conns: s.conns.keys()
        .filter(c => s.conns.get(c).peer != peer_id)
        .mapBy(c => s.conns.get(c)),
      peerStateCleaned: true }

  // ------------------------------------------------------------- pubsub.rs ----

  /// The pubsub behaviour for `protocol` is composed into the swarm
  /// (behaviour.rs:107); pubsub::subscribe/publish return an error otherwise.
  pure def protocolEnabled(s: LocalState, protocol: Protocol): bool =
    match protocol {
      | GossipSub => s.config.gossipsubEnabled
      | Broadcast => s.config.broadcastEnabled
    }

  /// get_mesh_peers (pubsub.rs:66) — a pure query; empty when gossipsub is off.
  pure def meshPeers(s: LocalState, channel: Channel): Set[PeerId] =
    if (not(s.config.gossipsubEnabled)) Set()
    else s.peers.keys().filter(p => s.peers.get(p).topics.contains(channel))

  pure def applySubscribe(s: LocalState, channels: Set[Channel]): LocalState =
    { ...s, subscribedChannels: s.subscribedChannels.union(channels) }

  pure def applyPublish(s: LocalState, protocol: Protocol, channel: Channel, data: Data): LocalState =
    { ...s,
      published: s.published.union(Set({ channel: channel, data: data })),
      publishedGossipsub: s.publishedGossipsub or protocol == GossipSub,
      publishedBroadcast: s.publishedBroadcast or protocol == Broadcast }
}

module p2p_network {
  import basicSpells.* from "./spells/basicSpells"
  import p2p_network_core.*

  var nodes: NodeId -> LocalState

  action init = all {
    nodes' = Map(),
  }

  // ------------------------------------------------------------ operations ----

  /// Behaviour::new_with_metrics + State::new (behaviour.rs:107, state.rs:324):
  /// installs the node's whole startup configuration as its baseline state.
  action Behaviournew_with_metrics(
    node: NodeId,
    max_connections_per_ip: int,
    num_inbound_peers: int,
    persistent_peers_only: bool,
    protocol: Protocol,
    gossipsub_enabled: bool,
    broadcast_enabled: bool,
    pubsub_max_size: int,
    consensus_address: ConsAddr
  ): bool = all {
    not(nodes.has(node)),
    nodes' = nodes.put(node, baselineFrom({
      maxConnectionsPerIp: max_connections_per_ip,
      numInboundPeers: num_inbound_peers,
      persistentPeersOnly: persistent_peers_only,
      protocol: protocol,
      gossipsubEnabled: gossipsub_enabled,
      broadcastEnabled: broadcast_enabled,
      pubsubMaxSize: pubsub_max_size,
      consensusAddress: consensus_address,
    })),
  }

  /// One configured persistent peer address, seeded by the constructor loop.
  action Stateconfigure_persistent_peer(node: NodeId, addr: Addr): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyConfigurePersistentPeer(nodes.get(node), addr)),
  }

  /// pubsub::subscribe (pubsub.rs:7) — errors out when the protocol's behaviour is
  /// not composed into the swarm.
  action pubsubsubscribe(node: NodeId, protocol: Protocol, channels: Set[Channel]): bool = all {
    nodes.has(node),
    protocolEnabled(nodes.get(node), protocol),
    nodes' = nodes.put(node, applySubscribe(nodes.get(node), channels)),
  }

  /// pubsub::publish (pubsub.rs:38) — the payload must fit pubsub_max_size
  /// (behaviour.rs:227), and gossipsub refuses to publish with an empty mesh.
  action pubsubpublish(
    node: NodeId, protocol: Protocol, channel: Channel, data_size: int
  ): bool = all {
    nodes.has(node),
    protocolEnabled(nodes.get(node), protocol),
    data_size <= nodes.get(node).config.pubsubMaxSize,
    protocol == Broadcast or meshPeers(nodes.get(node), channel).size() > 0,
    nodes' = nodes.put(node,
      applyPublish(nodes.get(node), protocol, channel, { size: data_size })),
  }

  /// State::process_validator_set_update (state.rs:178).
  action Stateprocess_validator_set_update(node: NodeId, new_validators: Set[Validator]): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyValidatorSetUpdate(nodes.get(node), new_validators)),
  }

  /// State::record_verified_proof (state.rs:283).
  action Staterecord_verified_proof(node: NodeId, peer_id: PeerId, public_key: PubKey): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyRecordVerifiedProof(nodes.get(node), peer_id, public_key)),
  }

  /// State::update_peer (state.rs:437) — driven by an Identify event.
  action Stateupdate_peer(
    node: NodeId, peer_id: PeerId, connection_id: ConnId, listen_addrs: List[Addr]
  ): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyUpdatePeer(nodes.get(node), peer_id, connection_id, listen_addrs)),
  }

  /// State::add_persistent_peer (state.rs:589) — AlreadyExists when the address is
  /// already configured.
  action Stateadd_persistent_peer(node: NodeId, addr: Addr): bool = all {
    nodes.has(node),
    not(listContains(nodes.get(node).persistentPeerAddrs, addr)),
    nodes' = nodes.put(node, applyAddPersistentPeer(nodes.get(node), addr)),
  }

  /// State::remove_persistent_peer (state.rs:636) — NotFound when the address is not
  /// in the persistent peer list.
  action Stateremove_persistent_peer(node: NodeId, addr: Addr): bool = all {
    nodes.has(node),
    listContains(nodes.get(node).persistentPeerAddrs, addr),
    nodes' = nodes.put(node, applyRemovePersistentPeer(nodes.get(node), addr)),
  }

  /// State::try_prioritize_peer (state.rs:688).
  action Statetry_prioritize_peer(node: NodeId, peer_id: PeerId): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyTryPrioritize(nodes.get(node), peer_id)),
  }

  /// State::update_peer_info (state.rs:383) — periodic gossipsub score/mesh refresh.
  action Stateupdate_peer_info(
    node: NodeId, mesh: Channel -> Set[PeerId], scores: PeerId -> int
  ): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyUpdatePeerInfo(nodes.get(node), mesh, scores)),
  }

  /// ip_limits::Behaviour::handle_pending_inbound_connection (ip_limits.rs:75).
  action ip_limitshandle_pending_inbound_connection(
    node: NodeId, connection_id: ConnId, remote_addr: Addr, throttled: bool
  ): bool = all {
    nodes.has(node),
    not(nodes.get(node).connectionIps.has(connection_id)),
    nodes' = nodes.put(node,
      applyPendingInbound(nodes.get(node), remote_addr, connection_id, throttled)),
  }

  /// FromSwarm::ConnectionClosed -> untrack_connection (ip_limits.rs:120).
  action ip_limitsconnection_closed(node: NodeId, connection_id: ConnId): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyUntrack(nodes.get(node), connection_id, true)),
  }

  /// FromSwarm::ListenFailure -> untrack_connection (ip_limits.rs:123).
  action ip_limitslisten_failure(node: NodeId, connection_id: ConnId): bool = all {
    nodes.has(node),
    nodes' = nodes.put(node, applyUntrack(nodes.get(node), connection_id, false)),
  }

  /// The full-disconnect teardown of peer state (lib.rs:859).
  action Stateremove_peer_on_disconnect(node: NodeId, peer_id: PeerId): bool = all {
    nodes.has(node),
    nodes.get(node).connected.contains(peer_id),
    nodes' = nodes.put(node, applyPeerDisconnected(nodes.get(node), peer_id)),
  }

  // --------------------------------------------------------- environment ----

  /// Sim-side only: the discovery layer records an established connection with its
  /// real remote address and its inbound/outbound/ephemeral classification. This is
  /// the precondition the modeled State operations read; it has no log site of its
  /// own in this component.
  action envconnection_established(
    node: NodeId, connection_id: ConnId, peer_id: PeerId, remote_addr: Addr, direction: Direction
  ): bool = all {
    nodes.has(node),
    not(nodes.get(node).conns.has(connection_id)),
    nodes' = nodes.put(node, { ...nodes.get(node),
      conns: nodes.get(node).conns.put(connection_id, { peer: peer_id, remoteAddr: remote_addr }),
      directions: nodes.get(node).directions.put(peer_id, direction),
      connected: nodes.get(node).connected.union(Set(peer_id)) }),
  }

  // ---------------------------------------------------------------- step ----

  action step = any {
    { nondet node = NODES.oneOf()
      nondet max_connections_per_ip = CONN_LIMITS.oneOf()
      nondet num_inbound_peers = INBOUND_SLOTS.oneOf()
      nondet persistent_peers_only = Set(false, true).oneOf()
      nondet protocol = Set(GossipSub, Broadcast).oneOf()
      nondet gossipsub_enabled = Set(false, true).oneOf()
      nondet broadcast_enabled = Set(false, true).oneOf()
      nondet pubsub_max_size = DATA_SIZES.oneOf()
      nondet consensus_address = CONS_ADDR_SLOTS.oneOf()
      Behaviournew_with_metrics(node, max_connections_per_ip, num_inbound_peers,
        persistent_peers_only, protocol, gossipsub_enabled, broadcast_enabled,
        pubsub_max_size, consensus_address) },

    { nondet node = NODES.oneOf()
      nondet addr = ADDRS.oneOf()
      Stateconfigure_persistent_peer(node, addr) },

    { nondet node = NODES.oneOf()
      nondet protocol = Set(GossipSub, Broadcast).oneOf()
      nondet channels = CHANNEL_SETS.oneOf()
      pubsubsubscribe(node, protocol, channels) },

    { nondet node = NODES.oneOf()
      nondet protocol = Set(GossipSub, Broadcast).oneOf()
      nondet channel = CHANNELS.oneOf()
      nondet data_size = DATA_SIZES.oneOf()
      pubsubpublish(node, protocol, channel, data_size) },

    { nondet node = NODES.oneOf()
      nondet new_validators = VALIDATOR_SETS.oneOf()
      Stateprocess_validator_set_update(node, new_validators) },

    { nondet node = NODES.oneOf()
      nondet peer_id = PEERS.oneOf()
      nondet public_key = KEYS.oneOf()
      Staterecord_verified_proof(node, peer_id, public_key) },

    { nondet node = NODES.oneOf()
      nondet peer_id = PEERS.oneOf()
      nondet connection_id = CONN_IDS.oneOf()
      nondet listen_addrs = LISTEN_ADDR_LISTS.oneOf()
      Stateupdate_peer(node, peer_id, connection_id, listen_addrs) },

    { nondet node = NODES.oneOf()
      nondet addr = ADDRS.oneOf()
      Stateadd_persistent_peer(node, addr) },

    { nondet node = NODES.oneOf()
      nondet addr = ADDRS.oneOf()
      Stateremove_persistent_peer(node, addr) },

    { nondet node = NODES.oneOf()
      nondet peer_id = PEERS.oneOf()
      Statetry_prioritize_peer(node, peer_id) },

    { nondet node = NODES.oneOf()
      nondet mesh = MESH_VIEWS.oneOf()
      nondet scores = SCORE_VIEWS.oneOf()
      Stateupdate_peer_info(node, mesh, scores) },

    { nondet node = NODES.oneOf()
      nondet connection_id = CONN_IDS.oneOf()
      nondet remote_addr = ADDRS.oneOf()
      nondet throttled = Set(false, true).oneOf()
      ip_limitshandle_pending_inbound_connection(node, connection_id, remote_addr, throttled) },

    { nondet node = NODES.oneOf()
      nondet connection_id = CONN_IDS.oneOf()
      ip_limitsconnection_closed(node, connection_id) },

    { nondet node = NODES.oneOf()
      nondet connection_id = CONN_IDS.oneOf()
      ip_limitslisten_failure(node, connection_id) },

    { nondet node = NODES.oneOf()
      nondet peer_id = PEERS.oneOf()
      Stateremove_peer_on_disconnect(node, peer_id) },

    { nondet node = NODES.oneOf()
      nondet connection_id = CONN_IDS.oneOf()
      nondet peer_id = PEERS.oneOf()
      nondet remote_addr = ADDRS.oneOf()
      nondet direction = Set(Outbound, Inbound, Ephemeral).oneOf()
      envconnection_established(node, connection_id, peer_id, remote_addr, direction) },
  }

  // --------------------------------------------- correctness properties ----

  /// Inbound connections counted for one IP never exceed max_connections_per_ip.
  val inbound_connections_per_ip_within_limit: bool =
    nodes.keys().forall(n => {
      val s = nodes.get(n)
      s.connectionsPerIp.keys().forall(ip =>
        s.connectionsPerIp.get(ip) <= s.config.maxConnectionsPerIp)
    })

  /// Each per-IP counter equals the number of inbound connections tracked for that IP.
  val ip_counters_match_tracked_connections: bool =
    nodes.keys().forall(n => {
      val s = nodes.get(n)
      s.connectionsPerIp.keys().forall(ip =>
        s.connectionsPerIp.get(ip) ==
          s.connectionIps.keys().filter(c => s.connectionIps.get(c) == ip).size())
    })

  /// A peer counts as a validator exactly when its recorded consensus public key
  /// belongs to a validator in the current validator set.
  val peer_classification_matches_validator_set: bool =
    nodes.keys().forall(n => {
      val s = nodes.get(n)
      s.peers.keys().forall(p => {
        val peer = s.peers.get(p)
        match peer.consensusPublicKey {
          | None => not(peer.isValidator)
          | Some(key) =>
            peer.isValidator == (validatorAddressFor(s.validatorSet, key) != None)
              and peer.consensusAddress == validatorAddressFor(s.validatorSet, key)
        }
      })
    })

  /// An evicted peer scored strictly below the peer it made room for.
  val eviction_victim_scores_below_promoted_peer: bool =
    nodes.keys().forall(n => not(nodes.get(n).evictionInverted))

  /// Prioritizing one peer never evicts a validator or a persistent peer.
  val eviction_spares_validators_and_persistent_peers: bool =
    nodes.keys().forall(n => not(nodes.get(n).evictedHighValue))

  /// Every peer id held as persistent is backed by a currently configured persistent
  /// address.
  val persistent_ids_backed_by_configured_addresses: bool =
    nodes.keys().forall(n => {
      val s = nodes.get(n)
      s.persistentPeerIds.forall(pid =>
        s.persistentPeerAddrs.foldl(false, (acc, a) =>
          acc or (hasPeerId(a) and a.peer == pid)
              or (s.conns.keys().exists(c =>
                    s.conns.get(c).peer == pid and baseOf(s.conns.get(c).remoteAddr) == baseOf(a)))))
    })

  /// A peer marked persistent has a real connection whose remote address is a
  /// configured persistent address, or a peer id configured as persistent.
  val persistent_status_not_from_self_reported_address: bool =
    nodes.keys().forall(n => {
      val s = nodes.get(n)
      s.peers.keys().forall(p =>
        not(s.peers.get(p).isPersistent) or
          s.persistentPeerIds.contains(p) or
          s.conns.keys().exists(c =>
            s.conns.get(c).peer == p and
              s.persistentPeerAddrs.foldl(false, (acc, a) =>
                acc or baseOf(a) == baseOf(s.conns.get(c).remoteAddr))))
    })

  /// The local node counts as a validator exactly when its configured consensus
  /// address is in the current validator set.
  val local_validator_status_matches_validator_set: bool =
    nodes.keys().forall(n => {
      val s = nodes.get(n)
      s.localIsValidator ==
        (s.config.consensusAddress != "" and
          s.validatorSet.exists(v => v.address == s.config.consensusAddress))
    })

  // ------------------------------------------------------- observations ----

  /// An inbound connection was refused because its IP was already at the limit.
  val inbound_connection_denied_at_ip_limit: bool =
    nodes.keys().exists(n => nodes.get(n).deniedInbound.size() > 0)

  /// An inbound connection was accepted without being counted, because its remote
  /// address carried no IP component.
  val inbound_connection_accepted_without_ip_tracking: bool =
    nodes.keys().exists(n => nodes.get(n).acceptedUntracked.size() > 0)

  /// A per-IP slot was released by a closed connection.
  val ip_slot_released_on_connection_closed: bool =
    nodes.keys().exists(n => nodes.get(n).untrackedOnClose)

  /// A per-IP slot was released by a failed inbound handshake.
  val ip_slot_released_on_listen_failure: bool =
    nodes.keys().exists(n => nodes.get(n).untrackedOnListenFailure)

  /// An untrack for a connection the limiter never counted was ignored.
  val untrack_of_unknown_connection_ignored: bool =
    nodes.keys().exists(n => nodes.get(n).untrackedUnknown)

  /// A verified proof made a known peer a validator.
  val proof_promoted_peer_to_validator: bool =
    nodes.keys().exists(n => nodes.get(n).proofPromotedValidator)

  /// A verified proof was stored for a peer that is not in the current validator set.
  val proof_recorded_without_validator_set_match: bool =
    nodes.keys().exists(n => nodes.get(n).proofWithoutValidatorMatch)

  /// A verified proof arrived before Identify and was buffered.
  val verified_proof_buffered_before_identify: bool =
    nodes.keys().exists(n => nodes.get(n).proofBuffered.size() > 0)

  /// A buffered proof was applied when Identify created the peer entry.
  val buffered_proof_applied_on_identify: bool =
    nodes.keys().exists(n => nodes.get(n).pendingProofApplied)

  /// A validator set update promoted a peer holding a stored proof.
  val validator_set_update_promoted_peer: bool =
    nodes.keys().exists(n => nodes.get(n).promotedByUpdate)

  /// A validator set update demoted a peer that was a validator.
  val validator_set_update_demoted_peer: bool =
    nodes.keys().exists(n => nodes.get(n).demotedByUpdate)

  /// The local node entered the active validator set.
  val local_node_became_validator: bool =
    nodes.keys().exists(n => nodes.get(n).localBecameValidator)

  /// The local node dropped out of the active validator set.
  val local_node_lost_validator_status: bool =
    nodes.keys().exists(n => nodes.get(n).localLostValidator)

  /// A high-value peer was promoted to inbound while a slot was free.
  val high_value_peer_promoted_without_eviction: bool =
    nodes.keys().exists(n => nodes.get(n).promotedWithoutEviction)

  /// A low-value inbound peer was evicted to make room for a high-value peer.
  val low_value_peer_evicted_for_high_value_peer: bool =
    nodes.keys().exists(n => nodes.get(n).evicted.size() > 0)

  /// Prioritization gave up because inbound was full of high-value peers.
  val prioritization_blocked_by_high_value_inbound: bool =
    nodes.keys().exists(n => nodes.get(n).prioritizationBlocked)

  /// A persistent peer was added at runtime.
  val persistent_peer_added_at_runtime: bool =
    nodes.keys().exists(n => nodes.get(n).persistentAdded)

  /// Removing a persistent peer disconnected it.
  val persistent_peer_removed_and_disconnected: bool =
    nodes.keys().exists(n => nodes.get(n).disconnected.size() > 0)

  /// A removed persistent peer stayed connected because it holds an inbound slot.
  val persistent_peer_removed_but_kept_inbound: bool =
    nodes.keys().exists(n => nodes.get(n).removedWhileInboundKept)

  /// A persistent peer id survived removal of its configured address.
  val stale_persistent_peer_id_retained: bool =
    nodes.keys().exists(n => nodes.get(n).staleIdRetained)

  /// A peer's recorded address came from its self-reported identify listen addresses.
  val peer_address_taken_from_self_reported_addrs: bool =
    nodes.keys().exists(n => nodes.get(n).addressFromListenAddrs)

  /// A peer's recorded address fell back to the zero multiaddr.
  val peer_address_fell_back_to_zero_addr: bool =
    nodes.keys().exists(n => nodes.get(n).addressFallbackZero)

  /// A reconnecting peer kept its outbound address instead of the new inbound one.
  val existing_peer_kept_outbound_address: bool =
    nodes.keys().exists(n => nodes.get(n).keptOutboundAddress)

  /// A message was published over gossipsub.
  val message_published_over_gossipsub: bool =
    nodes.keys().exists(n => nodes.get(n).publishedGossipsub)

  /// A message was published over the broadcast protocol.
  val message_published_over_broadcast: bool =
    nodes.keys().exists(n => nodes.get(n).publishedBroadcast)

  /// A node subscribed to every consensus channel.
  val subscribed_to_all_channels: bool =
    nodes.keys().exists(n => nodes.get(n).subscribedChannels == CHANNELS)

  /// A disconnect cleaned a peer's info and any proof buffered for it.
  val peer_state_cleaned_on_disconnect: bool =
    nodes.keys().exists(n => nodes.get(n).peerStateCleaned)

  /// A peer was recorded as a mesh member of a channel.
  val peer_recorded_in_channel_mesh: bool =
    nodes.keys().exists(n => {
      val s = nodes.get(n)
      s.peers.keys().exists(p => s.peers.get(p).topics.size() > 0)
    })
}
