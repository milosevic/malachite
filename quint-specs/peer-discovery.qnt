// Peer Discovery — one node's discovery state machine as implemented in
// code/crates/discovery: the Controller/Action bookkeeping (done_on, in_progress,
// delayed queues), the peers-request rate limiter, dial retries, and the
// outbound/inbound peer sets.
//
// The model MIRRORS the code, quirks included. Intent is stated as invariants.
//
// Domain layout: LOCAL is this node. Peer 1 is the configured bootstrap node
// (its address is the only trusted address). Peers 2 and 3 are two identities of
// one adversarial operator, so sybil identity churn is expressible.

module peer_discovery_core {
  import basicSpells.* from "./spells/basicSpells"

  type PeerData =
    | PId(int)
    | MAddr(int)

  type DialData = {
    // NO_PEER when the peer id is not (yet) known
    peer_id: int,
    listen_addrs: Set[int],
    retry: int,
    // set at construction; only DialData::new_bootstrap sets it (dial.rs:27-34)
    is_bootstrap: bool,
  }

  /// a queued dial; `ready_at` models Action::add_to_queue's optional delay
  type QDial = { d: DialData, ready_at: int }

  type RequestData = { peer: int, retry: int }
  type QRequest = { r: RequestData, ready_at: int }

  type OutboundState = Pending | Confirmed
  type Phase = Bootstrapping | Idle | Extending(int)

  type Window = { start: int, count: int }
  type Violation = { count: int, last: int }
  type RlResult = RlNone | Allowed | RateLimited | MaxViolations

  type ConnInfo = { peer: int, inbound: bool }

  type Ctrl = {
    dial_done_on: Set[PeerData],
    dial_in_progress: int -> DialData,
    dial_queue: List[QDial],
    peers_req_done_on: Set[int],
    peers_req_in_progress: int -> RequestData,
    peers_req_queue: List[QRequest],
    connect_req_done_on: Set[int],
    connect_req_in_progress: int -> RequestData,
    connect_req_queue: List[QRequest],
    close_queue: List[(int, int)],
  }

  type Node = {
    phase: Phase,
    connections: int -> ConnInfo,
    active_connections: int -> Set[int],
    discovered: int -> Set[int],
    outbound: int -> OutboundState,
    inbound: Set[int],
    // the single configured bootstrap entry's peer id; None until identified,
    // reset to NO_PEER again when its last connection closes (close.rs:112-124)
    bootstrap_pid: int,
    // the Kademlia routing table, filled from SELF-REPORTED identify addresses
    // (handlers/identify.rs:284-289)
    kad_table: int -> Set[int],
  }

  type RateLimiter = {
    requests: int -> Window,
    violations: int -> Violation,
    // set by DiscoveryRateLimiter::new (rate_limiter.rs:86-101)
    max_requests: int,
    max_violations: int,
    rate_window: int,
    violation_expiry: int,
  }

  /// bookkeeping the code does not keep; used only by observations and invariants
  type Ghost = {
    // every address ever inserted into dial.done_on
    registered_addrs: Set[int],
    // an address was marked done that is not owned by the dial's own peer id
    foreign_addr_marked_done: bool,
    // a peer at or above max_violations was nonetheless served
    blocked_peer_admitted: bool,
    // independently counted admissions per real-time window, per peer
    admitted: int -> Window,
    last_rl: RlResult,
    rl_expiry_fired: bool,
    dial_no_addrs: bool,
    dial_retry_scheduled: bool,
    bootstrap_done_on_cleared: bool,
    bootstrap_pid_reset: bool,
    poisoned_dial_queued: bool,
    inbound_upgrade_accepted: bool,
    inbound_upgrade_rejected: bool,
    connect_rejected: bool,
    ephemeral_closed: bool,
    max_conns_per_peer_closed: bool,
    selection_short: bool,
    kad_addr_added: bool,
  }

  // ─── configuration (code defaults, scaled down) ──────────────────────────

  pure val NO_PEER: int = 0
  pure val LOCAL: int = 9
  pure val LOCAL_ADDRS: Set[int] = Set(5)
  pure val PEERS: Set[int] = Set(1, 2, 3)
  /// two peer ids of the same adversarial operator (2 and 3)
  pure val OPERATOR: int -> int = Map(1 -> 1, 2 -> 2, 3 -> 2)
  pure val ADDRS: Set[int] = Set(5, 10, 20, 30)
  pure val ADDR_OWNER: int -> int = Map(5 -> LOCAL, 10 -> 1, 20 -> 2, 30 -> 3)
  /// the trusted, configured bootstrap address (peer 1)
  pure val BOOTSTRAP_ADDRS: Set[int] = Set(10)
  pure val CONNS: Set[int] = Set(1, 2, 3)
  pure val REQ_IDS: Set[int] = Set(1, 2, 3)

  pure val DIAL_CONCURRENT_FACTOR: int = 1
  pure val PEERS_REQUEST_CONCURRENT_FACTOR: int = 2
  pure val CONNECT_REQUEST_CONCURRENT_FACTOR: int = 2
  pure val NUM_OUTBOUND_PEERS: int = 1
  pure val NUM_INBOUND_PEERS: int = 1
  pure val MAX_CONNECTIONS_PER_PEER: int = 2
  pure val DIAL_MAX_RETRIES: int = 1
  pure val REQUEST_MAX_RETRIES: int = 1
  pure val CONNECT_REQUEST_MAX_RETRIES: int = 0
  pure val RETRY_DELAY: int = 0

  // rate_limiter.rs defaults, scaled: 6 per 60s / 3 violations / 10min expiry
  // milliseconds, the unit the instrumentation logs durations in
  pure val RATE_WINDOW: int = 5
  pure val MAX_REQUESTS_PER_WINDOW: int = 1
  pure val MAX_VIOLATIONS: int = 2
  pure val VIOLATION_EXPIRY: int = 12
  pure val TICKS: Set[int] = Set(1, 6, 13)

  pure val PERSISTENT_PEERS_ONLY: bool = false
  pure val DISCOVERY_ENABLED: bool = true
  pure val BOOTSTRAP_PROTOCOL_IS_KADEMLIA: bool = true

  // ─── queries (controller.rs / dial.rs pure logic) ────────────────────────

  /// Action::can_perform — in_progress below the concurrency factor (controller.rs:85-87)
  pure def dial_can_perform(c: Ctrl): bool =
    c.dial_in_progress.keys().size() < DIAL_CONCURRENT_FACTOR

  pure def peers_req_can_perform(c: Ctrl): bool =
    c.peers_req_in_progress.keys().size() < PEERS_REQUEST_CONCURRENT_FACTOR

  pure def connect_req_can_perform(c: Ctrl): bool =
    c.connect_req_in_progress.keys().size() < CONNECT_REQUEST_CONCURRENT_FACTOR

  /// Controller::dial_is_done_on (controller.rs:155-164)
  pure def dial_is_done_on(c: Ctrl, d: DialData): bool =
    or {
      d.peer_id != NO_PEER and c.dial_done_on.contains(PId(d.peer_id)),
      d.listen_addrs.exists(a => c.dial_done_on.contains(MAddr(a))),
    }

  /// DialData::build_dial_opts returns None when there are no addresses (dial.rs:52-72)
  pure def has_dial_opts(d: DialData): bool = d.listen_addrs != Set()

  /// Discovery::should_dial (handlers/dial.rs:20-35)
  pure def should_dial(n: Node, c: Ctrl, d: DialData, check_already_dialed: bool): bool =
    and {
      d.peer_id == NO_PEER or
        (d.peer_id != LOCAL and not(n.active_connections.has(d.peer_id))),
      or {
        not(check_already_dialed),
        not(dial_is_done_on(c, d)),
        d.retry != 0,
      },
      d.listen_addrs.intersect(LOCAL_ADDRS) == Set(),
    }

  /// Discovery::should_peers_request (handlers/peers_request.rs:23-30)
  pure def should_peers_request(c: Ctrl, r: RequestData): bool =
    not(c.peers_req_done_on.contains(r.peer)) or r.retry != 0

  /// Discovery::should_connect_request (handlers/connect_request.rs:22-27)
  pure def should_connect_request(c: Ctrl, r: RequestData): bool =
    not(c.connect_req_done_on.contains(r.peer)) or r.retry != 0

  /// Discovery::should_close — only ephemeral connections, or a connection that
  /// is not among the peer's active ones (handlers/close.rs:17-25)
  pure def should_close(n: Node, peer: int, conn: int): bool =
    or {
      not(n.outbound.has(peer)) and not(n.inbound.contains(peer)),
      not(n.active_connections.has(peer)) or
        not(n.active_connections.getOrElse(peer, Set()).contains(conn)),
    }

  /// Discovery::get_excluded_peers (selection/selector.rs:45-55)
  pure def excluded_peers(n: Node, c: Ctrl): Set[int] =
    n.discovered.keys().filter(p => n.outbound.has(p) or c.connect_req_done_on.contains(p))

  /// Selector::try_select_n_outbound_candidates — the eligible set; the code may
  /// return fewer than n of these (selection/selector.rs:70-76)
  pure def selection_candidates(n: Node, c: Ctrl): Set[int] =
    n.discovered.keys().exclude(excluded_peers(n, c))

  // ─── rate limiter (rate_limiter.rs:105-163) ──────────────────────────────

  pure def violations_of(rl: RateLimiter, p: int): int =
    if (rl.violations.has(p)) rl.violations.get(p).count else 0

  /// the violation-expiry branch: clears BOTH violations and the request window
  pure def rl_expired(rl: RateLimiter, p: int, now: int): bool =
    rl.violations.has(p) and now - rl.violations.get(p).last >= rl.violation_expiry

  pure def rl_expire(rl: RateLimiter, p: int, now: int): RateLimiter =
    if (rl_expired(rl, p, now))
      { ...rl, requests: rl.requests.mapRemove(p), violations: rl.violations.mapRemove(p) }
    else
      rl

  /// DiscoveryRateLimiter::check_request — the whole three-outcome machine
  pure def rl_check(rl: RateLimiter, p: int, now: int): (RateLimiter, RlResult) = {
    val r1 = rl_expire(rl, p, now)
    if (violations_of(r1, p) >= r1.max_violations)
      (r1, MaxViolations)
    else if (r1.requests.has(p) and now - r1.requests.get(p).start < r1.rate_window) {
      val w = r1.requests.get(p)
      if (w.count >= r1.max_requests) {
        val vc = violations_of(r1, p) + 1
        val r2 = { ...r1, violations: r1.violations.put(p, { count: vc, last: now }) }
        (r2, if (vc >= r1.max_violations) MaxViolations else RateLimited)
      } else
        ({ ...r1, requests: r1.requests.put(p, { ...w, count: w.count + 1 }) }, Allowed)
    } else
      ({ ...r1, requests: r1.requests.put(p, { start: now, count: 1 }) }, Allowed)
  }

  /// independent admission counter over the real-time window (ghost only)
  pure def bump_admitted(g: Ghost, p: int, now: int, window: int): int -> Window =
    if (g.admitted.has(p) and now - g.admitted.get(p).start < window) {
      val a = g.admitted.get(p)
      g.admitted.put(p, { ...a, count: a.count + 1 })
    } else
      g.admitted.put(p, { start: now, count: 1 })

  // ─── controller mutations ────────────────────────────────────────────────

  /// Controller::dial_register_done_on (controller.rs:141-153)
  pure def do_dial_register_done_on(c: Ctrl, d: DialData, register_addrs: bool): Ctrl = {
    val with_pid =
      if (d.peer_id != NO_PEER) c.dial_done_on.union(Set(PId(d.peer_id)))
      else c.dial_done_on
    val with_addrs =
      if (register_addrs) with_pid.union(d.listen_addrs.map(a => MAddr(a))) else with_pid
    { ...c, dial_done_on: with_addrs }
  }

  /// Controller::dial_clear_done_for_peer (controller.rs:166-174)
  pure def do_dial_clear_done_for_peer(c: Ctrl, peer: int, addrs: Set[int]): Ctrl =
    { ...c,
      dial_done_on: c.dial_done_on
        .exclude(Set(PId(peer)))
        .exclude(addrs.map(a => MAddr(a))) }

  /// DiscoveryRateLimiter::remove_peer — clears the window, KEEPS violations
  /// (rate_limiter.rs:193-196)
  pure def do_rl_remove_peer(rl: RateLimiter, p: int): RateLimiter =
    { ...rl, requests: rl.requests.mapRemove(p) }

  pure def addr_owner(a: int): int = ADDR_OWNER.getOrElse(a, LOCAL)

  /// addresses in this dial that belong to somebody other than its own peer id
  pure def foreign_addrs(d: DialData): Set[int] =
    if (d.peer_id != NO_PEER) d.listen_addrs.filter(a => addr_owner(a) != d.peer_id)
    else d.listen_addrs

  pure def initial_ctrl: Ctrl = {
    dial_done_on: Set(),
    dial_in_progress: Map(),
    dial_queue: List(),
    peers_req_done_on: Set(),
    peers_req_in_progress: Map(),
    peers_req_queue: List(),
    connect_req_done_on: Set(),
    connect_req_in_progress: Map(),
    connect_req_queue: List(),
    close_queue: List(),
  }

  pure val initial_node: Node = {
    phase: Bootstrapping,
    connections: Map(),
    active_connections: Map(),
    discovered: Map(),
    outbound: Map(),
    inbound: Set(),
    bootstrap_pid: NO_PEER,
    kad_table: Map(),
  }

  pure val initial_rl: RateLimiter = {
    requests: Map(),
    violations: Map(),
    max_requests: MAX_REQUESTS_PER_WINDOW,
    max_violations: MAX_VIOLATIONS,
    rate_window: RATE_WINDOW,
    violation_expiry: VIOLATION_EXPIRY,
  }

  pure val initial_ghost: Ghost = {
    registered_addrs: Set(),
    foreign_addr_marked_done: false,
    blocked_peer_admitted: false,
    admitted: Map(),
    last_rl: RlNone,
    rl_expiry_fired: false,
    dial_no_addrs: false,
    dial_retry_scheduled: false,
    bootstrap_done_on_cleared: false,
    bootstrap_pid_reset: false,
    poisoned_dial_queued: false,
    inbound_upgrade_accepted: false,
    inbound_upgrade_rejected: false,
    connect_rejected: false,
    ephemeral_closed: false,
    max_conns_per_peer_closed: false,
    selection_short: false,
    kad_addr_added: false,
  }
}

module peer_discovery {
  import basicSpells.* from "./spells/basicSpells"
  import peer_discovery_core.*

  var ctrl: Ctrl
  var rl: RateLimiter
  var node: Node
  var clock: int
  var ghost: Ghost

  action init = all {
    ctrl' = initial_ctrl,
    rl' = initial_rl,
    node' = initial_node,
    clock' = 0,
    ghost' = initial_ghost,
  }

  // ═══ Action / Controller operations ══════════════════════════════════════

  /// Action::add_to_queue(value, delay) — pushes onto the dial queue, immediately
  /// when delay is None, after the delay otherwise (controller.rs:45-63)
  action Actionadd_to_queue(value: DialData, delay: int): bool = all {
    delay >= 0,
    ctrl' = { ...ctrl, dial_queue: ctrl.dial_queue.append({ d: value, ready_at: clock + delay }) },
    ghost' = { ...ghost,
      poisoned_dial_queued: ghost.poisoned_dial_queued or foreign_addrs(value) != Set() },
    rl' = rl,
    node' = node,
    clock' = clock,
  }

  /// Controller::dial_register_done_on. `register_addrs = true` is documented as
  /// legal only for trusted (bootstrap) dial data (controller.rs:135-153).
  action Controllerdial_register_done_on(dial_data: DialData, register_addrs: bool): bool = all {
    // documented precondition, not enforced by the body: register_addrs is only
    // legal for TRUSTED dial data — either flagged bootstrap at construction, or
    // carrying nothing but configured bootstrap addresses (controller.rs:135-140)
    register_addrs implies
      (dial_data.is_bootstrap or dial_data.listen_addrs.subseteq(BOOTSTRAP_ADDRS)),
    ctrl' = do_dial_register_done_on(ctrl, dial_data, register_addrs),
    ghost' = { ...ghost,
      registered_addrs:
        if (register_addrs) ghost.registered_addrs.union(dial_data.listen_addrs)
        else ghost.registered_addrs,
      foreign_addr_marked_done:
        ghost.foreign_addr_marked_done or
        (register_addrs and foreign_addrs(dial_data) != Set()) },
    rl' = rl,
    node' = node,
    clock' = clock,
  }

  /// Controller::dial_clear_done_for_peer — the retry reset (controller.rs:166-174)
  action Controllerdial_clear_done_for_peer(peer_id: int, addrs: Set[int]): bool = all {
    PEERS.contains(peer_id),
    ctrl' = do_dial_clear_done_for_peer(ctrl, peer_id, addrs),
    rl' = rl,
    node' = node,
    clock' = clock,
    ghost' = ghost,
  }

  /// DiscoveryRateLimiter::remove_peer — clears the request window but preserves
  /// violations (rate_limiter.rs:193-196)
  action DiscoveryRateLimiterremove_peer(peer_id: int): bool = all {
    PEERS.contains(peer_id),
    rl' = do_rl_remove_peer(rl, peer_id),
    ctrl' = ctrl,
    node' = node,
    clock' = clock,
    ghost' = ghost,
  }

  /// DiscoveryRateLimiter::new — a fresh limiter with its configured bounds
  /// (rate_limiter.rs:86-101)
  action DiscoveryRateLimiternew(
      max_requests: int, max_violations: int,
      rate_window: int, violation_expiry: int): bool = all {
    rl' = { requests: Map(), violations: Map(), max_requests: max_requests,
            max_violations: max_violations, rate_window: rate_window,
            violation_expiry: violation_expiry },
    ghost' = { ...ghost, admitted: Map(), last_rl: RlNone },
    ctrl' = ctrl,
    node' = node,
    clock' = clock,
  }

  // ═══ dial path ═══════════════════════════════════════════════════════════

  /// Discovery::add_to_dial_queue — registers the peer id only (addresses from a
  /// peers response are untrusted) then queues (handlers/dial.rs:200-209)
  action add_to_dial_queue(dial_data: DialData): bool = all {
    should_dial(node, ctrl, dial_data, true),
    ctrl' = {
      ...do_dial_register_done_on(ctrl, dial_data, false),
      dial_queue: ctrl.dial_queue.append({ d: dial_data, ready_at: clock }),
    },
    ghost' = { ...ghost,
      poisoned_dial_queued: ghost.poisoned_dial_queued or foreign_addrs(dial_data) != Set() },
    rl' = rl,
    node' = node,
    clock' = clock,
  }

  /// Discovery::dial_bootstrap_nodes — skips already-attempted bootstrap nodes,
  /// and registers the configured addresses as trusted (handlers/dial.rs:211-246)
  action dial_bootstrap_nodes: bool = {
    val d: DialData = { peer_id: node.bootstrap_pid, listen_addrs: BOOTSTRAP_ADDRS,
                        retry: 0, is_bootstrap: true }
    all {
      not(BOOTSTRAP_ADDRS.exists(a => ctrl.dial_done_on.contains(MAddr(a)))),
      should_dial(node, ctrl, d, false),
      ctrl' = {
        ...do_dial_register_done_on(ctrl, d, true),
        dial_queue: ctrl.dial_queue.append({ d: d, ready_at: clock }),
      },
      ghost' = { ...ghost, registered_addrs: ghost.registered_addrs.union(BOOTSTRAP_ADDRS) },
      rl' = rl,
      node' = node,
      clock' = clock,
    }
  }

  /// Discovery::dial_peer, driven by the network select! loop which gates it on
  /// can_dial() (lib.rs:493-494, handlers/dial.rs:37-82). No addresses means the
  /// dial is silently skipped and the queue entry dropped.
  action dial_peer(connection_id: int): bool = {
    val front = ctrl.dial_queue.head()
    all {
      ctrl.dial_queue.length() > 0,
      front.ready_at <= clock,
      dial_can_perform(ctrl),
      val rest = ctrl.dial_queue.tail()
      // the drop branches never reach swarm.dial, so no connection id exists
      // for them (handlers/dial.rs:42-52) — the instrumentation logs 0 there
      if (not(should_dial(node, ctrl, front.d, false)) or not(has_dial_opts(front.d)))
        all {
          ctrl' = { ...ctrl, dial_queue: rest },
          ghost' = { ...ghost,
            dial_no_addrs: ghost.dial_no_addrs or not(has_dial_opts(front.d)) },
        }
      else
        all {
          CONNS.contains(connection_id),
          not(ctrl.dial_in_progress.has(connection_id)),
          ctrl' = {
            ...do_dial_register_done_on(ctrl, front.d, false),
            dial_queue: rest,
            dial_in_progress: ctrl.dial_in_progress.put(connection_id, front.d),
          },
          ghost' = ghost,
        },
      rl' = rl,
      node' = node,
      clock' = clock,
    }
  }

  /// Discovery::handle_connection — outbound connections mark the peer id done;
  /// inbound ones do not (handlers/dial.rs:84-146)
  action handle_connection(peer_id: int, connection_id: int, inbound: bool): bool = all {
    PEERS.contains(peer_id),
    CONNS.contains(connection_id),
    not(node.connections.has(connection_id)),
    node' = { ...node,
      connections: node.connections.put(connection_id, { peer: peer_id, inbound: inbound }) },
    ctrl' =
      if (node.active_connections.has(peer_id))
        // both nodes dialed each other: the dial attempt is dropped
        { ...ctrl, dial_in_progress: ctrl.dial_in_progress.mapRemove(connection_id) }
      else if (not(inbound))
        // dial_add_peer_id_to_dial_data + register_done_on(PeerId)
        { ...ctrl,
          dial_done_on: ctrl.dial_done_on.union(Set(PId(peer_id))),
          dial_in_progress:
            if (ctrl.dial_in_progress.has(connection_id))
              ctrl.dial_in_progress.put(connection_id,
                { ...ctrl.dial_in_progress.get(connection_id), peer_id: peer_id })
            else ctrl.dial_in_progress }
      else
        ctrl,
    rl' = rl,
    clock' = clock,
    ghost' = ghost,
  }

  /// Discovery::handle_failed_connection — fatal errors are not retried; for a
  /// bootstrap dial that exhausted its retries the address done_on marks are
  /// cleared so the timer can retry (handlers/dial.rs:148-198)
  action handle_failed_connection(connection_id: int, fatal: bool): bool = {
    val d = ctrl.dial_in_progress.get(connection_id)
    all {
      ctrl.dial_in_progress.has(connection_id),
      val base = { ...ctrl, dial_in_progress: ctrl.dial_in_progress.mapRemove(connection_id) }
      if (fatal)
        all { ctrl' = base, ghost' = ghost }
      else if (d.retry < DIAL_MAX_RETRIES)
        all {
          ctrl' = { ...base,
            dial_queue: base.dial_queue.append(
              { d: { ...d, retry: d.retry + 1 }, ready_at: clock + RETRY_DELAY }) },
          ghost' = { ...ghost, dial_retry_scheduled: true },
        }
      else if (d.is_bootstrap)
        all {
          ctrl' = { ...base,
            dial_done_on: base.dial_done_on.exclude(d.listen_addrs.map(a => MAddr(a))) },
          ghost' = { ...ghost, bootstrap_done_on_cleared: true },
        }
      else
        all { ctrl' = base, ghost' = ghost },
      rl' = rl,
      node' = node,
      clock' = clock,
    }
  }

  /// Discovery::handle_new_peer (identify) — records the peer, classifies the
  /// connection as outbound / inbound / ephemeral, and enforces
  /// max_connections_per_peer (handlers/identify.rs:126-305)
  action handle_new_peer(connection_id: int, listen_addrs: Set[int]): bool = {
    val info = node.connections.get(connection_id)
    val peer_id = info.peer
    val existing = node.active_connections.getOrElse(peer_id, Set())
    val at_conn_limit = existing.size() >= MAX_CONNECTIONS_PER_PEER
    // bootstrap identification uses the address we dialed / the TCP remote address
    val is_bootstrap_peer =
      node.bootstrap_pid == NO_PEER and
      ((not(info.inbound) and
        ctrl.dial_in_progress.keys().exists(cid =>
          ctrl.dial_in_progress.get(cid).listen_addrs.intersect(BOOTSTRAP_ADDRS) != Set() and
          ctrl.dial_in_progress.get(cid).peer_id == peer_id)) or
       (info.inbound and BOOTSTRAP_ADDRS.contains(peer_id * 10)))
    all {
      node.connections.has(connection_id),
      not(existing.contains(connection_id)),
      listen_addrs.subseteq(ADDRS),
      ctrl' =
        if (at_conn_limit)
          { ...ctrl,
            dial_in_progress: ctrl.dial_in_progress.mapRemove(connection_id),
            close_queue: ctrl.close_queue.append((peer_id, connection_id)) }
        else if (not(node.outbound.has(peer_id)) and not(node.inbound.contains(peer_id)) and
                 node.phase == Idle and node.outbound.keys().size() < NUM_OUTBOUND_PEERS)
          { ...ctrl,
            dial_in_progress: ctrl.dial_in_progress.mapRemove(connection_id),
            connect_req_queue: ctrl.connect_req_queue.append(
              { r: { peer: peer_id, retry: 0 }, ready_at: clock }) }
        else if (not(node.outbound.has(peer_id)) and not(node.inbound.contains(peer_id)))
          { ...ctrl,
            dial_in_progress: ctrl.dial_in_progress.mapRemove(connection_id),
            close_queue: ctrl.close_queue.append((peer_id, connection_id)) }
        else
          { ...ctrl, dial_in_progress: ctrl.dial_in_progress.mapRemove(connection_id) },
      node' =
        if (at_conn_limit)
          { ...node, discovered: node.discovered.put(peer_id, listen_addrs) }
        else {
          // Kademlia add_address: the addresses the peer reports for ITSELF are
          // inserted without the check dial_register_done_on applies
          val kad =
            if (BOOTSTRAP_PROTOCOL_IS_KADEMLIA and listen_addrs != Set())
              node.kad_table.put(peer_id,
                node.kad_table.getOrElse(peer_id, Set()).union(listen_addrs))
            else node.kad_table
          val n1 = { ...node,
            kad_table: kad,
            discovered: node.discovered.put(peer_id, listen_addrs),
            active_connections:
              node.active_connections.put(peer_id, existing.union(Set(connection_id))),
            bootstrap_pid: if (is_bootstrap_peer) peer_id else node.bootstrap_pid }
          if (not(n1.outbound.has(peer_id)) and not(n1.inbound.contains(peer_id)) and
              n1.phase == Idle and n1.outbound.keys().size() < NUM_OUTBOUND_PEERS)
            { ...n1, outbound: n1.outbound.put(peer_id, Pending) }
          else
            n1
        },
      ghost' = { ...ghost,
        max_conns_per_peer_closed: ghost.max_conns_per_peer_closed or at_conn_limit,
        kad_addr_added: ghost.kad_addr_added or
          (not(at_conn_limit) and BOOTSTRAP_PROTOCOL_IS_KADEMLIA and listen_addrs != Set()),
        ephemeral_closed: ghost.ephemeral_closed or
          (not(at_conn_limit) and not(node.outbound.has(peer_id)) and
           not(node.inbound.contains(peer_id)) and
           not(node.phase == Idle and node.outbound.keys().size() < NUM_OUTBOUND_PEERS)) },
      rl' = rl,
      clock' = clock,
    }
  }

  /// Discovery::close_connection, gated by can_close() (handlers/close.rs:27-39)
  action close_connection(peer_id: int, connection_id: int): bool = {
    val front = ctrl.close_queue.head()
    all {
      ctrl.close_queue.length() > 0,
      front._1 == peer_id,
      front._2 == connection_id,
      node.phase == Idle,
      ctrl' = { ...ctrl, close_queue: ctrl.close_queue.tail() },
      rl' = rl,
      node' = node,
      clock' = clock,
      ghost' = ghost,
    }
  }

  /// Discovery::handle_closed_connection, including cleanup_peer_on_disconnect:
  /// the rate limiter window is cleared (violations are NOT), connect_request
  /// done_on is cleared, and a bootstrap node's peer id is reset together with
  /// its dial history (handlers/close.rs:41-133)
  action handle_closed_connection(peer_id: int, connection_id: int): bool = {
    val conns = node.active_connections.getOrElse(peer_id, Set())
    val remaining = conns.exclude(Set(connection_id))
    val was_last = conns.contains(connection_id) and remaining == Set()
    val is_bootstrap_peer = node.bootstrap_pid == peer_id and peer_id != NO_PEER
    val addrs = node.discovered.getOrElse(peer_id, Set())
    all {
      PEERS.contains(peer_id),
      CONNS.contains(connection_id),
      node' =
        if (not(was_last))
          { ...node,
            connections: node.connections.mapRemove(connection_id),
            active_connections:
              if (conns.contains(connection_id))
                node.active_connections.put(peer_id, remaining)
              else node.active_connections }
        else
          { ...node,
            connections: node.connections.mapRemove(connection_id),
            active_connections: node.active_connections.mapRemove(peer_id),
            outbound: node.outbound.mapRemove(peer_id),
            inbound: node.inbound.exclude(Set(peer_id)),
            discovered: node.discovered.mapRemove(peer_id),
            bootstrap_pid: if (is_bootstrap_peer) NO_PEER else node.bootstrap_pid },
      ctrl' = {
        val c1 = { ...ctrl, dial_in_progress: ctrl.dial_in_progress.mapRemove(connection_id) }
        if (not(was_last)) c1
        else {
          val c2 = { ...c1, connect_req_done_on: c1.connect_req_done_on.exclude(Set(peer_id)) }
          if (is_bootstrap_peer) do_dial_clear_done_for_peer(c2, peer_id, BOOTSTRAP_ADDRS)
          else if (not(DISCOVERY_ENABLED)) do_dial_clear_done_for_peer(c2, peer_id, addrs)
          else c2
        }
      },
      rl' = if (was_last) do_rl_remove_peer(rl, peer_id) else rl,
      ghost' = { ...ghost,
        bootstrap_pid_reset: ghost.bootstrap_pid_reset or (was_last and is_bootstrap_peer) },
      clock' = clock,
    }
  }

  // ═══ peers request path ══════════════════════════════════════════════════

  /// Discovery::peers_request_peer, gated by can_peers_request()
  /// (lib.rs:498-499, handlers/peers_request.rs:73-102)
  action peers_request_peer(request_id: int): bool = {
    val front = ctrl.peers_req_queue.head()
    all {
      ctrl.peers_req_queue.length() > 0,
      front.ready_at <= clock,
      peers_req_can_perform(ctrl),
      REQ_IDS.contains(request_id),
      not(ctrl.peers_req_in_progress.has(request_id)),
      val rest = ctrl.peers_req_queue.tail()
      if (not(should_peers_request(ctrl, front.r)))
        ctrl' = { ...ctrl, peers_req_queue: rest }
      else
        ctrl' = { ...ctrl,
          peers_req_queue: rest,
          peers_req_done_on: ctrl.peers_req_done_on.union(Set(front.r.peer)),
          peers_req_in_progress: ctrl.peers_req_in_progress.put(request_id, front.r) },
      rl' = rl,
      node' = node,
      clock' = clock,
      ghost' = ghost,
    }
  }

  /// Discovery::handle_peers_request — an INCOMING request; the rate limiter's
  /// check_request runs here and a max-violations peer is disconnected
  /// (handlers/peers_request.rs:104-141)
  action handle_peers_request(peer: int): bool = {
    val res = rl_check(rl, peer, clock)
    val allowed = res._2 == Allowed
    all {
      PEERS.contains(peer),
      rl' = res._1,
      ctrl' =
        if (res._2 == MaxViolations and node.active_connections.has(peer))
          { ...ctrl,
            close_queue: node.active_connections.get(peer)
              .fold(ctrl.close_queue, (q, cid) => q.append((peer, cid))) }
        else ctrl,
      ghost' = { ...ghost,
        last_rl: res._2,
        rl_expiry_fired: ghost.rl_expiry_fired or rl_expired(rl, peer, clock),
        admitted: if (allowed) bump_admitted(ghost, peer, clock, rl.rate_window)
                  else ghost.admitted,
        blocked_peer_admitted: ghost.blocked_peer_admitted or
          (allowed and violations_of(rl, peer) >= rl.max_violations and
           not(rl_expired(rl, peer, clock))) },
      node' = node,
      clock' = clock,
    }
  }

  /// Discovery::handle_peers_response — the outer handler only clears the
  /// in-progress request; every verified record with at least one address is
  /// then dialed through add_to_dial_queue, which the model represents by its
  /// own register + queue steps (handlers/peers_request.rs:167-181, 215-262)
  action handle_peers_response(request_id: int): bool = all {
    ctrl.peers_req_in_progress.has(request_id),
    ctrl' = { ...ctrl,
      peers_req_in_progress: ctrl.peers_req_in_progress.mapRemove(request_id) },
    rl' = rl,
    node' = node,
    clock' = clock,
    ghost' = ghost,
  }

  /// Discovery::handle_failed_peers_request — retry with backoff, or give up
  /// (handlers/peers_request.rs:143-167)
  action handle_failed_peers_request(request_id: int): bool = {
    val r = ctrl.peers_req_in_progress.get(request_id)
    all {
      ctrl.peers_req_in_progress.has(request_id),
      val base = { ...ctrl, peers_req_in_progress: ctrl.peers_req_in_progress.mapRemove(request_id) }
      if (r.retry < REQUEST_MAX_RETRIES)
        ctrl' = { ...base,
          peers_req_queue: base.peers_req_queue.append(
            { r: { ...r, retry: r.retry + 1 }, ready_at: clock + RETRY_DELAY }) }
      else
        ctrl' = base,
      rl' = rl,
      node' = node,
      clock' = clock,
      ghost' = ghost,
    }
  }

  // ═══ connect request path ════════════════════════════════════════════════

  /// Discovery::connect_request_peer, gated by can_connect_request()
  /// (lib.rs:503-504, handlers/connect_request.rs:29-56)
  action connect_request_peer(request_id: int): bool = {
    val front = ctrl.connect_req_queue.head()
    all {
      ctrl.connect_req_queue.length() > 0,
      front.ready_at <= clock,
      connect_req_can_perform(ctrl),
      REQ_IDS.contains(request_id),
      not(ctrl.connect_req_in_progress.has(request_id)),
      val rest = ctrl.connect_req_queue.tail()
      if (not(should_connect_request(ctrl, front.r)))
        ctrl' = { ...ctrl, connect_req_queue: rest }
      else
        ctrl' = { ...ctrl,
          connect_req_queue: rest,
          connect_req_done_on: ctrl.connect_req_done_on.union(Set(front.r.peer)),
          connect_req_in_progress: ctrl.connect_req_in_progress.put(request_id, front.r) },
      rl' = rl,
      node' = node,
      clock' = clock,
      ghost' = ghost,
    }
  }

  /// Discovery::handle_connect_request — an INCOMING upgrade request; accepted
  /// while below num_inbound_peers (handlers/connect_request.rs:58-95)
  action handle_connect_request(peer: int): bool = {
    val already = node.outbound.has(peer) or node.inbound.contains(peer)
    val has_room = node.inbound.size() < NUM_INBOUND_PEERS
    val accepted = already or has_room
    all {
      PEERS.contains(peer),
      node' =
        if (not(already) and has_room) { ...node, inbound: node.inbound.union(Set(peer)) }
        else node,
      ghost' = { ...ghost,
        inbound_upgrade_accepted: ghost.inbound_upgrade_accepted or accepted,
        inbound_upgrade_rejected: ghost.inbound_upgrade_rejected or not(accepted) },
      ctrl' = ctrl,
      rl' = rl,
      clock' = clock,
    }
  }

  /// Discovery::handle_connect_response — accepted confirms the outbound peer,
  /// rejected drops it and triggers repair (handlers/connect_request.rs:97-135)
  action handle_connect_response(request_id: int, accepted: bool): bool = {
    val peer = ctrl.connect_req_in_progress.get(request_id).peer
    all {
      ctrl.connect_req_in_progress.has(request_id),
      ctrl' = { ...ctrl,
        connect_req_in_progress: ctrl.connect_req_in_progress.mapRemove(request_id) },
      node' =
        if (accepted)
          { ...node,
            outbound: if (node.outbound.has(peer)) node.outbound.put(peer, Confirmed)
                      else node.outbound }
        else
          { ...node, outbound: node.outbound.mapRemove(peer) },
      ghost' = { ...ghost, connect_rejected: ghost.connect_rejected or not(accepted) },
      rl' = rl,
      clock' = clock,
    }
  }

  /// Discovery::handle_failed_connect_request (handlers/connect_request.rs:143-176)
  action handle_failed_connect_request(request_id: int): bool = {
    val r = ctrl.connect_req_in_progress.get(request_id)
    all {
      ctrl.connect_req_in_progress.has(request_id),
      r.retry >= CONNECT_REQUEST_MAX_RETRIES,
      ctrl' = { ...ctrl,
        connect_req_in_progress: ctrl.connect_req_in_progress.mapRemove(request_id) },
      node' = { ...node, outbound: node.outbound.mapRemove(r.peer) },
      ghost' = { ...ghost, connect_rejected: true },
      rl' = rl,
      clock' = clock,
    }
  }

  // ═══ peers management / bootstrap ════════════════════════════════════════

  /// Discovery::adjust_peers — selects one outbound candidate and schedules the
  /// remaining ephemeral connections for close (handlers/peers_management.rs:12-83)
  action adjust_peers(candidate: int): bool = {
    val eligible = selection_candidates(node, ctrl)
    val want = NUM_OUTBOUND_PEERS - node.outbound.keys().size()
    all {
      DISCOVERY_ENABLED,
      want > 0,
      // Selection::None / Selection::Only — the selector returns fewer than n
      if (eligible.size() < want)
        all {
          node' = node,
          ctrl' = ctrl,
          ghost' = { ...ghost, selection_short: true },
        }
      else
        all {
          eligible.contains(candidate),
          node' = { ...node,
            outbound: node.outbound.put(candidate, Pending),
            inbound: node.inbound.exclude(Set(candidate)) },
          ctrl' = { ...ctrl,
            connect_req_queue: ctrl.connect_req_queue.append(
              { r: { peer: candidate, retry: 0 }, ready_at: clock }) },
          ghost' = ghost,
        },
      rl' = rl,
      clock' = clock,
    }
  }

  /// Discovery::repair_outbound_peers — promotes an inbound peer, marking the
  /// connect request as done without ever sending one
  /// (handlers/peers_management.rs:85-139)
  action repair_outbound_peers(peer: int): bool = all {
    DISCOVERY_ENABLED,
    node.outbound.keys().size() < NUM_OUTBOUND_PEERS,
    node.inbound.contains(peer),
    not(node.outbound.has(peer)),
    node' = { ...node,
      inbound: node.inbound.exclude(Set(peer)),
      outbound: node.outbound.put(peer, Confirmed) },
    ctrl' = { ...ctrl, connect_req_done_on: ctrl.connect_req_done_on.union(Set(peer)) },
    rl' = rl,
    clock' = clock,
    ghost' = ghost,
  }

  /// Discovery::handle_successful_bootstrap (handlers/bootstrap.rs:10-45)
  action handle_successful_bootstrap: bool = all {
    node.phase == Bootstrapping,
    node' =
      if (node.active_connections.keys().size() < NUM_OUTBOUND_PEERS)
        { ...node, phase: Extending(NUM_OUTBOUND_PEERS) }
      else
        { ...node, phase: Idle },
    ctrl' = ctrl,
    rl' = rl,
    clock' = clock,
    ghost' = ghost,
  }

  /// Discovery::handle_failed_bootstrap (handlers/bootstrap.rs:47-51)
  action handle_failed_bootstrap: bool = all {
    node.phase == Bootstrapping,
    node' = { ...node, phase: Idle },
    ctrl' = ctrl,
    rl' = rl,
    clock' = clock,
    ghost' = ghost,
  }

  /// the extension step completing: discovery moves back to Idle
  action make_extension_step: bool = all {
    match node.phase { | Extending(_) => true | _ => false },
    node' = { ...node, phase: Idle },
    ctrl' = ctrl,
    rl' = rl,
    clock' = clock,
    ghost' = ghost,
  }

  /// time passing — what makes rate windows and violation expiry reachable
  action clock_tick(amount: int): bool = all {
    amount > 0,
    clock' = clock + amount,
    ctrl' = ctrl,
    rl' = rl,
    node' = node,
    ghost' = ghost,
  }

  // ═══ step ════════════════════════════════════════════════════════════════

  /// dial data an adversary or a peers response can present: any peer id (or
  /// none), any address set including addresses owned by somebody else
  pure val DIAL_DATAS: Set[DialData] =
    tuples(PEERS.union(Set(NO_PEER)),
           ADDRS.powerset().filter(s => s.size() <= 2),
           Set(false, true))
      .map(t => { peer_id: t._1, listen_addrs: t._2, retry: 0, is_bootstrap: t._3 })

  action step = any {
    {
      nondet value = DIAL_DATAS.oneOf()
      nondet delay = Set(0, 6).oneOf()
      Actionadd_to_queue(value, delay)
    },
    {
      nondet dial_data = DIAL_DATAS.oneOf()
      nondet register_addrs = Set(false, true).oneOf()
      Controllerdial_register_done_on(dial_data, register_addrs)
    },
    {
      nondet peer_id = PEERS.oneOf()
      nondet addrs = ADDRS.powerset().filter(s => s.size() <= 2).oneOf()
      Controllerdial_clear_done_for_peer(peer_id, addrs)
    },
    {
      nondet peer_id = PEERS.oneOf()
      DiscoveryRateLimiterremove_peer(peer_id)
    },
    {
      nondet max_requests = Set(0, 1, 2, 3, 6).oneOf()
      nondet max_violations = Set(0, 2, 3).oneOf()
      nondet rate_window = Set(0, 60000).oneOf()
      nondet violation_expiry = Set(0, 1, 600000, 3600000).oneOf()
      DiscoveryRateLimiternew(max_requests, max_violations, rate_window, violation_expiry)
    },
    {
      nondet dial_data = DIAL_DATAS.oneOf()
      add_to_dial_queue(dial_data)
    },
    dial_bootstrap_nodes,
    {
      nondet connection_id = CONNS.oneOf()
      dial_peer(connection_id)
    },
    {
      nondet peer_id = PEERS.oneOf()
      nondet connection_id = CONNS.oneOf()
      nondet inbound = Set(false, true).oneOf()
      handle_connection(peer_id, connection_id, inbound)
    },
    {
      nondet connection_id = CONNS.oneOf()
      nondet fatal = Set(false, true).oneOf()
      handle_failed_connection(connection_id, fatal)
    },
    {
      nondet connection_id = CONNS.oneOf()
      nondet listen_addrs = ADDRS.powerset().filter(s => s.size() <= 2).oneOf()
      handle_new_peer(connection_id, listen_addrs)
    },
    {
      nondet peer_id = PEERS.oneOf()
      nondet connection_id = CONNS.oneOf()
      close_connection(peer_id, connection_id)
    },
    {
      nondet peer_id = PEERS.oneOf()
      nondet connection_id = CONNS.oneOf()
      handle_closed_connection(peer_id, connection_id)
    },
    {
      nondet request_id = REQ_IDS.oneOf()
      peers_request_peer(request_id)
    },
    {
      nondet peer = PEERS.oneOf()
      handle_peers_request(peer)
    },
    {
      nondet request_id = REQ_IDS.oneOf()
      handle_peers_response(request_id)
    },
    {
      nondet request_id = REQ_IDS.oneOf()
      handle_failed_peers_request(request_id)
    },
    {
      nondet request_id = REQ_IDS.oneOf()
      connect_request_peer(request_id)
    },
    {
      nondet peer = PEERS.oneOf()
      handle_connect_request(peer)
    },
    {
      nondet request_id = REQ_IDS.oneOf()
      nondet accepted = Set(false, true).oneOf()
      handle_connect_response(request_id, accepted)
    },
    {
      nondet request_id = REQ_IDS.oneOf()
      handle_failed_connect_request(request_id)
    },
    {
      nondet candidate = PEERS.oneOf()
      adjust_peers(candidate)
    },
    {
      nondet peer = PEERS.oneOf()
      repair_outbound_peers(peer)
    },
    handle_successful_bootstrap,
    handle_failed_bootstrap,
    make_extension_step,
    {
      nondet amount = TICKS.oneOf()
      clock_tick(amount)
    },
  }

  // ═══ correctness properties ══════════════════════════════════════════════

  /// Address poisoning is prevented: an address is only ever marked as
  /// "already dialed" when it is one of the configured bootstrap addresses, so a
  /// peer that claims somebody else's multiaddr cannot make us stop dialing the
  /// real owner of that address (controller.rs:141-153).
  val no_foreign_address_marked_done: bool =
    and {
      not(ghost.foreign_addr_marked_done),
      ghost.registered_addrs.subseteq(BOOTSTRAP_ADDRS),
      ctrl.dial_done_on.forall(pd =>
        match pd {
          | MAddr(a) => BOOTSTRAP_ADDRS.contains(a)
          | PId(_) => true
        }),
    }

  /// A dial is only treated as trusted (bootstrap) when its addresses really are
  /// the configured bootstrap addresses; otherwise a peer that advertises a
  /// bootstrap address in peer exchange would inherit unlimited retries and
  /// address registration.
  val bootstrap_flag_only_from_config: bool =
    and {
      ctrl.dial_queue.foldl(true, (ok, q) =>
        ok and (q.d.is_bootstrap implies q.d.listen_addrs.subseteq(BOOTSTRAP_ADDRS))),
      ctrl.dial_in_progress.keys().forall(cid => {
        val d = ctrl.dial_in_progress.get(cid)
        d.is_bootstrap implies d.listen_addrs.subseteq(BOOTSTRAP_ADDRS)
      }),
    }

  /// A peer that has reached max_violations stays blocked: it is never served
  /// another peers request across reconnects or remove_peer, until its violations
  /// expire or are explicitly cleared (rate_limiter.rs:112-133). Otherwise a
  /// flooding peer regains its full request budget by disconnecting.
  val max_violations_stays_blocked: bool =
    not(ghost.blocked_peer_admitted)

  /// In-progress dials, peers requests and connect requests never exceed their
  /// concurrency factor, so a dial storm cannot exhaust the node's file
  /// descriptors (controller.rs:85-87).
  val in_progress_within_concurrency: bool =
    and {
      ctrl.dial_in_progress.keys().size() <= DIAL_CONCURRENT_FACTOR,
      ctrl.peers_req_in_progress.keys().size() <= PEERS_REQUEST_CONCURRENT_FACTOR,
      ctrl.connect_req_in_progress.keys().size() <= CONNECT_REQUEST_CONCURRENT_FACTOR,
    }

  /// At most max_requests_per_window peers requests from one peer are ever served
  /// within one rate window (default 6 per 60s). Counted independently of the
  /// limiter's own counter, so a window that is reset out from under the count
  /// (e.g. by violation expiry) shows up here.
  val rate_limit_admits_at_most_max_per_window: bool =
    ghost.admitted.keys().forall(p =>
      ghost.admitted.get(p).count <= rl.max_requests)

  /// A peer is never both an inbound and an outbound peer — the two sets are the
  /// node's accounting of its persistent slots, and double counting would let one
  /// peer occupy two slots (handlers/peers_management.rs:44-46).
  val inbound_and_outbound_disjoint: bool =
    node.inbound.forall(p => not(node.outbound.has(p)))

  /// The node never keeps more persistent peers than configured, so an adversary
  /// cannot grow the peer set past its limits by repeated upgrade requests.
  val persistent_peer_limits_respected: bool =
    and {
      node.inbound.size() <= NUM_INBOUND_PEERS,
      node.outbound.keys().size() <= NUM_OUTBOUND_PEERS,
    }

  /// Never more than max_connections_per_peer active connections to one peer.
  val connections_per_peer_bounded: bool =
    node.active_connections.keys().forall(p =>
      node.active_connections.get(p).size() <= MAX_CONNECTIONS_PER_PEER)

  /// Every connection recorded as active for a peer is a known connection whose
  /// recorded peer is that same peer — otherwise close and disconnect decisions
  /// act on the wrong peer.
  val active_connections_are_consistent: bool =
    node.active_connections.keys().forall(p =>
      node.active_connections.get(p).forall(cid =>
        node.connections.has(cid) and node.connections.get(cid).peer == p))

  /// Every address in the Kademlia routing table belongs to the peer it is
  /// stored under, so a peer cannot make the node route another peer's traffic
  /// to an address it controls (handlers/identify.rs:284-289).
  val kad_table_addresses_owned_by_their_peer: bool =
    node.kad_table.keys().forall(p =>
      node.kad_table.get(p).forall(a => addr_owner(a) == p))

  // ═══ observations ════════════════════════════════════════════════════════

  /// A discovered peer's dial was marked done by peer id only — the
  /// poisoning-safe registration path.
  val discovered_dial_registered_peer_id_only: bool =
    ctrl.dial_done_on.exists(pd => match pd { | PId(_) => true | MAddr(_) => false })
      and ghost.registered_addrs == Set()

  /// A configured bootstrap dial registered its trusted addresses.
  val bootstrap_addresses_registered: bool =
    BOOTSTRAP_ADDRS.subseteq(ghost.registered_addrs)

  /// A dial for an address owned by a different peer was queued (the poisoning
  /// attempt actually reached the dial queue).
  val poisoned_dial_attempted: bool = ghost.poisoned_dial_queued

  /// A peers request was served.
  val peers_request_allowed: bool = ghost.last_rl == Allowed

  /// A peers request was rate limited while the peer stayed connected.
  val peers_request_rate_limited: bool = ghost.last_rl == RateLimited

  /// A peer hit max_violations and was scheduled for disconnect.
  val peers_request_max_violations: bool = ghost.last_rl == MaxViolations

  /// A peer's violations expired, wiping both its violations and its window.
  val rate_limiter_violations_expired: bool = ghost.rl_expiry_fired

  /// A blocked peer's window was cleared by remove_peer while its violations
  /// survived — the state the reconnect bypass would need.
  val violations_survived_window_clear: bool =
    rl.violations.keys().exists(p =>
      rl.violations.get(p).count >= MAX_VIOLATIONS and not(rl.requests.has(p)))

  /// One identity of an operator is blocked at max_violations while another
  /// identity of the SAME operator is still being served.
  val sybil_sibling_still_served: bool =
    rl.violations.keys().exists(blocked =>
      rl.violations.get(blocked).count >= MAX_VIOLATIONS and
      ghost.admitted.keys().exists(other =>
        other != blocked and
        OPERATOR.getOrElse(other, 0) == OPERATOR.getOrElse(blocked, 0) and
        ghost.admitted.get(other).count > 0))

  /// A queued dial had no addresses, so build_dial_opts returned None and the
  /// dial was silently skipped.
  val dial_skipped_no_addresses: bool = ghost.dial_no_addrs

  /// A failed dial was retried with backoff.
  val dial_retry_scheduled: bool = ghost.dial_retry_scheduled

  /// A bootstrap dial exhausted its retries and its address done_on marks were
  /// cleared so the periodic timer can start over.
  val bootstrap_dial_history_cleared: bool = ghost.bootstrap_done_on_cleared

  /// The dial concurrency budget is fully occupied.
  val dial_concurrency_saturated: bool =
    ctrl.dial_in_progress.keys().size() == DIAL_CONCURRENT_FACTOR

  /// An incoming upgrade request was accepted into the inbound set.
  val inbound_upgrade_accepted: bool = ghost.inbound_upgrade_accepted

  /// An incoming upgrade request was refused because the inbound limit is full.
  val inbound_upgrade_rejected: bool = ghost.inbound_upgrade_rejected

  /// A peer refused our upgrade request, or the request failed outright, and the
  /// outbound slot was released.
  val connect_request_rejected: bool = ghost.connect_rejected

  /// A connection was classified as ephemeral and scheduled for close.
  val ephemeral_connection_closed: bool = ghost.ephemeral_closed

  /// An extra connection to a peer already at max_connections_per_peer was closed.
  val max_connections_per_peer_enforced: bool = ghost.max_conns_per_peer_closed

  /// Selection returned fewer outbound candidates than requested.
  val outbound_selection_short: bool = ghost.selection_short

  /// A bootstrap node's peer id was reset on disconnect and its dial history
  /// cleared so it can be re-identified.
  val bootstrap_peer_id_reset: bool = ghost.bootstrap_pid_reset

  /// A self-reported identify address was inserted into the Kademlia routing
  /// table.
  val kad_address_added: bool = ghost.kad_addr_added

  /// All outbound slots are filled and confirmed — initial discovery is done.
  val all_outbound_confirmed: bool =
    node.outbound.keys().size() >= 1 and
    node.outbound.keys().forall(p => node.outbound.get(p) == Confirmed)
}
