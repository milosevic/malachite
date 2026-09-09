// Value Sync — the client/server catch-up protocol that pulls decided values
// and their commit certificates from scored peers
// (code/crates/sync/src/handle.rs, state.rs, scoring.rs, scoring/ema.rs)
// together with the engine-side actor's buffering of arrived values against
// the consensus height (code/crates/engine/src/sync.rs:462-520).
//
// The model MIRRORS the code, bugs included. Intent lives in the invariants.
//
// ABSTRACTIONS, stated once:
//   * A height is an `int`; a range is `{ s, e }`, empty when `s > e`.
//   * `request_values` (handle.rs:805-865) is a WHILE loop over the parallel
//     budget. Quint has no recursion, so ONE loop iteration is one
//     `request_values` action: the loop unfolds over successive steps. Every
//     handler that ends with `request_values(...)` therefore performs only its
//     own state update here, and the request pass follows as its own step.
//   * Peer selection is score-weighted random (scoring.rs:154-167). The model
//     keeps the scores (integers scaled to 0..SCORE_MAX) and the eligibility
//     filter exactly, and makes the winner a nondet pick among the eligible —
//     the weighting only biases WHICH eligible peer wins, never which peers
//     are eligible.
//   * `Effect::SendValueRequest` can fail at the transport level
//     (engine/src/sync.rs:417-421 resumes with `None`); that outcome is the
//     `send_ok` pick.
//   * Value bytes and certificates are not modeled; a response is described by
//     its start height, its length, and whether its certificate heights are
//     contiguous.
module valueSyncCore {
  import basicSpells.* from "./spells/basicSpells"

  //////////////////////////////////////////////////////////////////////////////
  // Domains
  //////////////////////////////////////////////////////////////////////////////

  /// `PeerId` — a libp2p identity. The real ids are random per run, so the
  /// code logs each peer's stable sequential oracle identity instead
  /// (`State::oracle_peer`, state.rs), the same pattern the WAL uses for file
  /// paths.
  type PeerId = int

  /// `OutboundRequestId` — the network layer's opaque request handle, likewise
  /// logged as its stable sequential oracle identity
  /// (`State::oracle_request`).
  type ReqId = int

  /// The peers we may exchange status and values with.
  pure val PEER_IDS: Set[PeerId] = 1.to(6)

  /// The request ids the network layer may mint.
  pure val REQ_IDS: Set[ReqId] = 1.to(40)

  /// No request id — what the code logs when nothing was tracked, so an arm
  /// picking it tracks nothing.
  pure val NO_REQ: ReqId = 0

  /// Highest height any actor in the model talks about.
  pure val MAX_HEIGHT: int = 130

  /// The `Config::parallel_requests` values the suite configures; replay
  /// extends the set with whatever a test actually sets.
  pure val PARALLELS: Set[int] = 1.to(8)

  /// The `Config::batch_size` values the suite configures.
  pure val BATCHES: Set[int] = 1.to(8)

  /// Scores live in `0.0..=1.0` (scoring.rs:46-54); the model scales that unit
  /// interval to `0..SCORE_MAX` integers.
  pure val SCORE_MAX: int = 100

  /// `ExponentialMovingAverage::initial_score` = 0.5 (scoring/ema.rs:88).
  pure val INITIAL_SCORE: int = 50

  /// EMA learning rates (scoring/ema.rs), as percentages.
  pure val ALPHA_SUCCESS: int = 30
  pure val ALPHA_TIMEOUT: int = 20
  pure val ALPHA_FAILURE: int = 50

  //////////////////////////////////////////////////////////////////////////////
  // Types
  //////////////////////////////////////////////////////////////////////////////

  /// An inclusive height range, `RangeInclusive<Ctx::Height>`.
  type Range = { s: int, e: int }

  /// `PendingRequestEntry` (state.rs:12-27).
  type PendingEntry = {
    range: Range,
    peer: PeerId,
    excluded_peers: Set[PeerId],
    inflight: bool,
    // Ghosts: what the peer advertised at the moment it was SELECTED. A later
    // status update must not retroactively invalidate the selection, so
    // `requests_go_to_capable_peers` reads these rather than the live status.
    peer_tip_at_send: int,
    peer_hist_min_at_send: int,
  }

  /// `Status<Ctx>` (types.rs:104-108) — what a peer advertises about itself.
  type PeerStatus = { tip: int, hist_min: int }

  /// `HeightStartType` (types.rs:14-20).
  type StartType = Start | Restart

  /// Why a response was rejected as invalid — the four call sites that reach
  /// `on_invalid_value_response` (handle.rs:152, 172, 187, 103).
  type RejectCause = NoResponse | WrongPeer | WrongRange | NonContiguous

  /// `SyncResult` (scoring.rs:17-38). Response times are abstracted to the
  /// quality score the EMA derives from them (`response_quality`, ema.rs:74).
  type SyncOutcome =
      Success(int)
    | PartialSuccess({ received: int, requested: int, quality: int })
    | Timeout
    | Failure

  /// Everything `sync::State` holds (state.rs:29-60), the engine actor's
  /// buffering state (engine/src/sync.rs:220-240), and the ghost fields the
  /// properties and observations need.
  type SyncState = {
    // ---- sync::State ----
    started: bool,
    consensus_height: int,
    tip_height: int,
    sync_height: int,
    // `effective_parallel_requests` / `effective_batch_size` (config.rs:66-72),
    // fixed by `State::new` from the node's Config.
    max_parallel: int,
    batch_size: int,

    pending: ReqId -> PendingEntry,
    peers: PeerId -> PeerStatus,
    scores: PeerId -> int,

    // ---- engine actor: the bounded sync queue and what left it ----
    sync_queue: Set[int],
    forwarded: Set[int],
    ignored: Set[int],

    // ---- ghosts ----
    // Per range START height, the union of every peer ever excluded while
    // retrying that range. Lineage for `excluded_peers_grow_monotonically`.
    excl_ghost: int -> Set[PeerId],
    // Highest tip ever seen, so a lower `Decided` is recognisable.
    max_tip_seen: int,

    // ---- latches for behaviours that leave no other trace ----
    dropped_unknown_request: bool,
    wrong_peer_rejected: bool,
    wrong_range_rejected: bool,
    noncontiguous_rejected: bool,
    empty_response_rejected: bool,
    partial_accepted: bool,
    reservation_made: bool,
    host_truncated: bool,
    peers_exhausted: bool,
    sync_height_bumped: bool,
    read_ahead_blocked: bool,
    budget_blocked: bool,
    send_rolled_back: bool,
    queue_drop: bool,
    server_rejected_range: bool,
    server_clamped_range: bool,
    restart_cleared_pending: bool,
    out_of_order_decide: bool,
    disconnect_rerequest: bool,
    inactive_scores_reset: bool,
    status_triggered_sync: bool,
    timeout_retried: bool,
    failure_retried: bool,
    peer_fault_retried: bool,
    transient_retried: bool,
    exclusion_set_dropped: bool,
  }

  //////////////////////////////////////////////////////////////////////////////
  // Range helpers
  //////////////////////////////////////////////////////////////////////////////

  pure def range_empty(r: Range): bool = r.s > r.e
  pure def range_len(r: Range): int = if (r.e >= r.s) r.e - r.s + 1 else 0
  pure def range_contains(r: Range, h: int): bool = h >= r.s and h <= r.e

  pure def imax(a: int, b: int): int = if (a > b) a else b
  pure def imin(a: int, b: int): int = if (a < b) a else b

  //////////////////////////////////////////////////////////////////////////////
  // Pending-request geometry (handle.rs:1093-1186)
  //////////////////////////////////////////////////////////////////////////////

  /// One step of `find_next_uncovered_height`'s loop: if `h` sits inside a
  /// pending range, jump past it.
  pure def bump_past_covering(h: int, pend: ReqId -> PendingEntry): int =
    pend.keys().fold(h, (acc, k) =>
      if (range_contains(pend.get(k).range, h)) imax(acc, pend.get(k).range.e + 1) else acc)

  /// `find_next_uncovered_height` (handle.rs:1169-1183). The loop runs at most
  /// once per pending entry, so folding over the keys is the whole loop.
  pure def next_uncovered_height(h: int, pend: ReqId -> PendingEntry): int =
    pend.keys().fold(h, (acc, _) => bump_past_covering(acc, pend))

  /// `find_next_uncovered_range_from` (handle.rs:1120-1166): a batch-sized
  /// range from the first uncovered height, cut short by the next pending range.
  pure def next_uncovered_range(h: int, max_size: int, pend: ReqId -> PendingEntry): Range = {
    val start = next_uncovered_height(h, pend)
    val blocking_starts =
      pend.keys()
          .filter(k => pend.get(k).range.e >= start)
          .map(k => pend.get(k).range.s)
    val cap =
      if (blocking_starts.size() == 0)
        MAX_HEIGHT * 2
      else
        blocking_starts.fold(MAX_HEIGHT * 2, (acc, x) => imin(acc, x)) - 1
    { s: start, e: imin(start + imax(1, max_size) - 1, cap) }
  }

  /// `set_sync_height` (handle.rs:1098-1111): raise the candidate to
  /// `tip_height + 1` and then past any pending range covering it. The latch
  /// records the pending-range skip the code warns about.
  pure def with_sync_height(s: SyncState, candidate: int): SyncState = {
    val floor = imax(s.tip_height + 1, candidate)
    val nxt = next_uncovered_height(floor, s.pending)
    { ...s, sync_height: nxt, sync_height_bumped: s.sync_height_bumped or nxt != floor }
  }

  /// `State::inflight_requests` (state.rs:96-102) — only these spend the
  /// parallel-request budget.
  pure def inflight_requests(s: SyncState): int =
    s.pending.keys().filter(k => s.pending.get(k).inflight).size()

  /// `Config::read_ahead_window` = parallel_requests * batch_size (config.rs:76).
  pure def read_ahead_window(s: SyncState): int = s.max_parallel * s.batch_size

  /// `State::read_ahead_limit` (state.rs:110-114).
  pure def read_ahead_limit(s: SyncState): int = s.tip_height + read_ahead_window(s)

  /// `sync_queue_capacity` = read_ahead_window * 2 (engine/src/sync.rs:200).
  pure def sync_queue_capacity(s: SyncState): int = read_ahead_window(s) * 2

  /// `State::prune_pending_requests` (state.rs:222-227).
  pure def prune_pending(s: SyncState): SyncState =
    { ...s,
      pending: s.pending.keys()
                        .filter(k => s.pending.get(k).range.e > s.tip_height)
                        .mapBy(k => s.pending.get(k)) }

  /// `State::get_request_id_by` (state.rs:203-209).
  pure def request_ids_covering(s: SyncState, h: int): Set[ReqId] =
    s.pending.keys().filter(k => range_contains(s.pending.get(k).range, h))

  //////////////////////////////////////////////////////////////////////////////
  // Peer selection (state.rs:139-190)
  //////////////////////////////////////////////////////////////////////////////

  /// Peers whose advertised history covers the WHOLE range.
  pure def peers_with_whole_range(s: SyncState, r: Range, except: Set[PeerId]): Set[PeerId] =
    s.peers.keys().filter(p =>
      not(except.contains(p))
        and s.peers.get(p).hist_min <= r.s
        and r.s <= r.e
        and r.e <= s.peers.get(p).tip)

  /// Peers whose advertised history covers a non-empty PREFIX of the range.
  pure def peers_with_prefix(s: SyncState, r: Range, except: Set[PeerId]): Set[PeerId] =
    s.peers.keys().filter(p =>
      not(except.contains(p))
        and s.peers.get(p).hist_min <= r.s
        and s.peers.get(p).tip >= r.s)

  /// `filter_peers_by_range`'s key set: whole-range peers when there are any,
  /// prefix peers otherwise.
  pure def eligible_peers(s: SyncState, r: Range, except: Set[PeerId]): Set[PeerId] = {
    val whole = peers_with_whole_range(s, r, except)
    if (whole.size() != 0) whole else peers_with_prefix(s, r, except)
  }

  /// The range the selected peer is asked for: the whole range when it has all
  /// of it, otherwise the prefix up to that peer's advertised tip.
  pure def offered_range(s: SyncState, r: Range, except: Set[PeerId], peer: PeerId): Range =
    if (peers_with_whole_range(s, r, except).size() != 0)
      r
    else
      { s: r.s, e: s.peers.get(peer).tip }

  //////////////////////////////////////////////////////////////////////////////
  // Peer scoring (scoring.rs:119-141, scoring/ema.rs:92-153)
  //////////////////////////////////////////////////////////////////////////////

  /// `PeerScorer::get_score` — an unknown peer reads as the initial score.
  pure def score_of(s: SyncState, peer: PeerId): int =
    s.scores.getOrElse(peer, INITIAL_SCORE)

  /// `ExponentialMovingAverage::update_score` (ema.rs:92-153), on the model's
  /// 0..SCORE_MAX scale. Integer division truncates, which only ever moves the
  /// result downwards inside the range.
  pure def ema_update(prev: int, outcome: SyncOutcome): int =
    match outcome {
      | Success(quality) => (ALPHA_SUCCESS * quality + (100 - ALPHA_SUCCESS) * prev) / 100
      | PartialSuccess(p) => {
          // `ratio = received / requested`, clamped; folded into the quality.
          val quality = if (p.requested == 0) 0 else (p.quality * p.received) / p.requested
          (ALPHA_SUCCESS * quality + (100 - ALPHA_SUCCESS) * prev) / 100
        }
      | Timeout => ((100 - ALPHA_TIMEOUT) * prev) / 100
      | Failure => ((100 - ALPHA_FAILURE) * prev) / 100
    }

  /// `PeerScorer::update_score` (scoring.rs:122-141).
  pure def rescore(s: SyncState, peer: PeerId, outcome: SyncOutcome): SyncState =
    { ...s, scores: s.scores.put(peer, ema_update(score_of(s, peer), outcome)) }

  //////////////////////////////////////////////////////////////////////////////
  // Sending and tracking a request (handle.rs:876-935)
  //////////////////////////////////////////////////////////////////////////////

  /// `send_and_track_request_to_peer`: trim the already-validated prefix, send,
  /// and either track the request or roll `sync_height` back to the range start.
  pure def send_and_track(s: SyncState, peer: PeerId, r: Range, excluded: Set[PeerId],
                          request_id: ReqId, send_ok: bool): SyncState = {
    // `send_request_to_peer` -> `State::trim_validated_heights` (state.rs:214-219).
    val trimmed = { s: imax(s.tip_height + 1, r.s), e: r.e }
    if (range_empty(r) or range_empty(trimmed) or not(send_ok) or request_id == NO_REQ)
      // Ok(None): roll sync_height back so the range is reconsidered.
      with_sync_height({ ...s, send_rolled_back: true }, imin(s.sync_height, r.s))
    else {
      val tracked =
        { ...s,
          pending: s.pending.put(request_id, { range: trimmed, peer: peer,
                                        excluded_peers: excluded, inflight: true,
                                        peer_tip_at_send: s.peers.get(peer).tip,
                                        peer_hist_min_at_send: s.peers.get(peer).hist_min }),
          excl_ghost: s.excl_ghost.put(
            trimmed.s, s.excl_ghost.getOrElse(trimmed.s, Set()).union(excluded)) }
      // Advance sync_height past this range only if it sat inside the range.
      if (range_contains(trimmed, tracked.sync_height))
        with_sync_height(tracked, trimmed.e + 1)
      else
        tracked
    }
  }

  //////////////////////////////////////////////////////////////////////////////
  // Re-requesting a failed range (handle.rs:995-1085)
  //////////////////////////////////////////////////////////////////////////////

  /// The exclusion set `re_request_values_from_peer_except` builds for an entry.
  pure def retry_exclusions(entry: PendingEntry, except_peer: Option[PeerId]): Set[PeerId] =
    match except_peer {
      | None => entry.excluded_peers
      | Some(p) =>
          if (entry.peer == p)
            entry.excluded_peers.union(Set(p))
          else
            // Response from a peer other than the recorded one: exclude both.
            entry.excluded_peers.union(Set(entry.peer, p))
    }

  /// The eligible peers a retry of `rid` may pick from.
  pure def retry_candidates(s: SyncState, rid: ReqId, except_peer: Option[PeerId]): Set[PeerId] = {
    val entry = s.pending.get(rid)
    eligible_peers(s, entry.range, retry_exclusions(entry, except_peer))
  }

  /// `re_request_values_from_peer_except`. `retry_peer` is the score-weighted
  /// winner among `retry_candidates`; it is ignored on the two early returns.
  pure def do_re_request(s: SyncState, rid: ReqId, except_peer: Option[PeerId],
                         retry_peer: PeerId, new_request_id: ReqId,
                         send_ok: bool): SyncState = {
    if (not(s.pending.keys().contains(rid)))
      // "Unknown request ID when re-requesting values" — nothing happens.
      s
    else {
      val entry = s.pending.get(rid)
      val excluded = retry_exclusions(entry, except_peer)
      val without = { ...s,
                      pending: s.pending.mapRemove(rid),
                      excl_ghost: s.excl_ghost.put(
                        entry.range.s,
                        s.excl_ghost.getOrElse(entry.range.s, Set()).union(excluded)) }
      if (inflight_requests(without) >= without.max_parallel)
        // Budget full: leave the range to the next request pass.
        with_sync_height({ ...without, budget_blocked: true },
                         imin(without.sync_height, entry.range.s))
      else {
        val candidates = eligible_peers(without, entry.range, excluded)
        if (candidates.size() == 0)
          // All eligible peers exhausted: reset sync_height to the range start.
          with_sync_height({ ...without, peers_exhausted: true },
                           imin(without.sync_height, entry.range.s))
        else {
          // A retry that never reached peer selection logs NO_PEER; nothing is
          // sent, so the range simply returns to the frontier below.
          val peer_range =
            if (without.peers.keys().contains(retry_peer))
              offered_range(without, entry.range, excluded, retry_peer)
            else
              entry.range
          // NOTE (handle.rs:1064-1072): the exclusion set is MOVED into the send
          // and dropped when the send fails.
          val sent = send_and_track(
            { ...without,
              exclusion_set_dropped: without.exclusion_set_dropped or not(send_ok) },
            retry_peer, peer_range, excluded, new_request_id, send_ok)
          // Keep any suffix a prefix-only retry omitted on the next frontier.
          if (peer_range.e < entry.range.e)
            with_sync_height(sent, imin(sent.sync_height, peer_range.e + 1))
          else
            sent
        }
      }
    }
  }

  //////////////////////////////////////////////////////////////////////////////
  // Server-side request validation (handle.rs:389-434)
  //////////////////////////////////////////////////////////////////////////////

  /// `validate_request_range`.
  pure def validate_request_range(r: Range, tip: int, batch_size: int): bool =
    not(range_empty(r)) and r.s <= tip and range_len(r) <= batch_size

  /// `clamp_request_range` (handle.rs:419-434).
  pure def clamp_request_range(r: Range, tip: int): Range = { s: r.s, e: imin(r.e, tip) }

  //////////////////////////////////////////////////////////////////////////////
  // Initial state — `State::new` (state.rs:63-88)
  //////////////////////////////////////////////////////////////////////////////

  pure val initial_state: SyncState = {
    // Before `State::new` runs the model carries the clamped-minimum config;
    // `state_new` installs the node's real one.
    max_parallel: 1,
    batch_size: 1,
    started: false,
    consensus_height: 0,
    tip_height: 0,
    sync_height: 0,
    pending: Map(),
    peers: Map(),
    scores: Map(),
    sync_queue: Set(),
    forwarded: Set(),
    ignored: Set(),
    excl_ghost: Map(),
    max_tip_seen: 0,
    dropped_unknown_request: false,
    wrong_peer_rejected: false,
    wrong_range_rejected: false,
    noncontiguous_rejected: false,
    empty_response_rejected: false,
    partial_accepted: false,
    reservation_made: false,
    host_truncated: false,
    peers_exhausted: false,
    sync_height_bumped: false,
    read_ahead_blocked: false,
    budget_blocked: false,
    send_rolled_back: false,
    queue_drop: false,
    server_rejected_range: false,
    server_clamped_range: false,
    restart_cleared_pending: false,
    out_of_order_decide: false,
    disconnect_rerequest: false,
    inactive_scores_reset: false,
    status_triggered_sync: false,
    timeout_retried: false,
    failure_retried: false,
    peer_fault_retried: false,
    transient_retried: false,
    exclusion_set_dropped: false,
  }
}

module valueSync {
  import basicSpells.* from "./spells/basicSpells"
  import valueSyncCore.*

  var st: SyncState

  action init = all {
    st' = initial_state,
  }

  //////////////////////////////////////////////////////////////////////////////
  // Client side — status, heights, decisions
  //////////////////////////////////////////////////////////////////////////////

  /// `State::new` (state.rs:63-88): a fresh sync state carrying this node's
  /// effective request budget and batch size.
  action state_new(parallel_requests: int, batch_size: int): bool = all {
    st' = { ...initial_state,
            max_parallel: imax(1, parallel_requests),
            batch_size: imax(1, batch_size) },
  }

  /// `on_send_status_update` (handle.rs:203-228): broadcast the tip and, when an
  /// inactive threshold is configured, drop scores that have gone stale.
  action on_send_status_update(prune_inactive: bool): bool = all {
    st' = if (prune_inactive)
            // `reset_inactive_peers_scores` (scoring.rs:174-182) forgets the
            // stale entries, so they read as the initial score again.
            { ...st, scores: Map(), inactive_scores_reset: true }
          else
            st,
  }

  /// `on_status` (handle.rs:230-268): record the peer's advertised tip, then
  /// request values if consensus has started and the peer is at or above our
  /// sync height. The advertised tip is taken on trust.
  action on_status(peer: PeerId, peer_tip: int, hist_min: int): bool = all {
    hist_min <= peer_tip,
    val updated = { ...st, peers: st.peers.put(peer, { tip: peer_tip, hist_min: hist_min }) }
    st' = if (updated.started and peer_tip >= updated.sync_height)
            { ...updated, status_triggered_sync: true }
          else
            updated,
  }

  /// `on_started_height` (handle.rs:270-305): the tip is the height below the
  /// one starting; a restart clears every pending request and rewinds
  /// `sync_height`, a fresh start keeps the higher of the two.
  action on_started_height(height: int, start_type: StartType): bool = all {
    val base = { ...st,
                 started: true,
                 consensus_height: height,
                 tip_height: if (height > 0) height - 1 else 0,
                 max_tip_seen: imax(st.max_tip_seen, if (height > 0) height - 1 else 0) }
    val pruned = prune_pending(base)
    val next_state = match start_type {
      | Restart =>
          with_sync_height(
            { ...pruned,
              pending: Map(),
              restart_cleared_pending: pruned.restart_cleared_pending
                                         or pruned.pending.keys().size() != 0 },
            height)
      | Start => with_sync_height(pruned, imax(pruned.sync_height, height))
    }
    st' = next_state,
  }

  /// `on_decided` (handle.rs:307-329): keep the tip at the highest height seen,
  /// prune what the tip covers, and re-validate `sync_height`.
  action on_decided(height: int): bool = all {
    val base = { ...st,
                 tip_height: imax(st.tip_height, height),
                 max_tip_seen: imax(st.max_tip_seen, height),
                 out_of_order_decide: st.out_of_order_decide or height < st.max_tip_seen }
    st' = with_sync_height(prune_pending(base), base.sync_height),
  }

  /// One iteration of `request_values` (handle.rs:805-865): pick the next
  /// uncovered range and send it to an eligible peer, unless the budget is
  /// spent, the read-ahead limit is reached, or no peer can serve it.
  action request_values(peer: PeerId, new_request_id: ReqId, send_ok: bool): bool = all {
    st.started,
    not(st.pending.keys().contains(new_request_id)),
    val rng = next_uncovered_range(st.sync_height, st.batch_size, st.pending)
    val candidates = eligible_peers(st, rng, Set())
    all {
      // The winner of the score-weighted draw, when there is a draw to win.
      candidates.size() == 0 or candidates.contains(peer),
      st' =
        if (inflight_requests(st) >= st.max_parallel)
          { ...st, budget_blocked: true }
        else if (rng.s > read_ahead_limit(st))
          { ...st, read_ahead_blocked: true }
        else if (candidates.size() == 0)
          st
        else
          send_and_track(st, peer, offered_range(st, rng, Set(), peer), Set(),
                         new_request_id, send_ok),
    },
  }

  //////////////////////////////////////////////////////////////////////////////
  // Client side — responses
  //////////////////////////////////////////////////////////////////////////////

  /// `on_value_response`'s first guard (handle.rs:127-131): a response whose
  /// request id we no longer hold is dropped without a trace.
  action on_value_response(request_id: ReqId, peer: PeerId): bool = all {
    not(st.pending.keys().contains(request_id)),
    st' = { ...st, dropped_unknown_request: true },
  }

  /// `on_valid_value_response` (handle.rs:436-537). Guards are exactly
  /// `on_value_response`'s acceptance checks (handle.rs:127-186): the request
  /// is known, the peer is the recorded one, the response starts at the
  /// requested start height, is non-empty, is no longer than the request, and
  /// has contiguous certificate heights.
  action on_valid_value_response(request_id: ReqId, peer: PeerId, start_height: int,
                                 count: int, quality: int): bool = all {
    st.pending.keys().contains(request_id),
    st.pending.get(request_id).peer == peer,
    start_height == st.pending.get(request_id).range.s,
    count > 0,
    count <= range_len(st.pending.get(request_id).range),
    val entry = st.pending.get(request_id)
    val requested_len = range_len(entry.range)
    val outcome =
      if (count < requested_len)
        PartialSuccess({ received: count, requested: requested_len, quality: quality })
      else
        Success(quality)
    val scored = rescore(st, peer, outcome)
    // `Effect::ProcessValueResponse` -> `process_value_response`
    // (engine/src/sync.rs:462-520): each value is dropped, forwarded, or
    // buffered against the consensus height, and the queue is bounded.
    val delivered = deliver_values(scored, entry.range.s, count)
    if (count < requested_len) {
      // Shrink the entry to what arrived, turn it into a reservation, and
      // return the suffix to the global frontier.
      val new_start = entry.range.s + count
      val shrunk = { ...delivered,
                     partial_accepted: true,
                     pending: delivered.pending.put(
                       request_id,
                       { ...entry, range: { s: entry.range.s, e: new_start - 1 },
                         inflight: false }) }
      st' = with_sync_height(prune_pending(shrunk), imin(shrunk.sync_height, new_start))
    } else {
      // Full response: the entry becomes a reservation and releases its slot,
      // and the released slot is spent immediately.
      val reserved = { ...delivered,
                       reservation_made: true,
                       pending: delivered.pending.put(request_id, { ...entry, inflight: false }) }
      st' = reserved
    },
  }

  /// `on_invalid_value_response` (handle.rs:539-560): score the peer down and
  /// re-request the whole range from another peer. Reached from a `None`
  /// response, a response from the wrong peer, a wrong-length or wrong-start
  /// response, and non-contiguous certificate heights.
  action on_invalid_value_response(request_id: ReqId, peer: PeerId, cause: RejectCause,
                                   retry_peer: PeerId, new_request_id: ReqId,
                                   send_ok: bool): bool = all {
    not(st.pending.keys().contains(new_request_id)),
    reject_cause_reachable(request_id, peer, cause),
    val scored = latch_cause(rescore(st, peer, Failure), cause)
    all {
      retry_choice_ok(scored, request_id, Some(peer), retry_peer),
      st' = do_re_request(scored, request_id, Some(peer), retry_peer, new_request_id, send_ok),
    },
  }

  /// `on_sync_request_timed_out` (handle.rs:625-663): score a Timeout, cancel
  /// the request at the network layer, retry excluding that peer.
  action on_sync_request_timed_out(request_id: ReqId, peer: PeerId, retry_peer: PeerId,
                                   new_request_id: ReqId, send_ok: bool): bool = all {
    not(st.pending.keys().contains(new_request_id)),
    st.pending.keys().contains(request_id),
    st.pending.get(request_id).peer == peer,
    val scored = { ...rescore(st, peer, Timeout), timeout_retried: true }
    all {
      retry_choice_ok(scored, request_id, Some(peer), retry_peer),
      st' = do_re_request(scored, request_id, Some(peer), retry_peer, new_request_id, send_ok),
    },
  }

  /// `on_sync_request_failed` (handle.rs:665-692): the network layer could not
  /// deliver the request. Score a Failure and retry excluding that peer.
  action on_sync_request_failed(request_id: ReqId, peer: PeerId, retry_peer: PeerId,
                                new_request_id: ReqId, send_ok: bool): bool = all {
    not(st.pending.keys().contains(new_request_id)),
    st.pending.keys().contains(request_id),
    st.pending.get(request_id).peer == peer,
    val scored = { ...rescore(st, peer, Failure), failure_retried: true }
    all {
      retry_choice_ok(scored, request_id, Some(peer), retry_peer),
      st' = do_re_request(scored, request_id, Some(peer), retry_peer, new_request_id, send_ok),
    },
  }

  /// `on_peer_fault` -> `penalize_peer_and_retry` (handle.rs:733-802): a fault
  /// in a synced value is blamed on the peer that served it.
  action on_peer_fault(peer: PeerId, height: int, request_id: ReqId, retry_peer: PeerId,
                       new_request_id: ReqId, send_ok: bool): bool = all {
    not(st.pending.keys().contains(new_request_id)),
    request_ids_covering(st, height).contains(request_id),
    val scored = { ...rescore(st, peer, Failure), peer_fault_retried: true }
    all {
      retry_choice_ok(scored, request_id, Some(peer), retry_peer),
      st' = do_re_request(scored, request_id, Some(peer), retry_peer, new_request_id, send_ok),
    },
  }

  /// `on_local_transient_error` (handle.rs:707-731): a local failure while
  /// processing a synced value. Nobody is penalised or excluded.
  action on_local_transient_error(height: int, request_id: ReqId, retry_peer: PeerId,
                                  new_request_id: ReqId, send_ok: bool): bool = all {
    not(st.pending.keys().contains(new_request_id)),
    request_ids_covering(st, height).contains(request_id),
    val marked = { ...st, transient_retried: true }
    all {
      retry_choice_ok(marked, request_id, None, retry_peer),
      st' = do_re_request(marked, request_id, None, retry_peer, new_request_id, send_ok),
    },
  }

  /// `on_peer_disconnected` (handle.rs:694-731): forget the peer's status and
  /// re-request the ONE in-flight request assigned to it (the code loops over
  /// all of them; one per step unfolds the loop). Reservations are left alone.
  action on_peer_disconnected(peer: PeerId, request_id: ReqId, retry_peer: PeerId,
                              new_request_id: ReqId, send_ok: bool): bool = all {
    not(st.pending.keys().contains(new_request_id)),
    st.peers.keys().contains(peer),
    val dropped = { ...st, peers: st.peers.mapRemove(peer) }
    val victims = dropped.pending.keys()
                         .filter(k => dropped.pending.get(k).peer == peer
                                        and dropped.pending.get(k).inflight)
    all {
      victims.size() == 0 or victims.contains(request_id),
      st' = if (victims.size() == 0)
              dropped
            else all_retry(dropped, request_id, peer, retry_peer, new_request_id, send_ok),
    },
  }

  //////////////////////////////////////////////////////////////////////////////
  // Server side — answering a peer's request
  //////////////////////////////////////////////////////////////////////////////

  /// `on_value_request` (handle.rs:331-387): reject an empty, inverted,
  /// beyond-tip or oversized range with an empty response; otherwise clamp the
  /// range to our tip and ask the host for the values.
  action on_value_request(peer: PeerId, req_start: int, req_end: int): bool = all {
    val r = { s: req_start, e: req_end }
    st' = if (not(validate_request_range(r, st.tip_height, st.batch_size)))
            { ...st, server_rejected_range: true }
          else {
            val clamped = clamp_request_range(r, st.tip_height)
            { ...st, server_clamped_range: st.server_clamped_range or clamped != r }
          },
  }

  /// `on_got_decided_values` (handle.rs:562-624): the host's values are
  /// truncated at the first height that is not the expected one, and the valid
  /// contiguous prefix is still sent to the requesting peer.
  action on_got_decided_values(req_start: int, req_end: int, returned: int,
                               valid_prefix: int): bool = all {
    valid_prefix <= returned,
    st' = { ...st, host_truncated: st.host_truncated or valid_prefix < returned },
  }

  //////////////////////////////////////////////////////////////////////////////
  // Engine actor — buffering an arrived response (engine/src/sync.rs:462-520)
  //////////////////////////////////////////////////////////////////////////////

  /// `process_value_response`: a value below the consensus height is ignored,
  /// one at it is forwarded, one above it is buffered — and the buffer is
  /// bounded, so a push can be dropped when the queue is full.
  pure def deliver_one(s: SyncState, height: int): SyncState =
    if (height < s.consensus_height)
      { ...s, ignored: s.ignored.union(Set(height)) }
    else if (height == s.consensus_height)
      { ...s, forwarded: s.forwarded.union(Set(height)) }
    else if (s.sync_queue.size() >= sync_queue_capacity(s) and not(s.sync_queue.contains(height)))
      { ...s, queue_drop: true }
    else
      { ...s, sync_queue: s.sync_queue.union(Set(height)) }

  /// The whole response, height by height.
  pure def deliver_values(s: SyncState, start: int, count: int): SyncState =
    0.to(imax(0, count - 1)).fold(s, (acc, i) =>
      if (i < count) deliver_one(acc, start + i) else acc)

  /// The engine drains the buffered value once consensus reaches its height
  /// (engine/src/sync.rs, `process_buffered_values`).
  action process_value_response(height: int): bool = all {
    st.sync_queue.contains(height),
    height <= st.consensus_height,
    st' = { ...st,
            sync_queue: st.sync_queue.exclude(Set(height)),
            forwarded: st.forwarded.union(Set(height)) },
  }

  //////////////////////////////////////////////////////////////////////////////
  // Shared helpers used by the guards above
  //////////////////////////////////////////////////////////////////////////////

  /// The retry pick is the score-weighted winner among the eligible peers, or
  /// irrelevant when there are none (the exhaustion branch).
  pure def retry_choice_ok(s: SyncState, rid: ReqId, except_peer: Option[PeerId],
                           retry_peer: PeerId): bool =
    if (not(s.pending.keys().contains(rid)))
      true
    else {
      val c = retry_candidates(s, rid, except_peer)
      // NO_PEER is what the code logs when it returned before selecting a peer
      // (budget full, or every eligible peer exhausted).
      c.size() == 0 or retry_peer == NO_PEER or c.contains(retry_peer)
    }

  // NOTE: the handlers that end with `request_values(...)` in the code do NOT
  // perform the request pass here. The code's nested call reaches
  // `send_and_track_request_to_peer`, which logs its own `request_values`
  // event, so the model takes that pass as its own step.

  /// `on_peer_disconnected`'s per-victim retry.
  pure def all_retry(s: SyncState, rid: ReqId, peer: PeerId, retry_peer: PeerId,
                     new_request_id: ReqId, send_ok: bool): SyncState =
    do_re_request({ ...s, disconnect_rerequest: true }, rid, Some(peer), retry_peer,
                  new_request_id, send_ok)

  /// A reject cause is only reachable when the response really has that defect.
  /// `NoResponse` needs no defect (`Input::ValueResponse(.., None)`), the others
  /// are the checks `on_value_response` performs before dispatching here.
  def reject_cause_reachable(request_id: ReqId, peer: PeerId, cause: RejectCause): bool =
    match cause {
      | NoResponse => st.pending.keys().contains(request_id)
                        and st.pending.get(request_id).peer == peer
      | WrongPeer => st.pending.keys().contains(request_id)
                       and st.pending.get(request_id).peer != peer
      | WrongRange => st.pending.keys().contains(request_id)
                        and st.pending.get(request_id).peer == peer
      | NonContiguous => st.pending.keys().contains(request_id)
                           and st.pending.get(request_id).peer == peer
    }

  /// The peer a pending request was sent to (1 for the sentinel id, which no
  /// action accepts anyway).
  def pending_peer(rid: ReqId): PeerId =
    if (st.pending.keys().contains(rid)) st.pending.get(rid).peer else NO_PEER

  /// The start height a pending request asked for.
  def pending_start(rid: ReqId): int =
    if (st.pending.keys().contains(rid)) st.pending.get(rid).range.s else 0

  /// Heights consensus may start, including the height just above a pending
  /// range's start — the boundary where a range keeps a height consensus has
  /// already moved past.
  def height_pick_domain: Set[int] =
    HEIGHTS.union(st.pending.keys().map(k => st.pending.get(k).range.s + 1))

  /// The number of heights a pending request asked for.
  def pending_len(rid: ReqId): int =
    if (st.pending.keys().contains(rid)) range_len(st.pending.get(rid).range) else 0

  /// The end height a pending request asked for.
  def pending_end(rid: ReqId): int =
    if (st.pending.keys().contains(rid)) st.pending.get(rid).range.e else 0

  /// The peers a retry of `rid` may pick from. NO_PEER is always available:
  /// it is what the code logs when the retry found nobody, and every guard
  /// that consumes the pick ignores it in that case.
  def retry_pick_domain(rid: ReqId, except_peer: Option[PeerId]): Set[PeerId] =
    if (not(st.pending.keys().contains(rid)))
      PEER_IDS.union(Set(NO_PEER))
    else {
      val c = retry_candidates(st, rid, except_peer)
      if (c.size() == 0) PEER_IDS.union(Set(NO_PEER)) else c.union(Set(NO_PEER))
    }

  /// The peers a fresh request pass may pick from, PEER_IDS when there are none.
  def request_pick_domain: Set[PeerId] = {
    val c = eligible_peers(st, next_uncovered_range(st.sync_height, st.batch_size, st.pending), Set())
    if (c.size() == 0) PEER_IDS else c
  }

  /// A peer other than the one a pending request was sent to.
  /// No peer — what the code logs when no peer was selected.
  pure val NO_PEER: PeerId = 0

  def other_than_pending_peer(rid: ReqId): PeerId = {
    val others = PEER_IDS.exclude(Set(pending_peer(rid)))
    others.fold(NO_PEER, (acc, p) => if (acc == NO_PEER) p else acc)
  }

  pure def latch_cause(s: SyncState, cause: RejectCause): SyncState =
    match cause {
      | NoResponse => { ...s, empty_response_rejected: true }
      | WrongPeer => { ...s, wrong_peer_rejected: true }
      | WrongRange => { ...s, wrong_range_rejected: true }
      | NonContiguous => { ...s, noncontiguous_rejected: true }
    }

  //////////////////////////////////////////////////////////////////////////////
  // step — every nondet pick lives here
  //////////////////////////////////////////////////////////////////////////////

  pure val HEIGHTS: Set[int] = 0.to(MAX_HEIGHT)
  pure val COUNTS: Set[int] = 0.to(12)
  pure val QUALITIES: Set[int] = Set(0, 50, SCORE_MAX)
  pure val CAUSES: Set[RejectCause] = Set(NoResponse, WrongPeer, WrongRange, NonContiguous)

  action step = any {
    {
      nondet parallel_requests = PARALLELS.oneOf()
      nondet batch_size = BATCHES.oneOf()
      state_new(parallel_requests, batch_size)
    },
    {
      nondet prune_inactive = Bool.oneOf()
      on_send_status_update(prune_inactive)
    },
    {
      nondet peer = PEER_IDS.oneOf()
      nondet peer_tip = HEIGHTS.oneOf()
      // A pruning node advertises a floor above 0, which the eligibility
      // filter must respect; a floor above the tip is the degenerate status.
      nondet hist_min = HEIGHTS.union(Set(peer_tip + 1)).oneOf()
      on_status(peer, peer_tip, hist_min)
    },
    {
      nondet height = height_pick_domain.oneOf()
      nondet start_type = Set(Start, Restart).oneOf()
      on_started_height(height, start_type)
    },
    {
      nondet height = HEIGHTS.oneOf()
      on_decided(height)
    },
    {
      nondet peer = request_pick_domain.oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      request_values(peer, new_request_id, send_ok)
    },
    {
      nondet request_id = REQ_IDS.oneOf()
      nondet peer = PEER_IDS.oneOf()
      on_value_response(request_id, peer)
    },
    {
      // The request id, the serving peer and the requested start height are
      // what the network layer hands back with the response, so they are read
      // off the pending request rather than drawn freely; the response LENGTH
      // (including lengths the guards reject) is the peer's own choice.
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      val entry_peer = pending_peer(request_id)
      val entry_start = pending_start(request_id)
      // `on_value_response` routes anything with the wrong start height or
      // length to `on_invalid_value_response`, so this arm carries only the
      // shapes it accepts: a non-empty prefix (partial) or the whole range.
      val start_height = entry_start
      nondet count = Set(1, pending_len(request_id)).oneOf()
      nondet quality = QUALITIES.oneOf()
      on_valid_value_response(request_id, entry_peer, start_height, count, quality)
    },
    {
      // The recorded peer answered, but with nothing, a wrong range, or
      // non-contiguous certificate heights.
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      val peer = pending_peer(request_id)
      nondet cause = Set(NoResponse, WrongRange, NonContiguous).oneOf()
      nondet retry_peer = retry_pick_domain(request_id, Some(peer)).oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      on_invalid_value_response(request_id, peer, cause, retry_peer, new_request_id, send_ok)
    },
    {
      // Someone other than the recorded peer answered the request.
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      val peer = other_than_pending_peer(request_id)
      nondet retry_peer = retry_pick_domain(request_id, Some(peer)).oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      on_invalid_value_response(request_id, peer, WrongPeer, retry_peer, new_request_id, send_ok)
    },
    {
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      val peer = pending_peer(request_id)
      nondet retry_peer = retry_pick_domain(request_id, Some(peer)).oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      on_sync_request_timed_out(request_id, peer, retry_peer, new_request_id, send_ok)
    },
    {
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      val peer = pending_peer(request_id)
      nondet retry_peer = retry_pick_domain(request_id, Some(peer)).oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      on_sync_request_failed(request_id, peer, retry_peer, new_request_id, send_ok)
    },
    {
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      val peer = pending_peer(request_id)
      nondet height = Set(pending_start(request_id), pending_end(request_id)).oneOf()
      nondet retry_peer = retry_pick_domain(request_id, Some(peer)).oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      on_peer_fault(peer, height, request_id, retry_peer, new_request_id, send_ok)
    },
    {
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      nondet height = Set(pending_start(request_id), pending_end(request_id)).oneOf()
      nondet retry_peer = retry_pick_domain(request_id, None).oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      on_local_transient_error(height, request_id, retry_peer, new_request_id, send_ok)
    },
    {
      nondet peer = PEER_IDS.oneOf()
      nondet request_id = st.pending.keys().union(Set(NO_REQ)).oneOf()
      nondet retry_peer = retry_pick_domain(request_id, Some(peer)).oneOf()
      nondet new_request_id = REQ_IDS.exclude(st.pending.keys()).union(Set(NO_REQ)).oneOf()
      nondet send_ok = Bool.oneOf()
      on_peer_disconnected(peer, request_id, retry_peer, new_request_id, send_ok)
    },
    {
      nondet peer = PEER_IDS.oneOf()
      nondet req_start = HEIGHTS.oneOf()
      nondet req_end = HEIGHTS.oneOf()
      on_value_request(peer, req_start, req_end)
    },
    {
      nondet req_start = HEIGHTS.oneOf()
      nondet req_end = HEIGHTS.oneOf()
      nondet returned = COUNTS.oneOf()
      nondet valid_prefix = COUNTS.oneOf()
      on_got_decided_values(req_start, req_end, returned, valid_prefix)
    },
    {
      nondet height = st.sync_queue.union(Set(0)).oneOf()
      process_value_response(height)
    },
  }

  //////////////////////////////////////////////////////////////////////////////
  // Correctness properties
  //////////////////////////////////////////////////////////////////////////////

  /// Once consensus has started, sync_height is always strictly above the tip
  /// height.
  val sync_height_above_tip: bool = st.started implies st.sync_height > st.tip_height

  /// sync_height never falls inside the height range of a pending request.
  val sync_height_outside_pending_ranges: bool =
    st.pending.keys().forall(k => not(range_contains(st.pending.get(k).range, st.sync_height)))

  /// The height ranges of two distinct pending requests never overlap.
  val pending_ranges_are_disjoint: bool =
    tuples(st.pending.keys(), st.pending.keys()).forall(pair =>
      pair._1 == pair._2 or
        not(ranges_overlap(st.pending.get(pair._1).range, st.pending.get(pair._2).range)))

  /// A request only ever goes to a peer whose advertised history covered the
  /// start of the requested range when the peer was selected.
  val requests_go_to_capable_peers: bool =
    st.pending.keys().forall(k => {
      val entry = st.pending.get(k)
      entry.peer_hist_min_at_send <= entry.range.s and entry.peer_tip_at_send >= entry.range.s
    })

  /// The number of requests awaiting a response never exceeds the configured
  /// parallel-request budget.
  val inflight_requests_within_budget: bool =
    inflight_requests(st) <= st.max_parallel

  /// Every peer already tried for a range stays excluded while that range is
  /// still being retried.
  val excluded_peers_grow_monotonically: bool =
    st.pending.keys().forall(k => {
      val entry = st.pending.get(k)
      st.excl_ghost.getOrElse(entry.range.s, Set())
        .exclude(Set(entry.peer))
        .subseteq(entry.excluded_peers)
    })

  /// Every peer score stays inside the unit interval the scoring strategy
  /// promises.
  val peer_scores_stay_in_unit_range: bool =
    st.scores.keys().forall(p => st.scores.get(p) >= 0 and st.scores.get(p) <= SCORE_MAX)

  // NOTE: "a height is never both buffered and already forwarded" is NOT a
  // property of this component: a re-requested range legitimately delivers a
  // second copy of a height consensus has already been given, and the engine
  // buffers it again.

  /// The bounded sync queue never holds more values than its capacity.
  val sync_queue_within_capacity: bool = st.sync_queue.size() <= sync_queue_capacity(st)

  pure def ranges_overlap(a: Range, b: Range): bool =
    not(range_empty(a)) and not(range_empty(b)) and a.s <= b.e and b.s <= a.e

  //////////////////////////////////////////////////////////////////////////////
  // Observations
  //////////////////////////////////////////////////////////////////////////////

  /// A peer status showed we were behind and triggered a request pass.
  val status_triggered_sync: bool = st.status_triggered_sync

  /// A consensus restart cleared pending requests and rewound the sync height.
  val restart_cleared_pending: bool = st.restart_cleared_pending

  /// A decision arrived for a height below the highest tip already seen.
  val decided_arrived_out_of_order: bool = st.out_of_order_decide

  /// A full response turned its pending request into a reservation.
  val full_response_became_reservation: bool = st.reservation_made

  /// A truncated response was accepted and its remainder returned to the frontier.
  val partial_response_accepted: bool = st.partial_accepted

  /// A response arrived for a request id no longer held and was dropped.
  val response_for_unknown_request_dropped: bool = st.dropped_unknown_request

  /// A response came from a different peer than the request was sent to.
  val response_from_wrong_peer_rejected: bool = st.wrong_peer_rejected

  /// A response with the wrong start height or length was rejected.
  val response_with_wrong_range_rejected: bool = st.wrong_range_rejected

  /// A response whose certificate heights were not contiguous was rejected.
  val noncontiguous_response_rejected: bool = st.noncontiguous_rejected

  /// A peer answered with no response at all.
  val empty_response_rejected: bool = st.empty_response_rejected

  /// A request timed out and was retried against another peer.
  val request_timed_out_and_retried: bool = st.timeout_retried

  /// The network layer failed to deliver a request and it was retried.
  val request_failed_and_retried: bool = st.failure_retried

  /// A fault in a synced value was blamed on the peer that served it.
  val peer_fault_penalised_and_retried: bool = st.peer_fault_retried

  /// A local transient error retried a range without penalising anyone.
  val transient_error_retried_without_penalty: bool = st.transient_retried

  /// A peer disconnected and its in-flight request was reassigned.
  val disconnect_triggered_rerequest: bool = st.disconnect_rerequest

  /// Every eligible peer for a range had been tried and the range was reset.
  val all_peers_exhausted_for_range: bool = st.peers_exhausted

  /// A retry lost its accumulated exclusion set because the send failed.
  val exclusion_set_dropped_on_failed_send: bool = st.exclusion_set_dropped

  /// The read-ahead limit stopped a request pass short.
  val read_ahead_limit_blocked_request: bool = st.read_ahead_blocked

  /// The parallel-request budget stopped a request pass short.
  val parallel_budget_blocked_request: bool = st.budget_blocked

  /// A send was skipped or failed and the sync height was rolled back.
  val send_failure_rolled_back_sync_height: bool = st.send_rolled_back

  /// A sync-height candidate landed inside a pending range and was advanced
  /// past it. NOT submitted as an observation: every caller is expected to pass
  /// a candidate outside every pending range, so this is the defensive path the
  /// code only warns about — `sync_height_outside_pending_ranges` is the
  /// property that guards it.
  val sync_height_advanced_past_pending_range: bool = st.sync_height_bumped

  /// An inbound request was refused with an empty response.
  val inbound_request_rejected_as_invalid: bool = st.server_rejected_range

  /// An inbound request range was clamped down to our own tip.
  val inbound_request_clamped_to_tip: bool = st.server_clamped_range

  /// The host returned values that did not match the requested heights and the
  /// response was truncated to the valid prefix.
  val host_values_truncated: bool = st.host_truncated

  /// Inactive peer scores were reset back to the initial score.
  val inactive_peer_scores_reset: bool = st.inactive_scores_reset

  /// A synced value arrived ahead of consensus and was buffered.
  val value_buffered_ahead_of_consensus: bool = st.sync_queue.size() != 0

  /// A synced value arrived for a height consensus had already decided. NOT
  /// submitted as an observation: it needs a pending range to outlive a height
  /// start that moves consensus past the range's own start, which random
  /// walks reach too rarely to measure reliably.
  val value_ignored_as_already_decided: bool = st.ignored.size() != 0

  /// The bounded sync queue was full and a buffered value was dropped. NOT
  /// submitted as an observation: the queue holds `read_ahead_window * 2`
  /// heights, more than the modeled height range can fill, so overflow is
  /// guarded by the `sync_queue_within_capacity` property instead.
  val sync_queue_dropped_value: bool = st.queue_drop
}
