// Sync value buffering: where a sync value response for a height AHEAD of
// consensus is held, and what happens to it when consensus advances, restarts,
// or reports the value invalid.
//
// Pre-PR behavior: the sync actor forwards every value response straight to
// consensus; consensus buffers future-height values in its *shared* input queue
// (the same bounded queue that holds gossip votes/proposals), and drains it when
// it starts the corresponding height.
module syncValueBuffering {

  pure val MaxHeight = 4
  pure val Heights = 0.to(MaxHeight)
  pure val Requests = Set(1, 2)
  pure val Peers = Set("p1", "p2")

  /// Capacity (in unique heights) of the consensus input queue.
  pure val consensusQueueCapacity = 1

  /// Capacity (in unique heights) of the sync actor's own buffer.
  pure val syncQueueCapacity = 1

  /// A buffered item, tagged with the sync request that produced it
  /// (requestId 0 = a gossip message, which belongs to no sync request).
  type Entry = {
    height: int,
    requestId: int,
    peer: str,
    isSync: bool
  }

  /// The height consensus is currently at.
  var consensusHeight: int
  /// The consensus input queue: gossip messages for future heights (and, pre-PR, sync values too).
  var consensusQueue: Set[Entry]
  /// The sync actor's buffer of values for heights ahead of consensus.
  var syncBuffer: Set[Entry]
  /// Which outbound sync request covers which height.
  var requestOf: int -> int
  /// Requests whose values consensus has rejected as invalid.
  var invalidated: Set[int]
  /// Values handed to the consensus state machine.
  var deliveredToConsensus: Set[Entry]

  // Observations (positive tracks; false at init)

  /// A buffered value from a request already known to be invalid reached consensus.
  var staleValueDelivered: bool
  /// A gossip message was evicted from the consensus input queue by a sync value.
  var gossipEvictedBySyncValue: bool
  /// A sync value was dropped because the buffer holding it was full.
  var syncValueDroppedQueueFull: bool
  /// A value buffered for a future height was later delivered when consensus reached it.
  var bufferedValueDelivered: bool
  /// A consensus restart discarded buffered sync values.
  var restartDroppedBufferedValues: bool
  /// A sync value arrived for a height consensus had already passed, and was ignored.
  var decidedHeightValueIgnored: bool
  /// A sync value arrived for exactly the current consensus height and went straight through.
  var currentHeightValueProcessed: bool

  // ---------------------------------------------------------------- helpers

  pure def heightsOf(q: Set[Entry]): Set[int] = q.map(e => e.height)

  pure def maxOf(hs: Set[int]): int = hs.fold(-1, (acc, h) => if (h > acc) h else acc)

  /// BoundedQueue::push — a new height is accepted if the height is already
  /// present, or there is room, or it is lower than the highest buffered height
  /// (in which case the highest height is evicted).
  pure def pushable(q: Set[Entry], cap: int, h: int): bool = {
    val hs = heightsOf(q)
    hs.contains(h) or hs.size() < cap or h < maxOf(hs)
  }

  pure def pushInto(q: Set[Entry], cap: int, e: Entry): Set[Entry] = {
    val hs = heightsOf(q)
    if (hs.contains(e.height) or hs.size() < cap) q.union(Set(e))
    else if (e.height < maxOf(hs)) q.filter(x => x.height != maxOf(hs)).union(Set(e))
    else q
  }

  /// Whether pushing `e` evicts an entry that is a gossip message.
  pure def evictsGossip(q: Set[Entry], cap: int, e: Entry): bool = {
    val hs = heightsOf(q)
    val mx = maxOf(hs)
    and {
      not(hs.contains(e.height)),
      hs.size() >= cap,
      e.height < mx,
      q.filter(x => x.height == mx).exists(x => not(x.isSync))
    }
  }

  // ---------------------------------------------------------------- actions

  action init = all {
    consensusHeight' = 0,
    consensusQueue' = Set(),
    syncBuffer' = Set(),
    requestOf' = Map(),
    invalidated' = Set(),
    deliveredToConsensus' = Set(),
    staleValueDelivered' = false,
    gossipEvictedBySyncValue' = false,
    syncValueDroppedQueueFull' = false,
    bufferedValueDelivered' = false,
    restartDroppedBufferedValues' = false,
    decidedHeightValueIgnored' = false,
    currentHeightValueProcessed' = false,
  }

  /// The sync actor issues an outbound request covering the batch `h, h + 1`.
  action sendRequest(requestId: int, h: int): bool = all {
    h >= consensusHeight,
    requestOf' = requestOf.put(h, requestId).put(h + 1, requestId),
    consensusHeight' = consensusHeight,
    consensusQueue' = consensusQueue,
    syncBuffer' = syncBuffer,
    invalidated' = invalidated,
    deliveredToConsensus' = deliveredToConsensus,
    staleValueDelivered' = staleValueDelivered,
    gossipEvictedBySyncValue' = gossipEvictedBySyncValue,
    syncValueDroppedQueueFull' = syncValueDroppedQueueFull,
    bufferedValueDelivered' = bufferedValueDelivered,
    restartDroppedBufferedValues' = restartDroppedBufferedValues,
    decidedHeightValueIgnored' = decidedHeightValueIgnored,
    currentHeightValueProcessed' = currentHeightValueProcessed,
  }

  /// One value of a sync response for height `h`, from `peer`, produced by `requestId`.
  action syncResponse(requestId: int, peer: str, h: int): bool = {
    val e = { height: h, requestId: requestId, peer: peer, isSync: true }
    all {
      requestOf.keys().contains(h),
      requestOf.get(h) == requestId,
      if (h < consensusHeight) all {
        // Already decided: ignored.
        consensusQueue' = consensusQueue,
        syncBuffer' = syncBuffer,
        deliveredToConsensus' = deliveredToConsensus,
        syncValueDroppedQueueFull' = syncValueDroppedQueueFull,
        gossipEvictedBySyncValue' = gossipEvictedBySyncValue,
        decidedHeightValueIgnored' = true,
        currentHeightValueProcessed' = currentHeightValueProcessed,
      } else if (h == consensusHeight) all {
        // Current height: processed right away.
        consensusQueue' = consensusQueue,
        syncBuffer' = syncBuffer,
        deliveredToConsensus' = deliveredToConsensus.union(Set(e)),
        syncValueDroppedQueueFull' = syncValueDroppedQueueFull,
        gossipEvictedBySyncValue' = gossipEvictedBySyncValue,
        decidedHeightValueIgnored' = decidedHeightValueIgnored,
        currentHeightValueProcessed' = true,
      } else all {
        // Ahead of consensus: buffered in the sync actor's own queue.
        consensusQueue' = consensusQueue,
        syncBuffer' = pushInto(syncBuffer, syncQueueCapacity, e),
        deliveredToConsensus' = deliveredToConsensus,
        syncValueDroppedQueueFull' =
          (syncValueDroppedQueueFull or not(pushable(syncBuffer, syncQueueCapacity, h))),
        gossipEvictedBySyncValue' = gossipEvictedBySyncValue,
        decidedHeightValueIgnored' = decidedHeightValueIgnored,
        currentHeightValueProcessed' = currentHeightValueProcessed,
      },
      consensusHeight' = consensusHeight,
      requestOf' = requestOf,
      invalidated' = invalidated,
      staleValueDelivered' = staleValueDelivered,
      bufferedValueDelivered' = bufferedValueDelivered,
      restartDroppedBufferedValues' = restartDroppedBufferedValues,
    }
  }

  /// A gossip message (vote / proposal / proposed value) for a future height.
  action gossipMessage(h: int): bool = {
    val e = { height: h, requestId: 0, peer: "none", isSync: false }
    all {
      h > consensusHeight,
      consensusQueue' = pushInto(consensusQueue, consensusQueueCapacity, e),
      consensusHeight' = consensusHeight,
      syncBuffer' = syncBuffer,
      requestOf' = requestOf,
      invalidated' = invalidated,
      deliveredToConsensus' = deliveredToConsensus,
      staleValueDelivered' = staleValueDelivered,
      gossipEvictedBySyncValue' = gossipEvictedBySyncValue,
      syncValueDroppedQueueFull' = syncValueDroppedQueueFull,
      bufferedValueDelivered' = bufferedValueDelivered,
      restartDroppedBufferedValues' = restartDroppedBufferedValues,
      decidedHeightValueIgnored' = decidedHeightValueIgnored,
      currentHeightValueProcessed' = currentHeightValueProcessed,
    }
  }

  /// Consensus reports the value for height `h` from `peer` as invalid;
  /// the sync actor re-requests the covering range from a different peer.
  action invalidValue(peer: str, h: int): bool = all {
    requestOf.keys().contains(h),
    invalidated' = invalidated.union(Set(requestOf.get(h))),
    // Buffered values from the invalidated request are removed.
    syncBuffer' = syncBuffer.filter(e => e.requestId != requestOf.get(h)),
    consensusQueue' = consensusQueue,
    consensusHeight' = consensusHeight,
    requestOf' = requestOf,
    deliveredToConsensus' = deliveredToConsensus,
    staleValueDelivered' = staleValueDelivered,
    gossipEvictedBySyncValue' = gossipEvictedBySyncValue,
    syncValueDroppedQueueFull' = syncValueDroppedQueueFull,
    bufferedValueDelivered' = bufferedValueDelivered,
    restartDroppedBufferedValues' = restartDroppedBufferedValues,
    decidedHeightValueIgnored' = decidedHeightValueIgnored,
    currentHeightValueProcessed' = currentHeightValueProcessed,
  }

  /// Consensus (re)starts height `h`; buffered items for `h` are drained to it.
  action startHeight(h: int, isRestart: bool): bool = {
    val keptBuffer = if (isRestart) Set() else syncBuffer
    val deliveredNow =
      consensusQueue.filter(e => e.height == h).union(keptBuffer.filter(e => e.height == h))
    all {
      h > consensusHeight or (isRestart and h == consensusHeight),
      consensusHeight' = h,
      consensusQueue' = consensusQueue.filter(e => e.height > h),
      syncBuffer' = keptBuffer.filter(e => e.height > h),
      deliveredToConsensus' = deliveredToConsensus.union(deliveredNow),
      staleValueDelivered' =
        (staleValueDelivered or
          deliveredNow.exists(e => e.isSync and invalidated.contains(e.requestId))),
      bufferedValueDelivered' = (bufferedValueDelivered or deliveredNow.exists(e => e.isSync)),
      restartDroppedBufferedValues' =
        (restartDroppedBufferedValues or (isRestart and syncBuffer != Set())),
      requestOf' = requestOf,
      invalidated' = invalidated,
      gossipEvictedBySyncValue' = gossipEvictedBySyncValue,
      syncValueDroppedQueueFull' = syncValueDroppedQueueFull,
      decidedHeightValueIgnored' = decidedHeightValueIgnored,
      currentHeightValueProcessed' = currentHeightValueProcessed,
    }
  }

  action step = any {
    nondet requestId = oneOf(Requests)
    nondet h = oneOf(Heights)
    sendRequest(requestId, h),

    nondet requestId = oneOf(Requests)
    nondet peer = oneOf(Peers)
    nondet h = oneOf(Heights)
    syncResponse(requestId, peer, h),

    nondet h = oneOf(Heights)
    gossipMessage(h),

    nondet peer = oneOf(Peers)
    nondet h = oneOf(Heights)
    invalidValue(peer, h),

    nondet h = oneOf(Heights)
    nondet isRestart = oneOf(Set(false, true))
    startHeight(h, isRestart),
  }

  // ------------------------------------------------------------- properties

  /// A value from a request consensus already rejected as invalid is never
  /// later handed to consensus.
  val noStaleValueAfterInvalidation: bool = not(staleValueDelivered)

  /// Sync values never cost the consensus input queue room needed by gossip.
  val gossipQueueUncontended: bool = not(gossipEvictedBySyncValue)
}

module syncValueBufferingOracle {
  import syncValueBuffering.*
}

module syncValueBufferingTest {
  import syncValueBuffering.*

  /// A value for the current height goes straight to consensus.
  run happyPathTest =
    init
      .then(sendRequest(1, 0))
      .then(syncResponse(1, "p1", 0))
      .expect(deliveredToConsensus.size() == 1 and not(bufferedValueDelivered))

  /// A value for a future height is held, then drained when consensus gets there.
  run bufferAndDrainTest =
    init
      .then(sendRequest(1, 1))
      .then(syncResponse(1, "p1", 1))
      .expect(deliveredToConsensus.size() == 0)
      .then(startHeight(1, false))
      .expect(bufferedValueDelivered and deliveredToConsensus.size() == 1)

  /// Repeatability: two successive buffer-then-drain cycles.
  run streamTest =
    init
      .then(sendRequest(1, 1))
      .then(sendRequest(1, 2))
      .then(syncResponse(1, "p1", 1))
      .then(startHeight(1, false))
      .then(syncResponse(1, "p1", 2))
      .then(startHeight(2, false))
      .expect(deliveredToConsensus.size() == 2)

  /// Regression: a value buffered by a request that later turns out to serve
  /// invalid values is no longer drained to consensus when the height advances.
  run staleValueAfterInvalidationTest =
    init
      .then(sendRequest(1, 1))
      .then(sendRequest(1, 2))
      .then(syncResponse(1, "p1", 2))
      .then(startHeight(1, false))
      .then(syncResponse(1, "p1", 1))
      .then(invalidValue("p1", 1))
      .then(startHeight(2, false))
      .expect(not(staleValueDelivered))

  /// A consensus restart discards everything buffered by the sync actor.
  run restartClearsBufferTest =
    init
      .then(sendRequest(1, 2))
      .then(syncResponse(1, "p1", 2))
      .then(startHeight(0, true))
      .expect(restartDroppedBufferedValues and syncBuffer == Set())
}
