// -*- mode: Bluespec; -*-
//
// Consensus Write-Ahead Log (WAL) append/flush durability model.
//
// Models the WAL persistence path in the Malachite engine
// (code/crates/engine/src/consensus.rs). The WAL persists consensus messages
// (votes, proposals, timeouts) so a crashed validator recovers without
// equivocating. The protocol relies on ONE ordering guarantee: every entry
// appended to the WAL is fsynced (made durable) before the triggering consensus
// message is broadcast / the value is decided. That fsync is `WalMsg::Flush`,
// issued right before StartRound / PublishConsensusMsg / Decide.
//
// Entries are abstracted to counts (identity is irrelevant to durability):
//   - `wal`     : entries written to the WAL buffer (kernel page cache), not yet fsynced
//   - `durable` : entries fsynced to disk
//   - `pending` : appends issued fire-and-forget, awaiting completion (drained before a flush)
//
// The pending queue, its overflow cap (MAX_PENDING), and the drop-on-Recovering
// form the mechanism the WAL uses. The ONLY behavioral difference between the
// base and PR versions is inside `walAppend` (see the inline comments there):
// synchronously applying the append to the WAL buffer, versus enqueueing it on
// the fire-and-forget pending queue that a later flush drains.
module consensusWal {
  // WAL-relevant consensus phases. WAL ops run only while Running; during
  // Recovering they are no-ops (the WAL is being replayed, not written).
  type Phase = Unstarted | Running | Recovering

  // Abstracts MAX_PENDING_WAL_APPENDS (1024 in the code): the cap on appends
  // that may be queued before a flush must drain them. Kept small so the
  // overflow behavior is reachable in a few steps.
  pure val MAX_PENDING: int = 2

  // Appends issued fire-and-forget, awaiting completion (drained before a flush).
  var pending: int
  // Entries written to the WAL buffer (kernel page cache), awaiting fsync.
  var wal: int
  // Entries fsynced to disk (durable).
  var durable: int
  // The consensus phase.
  var phase: Phase
  // Sticky: an append was rejected because the pending queue was full.
  var overflowed: bool
  // Sticky: pending appends were dropped on transition to Recovering.
  var droppedOnRecovery: bool
  // Sticky: a flush drained a non-empty pending queue.
  var drainedNonEmpty: bool
  // Whether the last transition was a flush (for the durability invariant).
  var lastWasFlush: bool

  action init = all {
    pending' = 0,
    wal' = 0,
    durable' = 0,
    phase' = Running,
    overflowed' = false,
    droppedOnRecovery' = false,
    drainedNonEmpty' = false,
    lastWasFlush' = false,
  }

  // Effect::WalAppend: record a WAL append of a consensus message.
  action walAppend: bool =
    val full = pending >= MAX_PENDING
    all {
      phase == Running,
      not(overflowed),
      overflowed' = full,
      wal' = wal + 1,          // append applied synchronously to the WAL buffer
      pending' = pending,      // the fire-and-forget queue is never used
      durable' = durable,
      phase' = phase,
      droppedOnRecovery' = droppedOnRecovery,
      drainedNonEmpty' = drainedNonEmpty,
      lastWasFlush' = false,
    }

  // wal_flush: drain all pending appends into the WAL buffer, then fsync.
  // Triggered before StartRound / PublishConsensusMsg / Decide.
  action walFlush = all {
    phase == Running,
    not(overflowed),
    wal' = wal + pending,
    durable' = wal + pending,
    pending' = 0,
    drainedNonEmpty' = (drainedNonEmpty or (pending > 0)),
    phase' = phase,
    overflowed' = overflowed,
    droppedOnRecovery' = droppedOnRecovery,
    lastWasFlush' = true,
  }

  // set_phase(Recovering): drop any pending appends — their receivers can never
  // be drained since WAL ops are no-ops during Recovering.
  action startRecovering = all {
    phase == Running,
    not(overflowed),
    phase' = Recovering,
    droppedOnRecovery' = (droppedOnRecovery or (pending > 0)),
    pending' = 0,
    wal' = wal,
    durable' = durable,
    overflowed' = overflowed,
    drainedNonEmpty' = drainedNonEmpty,
    lastWasFlush' = false,
  }

  // Leaving Recovering once WAL replay completes (StartHeight -> Running).
  action finishRecovering = all {
    phase == Recovering,
    not(overflowed),
    phase' = Running,
    pending' = pending,
    wal' = wal,
    durable' = durable,
    overflowed' = overflowed,
    droppedOnRecovery' = droppedOnRecovery,
    drainedNonEmpty' = drainedNonEmpty,
    lastWasFlush' = false,
  }

  action step = any {
    walAppend,
    walFlush,
    startRecovering,
    finishRecovering,
  }

  // ---- Invariants: the durability safety claim ----

  // You can only fsync entries that are in the WAL buffer.
  val durableWithinBuffer: bool = durable <= wal

  // THE safety claim: after a flush, no append is left un-persisted — the
  // pending queue is empty and the whole WAL buffer is durable.
  val flushPersistsAll: bool =
    lastWasFlush implies (pending == 0 and wal == durable)

  // ---- Observations: positive behavior tracks ----

  // Baseline: some entry became durable.
  val hasDurable: bool = durable > 0
  // A flush drained a non-empty pending queue (PR mechanism).
  val hasDrainedNonEmpty: bool = drainedNonEmpty
  // The pending queue overflowed its cap (PR mechanism).
  val hasOverflowed: bool = overflowed
  // Pending appends were dropped on transition to Recovering (PR mechanism).
  val hasDroppedOnRecovery: bool = droppedOnRecovery

  // ---- Tests ----

  // Happy path: append then flush makes the entry durable.
  run happyPathTest =
    init.then(walAppend).then(walFlush).expect(durable == 1 and pending == 0)

  // Stream: two append/flush cycles (the WAL handles many appends over time).
  run streamTest =
    init.then(walAppend).then(walFlush)
        .then(walAppend).then(walFlush)
        .expect(durable == 2 and pending == 0)

  // Recovery cycle: flush, enter and leave Recovering, keep serving.
  run recoveryCycleTest =
    init.then(walAppend).then(walFlush)
        .then(startRecovering).then(finishRecovering)
        .expect(durable == 1)
}
