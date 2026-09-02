// Abstract system model of the Consensus Orchestrator running on top of the
// write-ahead log — built ONLY to make violations of the 'Surviving a crash'
// guarantees cheap to find. It is not code-aligned; the code-aligned
// expression of every violation it finds lives in
// consensus-orchestrator-wal-distributed.qnt.
//
// One orchestrator and one log: every guarantee here is about a SINGLE node
// losing its memory, so one instance of each role is the minimum and the
// maximum that the anomalies need.
//
// COLLAPSES, each discharged by a component-spec action or invariant:
//
//  * append-then-broadcast is ONE atomic step. Discharged by the write-ahead
//    log spec's own `consensus_wal_append_and_broadcast` (wal.qnt), which
//    already models the whole `Effect::WalAppend` resume-and-broadcast
//    sequence as a single action, and by `Wal_actor_MsgAppend`, which models
//    the height-mismatch drop as a single action.
//  * the orchestrator's routing, vote admission, driver tallying, rounds,
//    finalization latch and sync path are NOT modelled. Discharged by the
//    orchestrator's own invariants `published_votes_are_wal_logged` and
//    `wal_appends_are_not_duplicated`, which establish that every published
//    vote reaches the log exactly once — so for these guarantees the
//    orchestrator reduces to 'votes at most once per (height, round), and
//    publishes through the log'. The `known` guard below encodes exactly that.
//  * byte-level framing, CRCs, entry sizes, headers, truncate/reset/dump and
//    the open scan are NOT modelled. Discharged by the log's `readable` /
//    `replayedPayloads` helpers: their net effect on a replay is 'entries up
//    to the first unreadable one', which is what `readablePrefix` computes.
//  * flushing is per-log, not per-entry. Discharged by `Logflush`, which makes
//    everything written so far durable in one step.
//
// NOT modelled at all: rounds beyond a bare label, values beyond two, vote
// types, multiple log files, the log thread panic, disk failure, foreign
// version headers, and every orchestrator input other than a vote publish.
module consensusOrchestratorWalSystem {

  /// A vote the node publishes: the height and round it is for, and its value.
  type V = { h: int, r: int, value: int }

  /// One on-disk entry. `ok` is false once the entry can no longer be read
  /// back (a damaged CRC or a torn tail).
  type E = { v: V, ok: bool }

  pure val HEIGHTS: Set[int] = 1.to(3)
  pure val ROUNDS:  Set[int] = 0.to(1)
  pure val VALUES:  Set[int] = 1.to(2)

  // ─────────────────────────── state ───────────────────────────

  /// The log's entries, in write order.
  var log: List[E]
  /// The log's sequence number — the height the log belongs to.
  var logSeq: int
  /// How many leading entries are fsynced. A crash loses the rest.
  var flushed: int
  /// The log actor's in-memory height (-1 while it has none).
  var actorH: int
  /// The orchestrator's current height (-1 before any height started).
  var orchH: int
  /// Every vote ever broadcast to the network.
  var published: Set[V]
  /// The votes the node currently believes, in memory, that it has cast.
  var known: Set[V]
  /// How many times the process has died.
  var crashes: int

  // ghost history — the minimum that makes the guarantees decidable per state
  /// Everything published as of the most recent crash.
  var publishedBefore: Set[V]
  /// What the most recent replay handed back.
  var recovered: Set[V]
  /// A replay has run at least once.
  var replayRan: bool
  /// The node published a vote that contradicts one it published before a crash.
  var contradicted: bool
  /// A replay handed back a set of votes other than exactly those published
  /// for that height.
  var fidelityBroken: bool
  /// A replay handed back an entry belonging to another height.
  var crossHeight: bool
  /// After a restart the node took in a logged vote for a height it had
  /// already moved past.
  var staleApplied: bool

  // ────────────────────── pure helpers ──────────────────────

  /// The entries a replay hands back: everything up to the first unreadable
  /// one (the net effect of the log's read-and-truncate scan).
  pure def readablePrefix(es: List[E]): List[E] =
    es.foldl((List(), true), (acc, e) =>
      if (acc._2 and e.ok) (acc._1.append(e), true) else (acc._1, false))._1

  pure def votesOf(es: List[E]): Set[V] =
    es.foldl(Set(), (acc, e) => acc.union(Set(e.v)))

  /// The first `n` entries.
  pure def firstN(es: List[E], n: int): List[E] =
    es.foldl((List(), 0), (acc, e) =>
      if (acc._2 < n) (acc._1.append(e), acc._2 + 1) else (acc._1, acc._2 + 1))._1

  pure def votesAt(vs: Set[V], h: int): Set[V] = vs.filter(v => v.h == h)

  // ─────────────────────────── init ───────────────────────────

  action init = all {
    log' = List(), logSeq' = 0, flushed' = 0,
    actorH' = -1, orchH' = -1,
    published' = Set(), known' = Set(), crashes' = 0,
    publishedBefore' = Set(), recovered' = Set(), replayRan' = false,
    contradicted' = false, fidelityBroken' = false, crossHeight' = false,
    staleApplied' = false,
  }

  // ───────────────────────── actions ─────────────────────────

  /// The orchestrator starts a height and the log actor is told about it.
  /// Three branches, exactly as the log actor has them: already at that
  /// height -> return early and leave the log alone; sequence matches ->
  /// replay; otherwise -> reset the log to the new height.
  action startHeight(h: int): bool = all {
    orchH <= h,
    orchH' = h,
    published' = published,
    publishedBefore' = publishedBefore,
    crashes' = crashes,
    contradicted' = contradicted,
    if (actorH == h) all {
      // early return: no entries handed back, the log keeps its old sequence
      actorH' = actorH, log' = log, logSeq' = logSeq, flushed' = flushed,
      known' = Set(), recovered' = Set(), replayRan' = replayRan,
      fidelityBroken' = fidelityBroken, crossHeight' = crossHeight,
      staleApplied' = staleApplied,
    } else if (h == logSeq) {
      val kept = readablePrefix(log)
      val got  = votesOf(kept)
      all {
        actorH' = h,
        log' = kept, logSeq' = logSeq, flushed' = kept.length(),
        known' = got, recovered' = got, replayRan' = true,
        fidelityBroken' = (fidelityBroken or got != votesAt(published, h)),
        crossHeight' = (crossHeight or got.exists(v => v.h != h)),
        staleApplied' = (staleApplied or (crashes > 0 and got.exists(v => v.h < h))),
      }
    } else all {
      // reset: the log is cleared and re-sequenced to the new height
      actorH' = h, log' = List(), logSeq' = h, flushed' = 0,
      known' = Set(), recovered' = Set(), replayRan' = replayRan,
      fidelityBroken' = fidelityBroken, crossHeight' = crossHeight,
      staleApplied' = staleApplied,
    },
  }

  /// `Effect::WalAppend` followed by the broadcast. The entry is dropped when
  /// the actor's height has moved on, and the vote is published either way.
  /// The node only votes when it does not already know it has voted for this
  /// height and round.
  action appendAndPublish(r: int, value: int): bool = all {
    orchH >= 0,
    not(known.exists(v => v.h == orchH and v.r == r)),
    val e = { v: { h: orchH, r: r, value: value }, ok: true }
    all {
      log' = if (actorH != orchH) log else log.append(e),
      published' = published.union(Set(e.v)),
      known' = known.union(Set(e.v)),
      contradicted' = (contradicted or
        (crashes > 0 and
          publishedBefore.exists(p => p.h == e.v.h and p.r == e.v.r and p.value != e.v.value))),
      logSeq' = logSeq, flushed' = flushed, actorH' = actorH, orchH' = orchH,
      crashes' = crashes, publishedBefore' = publishedBefore,
      recovered' = recovered, replayRan' = replayRan,
      fidelityBroken' = fidelityBroken, crossHeight' = crossHeight,
      staleApplied' = staleApplied,
    },
  }

  /// `Log::flush` — everything written so far becomes durable.
  action flush: bool = all {
    flushed' = log.length(),
    log' = log, logSeq' = logSeq, actorH' = actorH, orchH' = orchH,
    published' = published, known' = known, crashes' = crashes,
    publishedBefore' = publishedBefore, recovered' = recovered,
    replayRan' = replayRan, contradicted' = contradicted,
    fidelityBroken' = fidelityBroken, crossHeight' = crossHeight,
    staleApplied' = staleApplied,
  }

  /// The process dies: whatever was written but not fsynced is gone, and so is
  /// every scrap of in-memory state.
  action crash: bool = all {
    log' = firstN(log, flushed),
    flushed' = flushed,
    actorH' = -1,
    known' = Set(),
    crashes' = crashes + 1,
    publishedBefore' = published,
    logSeq' = logSeq, orchH' = orchH, published' = published,
    recovered' = recovered, replayRan' = replayRan,
    contradicted' = contradicted, fidelityBroken' = fidelityBroken,
    crossHeight' = crossHeight, staleApplied' = staleApplied,
  }

  /// A stored entry stops reading back (a damaged CRC).
  action damage(i: int): bool = all {
    i < log.length(),
    log.nth(i).ok,
    log' = log.replaceAt(i, { ...log.nth(i), ok: false }),
    logSeq' = logSeq, flushed' = flushed, actorH' = actorH, orchH' = orchH,
    published' = published, known' = known, crashes' = crashes,
    publishedBefore' = publishedBefore, recovered' = recovered,
    replayRan' = replayRan, contradicted' = contradicted,
    fidelityBroken' = fidelityBroken, crossHeight' = crossHeight,
    staleApplied' = staleApplied,
  }

  /// Wal actor `Msg::Reset(height)` — sets the actor's in-memory height and
  /// leaves the log's own sequence number untouched. This is what lets the
  /// actor's height and the log's sequence come apart.
  action resetActorHeight(h: int): bool = all {
    log.length() >= 0,
    actorH' = h,
    log' = log, logSeq' = logSeq, flushed' = flushed, orchH' = orchH,
    published' = published, known' = known, crashes' = crashes,
    publishedBefore' = publishedBefore, recovered' = recovered,
    replayRan' = replayRan, contradicted' = contradicted,
    fidelityBroken' = fidelityBroken, crossHeight' = crossHeight,
    staleApplied' = staleApplied,
  }

  action step = {
    nondet h   = oneOf(HEIGHTS)
    nondet r   = oneOf(ROUNDS)
    nondet value = oneOf(VALUES)
    nondet i   = oneOf(0.to(4))
    any {
      startHeight(h),
      resetActorHeight(h),
      appendAndPublish(r, value),
      flush,
      crash,
      damage(i),
    }
  }

  // ────────────────────── system guarantees ──────────────────────

  /// A validator that crashes and restarts never contradicts a vote it
  /// published before the crash.
  val no_amnesia: bool = not(contradicted)

  /// Replaying the log for a height reproduces exactly the votes published at
  /// that height — no more and no fewer.
  val replay_fidelity: bool = not(fidelityBroken)

  /// Entries from a previous height are never replayed into a later one.
  val height_isolation: bool = not(crossHeight)

  /// After a restart the node never applies a logged vote for a height it has
  /// already moved past.
  val restart_does_not_resurrect_stale_votes: bool = not(staleApplied)

  // ────────────────────── scenario witnesses ──────────────────────

  /// Some run published a vote and then crashed and restarted.
  val crash_after_publish_reached: bool =
    crashes > 0 and publishedBefore != Set() and replayRan

  /// Some run replayed a log for a height at which votes had been published.
  val replay_after_restart_reached: bool =
    replayRan and votesAt(published, logSeq) != Set()

  /// Some run started a second height after appending entries at the first.
  val second_height_started_reached: bool =
    published.exists(a => published.exists(b => a.h != b.h))

  /// Some run restarted with log entries for a height below the height being
  /// started.
  val restart_with_stale_log_reached: bool =
    crashes > 0 and log.foldl(false, (acc, e) => acc or e.v.h < orchH)
}
