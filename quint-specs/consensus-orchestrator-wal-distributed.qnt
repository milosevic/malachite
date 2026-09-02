// The Consensus Orchestrator composed with the write-ahead log it appends to.
//
// INHERITANCE ARGUMENT: every action below applies the same imported pure
// logic the component specs apply — the orchestrator's actions are
// `o' = proc*(o, ...)` and the log's actions carry the bodies of the `wal`
// module's own actions over the same `logs` / `actor` / `ghost` variables — so
// the components' alignment with the code transfers to this spec by
// construction. Nothing is re-modelled here.
//
// The one thing this spec ADDS is the wire between them: the orchestrator's
// `Effect::WalAppend` (handle/vote.rs:95-102) is carried to the log actor's
// `Msg::Append` and the log thread's write, and the vote is put on the network
// afterwards, exactly as consensus.rs:1141-1167 does it. That wire is
// `applyWalAppendAndBroadcast`.
//
// `sys` is ghost state. It observes the run — it never appears in the guard of
// a lifted component action.
module consensusOrchestratorWalDistributed {
  import consensusOrchestratorCore.* from "./consensus-orchestrator"
  import walCore.* from "./wal"
  import basicSpells.* from "./spells/basicSpells"

  /// A vote on the wire / in the log: (vote type, height, round, value).
  /// Vote type 0 is a prevote, 1 a precommit.
  type Key = (int, int, int, int)

  /// The size the orchestrator's WAL entries are recorded with. Any value
  /// within the log's accepted sizes does; the guarantees do not read it.
  pure val VOTE_ENTRY_SIZE: int = 56

  pure def keyOf(vt: VoteType, h: int, r: int, v: int): Key =
    (if (vt == PrevoteT) 0 else 1, h, r, v)

  /// Observer state for the composed guarantees.
  type Sys = {
    // votes that reached the network
    broadcast: Set[Key],
    // log payload id -> the vote that entry carries
    entryVote: int -> Key,
    // everything broadcast as of the most recent crash
    publishedBefore: Set[Key],
    // what the most recent replay handed back
    recovered: Set[Key],
    crashes: int,
    replayRan: bool,
    contradicted: bool,
    fidelityBroken: bool,
    crossHeight: bool,
    staleApplied: bool,
    appendDroppedButPublished: bool,
    appendBeforeStartedHeight: bool,
    startedHeights: Set[int],
    ledgerMismatch: bool,
  }

  pure val initialSys: Sys = {
    broadcast: Set(), entryVote: Map(), publishedBefore: Set(), recovered: Set(),
    crashes: 0, replayRan: false, contradicted: false, fidelityBroken: false,
    crossHeight: false, staleApplied: false, appendDroppedButPublished: false,
    appendBeforeStartedHeight: false, startedHeights: Set(), ledgerMismatch: false,
  }

  // ─────────────────────────── state ───────────────────────────
  var o: OrchState
  var logs: int -> Log
  var actor: Actor
  var ghost: Ghost
  var sys: Sys

  action init = all {
    o' = {
      height: 1, round: NilRound, step: Unstarted,
      finalizationPeriod: false,
      finalizationEntered: Set(), finalizationExited: Set(),
      buffered: Set(), bufferDropped: false,
      replayedOnStart: false, restartSkippedReplay: false,
      proposalsSeen: Set(), valuesSeen: Set(),
      prevotes: Set(), precommits: Set(), commitCerts: Set(), polkaCerts: Set(),
      decidedValue: NilValue, decidedRound: NilRound, decidedViaSync: false,
      decidedHeights: Set(),
      walEntries: Set(), walAppends: 0, publishedVotes: Set(),
      emitted: Set(),
      pastDropped: false,
      duplicateIgnored: false,
      unknownVoterRejected: false,
      badSignatureRejected: false,
    },
    logs' = initialLogs,
    actor' = initialActor,
    ghost' = initialGhost,
    sys' = initialSys,
  }

  // ───────────────── the wire: WalAppend, then broadcast ─────────────────

  /// The votes an orchestrator transition newly put on the wire.
  pure def newlyPublished(before: OrchState, after: OrchState): Set[(VoteType, int, int)] =
    after.publishedVotes.exclude(before.publishedVotes)

  /// One `Effect::WalAppend` carried to the log, then the broadcast.
  ///
  /// Branch 1 is the log actor's `Msg::Append` height-mismatch branch
  /// (wal.rs:107-120): the entry is dropped and the caller told `Ok(())`.
  /// Branch 2/3 are the thread's `Logappend__write_raw__write_compressed`
  /// success / write-error branches (log.rs:351-436).
  /// In EVERY branch the vote is broadcast, because `perform!` resumes and the
  /// message goes out whatever the append reply was (consensus.rs:1141-1167).
  pure def applyWalAppendAndBroadcast(
      lgs: int -> Log, act: Actor, gh: Ghost, sy: Sys,
      h: int, key: Key, writeOk: bool
    ): { lgs: int -> Log, gh: Ghost, sy: Sys } =
    val lg = lgs.get(ACTOR_PATH)
    val n = lg.entries.length()
    val broadcastSy = { ...sy,
      broadcast: sy.broadcast.union(Set(key)),
      appendBeforeStartedHeight:
        (sy.appendBeforeStartedHeight or not(sy.startedHeights.contains(h))),
      contradicted: (sy.contradicted or
        (sy.crashes > 0 and
          sy.publishedBefore.exists(p =>
            p._1 == key._1 and p._2 == key._2 and p._3 == key._3 and p._4 != key._4))) }
    if (h != act.height)
      { lgs: lgs,
        gh: { ...gh, appendDroppedSilently: true,
              lastAppend: { valid: true, height: h, replyOk: true,
                            lenBefore: n, lenAfter: n } },
        sy: { ...broadcastSy, appendDroppedButPublished: true, ledgerMismatch: true } }
    else if (writeOk and gh.writable and lg.created)
      val e: Entry = { payload: gh.nextId, dataLength: VOTE_ENTRY_SIZE, crc: true,
                         framed: true, torn: false, height: act.height }
      { lgs: lgs.put(ACTOR_PATH, { ...lg, entries: lg.entries.append(e) }),
        gh: { ...gh, nextId: gh.nextId + 1,
              lastAppend: { valid: true, height: lg.sequence, replyOk: true,
                            lenBefore: n, lenAfter: n + 1 } },
        sy: { ...broadcastSy, entryVote: broadcastSy.entryVote.put(gh.nextId, key) } }
    else
      { lgs: lgs,
        gh: { ...gh, lastAppend: { valid: true, height: lg.sequence, replyOk: false,
                                   lenBefore: n, lenAfter: n } },
        sy: { ...broadcastSy, ledgerMismatch: true } }

  /// Carry every vote an orchestrator transition published through the wire.
  pure def wireAll(
      lgs: int -> Log, act: Actor, gh: Ghost, sy: Sys,
      h: int, vs: Set[(VoteType, int, int)], writeOk: bool
    ): { lgs: int -> Log, gh: Ghost, sy: Sys } =
    vs.fold({ lgs: lgs, gh: gh, sy: sy }, (acc, p) =>
      applyWalAppendAndBroadcast(acc.lgs, act, acc.gh, acc.sy, h,
                                 keyOf(p._1, h, p._2, p._3), writeOk))

  /// The votes that are durable in the actor's log: carried by an entry inside
  /// the fsynced prefix.
  pure def durableVotes(lgs: int -> Log, sy: Sys): Set[Key] =
    val lg = lgs.get(ACTOR_PATH)
    take(lg.entries, lg.flushed).foldl(Set(), (acc, e) =>
      if (sy.entryVote.has(e.payload)) acc.union(Set(sy.entryVote.get(e.payload))) else acc)

  /// The votes a set of replayed payload ids stands for.
  pure def votesOfPayloads(ps: Set[int], sy: Sys): Set[Key] =
    ps.fold(Set(), (acc, p) =>
      if (sy.entryVote.has(p)) acc.union(Set(sy.entryVote.get(p))) else acc)

  pure def votesAt(ks: Set[Key], h: int): Set[Key] = ks.filter(k => k._2 == h)

  // ══════════════ lifted orchestrator actions ══════════════
  // Each one: the component's guard verbatim, `s` substituted by `o`, the
  // update through the imported pure transition, and the published votes
  // carried over the wire.

  action startHeight(h: Height, isRestart: bool): bool = all {
    o.height <= h,
    val after = procStartHeight(o, h, isRestart)
    all {
      o' = after,
      logs' = logs, actor' = actor, ghost' = ghost, sys' = sys,
    },
  }

  action onVote(vt: VoteType, vh: Height, vr: Round, voter: Address,
                v: Value, sigOk: bool, writeOk: bool): bool = {
    val after = procVote(o, vt, vh, vr, voter, v, sigOk)
    val w = wireAll(logs, actor, ghost, sys, o.height, newlyPublished(o, after), writeOk)
    all { o' = after, logs' = w.lgs, ghost' = w.gh, sys' = w.sy, actor' = actor }
  }

  action onProposal(ph: Height, pr: Round, v: Value, sigOk: bool,
                    writeOk: bool): bool = {
    val after = procProposal(o, ph, pr, v, sigOk)
    val w = wireAll(logs, actor, ghost, sys, o.height, newlyPublished(o, after), writeOk)
    all { o' = after, logs' = w.lgs, ghost' = w.gh, sys' = w.sy, actor' = actor }
  }

  action onProposedValue(pvh: Height, pvr: Round, v: Value, valid: bool,
                         origin: Origin, writeOk: bool): bool = {
    val after = procValue(o, pvh, pvr, v, valid, origin)
    val w = wireAll(logs, actor, ghost, sys, o.height, newlyPublished(o, after), writeOk)
    all { o' = after, logs' = w.lgs, ghost' = w.gh, sys' = w.sy, actor' = actor }
  }

  action onSyncValueResponse(ch: Height, cr: Round, v: Value,
                             certOk: bool): bool = all {
    o' = procSync(o, ch, cr, v, certOk),
    logs' = logs, actor' = actor, ghost' = ghost, sys' = sys,
  }

  action onTimeoutElapsed(kind: TimeoutKind, tr: Round, writeOk: bool): bool = {
    val after = procTimeout(o, kind, tr)
    val w = wireAll(logs, actor, ghost, sys, o.height, newlyPublished(o, after), writeOk)
    all { o' = after, logs' = w.lgs, ghost' = w.gh, sys' = w.sy, actor' = actor }
  }

  action onPolkaCertificate(ph: Height, pr: Round, v: Value): bool = all {
    o' = procPolka(o, ph, pr, v),
    logs' = logs, actor' = actor, ghost' = ghost, sys' = sys,
  }

  action onRoundCertificate(ct: CertType, ch: Height, cr: Round): bool = all {
    o' = procRoundCert(o, ct, ch, cr),
    logs' = logs, actor' = actor, ghost' = ghost, sys' = sys,
  }

  action propose(v: Value, writeOk: bool): bool = all {
    o.step == Propose,
    val after = procPropose(o, v)
    val w = wireAll(logs, actor, ghost, sys, o.height, newlyPublished(o, after), writeOk)
    all { o' = after, logs' = w.lgs, ghost' = w.gh, sys' = w.sy, actor' = actor },
  }

  // ══════════════ lifted write-ahead log actions ══════════════
  // Bodies carried over from the `wal` module, over the same variables.

  action Logopen(path: int, ok: bool, len: int): bool = all {
    val lg = logs.get(path)
    all {
      not(lg.headerValid) implies not(ok),
      if (not(ok)) all {
        logs' = logs,
        ghost' = { ...ghost, openRan: true, openRejected: true },
      } else all {
        len <= scanLimit(lg.entries),
        logs' = logs.put(path, { ...lg, created: true,
                                 entries: take(lg.entries, len),
                                 flushed: min(lg.flushed, len) }),
        ghost' = { ...ghost, openRan: true, openRejected: false,
                   openTruncated: lg.entries.length() - len,
                   openLostValid: (ghost.openLostValid or
                     not(validPayloads(lg.entries)
                           .subseteq(validPayloads(take(lg.entries, len))))) },
      },
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action Logappend__write_raw__write_compressed(path: int, dataLength: int, ok: bool,
                                                len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      not(ghost.writable) implies not(ok),
      if (ok) {
        val e: Entry = { payload: ghost.nextId, dataLength: dataLength, crc: true,
                           framed: true, torn: false,
                           height: if (path == ACTOR_PATH) actor.height else lg.sequence }
        all {
          len == lg.entries.length() + 1,
          logs' = logs.put(path, { ...lg, entries: lg.entries.append(e) }),
          ghost' = { ...ghost, nextId: ghost.nextId + 1,
                     lastAppend: { valid: true, height: lg.sequence, replyOk: true,
                                   lenBefore: lg.entries.length(),
                                   lenAfter: lg.entries.length() + 1 } },
        }
      } else all {
        len == lg.entries.length(),
        logs' = logs,
        ghost' = { ...ghost,
                   lastAppend: { valid: true, height: lg.sequence, replyOk: false,
                                 lenBefore: lg.entries.length(),
                                 lenAfter: lg.entries.length() } },
      },
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action Logfirst_entry__iter(path: int, ok: bool, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      ok implies len == lg.entries.length(),
      logs' = logs,
      ghost' = { ...ghost, readRan: true, readErrorAt: -1 },
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action Logread_entry(path: int, idx: int, ok: bool): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      idx < lg.entries.length(),
      not(readable(lg.entries.nth(idx))) implies not(ok),
      logs' = if (ok) logs
              else logs.put(path, { ...lg, entries: lg.entries.replaceAt(idx,
                       { ...lg.entries.nth(idx), crc: false }) }),
      ghost' = { ...ghost, readRan: true,
                 readErrorAt: if (ok) ghost.readErrorAt else idx },
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action Logreset(path: int, sequence: int, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      len == 0,
      logs' = logs.put(path, { ...lg, sequence: sequence, entries: List(), flushed: 0 }),
      ghost' = { ...ghost, resetCleared: (ghost.resetCleared or lg.entries.length() > 0) },
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action Logtruncate(path: int, from_entry: int, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      if (from_entry >= lg.entries.length()) all {
        len == lg.entries.length(),
        logs' = logs,
        ghost' = { ...ghost, truncateNoop: true },
      } else all {
        len == from_entry,
        logs' = logs.put(path, { ...lg, entries: take(lg.entries, from_entry),
                                 flushed: min(lg.flushed, from_entry) }),
        ghost' = { ...ghost, truncateRemoved: true },
      },
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action Logflush(path: int, ok: bool, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      len == lg.entries.length(),
      logs' = logs.put(path,
        if (ok) { ...lg, flushed: lg.entries.length() } else lg),
      ghost' = ghost,
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action Logfrom_raw_parts(path: int, sequence: int, len: int): bool = all {
    val lg = logs.get(path)
    all {
      len <= lg.entries.length(),
      logs' = logs.put(path, { ...lg, created: true, sequence: sequence,
                               entries: take(lg.entries, len),
                               flushed: min(lg.flushed, len) }),
      ghost' = { ...ghost, bypassedValidation: true },
    },
    actor' = actor, o' = o, sys' = sys,
  }

  /// The actor's StartedHeight, plus the observation of what the replay handed
  /// back — the three guarantees about a restart are decided here.
  action Wal_actor_MsgStartedHeight(height: int): bool = all {
    val lg = logs.get(ACTOR_PATH)
    all {
      lg.created,
      actor.threadAlive,
      logs' = logs,
      o' = o,
      if (actor.height == height) all {
        actor' = actor,
        ghost' = { ...ghost, startedHeightNoop: true },
        sys' = { ...sys, startedHeights: sys.startedHeights.union(Set(height)),
                 recovered: Set() },
      } else if (height == lg.sequence) {
        val stop = firstUnreadable(lg.entries)
        val got = votesOfPayloads(replayedPayloads(lg.entries), sys)
        all {
          actor' = { ...actor, height: height },
          ghost' = { ...ghost,
                     startedHeightReplayed: true,
                     replayRan: true,
                     preReplayAll: payloads(lg.entries),
                     replayed: replayedPayloads(lg.entries),
                     replayErrorAt: stop,
                     replayTruncatedAt: stop,
                     replayLostLaterIntact: (ghost.replayLostLaterIntact or
                       (stop >= 0 and
                         not(intactPayloadsAfter(lg.entries, stop)
                               .subseteq(intactPayloads(take(lg.entries, stop)))))) },
          sys' = { ...sys,
                   startedHeights: sys.startedHeights.union(Set(height)),
                   recovered: got,
                   replayRan: true,
                   fidelityBroken: (sys.fidelityBroken or
                     got != votesAt(sys.broadcast, height)),
                   crossHeight: (sys.crossHeight or got.exists(k => k._2 != height)),
                   staleApplied: (sys.staleApplied or
                     (sys.crashes > 0 and got.exists(k => k._2 < height))) },
        }
      } else all {
        actor' = { ...actor, height: height },
        ghost' = { ...ghost, startedHeightReset: true },
        sys' = { ...sys, startedHeights: sys.startedHeights.union(Set(height)),
                 recovered: Set() },
      },
    },
  }

  action Wal_actor_MsgReset(height: int): bool = all {
    logs.get(ACTOR_PATH).created,
    actor.threadAlive,
    actor' = { ...actor, height: height },
    logs' = logs, ghost' = ghost, o' = o, sys' = sys,
  }

  action Wal_actor_MsgAppend(height: int): bool = all {
    val lg = logs.get(ACTOR_PATH)
    all {
      lg.created,
      actor.threadAlive,
      actor' = actor,
      logs' = logs,
      o' = o, sys' = sys,
      if (height != actor.height) {
        ghost' = { ...ghost, appendDroppedSilently: true,
                   lastAppend: { valid: true, height: height, replyOk: true,
                                 lenBefore: lg.entries.length(),
                                 lenAfter: lg.entries.length() } }
      } else {
        ghost' = ghost
      },
    },
  }

  action Wal_actor_MsgFlush = all {
    logs.get(ACTOR_PATH).created,
    actor.threadAlive,
    logs' = logs, actor' = actor, ghost' = ghost, o' = o, sys' = sys,
  }

  action Wal_actor_MsgDump = all {
    val lg = logs.get(ACTOR_PATH)
    all {
      lg.created,
      actor.threadAlive,
      logs' = logs,
      actor' = actor,
      o' = o, sys' = sys,
      ghost' = { ...ghost,
                 dumpMismatch: (ghost.dumpMismatch or
                   replayedPayloads(lg.entries).size() != lg.entries.length()) },
    },
  }

  action consensus_wal_append_and_broadcast(recovering: bool): bool = all {
    logs' = logs,
    actor' = actor,
    o' = o, sys' = sys,
    if (recovering) {
      ghost' = { ...ghost, consensusSkipped: true }
    } else {
      ghost' = { ...ghost,
                 nextId: ghost.nextId + 1,
                 broadcast: ghost.broadcast.union(Set(ghost.nextId)),
                 broadcastWithoutDurable: (ghost.broadcastWithoutDurable or
                   not(ghost.lastAppend.valid) or
                   ghost.lastAppend.lenAfter == ghost.lastAppend.lenBefore) }
    },
  }

  action adversary_corrupt_crc(path: int, idx: int): bool = all {
    val lg = logs.get(path)
    all {
      idx < lg.entries.length(),
      lg.entries.nth(idx).crc,
      logs' = logs.put(path, { ...lg, entries: lg.entries.replaceAt(idx,
                { ...lg.entries.nth(idx), crc: false }) }),
      ghost' = ghost,
    },
    actor' = actor, o' = o, sys' = sys,
  }

  action adversary_misframe_header(path: int, idx: int): bool = all {
    val lg = logs.get(path)
    all {
      idx < lg.entries.length(),
      lg.entries.nth(idx).framed,
      logs' = logs.put(path, { ...lg, entries: lg.entries.replaceAt(idx,
                { ...lg.entries.nth(idx), framed: false }) }),
      ghost' = ghost,
    },
    actor' = actor, o' = o, sys' = sys,
  }

  /// The process dies. The occurrence is global: the actor's in-memory state
  /// is gone and any unflushed tail may be torn. The orchestrator's own
  /// in-memory state is reset by the StartHeight that follows a restart, which
  /// is the component's own modelling of a restart — so this action does not
  /// touch `o`.
  action adversary_crash(path: int, tearTail: bool): bool = all {
    val lg = logs.get(path)
    val n = lg.entries.length()
    val torn = tearTail and n > lg.flushed
    all {
      lg.created,
      logs' = logs.put(path, { ...lg,
        entries: if (torn) lg.entries.replaceAt(n - 1,
                             { ...lg.entries.nth(n - 1), torn: true })
                 else lg.entries }),
      actor' = initialActor,
      ghost' = { ...ghost, crashed: true },
      o' = o,
      sys' = { ...sys, crashes: sys.crashes + 1, publishedBefore: sys.broadcast },
    },
  }

  action adversary_disk_failure = all {
    ghost.writable,
    logs' = logs, actor' = actor, o' = o, sys' = sys,
    ghost' = { ...ghost, writable: false },
  }

  action adversary_disk_recovers = all {
    not(ghost.writable),
    logs' = logs, actor' = actor, o' = o, sys' = sys,
    ghost' = { ...ghost, writable: true },
  }

  action adversary_wal_thread_panic = all {
    actor.threadAlive,
    logs' = logs, o' = o, sys' = sys, ghost' = ghost,
    actor' = { ...actor, threadAlive: false },
  }

  action adversary_foreign_version(path: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.headerValid,
      logs' = logs.put(path, { ...lg, headerValid: false }),
      ghost' = ghost,
    },
    actor' = actor, o' = o, sys' = sys,
  }

  // ─────────────────────────── step ───────────────────────────
  // The orchestrator's arm set and the log's arm set, interleaved. Each
  // component's own arm structure and pick placement is preserved.
  action step = {
    nondet h         = oneOf(Heights)
    nondet isRestart = oneOf(Set(false, true))
    nondet vt        = oneOf(Set(PrevoteT, PrecommitT))
    nondet vh        = oneOf(Heights)
    nondet vr        = oneOf(Rounds)
    nondet voter     = oneOf(Voters)
    nondet vval      = oneOf(Values.union(Set(NilValue)))
    nondet sigOk     = oneOf(Set(true, false))
    nondet ph        = oneOf(Heights)
    nondet pr        = oneOf(Rounds)
    nondet pval      = oneOf(Values)
    nondet valid     = oneOf(Set(true, false))
    nondet origin    = oneOf(Set(ConsensusOrigin, SyncOrigin))
    nondet tkind     = oneOf(Set(TOPropose, TOPrevote, TOPrecommit,
                                 TOFinalize, TORebroadcast))
    nondet tr        = oneOf(Rounds)
    nondet ct        = oneOf(Set(PrecommitCert, SkipCert))
    nondet writeOk   = oneOf(Set(true, false))
    any {
      // orchestrator arms
      startHeight(h, isRestart),
      onVote(vt, vh, vr, voter, vval, sigOk, writeOk),
      onProposal(ph, pr, pval, sigOk, writeOk),
      onProposedValue(ph, pr, pval, valid, origin, writeOk),
      onSyncValueResponse(ph, pr, pval, valid),
      onTimeoutElapsed(tkind, tr, writeOk),
      onPolkaCertificate(ph, pr, pval),
      onRoundCertificate(ct, ph, pr),
      propose(pval, writeOk),
      // write-ahead log arms
      { nondet path = PATHS.oneOf()
        nondet ok = Set(false, true).oneOf()
        nondet len = 0.to(scanLimit(logs.get(path).entries) + 1).oneOf()
        Logopen(path, ok, len) },
      { nondet path = PATHS.oneOf()
        nondet ok = Set(false, true).oneOf()
        nondet dataLength = SIZES.oneOf()
        val n = logs.get(path).entries.length()
        nondet len = Set(n, n + 1).oneOf()
        Logappend__write_raw__write_compressed(path, dataLength, ok, len) },
      { nondet path = PATHS.oneOf()
        nondet ok = Set(false, true).oneOf()
        val n = logs.get(path).entries.length()
        nondet len = Set(n, n + 1).oneOf()
        Logfirst_entry__iter(path, ok, len) },
      { nondet path = PATHS.oneOf()
        nondet idx = 0.to(logs.get(path).entries.length()).oneOf()
        nondet ok = Set(false, true).oneOf()
        Logread_entry(path, idx, ok) },
      { nondet path = PATHS.oneOf()
        nondet sequence = HEIGHTS.oneOf()
        nondet len = Set(0, 1).oneOf()
        Logreset(path, sequence, len) },
      { nondet path = PATHS.oneOf()
        nondet from_entry = INDICES.oneOf()
        val n = logs.get(path).entries.length()
        nondet len = Set(n, from_entry).oneOf()
        Logtruncate(path, from_entry, len) },
      { nondet path = PATHS.oneOf()
        nondet ok = Set(false, true).oneOf()
        val n = logs.get(path).entries.length()
        nondet len = Set(n, n + 1).oneOf()
        Logflush(path, ok, len) },
      { nondet path = PATHS.oneOf()
        nondet sequence = HEIGHTS.oneOf()
        nondet len = 0.to(logs.get(path).entries.length() + 1).oneOf()
        Logfrom_raw_parts(path, sequence, len) },
      { nondet height = HEIGHTS.oneOf()
        Wal_actor_MsgStartedHeight(height) },
      { nondet height = HEIGHTS.oneOf()
        Wal_actor_MsgReset(height) },
      { nondet height = HEIGHTS.oneOf()
        Wal_actor_MsgAppend(height) },
      Wal_actor_MsgFlush,
      Wal_actor_MsgDump,
      { nondet recovering = Set(false, true).oneOf()
        consensus_wal_append_and_broadcast(recovering) },
      { nondet path = PATHS.oneOf()
        nondet idx = 0.to(logs.get(path).entries.length() + 1).oneOf()
        adversary_corrupt_crc(path, idx) },
      { nondet path = PATHS.oneOf()
        nondet idx = 0.to(logs.get(path).entries.length()).oneOf()
        adversary_misframe_header(path, idx) },
      { nondet path = PATHS.oneOf()
        nondet tearTail = Set(false, true).oneOf()
        adversary_crash(path, tearTail) },
      { nondet ok = Set(false, true).oneOf()
        nondet len = 0.to(scanLimit(logs.get(ACTOR_PATH).entries) + 1).oneOf()
        Logopen(ACTOR_PATH, ok, len) },
      { nondet dataLength = SIZES.oneOf()
        val n = logs.get(ACTOR_PATH).entries.length()
        nondet len = Set(n, n + 1).oneOf()
        Logappend__write_raw__write_compressed(ACTOR_PATH, dataLength, true, len) },
      { nondet idx = 0.to(logs.get(ACTOR_PATH).entries.length()).oneOf()
        adversary_corrupt_crc(ACTOR_PATH, idx) },
      adversary_disk_failure,
      adversary_disk_recovers,
      adversary_wal_thread_panic,
      { nondet path = PATHS.oneOf()
        adversary_foreign_version(path) },
    }
  }

  // ════════════ the composed guarantees ════════════

  /// A validator that crashes and restarts never contradicts a vote it
  /// published before the crash.
  val no_amnesia: bool = not(sys.contradicted)

  /// Replaying the log for a height reproduces exactly the votes published at
  /// that height.
  val replay_fidelity: bool = not(sys.fidelityBroken)

  /// Entries from a previous height are never replayed into a later one.
  val height_isolation: bool = not(sys.crossHeight)

  /// After a restart the node never applies a logged vote for a height it has
  /// already moved past.
  val restart_does_not_resurrect_stale_votes: bool = not(sys.staleApplied)

  val crash_after_publish_reached: bool =
    sys.crashes > 0 and sys.publishedBefore != Set() and sys.replayRan

  val replay_after_restart_reached: bool =
    sys.replayRan and votesAt(sys.broadcast, logs.get(ACTOR_PATH).sequence) != Set()

  val second_height_started_reached: bool =
    sys.broadcast.exists(a => sys.broadcast.exists(b => a._2 != b._2))

  val restart_with_stale_log_reached: bool =
    sys.crashes > 0 and
    logs.get(ACTOR_PATH).entries.foldl(false, (acc, e) => acc or e.height < o.height)

  // ════════════ the wiring checks ════════════

  /// Every vote on the wire is carried by an entry that is durable in the log.
  val wal_append_durable_before_publish: bool =
    sys.broadcast.subseteq(durableVotes(logs, sys))

  /// No entry was appended for a height the actor was never told had started.
  val started_height_precedes_appends: bool = not(sys.appendBeforeStartedHeight)

  /// Every append the orchestrator recorded is really in the log.
  val orchestrator_wal_ledger_matches_log: bool = not(sys.ledgerMismatch)

  val append_then_publish_reached: bool = sys.broadcast != Set()
  val append_at_height_reached: bool = logs.get(ACTOR_PATH).entries.length() > 0
  val orchestrator_append_recorded_reached: bool = o.walAppends > 0

  // ════════════ inherited: Consensus Orchestrator ════════════
  // Restated over `o`; bodies identical to consensus-orchestrator.qnt apart
  // from the `s` -> `o` substitution.

  val latch_exit_follows_entry: bool =
    o.finalizationExited.subseteq(o.finalizationEntered)

  val finalization_period_only_in_commit: bool =
    o.finalizationPeriod implies (o.step == Commit
      and o.finalizationEntered.contains(o.height)
      and not(o.finalizationExited.contains(o.height)))

  val buffered_inputs_are_future: bool = o.buffered.forall(x => x > o.height)

  val buffer_within_capacity: bool = o.buffered.size() <= QueueCapacity

  val sync_decision_requires_certificate: bool =
    o.decidedViaSync implies o.commitCerts.contains((o.decidedRound, o.decidedValue))

  val published_votes_are_wal_logged: bool =
    o.publishedVotes.forall(p =>
      o.walEntries.contains((p._1, o.height, p._2, MyAddress, p._3)))

  val wal_appends_are_not_duplicated: bool = o.walAppends == o.walEntries.size()

  val local_decision_has_precommit_quorum: bool =
    (o.decidedValue != NilValue and not(o.decidedViaSync)) implies
      hasQuorum(votersFor(o.precommits, o.decidedRound, o.decidedValue))

  val decision_is_unique_per_height: bool =
    o.decidedHeights.forall(a => o.decidedHeights.forall(b =>
      a._1 == b._1 implies a._2 == b._2))

  val height_started: bool = o.step != Unstarted
  val proposal_became_full: bool =
    o.valuesSeen.exists(x => o.proposalsSeen.contains((x._1, x._2)))
  val prevote_published: bool = o.publishedVotes.exists(x => x._1 == PrevoteT)
  val precommit_published: bool = o.publishedVotes.exists(x => x._1 == PrecommitT)
  val local_decided: bool = o.decidedValue != NilValue and not(o.decidedViaSync)
  val sync_decided: bool = o.decidedViaSync
  val finalization_entered: bool = o.finalizationEntered != Set()
  val finalization_exited: bool = o.finalizationExited != Set()
  val valid_sync_value_emitted: bool = o.emitted.contains(EffValidSyncValue)
  val invalid_sync_value_rejected: bool = o.emitted.contains(EffInvalidSyncValue)
  val future_input_buffered: bool = o.buffered != Set()
  val buffered_input_dropped: bool = o.bufferDropped
  val buffered_input_replayed: bool = o.replayedOnStart
  val restart_skipped_replay: bool = o.restartSkippedReplay
  val past_input_dropped: bool = o.pastDropped
  val duplicate_vote_ignored: bool = o.duplicateIgnored
  val unknown_validator_vote_rejected: bool = o.unknownVoterRejected
  val invalid_signature_rejected: bool = o.badSignatureRejected
  val conflicting_votes_stored: bool =
    o.prevotes.exists(a => o.prevotes.exists(b =>
      a._1 == b._1 and a._2 == b._2 and a._3 != b._3))
    or o.precommits.exists(a => o.precommits.exists(b =>
      a._1 == b._1 and a._2 == b._2 and a._3 != b._3))
  val round_advanced: bool = o.round > 0
  val rebroadcast_emitted: bool = o.emitted.contains(EffRepublish)
  val polka_processed: bool = o.polkaCerts != Set()
  val height_finalized: bool = o.decidedHeights != Set()

  // ════════════ inherited: write-ahead log ════════════
  // Restated over the same variables; bodies identical to wal.qnt.

  val append_ack_is_honest: bool =
    ghost.lastAppend.valid implies
      (ghost.lastAppend.replyOk implies
        ghost.lastAppend.lenAfter == ghost.lastAppend.lenBefore + 1)

  val failed_append_leaves_no_partial_entry: bool =
    ghost.lastAppend.valid implies
      (ghost.lastAppend.replyOk or
        ghost.lastAppend.lenAfter == ghost.lastAppend.lenBefore)

  val no_unreadable_durable_entry: bool =
    PATHS.forall(p =>
      logs.get(p).entries.foldl(true, (acc, e) => acc and e.dataLength <= MAX_ENTRY_SIZE))

  val open_keeps_intact_entries: bool = not(ghost.openLostValid)

  val replay_keeps_later_intact_entries: bool = not(ghost.replayLostLaterIntact)

  val no_broadcast_without_durable_entry: bool = not(ghost.broadcastWithoutDurable)

  val entries_belong_to_the_logs_height: bool =
    val lg = logs.get(ACTOR_PATH)
    lg.entries.foldl(true, (acc, e) => acc and e.height == lg.sequence)

  val unreadable_entry_is_reported: bool =
    ghost.replayRan implies
      (ghost.replayed == ghost.preReplayAll or ghost.replayErrorAt >= 0)

  val replay_returns_all_durable_entries: bool =
    (ghost.replayRan and ghost.replayErrorAt < 0) implies
      ghost.preReplayAll.subseteq(ghost.replayed)

  val append_succeeded: bool =
    ghost.lastAppend.valid and ghost.lastAppend.replyOk and
    ghost.lastAppend.lenAfter > ghost.lastAppend.lenBefore
  val append_failed_on_write_error: bool =
    ghost.lastAppend.valid and not(ghost.lastAppend.replyOk) and
    ghost.lastAppend.lenAfter == ghost.lastAppend.lenBefore
  val oversized_entry_written: bool = not(no_unreadable_durable_entry)
  val append_dropped_on_height_mismatch: bool = ghost.appendDroppedSilently
  val started_height_returned_early: bool = ghost.startedHeightNoop
  val started_height_reset_log: bool = ghost.startedHeightReset
  val started_height_replayed_entries: bool = ghost.startedHeightReplayed
  val open_truncated_tail: bool = ghost.openTruncated > 0
  val open_dropped_intact_entries: bool = not(open_keeps_intact_entries)
  val replay_stopped_at_unreadable_entry: bool = ghost.replayTruncatedAt >= 0
  val replay_discarded_later_intact_entries: bool =
    not(replay_keeps_later_intact_entries)
  val truncate_was_a_noop: bool = ghost.truncateNoop
  val truncate_removed_entries: bool = ghost.truncateRemoved
  val reset_cleared_entries: bool = ghost.resetCleared
  val all_entries_flushed: bool =
    PATHS.exists(p =>
      logs.get(p).entries.length() > 0 and
      logs.get(p).flushed == logs.get(p).entries.length())
  val open_rejected_foreign_version: bool = ghost.openRejected
  val dump_count_mismatch: bool = ghost.dumpMismatch
  val wal_thread_dead_actor_running: bool = not(actor.threadAlive)
  val broadcast_without_durable_entry: bool = ghost.broadcastWithoutDurable
  val entries_span_multiple_heights: bool = not(entries_belong_to_the_logs_height)
  val consensus_append_skipped: bool = ghost.consensusSkipped
  val crash_left_torn_tail: bool =
    PATHS.exists(p =>
      logs.get(p).entries.foldl(false, (acc, e) => acc or e.torn))
  val raw_parts_bypassed_validation: bool = ghost.bypassedValidation
  val read_hit_unreadable_entry: bool = ghost.readRan and ghost.readErrorAt >= 0

  // ══════════════════════════════════════════════════════════════════
  // One deterministic run per broken guarantee. Each step is an operation
  // of the real system; each run ends by asserting the guarantee fails.
  // ══════════════════════════════════════════════════════════════════

  /// The orchestrator publishes a prevote while the log actor is still at a
  /// different height, so `Msg::Append` drops the entry and answers Ok, and
  /// the vote goes out with nothing recorded for it.
  run wal_append_durable_before_publishTest =
    init
      .then(startHeight(1, false))            // Input::StartHeight(1)
      .then(propose(1, true))                 // Input::Propose -> prevote published
      .expect(not(wal_append_durable_before_publish))

  /// The same append reaches the log actor for a height it was never told had
  /// started.
  run started_height_precedes_appendsTest =
    init
      .then(startHeight(1, false))            // Input::StartHeight(1)
      .then(propose(1, true))                 // Input::Propose -> Effect::WalAppend
      .expect(not(started_height_precedes_appends))

  /// The orchestrator counts the append as done while the log holds nothing.
  run orchestrator_wal_ledger_matches_logTest =
    init
      .then(startHeight(1, false))            // Input::StartHeight(1)
      .then(propose(1, true))                 // Input::Propose -> Effect::WalAppend
      .expect(not(orchestrator_wal_ledger_matches_log))

  /// A prevote for value 1 goes out with nothing durable behind it; the
  /// process dies; the restart replays an empty log, so the node has no record
  /// of having voted and prevotes for value 2 in the same round.
  run no_amnesiaTest =
    init
      .then(Logopen(0, true, 0))              // Log::open on the actor's log
      .then(startHeight(1, false))            // Input::StartHeight(1)
      .then(propose(1, true))                 // prevote for value 1 published
      .then(adversary_crash(0, false))        // the process dies
      .then(startHeight(1, false))            // restart: Input::StartHeight(1)
      .then(propose(2, true))                 // prevote for value 2 published
      .expect(not(no_amnesia))

  /// A prevote is appended and its entry later stops reading back, so the
  /// replay for that height hands back nothing while the vote is on the wire.
  run replay_fidelityTest =
    init
      .then(Logopen(0, true, 0))              // Log::open
      .then(Logreset(0, 1, 0))                // Log::reset(sequence = 1)
      .then(Wal_actor_MsgReset(1))            // Msg::Reset(1)
      .then(startHeight(1, false))            // Input::StartHeight(1)
      .then(propose(1, true))                 // prevote appended and published
      .then(adversary_corrupt_crc(0, 0))      // the entry's CRC no longer matches
      .then(Wal_actor_MsgReset(2))            // Msg::Reset(2)
      .then(Wal_actor_MsgStartedHeight(1))    // Msg::StartedHeight(1) -> replay
      .expect(not(replay_fidelity))

  /// An entry written under consensus height 1 sits in a log whose sequence
  /// number is 0, so the replay for height 0 hands back a height-1 vote.
  run height_isolationTest =
    init
      .then(Logopen(0, true, 0))              // Log::open, sequence 0
      .then(Wal_actor_MsgReset(1))            // Msg::Reset(1)
      .then(startHeight(1, false))            // Input::StartHeight(1)
      .then(propose(1, true))                 // entry written under height 1
      .then(Wal_actor_MsgStartedHeight(0))    // Msg::StartedHeight(0) -> replay
      .expect(not(height_isolation))

  /// The same log holds an entry whose height is not its sequence number.
  run entries_belong_to_the_logs_heightTest =
    init
      .then(Logopen(0, true, 0))              // Log::open, sequence 0
      .then(Wal_actor_MsgReset(1))            // Msg::Reset(1)
      .then(startHeight(1, false))            // Input::StartHeight(1)
      .then(propose(1, true))                 // entry written under height 1
      .expect(not(entries_belong_to_the_logs_height))

  /// Msg::Append for a height the actor is not at answers Ok without the log
  /// growing.
  run append_ack_is_honestTest =
    init
      .then(Logopen(0, true, 0))              // Log::open
      .then(Wal_actor_MsgAppend(2))           // Msg::Append(2) while actor is at 0
      .expect(not(append_ack_is_honest))

  /// The write path applies no size check, so an entry larger than any read
  /// will accept becomes durable.
  run no_unreadable_durable_entryTest =
    init
      .then(Logopen(0, true, 0))                                              // Log::open
      .then(Logappend__write_raw__write_compressed(0, MAX_ENTRY_SIZE + 1, true, 1))
      .expect(not(no_unreadable_durable_entry))

  /// The open scan settles on a shorter prefix and truncates away an entry
  /// whose CRC was still valid.
  run open_keeps_intact_entriesTest =
    init
      .then(Logopen(0, true, 0))                                    // Log::open
      .then(Logappend__write_raw__write_compressed(0, 56, true, 1))  // one good entry
      .then(Logopen(0, true, 0))                                    // re-open, scan keeps 0
      .expect(not(open_keeps_intact_entries))

  /// The append reply is only logged, so the message is broadcast with no
  /// entry behind it at all.
  run no_broadcast_without_durable_entryTest =
    init
      .then(consensus_wal_append_and_broadcast(false))   // Effect::WalAppend resumed
      .expect(not(no_broadcast_without_durable_entry))

  /// A vote that arrives while the driver is still in the Nil round is
  /// buffered under the height the node is already on.
  run buffered_inputs_are_futureTest =
    init
      .then(onVote(PrevoteT, 1, 0, 2, 1, true, true))   // Input::Vote at height 1
      .expect(not(buffered_inputs_are_future))

  /// A restart at the same height republishes the same prevote, and the entry
  /// is appended a second time.
  run wal_appends_are_not_duplicatedTest =
    init
      .then(startHeight(1, false))    // Input::StartHeight(1)
      .then(propose(1, true))         // prevote appended
      .then(startHeight(1, false))    // restart at the same height
      .then(propose(1, true))         // the same prevote appended again
      .expect(not(wal_appends_are_not_duplicated))
}
