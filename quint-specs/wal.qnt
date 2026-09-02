// Write-Ahead Log (WAL) — the durable append-only CRC-checked log
// (code/crates/wal/src/log.rs) together with the engine-side actor and its
// blocking thread (code/crates/engine/src/wal.rs, engine/src/wal/thread.rs)
// and the one consensus call site that consumes an append reply
// (code/crates/engine/src/consensus.rs:1141-1167).
//
// The model MIRRORS the code, bugs included. Intent lives in the invariants.
//
// One log per FILE PATH: a single test routinely opens several WAL files, so
// every Log operation carries the `path` it acts on. Whether an open, an
// append or a flush SUCCEEDS depends on damage and I/O conditions the model
// does not track byte for byte, so those outcomes are nondeterministic picks
// that a real run pins from its logged arguments.

module walCore {
  import basicSpells.* from "./spells/basicSpells"

  /// MAX_ENTRY_SIZE (1 GiB, log.rs:15). Enforced on READ (read_to_next,
  /// log.rs:66-71) and NOT on the write path (write_entry, log.rs:392).
  pure val MAX_ENTRY_SIZE: int = 1073741824

  /// WAL file paths the model distinguishes.
  pure val PATHS: Set[int] = 0.to(5)

  /// The path the engine's WAL actor owns.
  pure val ACTOR_PATH: int = 0

  /// Consensus heights the model explores.
  pure val HEIGHTS: Set[int] = 0.to(3)

  /// Entry payload sizes, including the two past MAX_ENTRY_SIZE.
  pure val SIZES: Set[int] =
    0.to(16).union(Set(56, MAX_ENTRY_SIZE, MAX_ENTRY_SIZE + 1))

  /// Entry indices `truncate` and the adversary may target — one past the end
  /// is included so the `from_entry >= len` no-op branch is falsifiable.
  pure val INDICES: Set[int] = 0.to(9)

  /// Entry counts an operation may report back.
  pure val LENS: Set[int] = 0.to(9)

  /// One on-disk entry: flag | length | CRC | data (log.rs:19-27).
  /// `framed` is false when the LENGTH field no longer matches the bytes that
  /// follow — a misframed header the open scan cannot tell from a short entry
  /// (log.rs:264-290). `torn` is a partially written tail entry.
  type Entry = {
    payload: int,
    dataLength: int,
    crc: bool,
    framed: bool,
    torn: bool,
    height: int,
  }

  /// The Log<S> struct (log.rs:120-127) for one path.
  type Log = {
    created: bool,
    headerValid: bool,
    sequence: int,
    entries: List[Entry],
    flushed: int,
  }

  /// The WAL actor's State (engine/src/wal.rs:67-71) and its blocking thread.
  type Actor = {
    height: int,
    threadAlive: bool,
  }

  /// The last append attempt, recorded when it happens so a property can
  /// compare the reply against the length the log actually reached.
  type AppendRecord = {
    valid: bool,
    height: int,
    replyOk: bool,
    lenBefore: int,
    lenAfter: int,
  }

  /// Ghost/observation state. Entry indices use -1 for "none".
  type Ghost = {
    nextId: int,
    writable: bool,
    broadcast: Set[int],
    lastAppend: AppendRecord,
    openRan: bool,
    openRejected: bool,
    openTruncated: int,
    openLostValid: bool,
    replayRan: bool,
    replayLostLaterIntact: bool,
    preReplayAll: Set[int],
    replayed: Set[int],
    replayErrorAt: int,
    replayTruncatedAt: int,
    readRan: bool,
    readErrorAt: int,
    appendDroppedSilently: bool,
    startedHeightNoop: bool,
    startedHeightReset: bool,
    startedHeightReplayed: bool,
    truncateNoop: bool,
    truncateRemoved: bool,
    resetCleared: bool,
    dumpMismatch: bool,
    bypassedValidation: bool,
    crashed: bool,
    consensusSkipped: bool,
    broadcastWithoutDurable: bool,
  }

  // ───────────────────────── pure helpers ─────────────────────────

  /// An entry the open scan walks past: its length field frames real bytes and
  /// it is not a partial tail. The scan checks NO CRC (log.rs:264-290).
  pure def scannable(e: Entry): bool = e.framed and not(e.torn)

  /// An entry `read_to_next` returns data for: within MAX_ENTRY_SIZE, with a
  /// matching CRC over intact bytes (log.rs:66-98).
  pure def readable(e: Entry): bool =
    e.crc and e.dataLength <= MAX_ENTRY_SIZE and e.framed and not(e.torn)

  /// Leading entries the open scan counts before it breaks.
  pure def scanLimit(es: List[Entry]): int =
    es.foldl({ n: 0, stop: false }, (acc, e) =>
      if (acc.stop) acc
      else if (scannable(e)) { n: acc.n + 1, stop: false }
      else { ...acc, stop: true }).n

  /// Index of the first unreadable entry, or -1 when every entry reads back.
  pure def firstUnreadable(es: List[Entry]): int =
    es.foldl({ i: 0, found: -1 }, (acc, e) =>
      if (acc.found >= 0) { ...acc, i: acc.i + 1 }
      else if (readable(e)) { i: acc.i + 1, found: -1 }
      else { i: acc.i + 1, found: acc.i }).found

  /// The first `n` entries of a log.
  pure def take(es: List[Entry], n: int): List[Entry] =
    es.foldl(List(), (acc, e) => if (acc.length() < n) acc.append(e) else acc)

  /// Payloads of every entry in the log.
  pure def payloads(es: List[Entry]): Set[int] =
    es.foldl(Set(), (acc, e) => acc.union(Set(e.payload)))

  /// Payloads of the entries whose CRC is still valid. A partially written
  /// tail entry has no valid CRC on disk, so it does not count.
  pure def validPayloads(es: List[Entry]): Set[int] =
    es.foldl(Set(), (acc, e) =>
      if (e.crc and not(e.torn)) acc.union(Set(e.payload)) else acc)

  /// Payloads of the entries that read back cleanly.
  pure def intactPayloads(es: List[Entry]): Set[int] =
    es.foldl(Set(), (acc, e) => if (readable(e)) acc.union(Set(e.payload)) else acc)

  /// Payloads of the readable entries strictly after index `i`.
  pure def intactPayloadsAfter(es: List[Entry], i: int): Set[int] =
    es.foldl({ idx: 0, s: Set() }, (acc, e) =>
      { idx: acc.idx + 1,
        s: if (acc.idx > i and readable(e)) acc.s.union(Set(e.payload)) else acc.s }).s

  /// Payloads the replay hands back: every entry up to the first unreadable
  /// one (thread.rs:185-208).
  pure def replayedPayloads(es: List[Entry]): Set[int] =
    val stop = firstUnreadable(es)
    if (stop < 0) payloads(es) else payloads(es.take(stop))

  pure val emptyAppend: AppendRecord =
    { valid: false, height: -1, replyOk: false, lenBefore: 0, lenAfter: 0 }

  pure val emptyLog: Log =
    { created: false, headerValid: true, sequence: 0, entries: List(), flushed: 0 }

  pure val initialLogs: int -> Log = PATHS.mapBy(_ => emptyLog)

  pure val initialActor: Actor = { height: 0, threadAlive: true }

  pure val initialGhost: Ghost = {
    nextId: 1,
    writable: true,
    broadcast: Set(),
    lastAppend: emptyAppend,
    openRan: false,
    openRejected: false,
    openTruncated: 0,
    openLostValid: false,
    replayRan: false,
    replayLostLaterIntact: false,
    preReplayAll: Set(),
    replayed: Set(),
    replayErrorAt: -1,
    replayTruncatedAt: -1,
    readRan: false,
    readErrorAt: -1,
    appendDroppedSilently: false,
    startedHeightNoop: false,
    startedHeightReset: false,
    startedHeightReplayed: false,
    truncateNoop: false,
    truncateRemoved: false,
    resetCleared: false,
    dumpMismatch: false,
    bypassedValidation: false,
    crashed: false,
    consensusSkipped: false,
    broadcastWithoutDurable: false,
  }
}

module wal {
  import basicSpells.* from "./spells/basicSpells"
  import walCore.*

  var logs: int -> Log
  var actor: Actor
  var ghost: Ghost

  action init = all {
    logs' = initialLogs,
    actor' = initialActor,
    ghost' = initialGhost,
  }

  // ──────────────────── Log<S> — the raw log layer ────────────────────

  /// Log::open / open_with(path, options) — constructor (log.rs:219-336).
  /// Reads the header, then scans entries by their LENGTH field only and
  /// `truncate_to(pos)` everything from the first unscannable entry onward.
  /// No CRC is checked here. `ok` is false when the header is unusable;
  /// `len` is the entry count the scan settled on.
  action Logopen(path: int, ok: bool, len: int): bool = all {
    val lg = logs.get(path)
    all {
      // A damaged header can only produce a failed open.
      not(lg.headerValid) implies not(ok),
      if (not(ok)) all {
        logs' = logs,
        ghost' = { ...ghost, openRan: true, openRejected: true },
      } else all {
        // The scan keeps a prefix; how long a prefix also depends on damage
        // the model does not track byte for byte, so `len` pins it.
        len <= scanLimit(lg.entries),
        logs' = logs.put(path, { ...lg, created: true,
                                 entries: lg.entries.take(len),
                                 flushed: min(lg.flushed, len) }),
        ghost' = { ...ghost, openRan: true, openRejected: false,
                   openTruncated: lg.entries.length() - len,
                   openLostValid: ghost.openLostValid or
                     not(validPayloads(lg.entries)
                           .subseteq(validPayloads(lg.entries.take(len)))) },
      },
    },
    actor' = actor,
  }

  /// Log::append / write_raw / write_compressed(data) — mutates (log.rs:351-436).
  /// write_entry writes flag|length|CRC|data; on ANY write error it seeks back
  /// and `truncate_to(pos)`, leaving `len` untouched. There is NO size check on
  /// the write path, so an entry larger than MAX_ENTRY_SIZE becomes durable.
  action Logappend__write_raw__write_compressed(path: int, dataLength: int, ok: bool, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      // A storage that refuses writes cannot report success.
      not(ghost.writable) implies not(ok),
      if (ok) {
        // On the actor's own log an entry belongs to the height consensus is
        // at; on a bare log there is no actor, so it belongs to the sequence.
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
        // Truncated back to the pre-write position; Err returned.
        len == lg.entries.length(),
        logs' = logs,
        ghost' = { ...ghost,
                   lastAppend: { valid: true, height: lg.sequence, replyOk: false,
                                 lenBefore: lg.entries.length(),
                                 lenAfter: lg.entries.length() } },
      },
    },
    actor' = actor,
  }

  /// Log::first_entry() / iter() — query (log.rs:444-470). `ok` is false when
  /// the backing file is empty and the call reports NotFound.
  action Logfirst_entry__iter(path: int, ok: bool, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      ok implies len == lg.entries.length(),
      logs' = logs,
      ghost' = { ...ghost, readRan: true, readErrorAt: -1 },
    },
    actor' = actor,
  }

  /// LogIter::next() -> LogEntry::read_to_next (log.rs:60-105): reads entry
  /// `idx` and reports a hard error on a CRC mismatch or an oversized entry.
  /// The read is where damage the model does not track byte for byte becomes
  /// visible, so a failed read records that the entry is unreadable; an entry
  /// already known to be damaged can never read back cleanly.
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
    actor' = actor,
  }

  /// Log::reset(sequence) — mutates (log.rs:483-501). Writes the new sequence
  /// and truncates every entry away.
  action Logreset(path: int, sequence: int, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      len == 0,
      logs' = logs.put(path, { ...lg, sequence: sequence, entries: List(), flushed: 0 }),
      ghost' = { ...ghost, resetCleared: ghost.resetCleared or lg.entries.length() > 0 },
    },
    actor' = actor,
  }

  /// Log::truncate(from_entry) — mutates (log.rs:515-565).
  /// A no-op when `from_entry >= len`; otherwise drops entries from that index.
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
        logs' = logs.put(path, { ...lg, entries: lg.entries.take(from_entry),
                                 flushed: min(lg.flushed, from_entry) }),
        ghost' = { ...ghost, truncateRemoved: true },
      },
    },
    actor' = actor,
  }

  /// Log::flush() — mutates, fsync (log.rs:574). On success everything written
  /// so far is durable and can no longer be torn by a crash.
  action Logflush(path: int, ok: bool, len: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.created,
      len == lg.entries.length(),
      logs' = logs.put(path,
        if (ok) { ...lg, flushed: lg.entries.length() } else lg),
      ghost' = ghost,
    },
    actor' = actor,
  }

  /// Log::from_raw_parts(...) — the documented test-only bypass of validation
  /// (log.rs:586-600): builds a handle with a caller-supplied sequence and
  /// length, running no scan and no truncation.
  action Logfrom_raw_parts(path: int, sequence: int, len: int): bool = all {
    val lg = logs.get(path)
    all {
      len <= lg.entries.length(),
      logs' = logs.put(path, { ...lg, created: true, sequence: sequence,
                               entries: lg.entries.take(len),
                               flushed: min(lg.flushed, len) }),
      ghost' = { ...ghost, bypassedValidation: true },
    },
    actor' = actor,
  }

  // ──────────────── Wal actor + blocking thread ────────────────

  // The actor layer models only the actor's OWN decision. The log mutations it
  // asks the thread for arrive as their own Log-layer events (Logreset,
  // Logtruncate, Logappend, Logflush, Logfirst_entry__iter, Logread_entry), so
  // these actions never touch `logs` themselves.

  /// Wal actor Msg::StartedHeight(height, reply) (wal.rs:87-99, thread.rs:76-98).
  /// The actor returns early with no entries when it is ALREADY at that height,
  /// leaving log.sequence untouched. Otherwise the thread compares the height
  /// against log.sequence: equal -> replay the entries, different -> reset the
  /// log. A read error at entry `idx` stops the scan and truncates there, so
  /// later undamaged entries are dropped from both the replay and the log.
  action Wal_actor_MsgStartedHeight(height: int): bool = all {
    val lg = logs.get(ACTOR_PATH)
    all {
      lg.created,
      actor.threadAlive,
      logs' = logs,
      if (actor.height == height) all {
        actor' = actor,
        ghost' = { ...ghost, startedHeightNoop: true },
      } else if (height == lg.sequence) {
        val stop = firstUnreadable(lg.entries)
        all {
          actor' = { ...actor, height: height },
          ghost' = { ...ghost,
                     startedHeightReplayed: true,
                     replayRan: true,
                     preReplayAll: payloads(lg.entries),
                     replayed: replayedPayloads(lg.entries),
                     replayErrorAt: stop,
                     replayTruncatedAt: stop,
                     replayLostLaterIntact: ghost.replayLostLaterIntact or
                       (stop >= 0 and
                         not(intactPayloadsAfter(lg.entries, stop)
                               .subseteq(intactPayloads(lg.entries.take(stop))))) },
        }
      } else all {
        actor' = { ...actor, height: height },
        ghost' = { ...ghost, startedHeightReset: true },
      },
    },
  }

  /// Wal actor Msg::Reset(height, reply) — mutates (wal.rs:101-104).
  action Wal_actor_MsgReset(height: int): bool = all {
    logs.get(ACTOR_PATH).created,
    actor.threadAlive,
    actor' = { ...actor, height: height },
    logs' = logs,
    ghost' = ghost,
  }

  /// Wal actor Msg::Append(height, entry, reply) (wal.rs:107-120).
  /// When the height does not match the actor's in-memory height the entry is
  /// dropped and the caller is told `Ok(())` anyway; otherwise the entry is
  /// handed to the thread, which appends it to the log.
  action Wal_actor_MsgAppend(height: int): bool = all {
    val lg = logs.get(ACTOR_PATH)
    all {
      lg.created,
      actor.threadAlive,
      actor' = actor,
      logs' = logs,
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

  /// Wal actor Msg::Flush(reply) — mutates (wal.rs:122).
  action Wal_actor_MsgFlush = all {
    logs.get(ACTOR_PATH).created,
    actor.threadAlive,
    logs' = logs,
    actor' = actor,
    ghost' = ghost,
  }

  /// Wal actor Msg::Dump — query (wal.rs:126, thread.rs:236-267). Logs an
  /// error when the number of decodable entries differs from `log.len()`.
  action Wal_actor_MsgDump = all {
    val lg = logs.get(ACTOR_PATH)
    all {
      lg.created,
      actor.threadAlive,
      logs' = logs,
      actor' = actor,
      ghost' = { ...ghost,
                 dumpMismatch: ghost.dumpMismatch or
                   replayedPayloads(lg.entries).size() != lg.entries.length() },
    },
  }

  // ─────────── the consensus call site that consumes the reply ───────────

  /// Effect::WalAppend resumed by Consensus::wal_append (consensus.rs:1141-1167,
  /// call site core-consensus/src/handle/vote.rs:95-102). The append result is
  /// only logged; `perform!` resumes and the message is broadcast either way.
  /// While Recovering, or on a non-validator, the append is skipped entirely.
  action consensus_wal_append_and_broadcast(recovering: bool): bool = all {
    logs' = logs,
    actor' = actor,
    if (recovering) {
      // Phase::Recovering / non-validator: nothing appended, nothing broadcast.
      ghost' = { ...ghost, consensusSkipped: true }
    } else {
      ghost' = { ...ghost,
                 nextId: ghost.nextId + 1,
                 broadcast: ghost.broadcast.union(Set(ghost.nextId)),
                 broadcastWithoutDurable: ghost.broadcastWithoutDurable or
                   not(ghost.lastAppend.valid) or
                   ghost.lastAppend.lenAfter == ghost.lastAppend.lenBefore }
    },
  }

  // ─────────────────────── adversary surface ───────────────────────

  /// A bit flip damages entry `idx`'s data: its CRC no longer matches.
  action adversary_corrupt_crc(path: int, idx: int): bool = all {
    val lg = logs.get(path)
    all {
      idx < lg.entries.length(),
      lg.entries.nth(idx).crc,
      logs' = logs.put(path, { ...lg, entries: lg.entries.replaceAt(idx,
                { ...lg.entries.nth(idx), crc: false }) }),
      ghost' = ghost,
    },
    actor' = actor,
  }

  /// A bit flip damages entry `idx`'s LENGTH field: the header no longer frames
  /// the bytes that follow, which the open scan cannot distinguish from a short
  /// entry (log.rs:264-290).
  action adversary_misframe_header(path: int, idx: int): bool = all {
    val lg = logs.get(path)
    all {
      idx < lg.entries.length(),
      lg.entries.nth(idx).framed,
      logs' = logs.put(path, { ...lg, entries: lg.entries.replaceAt(idx,
                { ...lg.entries.nth(idx), framed: false }) }),
      ghost' = ghost,
    },
    actor' = actor,
  }

  /// The process dies. Anything written but not yet fsynced may be a torn tail,
  /// and all in-memory actor state is gone.
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
    },
  }

  /// The storage stops accepting writes (disk full, I/O error).
  action adversary_disk_failure = all {
    ghost.writable,
    logs' = logs,
    actor' = actor,
    ghost' = { ...ghost, writable: false },
  }

  /// The storage becomes writable again.
  action adversary_disk_recovers = all {
    not(ghost.writable),
    logs' = logs,
    actor' = actor,
    ghost' = { ...ghost, writable: true },
  }

  /// A panic inside the WAL thread is caught and logged; the thread exits and
  /// the channel is orphaned, but the actor is never stopped or restarted
  /// (thread.rs:37-56).
  action adversary_wal_thread_panic = all {
    actor.threadAlive,
    logs' = logs,
    actor' = { ...actor, threadAlive: false },
    ghost' = ghost,
  }

  /// The file's header names a WAL version this build does not support, or is
  /// too short to read, so `open` refuses it (log.rs:230-241).
  action adversary_foreign_version(path: int): bool = all {
    val lg = logs.get(path)
    all {
      lg.headerValid,
      logs' = logs.put(path, { ...lg, headerValid: false, created: true }),
      ghost' = ghost,
    },
    actor' = actor,
  }

  // ─────────────────────────── step ───────────────────────────

  // Every nondet lives here. The `len` picks are drawn from the handful of
  // counts the current state could produce (the operation's own count and the
  // one it would report on failure), so a wrong count still falsifies the
  // conformance guard while the search stays affordable.
  action step = any {
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
    // The engine owns exactly one log; these arms re-offer the operations that
    // build up its state so simulation reaches the replay scenarios.
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

  // ──────────────────── correctness properties ────────────────────

  /// An append answered Ok only when the log actually grew by that entry.
  val append_ack_is_honest: bool =
    ghost.lastAppend.valid implies
      (ghost.lastAppend.replyOk implies
        ghost.lastAppend.lenAfter == ghost.lastAppend.lenBefore + 1)

  /// An append that answered Err left the log exactly as long as it was.
  val failed_append_leaves_no_partial_entry: bool =
    ghost.lastAppend.valid implies
      (ghost.lastAppend.replyOk or
        ghost.lastAppend.lenAfter == ghost.lastAppend.lenBefore)

  /// No entry in a log is larger than the maximum size a read accepts.
  val no_unreadable_durable_entry: bool =
    PATHS.forall(p =>
      logs.get(p).entries.foldl(true, (acc, e) => acc and e.dataLength <= MAX_ENTRY_SIZE))

  /// Opening a log keeps every entry whose CRC was still valid.
  val open_keeps_intact_entries: bool = not(ghost.openLostValid)

  /// A replay that hits an unreadable entry keeps every later entry that
  /// still reads back cleanly.
  val replay_keeps_later_intact_entries: bool = not(ghost.replayLostLaterIntact)

  /// A consensus message is broadcast only after its entry is durable in the log.
  val no_broadcast_without_durable_entry: bool = not(ghost.broadcastWithoutDurable)

  /// Every entry the WAL holds was appended at the height its sequence number names.
  val entries_belong_to_the_logs_height: bool =
    val lg = logs.get(ACTOR_PATH)
    lg.entries.foldl(true, (acc, e) => acc and e.height == lg.sequence)

  /// A replay that hands back fewer entries than the log held reports an error
  /// instead of ending in silence.
  val unreadable_entry_is_reported: bool =
    ghost.replayRan implies
      (ghost.replayed == ghost.preReplayAll or ghost.replayErrorAt >= 0)

  /// A replay that hit no error hands back every entry the log held.
  val replay_returns_all_durable_entries: bool =
    (ghost.replayRan and ghost.replayErrorAt < 0) implies
      ghost.preReplayAll.subseteq(ghost.replayed)

  // ─────────────────────── observations ───────────────────────

  /// An entry was appended and the log grew.
  val append_succeeded: bool =
    ghost.lastAppend.valid and ghost.lastAppend.replyOk and
    ghost.lastAppend.lenAfter > ghost.lastAppend.lenBefore

  /// A write error was reported and nothing was left behind.
  val append_failed_on_write_error: bool =
    ghost.lastAppend.valid and not(ghost.lastAppend.replyOk)

  /// An entry larger than the read-side maximum sits in a log.
  val oversized_entry_written: bool = not(no_unreadable_durable_entry)

  /// An Append for another height was answered Ok without writing anything.
  val append_dropped_on_height_mismatch: bool = ghost.appendDroppedSilently

  /// StartedHeight found the log already at that height and returned early.
  val started_height_returned_early: bool = ghost.startedHeightNoop

  /// StartedHeight found a different sequence and reset the log.
  val started_height_reset_log: bool = ghost.startedHeightReset

  /// StartedHeight matched the log sequence and replayed entries.
  val started_height_replayed_entries: bool =
    ghost.startedHeightReplayed and ghost.replayed.size() > 0

  /// The open scan truncated a partial or misframed tail away.
  val open_truncated_tail: bool = ghost.openTruncated > 0

  /// The open scan deleted entries whose CRC was still valid.
  val open_dropped_intact_entries: bool = not(open_keeps_intact_entries)

  /// A replay stopped at an unreadable entry and truncated the log there.
  val replay_stopped_at_unreadable_entry: bool = ghost.replayTruncatedAt >= 0

  /// A replay's truncation discarded later entries that still read back.
  val replay_discarded_later_intact_entries: bool =
    not(replay_keeps_later_intact_entries)

  /// truncate() was called past the end of the log and did nothing.
  val truncate_was_a_noop: bool = ghost.truncateNoop

  /// truncate() removed entries from the log.
  val truncate_removed_entries: bool = ghost.truncateRemoved

  /// A reset cleared entries that were in the log.
  val reset_cleared_entries: bool = ghost.resetCleared

  /// Every entry in some log is fsynced.
  val all_entries_flushed: bool =
    PATHS.exists(p =>
      val lg = logs.get(p)
      lg.created and lg.flushed > 0 and lg.flushed == lg.entries.length())

  /// open() refused a file whose header it could not accept.
  val open_rejected_foreign_version: bool = ghost.openRejected

  /// Dump found fewer decodable entries than the log claims to hold.
  val dump_count_mismatch: bool = ghost.dumpMismatch

  /// The WAL thread is gone while the actor is still up.
  val wal_thread_dead_actor_running: bool = not(actor.threadAlive)

  /// A message reached the network with no matching entry in the log.
  val broadcast_without_durable_entry: bool =
    not(no_broadcast_without_durable_entry)

  /// A log holds entries appended under a height other than its sequence.
  val entries_span_multiple_heights: bool =
    not(entries_belong_to_the_logs_height)

  /// The consensus append path was skipped because the node was recovering
  /// or is not a validator.
  val consensus_append_skipped: bool = ghost.consensusSkipped

  /// A crash left a torn tail entry behind.
  val crash_left_torn_tail: bool =
    ghost.crashed and
    PATHS.exists(p => logs.get(p).entries.foldl(false, (acc, e) => acc or e.torn))

  /// A log handle was built through the validation-bypassing constructor.
  val raw_parts_bypassed_validation: bool = ghost.bypassedValidation

  /// A read walked the log and hit an unreadable entry.
  val read_hit_unreadable_entry: bool = ghost.readRan and ghost.readErrorAt >= 0
}
