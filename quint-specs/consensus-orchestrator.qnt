// Consensus Orchestrator — the effect-yielding handler layer of
// `code/crates/core-consensus/` (entry `handle::handle_input`, state
// `state::State<Ctx>`).
//
// The model captures the ORCHESTRATOR-DISTINCTIVE control layer that sits on
// top of the driver (modelled separately as `driver` / `vote-keeper` /
// `round-state-machine`). Driver tallying is abstracted to the minimum needed
// to observe the orchestrator's own behaviour:
//
//   * input routing        — past heights dropped, future heights (and any input
//                            arriving while the round is Nil) buffered in the
//                            bounded queue (`state::buffer_input`,
//                            `util/bounded_queue.rs`), replayed on a non-restart
//                            `StartHeight` (`handle/start_height.rs:69-92`).
//   * vote admission       — dedupe, unknown-validator rejection, signature /
//                            vote-extension rejection, then WAL append before
//                            the vote is applied and published
//                            (`handle/vote.rs:8-107`).
//   * finalization latch   — entered in `handle/decide.rs`, cleared in
//                            `handle/finalize.rs`, at most once per height.
//   * sync-decision path   — `handle/sync.rs::maybe_sync_decision` decides
//                            without voting, but only once a commit certificate
//                            is stored in the driver.
//
// The whole orchestrator state is one record `s : OrchState`, so every action is
// a thin guard + `s' = <pure transition>` and all nondeterminism lives in
// `init` / `step`.
module consensusOrchestratorCore {
  // The pure layer: domains, enums, the state type and every pure transition.
  // Split out unchanged so a system-level spec can import and re-apply this
  // logic verbatim instead of re-modelling it. No behaviour is defined here
  // that was not defined before the split.


  // ===========================================================================
  // Domains (small; the wire stage pins the logged arguments into these)
  // ===========================================================================
  type Address = int
  type Height  = int
  type Round   = int
  type Value   = int

  /// Sentinel for "no value" (Nil vote / no decision).
  pure val NilValue: Value = -1
  /// Sentinel for the Nil round (the driver before `NewRound`).
  pure val NilRound: Round = -1

  /// This node's address; a logged vote from our own address is logged as 1.
  pure val MyAddress: Address = 1
  /// The validator set (membership only — the weighted tallying itself belongs
  /// to the `vote-keeper` / `driver` components).
  pure val Validators: Set[Address] = Set(1, 2, 3, 4)
  /// An address that is NOT in the validator set.
  pure val UnknownAddress: Address = 99
  /// Addresses a vote may claim to come from.
  pure val Voters: Set[Address] = Validators.union(Set(UnknownAddress))

  /// Votes needed to complete a step. The driver's real >2/3 tallying is
  /// modelled by the `vote-keeper` component; here it is abstracted to "the
  /// step completes once the driver reports a quorum", so that this spec stays
  /// about the orchestrator's own routing, WAL and finalization behaviour.
  pure val QuorumSize: int = 1

  pure val Heights: Set[Height] = 0.to(5)
  pure val Rounds:  Set[Round]  = 0.to(3)
  pure val Values:  Set[Value]  = Set(1, 2)

  /// Distinct heights the input queue can hold (`State::new` queue capacity).
  pure val QueueCapacity: int = 1

  // ===========================================================================
  // Enums
  // ===========================================================================
  type Step =
    | Unstarted
    | Propose
    | Prevote
    | Precommit
    | Commit

  type VoteType =
    | PrevoteT
    | PrecommitT

  type TimeoutKind =
    | TOPropose
    | TOPrevote
    | TOPrecommit
    | TOFinalize
    | TORebroadcast

  type CertType =
    | PrecommitCert
    | SkipCert

  type Origin =
    | ConsensusOrigin
    | SyncOrigin

  /// Observable effects the orchestrator yields (abstracted for coverage).
  type Effect =
    | EffStartRound
    | EffGetValue
    | EffDecide
    | EffFinalize
    | EffScheduleFinalize
    | EffValidSyncValue
    | EffInvalidSyncValue
    | EffRepublish
    | EffPublishProposal

  // ===========================================================================
  // State
  // ===========================================================================
  type OrchState = {
    // consensus position
    height: Height,
    round:  Round,
    step:   Step,

    // finalization-period latch and its per-height audit trail
    finalizationPeriod:  bool,
    finalizationEntered: Set[Height],
    finalizationExited:  Set[Height],

    // bounded input queue: the heights that currently hold buffered inputs
    buffered:             Set[Height],
    bufferDropped:        bool,
    replayedOnStart:      bool,
    restartSkippedReplay: bool,

    // full-proposal keeper: signed proposals and proposed values per (round, value)
    proposalsSeen: Set[(Round, Value)],
    valuesSeen:    Set[(Round, Value, bool)],

    // driver vote store (abstract) and the certificates it holds
    prevotes:    Set[(Round, Address, Value)],
    precommits:  Set[(Round, Address, Value)],
    commitCerts: Set[(Round, Value)],
    polkaCerts:  Set[(Round, Value)],

    // decision for the current height, plus the per-height decision log
    decidedValue:   Value,
    decidedRound:   Round,
    decidedViaSync: bool,
    decidedHeights: Set[(Height, Value)],

    // WAL bookkeeping: the entries appended, and how many appends happened
    walEntries:     Set[(VoteType, Height, Round, Address, Value)],
    walAppends:     int,
    publishedVotes: Set[(VoteType, Round, Value)],

    // cumulative effects and rejection latches (silent behaviours need a latch
    // to be observable at all)
    emitted:               Set[Effect],
    pastDropped:           bool,
    duplicateIgnored:      bool,
    unknownVoterRejected:  bool,
    badSignatureRejected:  bool,
  }

  // ===========================================================================
  // Pure helpers
  // ===========================================================================

  /// The driver reported a quorum for these voters (see `QuorumSize`).
  pure def hasQuorum(voters: Set[Address]): bool =
    voters.size() >= QuorumSize

  pure def votersFor(votes: Set[(Round, Address, Value)], r: Round, v: Value): Set[Address] =
    votes.filter(x => x._1 == r and x._3 == v).map(x => x._2)

  /// A non-nil value with a quorum among `votes` at round `r`, else NilValue.
  pure def quorumValue(votes: Set[(Round, Address, Value)], r: Round): Value =
    val cands = votes.filter(x => x._1 == r and x._3 != NilValue).map(x => x._3)
    cands.fold(NilValue, (acc, v) =>
      if (acc != NilValue) acc
      else if (hasQuorum(votersFor(votes, r, v))) v
      else acc)

  /// A `Full` proposal exists for (r, v): a signed proposal AND its value.
  pure def isFull(st: OrchState, r: Round, v: Value): bool =
    st.proposalsSeen.contains((r, v)) and st.valuesSeen.exists(x => x._1 == r and x._2 == v)

  pure def maxOf(hs: Set[Height]): Height =
    hs.fold(0, (a, x) => if (x > a) x else a)

  /// `Effect::WalAppend` — always counted, so a missing dedupe upstream shows up
  /// as `walAppends > walEntries.size()`.
  pure def appendWal(st: OrchState, e: (VoteType, Height, Round, Address, Value)): OrchState =
    { ...st, walEntries: st.walEntries.union(Set(e)), walAppends: st.walAppends + 1 }

  // ----- publishing our own votes (WAL append, then publish) -----------------
  pure def emitPrevote(st: OrchState, r: Round, v: Value): OrchState =
    val logged = appendWal(st, (PrevoteT, st.height, r, MyAddress, v))
    { ...logged, step: Prevote,
      prevotes:       logged.prevotes.union(Set((r, MyAddress, v))),
      publishedVotes: logged.publishedVotes.union(Set((PrevoteT, r, v))) }

  pure def emitPrecommit(st: OrchState, r: Round, v: Value): OrchState =
    val logged = appendWal(st, (PrecommitT, st.height, r, MyAddress, v))
    { ...logged, step: Precommit,
      precommits:     logged.precommits.union(Set((r, MyAddress, v))),
      publishedVotes: logged.publishedVotes.union(Set((PrecommitT, r, v))) }

  /// Local decision (`handle/decide.rs`): build the commit certificate, emit
  /// Decide, and enter the finalization period (at most once per height).
  pure def decideLocal(st: OrchState, r: Round, v: Value): OrchState =
    val decided = { ...st, step: Commit,
      decidedValue: v, decidedRound: r, decidedViaSync: false,
      commitCerts: st.commitCerts.union(Set((r, v))),
      emitted: st.emitted.union(Set(EffDecide)) }
    if (not(st.finalizationEntered.contains(st.height)))
      { ...decided, finalizationPeriod: true,
        finalizationEntered: decided.finalizationEntered.union(Set(st.height)),
        emitted: decided.emitted.union(Set(EffScheduleFinalize)) }
    else decided

  /// Sync decision (`handle/sync.rs::maybe_sync_decision`): decide immediately,
  /// skipping the finalization period — the commit certificate must be stored.
  pure def decideSync(st: OrchState, r: Round, v: Value): OrchState =
    { ...st, step: Commit,
      decidedValue: v, decidedRound: r, decidedViaSync: true,
      commitCerts: st.commitCerts.union(Set((r, v))),
      decidedHeights: st.decidedHeights.union(Set((st.height, v))),
      emitted: st.emitted.union(Set(EffDecide, EffFinalize)) }

  /// Abstract driver progress: prevote quorum on a full value ⇒ precommit;
  /// precommit quorum on a full value ⇒ local decision.
  pure def driverProgress(st: OrchState): OrchState =
    if (st.step == Precommit and st.decidedValue == NilValue)
      val dv = quorumValue(st.precommits, st.round)
      if (dv != NilValue and isFull(st, st.round, dv)) decideLocal(st, st.round, dv) else st
    else if (st.step == Prevote)
      val pv = quorumValue(st.prevotes, st.round)
      if (pv != NilValue and isFull(st, st.round, pv)) emitPrecommit(st, st.round, pv) else st
    else st

  /// Run the driver to a fixpoint over Prevote → Precommit → Commit.
  pure def cascade(st: OrchState): OrchState =
    driverProgress(driverProgress(driverProgress(st)))

  /// `BoundedQueue::push`: at capacity, a LOWER index evicts the highest one,
  /// a higher index is silently rejected (`util/bounded_queue.rs:36-92`).
  pure def bufferInput(st: OrchState, bh: Height): OrchState =
    if (st.buffered.contains(bh)) st
    else if (st.buffered.size() < QueueCapacity) { ...st, buffered: st.buffered.union(Set(bh)) }
    else if (bh < maxOf(st.buffered))
      { ...st, buffered: st.buffered.exclude(Set(maxOf(st.buffered))).union(Set(bh)),
        bufferDropped: true }
    else { ...st, bufferDropped: true }

  pure def dropPast(st: OrchState): OrchState =
    { ...st, pastDropped: true }

  // ===========================================================================
  // Pure transitions (one per `Input` variant)
  // ===========================================================================

  /// `Input::StartHeight` → `state::reset_and_start_height` + `on_start_height`:
  /// reset per-height state, start round 0, drain the queue for this height and
  /// replay it unless this is a restart.
  pure def procStartHeight(st: OrchState, h: Height, isRestart: bool): OrchState =
    val hadPending = st.buffered.contains(h)
    { ...st, height: h, round: 0, step: Propose,
      finalizationPeriod: false,
      proposalsSeen: Set(), valuesSeen: Set(),
      prevotes: Set(), precommits: Set(), commitCerts: Set(), polkaCerts: Set(),
      publishedVotes: Set(),
      decidedValue: NilValue, decidedRound: NilRound, decidedViaSync: false,
      buffered: st.buffered.filter(x => x > h),
      replayedOnStart:      st.replayedOnStart or (hadPending and not(isRestart)),
      restartSkippedReplay: st.restartSkippedReplay or (hadPending and isRestart),
      emitted: st.emitted.union(Set(EffStartRound, EffGetValue)) }

  /// `Input::Vote` → `handle/vote.rs::on_vote`, in the code's own order:
  /// drop past height, buffer future height or a Nil round, ignore an
  /// already-seen vote, reject an unknown validator, reject a bad signature or
  /// vote extension, then WAL-append and apply.
  pure def procVote(st: OrchState, vt: VoteType, vh: Height, vr: Round,
                    voter: Address, v: Value, sigOk: bool): OrchState =
    val seen = if (vt == PrevoteT) st.prevotes.contains((vr, voter, v))
               else st.precommits.contains((vr, voter, v))
    if (vh < st.height) dropPast(st)
    else if (vh > st.height or st.round == NilRound) bufferInput(st, vh)
    else if (seen) { ...st, duplicateIgnored: true }
    else if (not(Validators.contains(voter))) { ...st, unknownVoterRejected: true }
    else if (not(sigOk)) { ...st, badSignatureRejected: true }
    else
      val logged = appendWal(st, (vt, st.height, vr, voter, v))
      val recorded =
        if (vt == PrevoteT) { ...logged, prevotes: logged.prevotes.union(Set((vr, voter, v))) }
        else { ...logged, precommits: logged.precommits.union(Set((vr, voter, v))) }
      cascade(recorded)

  /// `Input::Proposal` → `handle/proposal.rs::on_proposal`.
  pure def procProposal(st: OrchState, ph: Height, pr: Round, v: Value, sigOk: bool): OrchState =
    if (ph < st.height) dropPast(st)
    else if (ph > st.height or st.round == NilRound) bufferInput(st, ph)
    else if (not(sigOk)) { ...st, badSignatureRejected: true }
    else
      val stored = { ...st, proposalsSeen: st.proposalsSeen.union(Set((pr, v))) }
      val prevoted =
        if (isFull(stored, st.round, v) and pr == st.round and st.step == Propose)
          emitPrevote(stored, st.round, v)
        else stored
      cascade(prevoted)

  /// `Input::ProposedValue` → `handle/proposed_value.rs::on_proposed_value`;
  /// when a commit certificate for the value is already stored, this takes the
  /// sync-decision shortcut instead of voting.
  pure def procValue(st: OrchState, pvh: Height, pvr: Round, v: Value,
                     valid: bool, origin: Origin): OrchState =
    if (pvh < st.height) dropPast(st)
    else if (pvh > st.height) bufferInput(st, pvh)
    else
      val stored = { ...st, valuesSeen: st.valuesSeen.union(Set((pvr, v, valid))) }
      if (stored.commitCerts.contains((pvr, v)) and valid and st.decidedValue == NilValue)
        decideSync(stored, pvr, v)
      else
        val prevoted =
          if (isFull(stored, st.round, v) and pvr == st.round and st.step == Propose and valid)
            emitPrevote(stored, st.round, v)
          else stored
        cascade(prevoted)

  /// `Input::SyncValueResponse` → `handle/sync.rs::on_value_response`:
  /// heights other than the current one are ignored, an unverifiable commit
  /// certificate yields `Effect::InvalidSyncValue`, otherwise the certificate is
  /// stored and — if the value is already known — the decision is taken now.
  pure def procSync(st: OrchState, ch: Height, cr: Round, v: Value, certOk: bool): OrchState =
    if (ch < st.height) dropPast(st)
    else if (ch > st.height) st
    else if (not(certOk)) { ...st, emitted: st.emitted.union(Set(EffInvalidSyncValue)) }
    else
      val stored = { ...st, commitCerts: st.commitCerts.union(Set((cr, v))) }
      if (stored.valuesSeen.exists(x => x._1 == cr and x._2 == v and x._3)
          and st.decidedValue == NilValue)
        decideSync(stored, cr, v)
      else
        { ...stored, emitted: stored.emitted.union(Set(EffValidSyncValue)) }

  /// `Input::TimeoutElapsed` → `handle/timeout.rs`; `TOFinalize` is the exit of
  /// the finalization period (`handle/finalize.rs::finalize_height`).
  pure def procTimeout(st: OrchState, kind: TimeoutKind, tr: Round): OrchState =
    match kind {
      | TOFinalize =>
        if (st.finalizationPeriod and st.step == Commit)
          { ...st, finalizationPeriod: false,
            finalizationExited: st.finalizationExited.union(Set(st.height)),
            decidedHeights: st.decidedHeights.union(Set((st.height, st.decidedValue))),
            emitted: st.emitted.union(Set(EffFinalize)) }
        else st
      | TORebroadcast => { ...st, emitted: st.emitted.union(Set(EffRepublish)) }
      | TOPropose =>
        if (tr == st.round and st.step == Propose) emitPrevote(st, st.round, NilValue) else st
      | TOPrevote =>
        if (tr == st.round and st.step == Prevote) emitPrecommit(st, st.round, NilValue) else st
      | TOPrecommit =>
        // The driver's `on_timeout_precommit` enters the next round whenever
        // the timeout is for the current round, whatever step it is in — a
        // Precommit round certificate can schedule it from any step.
        if (tr == st.round and st.step != Commit and st.step != Unstarted)
          { ...st, round: st.round + 1, step: Propose }
        else st
    }

  /// `Input::PolkaCertificate` → `handle/liveness.rs::on_polka_certificate`.
  pure def procPolka(st: OrchState, ph: Height, pr: Round, v: Value): OrchState =
    if (ph < st.height) dropPast(st)
    else if (ph != st.height) st
    else { ...st, polkaCerts: st.polkaCerts.union(Set((pr, v))) }

  /// `Input::RoundCertificate` → `handle/liveness.rs::on_round_certificate`;
  /// a skip certificate for a higher round enters that round.
  pure def procRoundCert(st: OrchState, ct: CertType, ch: Height, cr: Round): OrchState =
    if (ch != st.height) st
    else match ct {
      | SkipCert      =>
        if (cr > st.round and st.step != Commit and st.step != Unstarted)
          { ...st, round: cr, step: Propose }
        else st
      | PrecommitCert => st
    }

  /// `Input::Propose` → `handle/propose.rs::on_propose`: our own value becomes a
  /// full proposal and is published, and we prevote for it.
  pure def procPropose(st: OrchState, v: Value): OrchState =
    val built = { ...st,
      proposalsSeen: st.proposalsSeen.union(Set((st.round, v))),
      valuesSeen: st.valuesSeen.union(Set((st.round, v, true))),
      emitted: st.emitted.union(Set(EffPublishProposal)) }
    cascade(if (st.step == Propose) emitPrevote(built, st.round, v) else built)

}

module consensus_orchestrator {
  import consensusOrchestratorCore.*

  var s: OrchState

  // ===========================================================================
  // Actions — thin: guard + one primed assignment. Logged event names are mapped
  // onto these through the oracle config's `actionNameMap`.
  // ===========================================================================

  /// `Input::StartHeight` — consensus only ever moves forward in height.
  action startHeight(h: Height, isRestart: bool): bool = all {
    s.height <= h,
    s' = procStartHeight(s, h, isRestart),
  }

  /// `Input::Vote` (`handle/vote.rs::on_vote`).
  action onVote(vt: VoteType, vh: Height, vr: Round, voter: Address,
                v: Value, sigOk: bool): bool = all {
    s' = procVote(s, vt, vh, vr, voter, v, sigOk),
  }

  /// `Input::Proposal` (`handle/proposal.rs::on_proposal`).
  action onProposal(ph: Height, pr: Round, v: Value, sigOk: bool): bool = all {
    s' = procProposal(s, ph, pr, v, sigOk),
  }

  /// `Input::ProposedValue` (`handle/proposed_value.rs::on_proposed_value`).
  action onProposedValue(pvh: Height, pvr: Round, v: Value, valid: bool,
                         origin: Origin): bool = all {
    s' = procValue(s, pvh, pvr, v, valid, origin),
  }

  /// `Input::SyncValueResponse` (`handle/sync.rs::on_value_response`).
  action onSyncValueResponse(ch: Height, cr: Round, v: Value, certOk: bool): bool = all {
    s' = procSync(s, ch, cr, v, certOk),
  }

  /// `Input::TimeoutElapsed` (`handle/timeout.rs`, `handle/finalize.rs`).
  action onTimeoutElapsed(kind: TimeoutKind, tr: Round): bool = all {
    s' = procTimeout(s, kind, tr),
  }

  /// `Input::PolkaCertificate` (`handle/liveness.rs::on_polka_certificate`).
  action onPolkaCertificate(ph: Height, pr: Round, v: Value): bool = all {
    s' = procPolka(s, ph, pr, v),
  }

  /// `Input::RoundCertificate` (`handle/liveness.rs::on_round_certificate`).
  action onRoundCertificate(ct: CertType, ch: Height, cr: Round): bool = all {
    s' = procRoundCert(s, ct, ch, cr),
  }

  /// `Input::Propose` — only provided when we are the proposer for the round.
  action propose(v: Value): bool = all {
    s.step == Propose,
    s' = procPropose(s, v),
  }

  // ===========================================================================
  // init / step
  // ===========================================================================
  action init = all {
    s' = {
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
    }
  }

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
    nondet tkind     = oneOf(Set(TOPropose, TOPrevote, TOPrecommit, TOFinalize, TORebroadcast))
    nondet tr        = oneOf(Rounds)
    nondet ct        = oneOf(Set(PrecommitCert, SkipCert))
    any {
      startHeight(h, isRestart),
      onVote(vt, vh, vr, voter, vval, sigOk),
      onProposal(ph, pr, pval, sigOk),
      onProposedValue(ph, pr, pval, valid, origin),
      onSyncValueResponse(ph, pr, pval, valid),
      onTimeoutElapsed(tkind, tr),
      onPolkaCertificate(ph, pr, pval),
      onRoundCertificate(ct, ph, pr),
      propose(pval),
    }
  }

  // ===========================================================================
  // Observations
  // ===========================================================================

  /// A height was started and the driver left the Nil round.
  val height_started: bool = s.step != Unstarted

  /// A proposal and its proposed value met, forming a full proposal.
  val proposal_became_full: bool =
    s.valuesSeen.exists(x => s.proposalsSeen.contains((x._1, x._2)))

  /// The node published a prevote.
  val prevote_published: bool = s.publishedVotes.exists(x => x._1 == PrevoteT)

  /// The node published a precommit.
  val precommit_published: bool = s.publishedVotes.exists(x => x._1 == PrecommitT)

  /// A decision was reached through local voting.
  val local_decided: bool = s.decidedValue != NilValue and not(s.decidedViaSync)

  /// A decision was reached through the sync shortcut.
  val sync_decided: bool = s.decidedViaSync

  /// The finalization period was entered for some height.
  val finalization_entered: bool = s.finalizationEntered != Set()

  /// The finalization period was left by the finalize-height timeout.
  val finalization_exited: bool = s.finalizationExited != Set()

  /// A sync commit certificate was accepted while the value was still missing.
  val valid_sync_value_emitted: bool = s.emitted.contains(EffValidSyncValue)

  /// A sync commit certificate failed verification and was reported invalid.
  val invalid_sync_value_rejected: bool = s.emitted.contains(EffInvalidSyncValue)

  /// An input for a future height was buffered.
  val future_input_buffered: bool = s.buffered != Set()

  /// The bounded input queue was full and an input was evicted or rejected.
  val buffered_input_dropped: bool = s.bufferDropped

  /// Buffered inputs were replayed when their height started.
  val buffered_input_replayed: bool = s.replayedOnStart

  /// A restart discarded the buffered inputs instead of replaying them.
  val restart_skipped_replay: bool = s.restartSkippedReplay

  /// An input for a past height was dropped.
  val past_input_dropped: bool = s.pastDropped

  /// An already-seen vote was ignored.
  val duplicate_vote_ignored: bool = s.duplicateIgnored

  /// A vote from an address outside the validator set was rejected.
  val unknown_validator_vote_rejected: bool = s.unknownVoterRejected

  /// A vote or proposal with an invalid signature or extension was rejected.
  val invalid_signature_rejected: bool = s.badSignatureRejected

  /// One validator's conflicting votes for the same round are both stored.
  val conflicting_votes_stored: bool =
    s.prevotes.exists(a => s.prevotes.exists(b =>
      a._1 == b._1 and a._2 == b._2 and a._3 != b._3))
    or s.precommits.exists(a => s.precommits.exists(b =>
      a._1 == b._1 and a._2 == b._2 and a._3 != b._3))

  /// The round advanced past round 0.
  val round_advanced: bool = s.round > 0

  /// A rebroadcast timeout made the node republish its last votes.
  val rebroadcast_emitted: bool = s.emitted.contains(EffRepublish)

  /// A polka certificate was stored.
  val polka_processed: bool = s.polkaCerts != Set()

  /// A height was finalized.
  val height_finalized: bool = s.decidedHeights != Set()

  // ===========================================================================
  // Correctness properties
  // ===========================================================================

  /// The finalization period is left only for a height that entered it.
  val latch_exit_follows_entry: bool =
    s.finalizationExited.subseteq(s.finalizationEntered)

  /// The finalization period is held only while the node sits in Commit for a
  /// height it entered and has not yet finalized.
  val finalization_period_only_in_commit: bool =
    s.finalizationPeriod implies (s.step == Commit
      and s.finalizationEntered.contains(s.height)
      and not(s.finalizationExited.contains(s.height)))

  /// Buffered inputs are only ever for heights ahead of the current one.
  val buffered_inputs_are_future: bool = s.buffered.forall(h => h > s.height)

  /// The input queue never holds more heights than its capacity.
  val buffer_within_capacity: bool = s.buffered.size() <= QueueCapacity

  /// A decision taken through the sync path has its commit certificate stored.
  val sync_decision_requires_certificate: bool =
    s.decidedViaSync implies s.commitCerts.contains((s.decidedRound, s.decidedValue))

  /// Every vote the node publishes was appended to the WAL first.
  val published_votes_are_wal_logged: bool =
    s.publishedVotes.forall(p =>
      s.walEntries.contains((p._1, s.height, p._2, MyAddress, p._3)))

  /// No message is appended to the WAL twice.
  val wal_appends_are_not_duplicated: bool = s.walAppends == s.walEntries.size()

  /// A decision reached locally is backed by a precommit quorum for that value.
  val local_decision_has_precommit_quorum: bool =
    (s.decidedValue != NilValue and not(s.decidedViaSync)) implies
      hasQuorum(votersFor(s.precommits, s.decidedRound, s.decidedValue))

  /// A height never finalizes two different values.
  val decision_is_unique_per_height: bool =
    s.decidedHeights.forall(a => s.decidedHeights.forall(b =>
      a._1 == b._1 implies a._2 == b._2))
}
