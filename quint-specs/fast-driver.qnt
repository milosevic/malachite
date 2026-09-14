// Model of the Fast Tendermint per-height DRIVER (`n > 5f`) —
// `fast::driver::Driver::process` and the multiplexing around it.
//
// Code under model:
//   code/crates/core-driver/src/fast/driver.rs     (process / apply_proposal / apply_vote / apply_round / resolve)
//   code/crates/core-driver/src/fast/proposals.rs  (FreshProposals)
//   code/crates/core-driver/src/fast/mod.rs        (the L27 / L42 / L15-L16 rationale)
//
// The driver owns three things across calls: the round state machine's state,
// the retained fresh proposals, and the vote keeper's tally. All three are
// modelled here, because every rule the driver exists for is a statement about
// the driver asking the keeper the right question — with injected quorum
// answers, "routed as justified iff a 2f+1 quorum exists in the named round"
// would be true by construction.
//
// The keeper transcription is DERIVED FROM quint-specs/fast-vote-keeper.qnt,
// not re-derived from the Rust: the threshold constants, the strict `isMet`,
// the per-round `reached` latches, the output order, and the discard rules are
// that spec's, so a divergence cannot surface here as a spurious driver
// finding. One deliberate difference: weights are unit (six equal validators,
// the driver test fixture, where 2f+1 = 3 and n-f = 5). A weight-dependent
// keeper bug is fast-vote-keeper's ground and is not claimed here.
//
// ACTIONS and ARGUMENTS mirror the Rust — that is what the oracle replays. The
// PROPERTIES are stated from Algorithm 1 of Vander Vos & Cason, "Fast
// Tendermint" (arXiv:2608.13434), NOT read off the implementation: a property
// read off the code would only prove the code equals itself.
module fast_driver {

  //--------------------------------------------------------------------------
  // Domain
  //--------------------------------------------------------------------------

  /// Round::Nil is -1; Round::Some(r) is r >= 0, matching `as_i64()`.
  type Round = int
  type Value = str
  type Addr = str

  /// A Ctx::Proposal: its own round, the value, and `pol_round` (the paper's `vr`).
  type Prop = { round: Round, value: Value, polRound: Round }

  type Step = Unstarted | Propose | Precommit | Commit
  type RoundValueId = { round: Round, value_id: Value }
  type MaybeRV = NoRV | SomeRV(RoundValueId)
  type MaybeDec = NoDec | SomeDec({ round: Round, value: Value })
  type NilOrVal = VNil | VVal(Value)
  type TimeoutKind = TPropose | TPrecommit | TPrevote | TRebroadcast | TFinalizeHeight
  type VoteKind = KPrevote | KPrecommit

  /// state_machine::input::Input<Ctx>
  type RInput =
    | RNewRound(Round)
    | RProposeValue(Value)
    | RProposal(Prop)
    | RInvalidProposal
    | RProposalAndVoteQuorumPrevious(Prop)
    | RInvalidProposalAndVoteQuorumPrevious(Prop)
    | RVoteQuorumForValue({ round: Round, value_id: Value })
    | RQuorumAny(Round)
    | RProposalAndDecisionQuorum(Prop)
    | RTimeoutPropose
    | RTimeoutPrecommit
    | RWaitForValidExpired

  /// state_machine::output::Output<Ctx>; ONone models `Transition.output == None`.
  type ROut =
    | ONone
    | ONewRound(Round)
    | OProposal(Prop)
    | OVote({ kind: VoteKind, value: NilOrVal })
    | OScheduleTimeout({ round: Round, kind: TimeoutKind })
    | OGetValueAndScheduleTimeout({ round: Round, kind: TimeoutKind })
    | OWaitForValid({ round: Round, kind: TimeoutKind })
    | ORepropose({ value_id: Value, valid_round: Round })
    | ODecision({ round: Round, value: Value })

  /// driver::Output<Ctx> — the same set with `Repropose` resolved away.
  type DOut =
    | DNewRound(Round)
    | DProposal(Prop)
    | DVote({ kind: VoteKind, value: NilOrVal })
    | DScheduleTimeout({ round: Round, kind: TimeoutKind })
    | DGetValueAndScheduleTimeout({ round: Round, kind: TimeoutKind })
    | DWaitForValid({ round: Round, kind: TimeoutKind })
    | DDecision({ round: Round, value: Value })

  type Info = { input_round: Round, address: Addr, proposer: Addr }

  /// state.rs State<Ctx>, per height.
  type SMState = {
    round: Round,
    step: Step,
    valid: MaybeRV,
    decision: MaybeDec,
    awaiting_valid: bool,
    scheduled: Set[TimeoutKind],
    armedPrecommit: Set[Round],
  }

  /// FastTransition<Ctx>.
  type Result = { st: SMState, out: ROut, ok: bool }

  /// One counted vote, as `first_votes` retains it.
  type SVote = { round: Round, voter: Addr, value: NilOrVal }

  /// FastVoteKeeper<Ctx>, unit weights. `reached` deliberately survives everything.
  type KState = {
    votes: Set[SVote],
    reachedQuorum: Set[(Round, Value)],
    reachedDecision: Set[(Round, Value)],
    reachedAny: Set[Round],
  }

  /// votekeeper::fast::keeper::Output<Ctx>
  type KOut =
    | KVoteQuorum({ round: Round, value: Value })
    | KDecisionQuorum({ round: Round, value: Value })
    | KQuorumAny(Round)

  /// Driver<Ctx>: the round state, the retained fresh proposals, the proposer
  /// of the round being entered, and the keeper.
  type DState = {
    rs: SMState,
    props: Value -> Prop,
    proposer: Addr,
    kv: KState,
  }

  /// The result of one driver call: the new state, the outputs it returned, the
  /// outcome classes it hit, and the paper-rule violations it committed.
  type DRes = { d: DState, outs: List[DOut], tags: Set[str], bad: Set[str] }

  //--------------------------------------------------------------------------
  // Domains for the nondet picks
  //--------------------------------------------------------------------------

  /// The six equal validators of the driver test fixture.
  pure val VALIDATORS: Set[Addr] = Set("a", "b", "c", "d", "e", "f")
  pure val TOTAL: int = 6
  pure val ME: Addr = "a"
  /// Addresses a vote may claim, including one outside the set.
  pure val VOTERS: Set[Addr] = VALIDATORS.union(Set("z"))

  /// The value identifiers: two abstract symbols plus "7", the only `ValueId`
  /// the driver suite produces (ValueId's Display is lower-case hex).
  pure val VALUES: Set[Value] = Set("7", "v", "w")
  /// A vote's value, with "Nil" for a nil vote.
  pure val VOTE_VALUES: Set[str] = Set("Nil").union(VALUES)

  /// -1 is Round::Nil. The suite drives rounds 0 and 1; the band keeps a couple
  /// above so `vr >= state.round` and a future-round quorum stay expressible.
  pure val ROUND_BAND: Set[Round] = Set(-1, 0, 1, 2, 3)

  pure val TIMEOUT_KINDS: Set[TimeoutKind] =
    Set(TPropose, TPrecommit, TPrevote, TRebroadcast, TFinalizeHeight)

  /// `TimeoutKind` as the instrumentation renders it, so the logged argument is
  /// a plain scalar the replay can pin.
  pure val KIND_NAMES: Set[str] =
    Set("Propose", "Precommit", "Prevote", "Rebroadcast", "FinalizeHeight")

  pure def kindOf(k: str): TimeoutKind =
    if (k == "Propose") TPropose
    else if (k == "Precommit") TPrecommit
    else if (k == "Prevote") TPrevote
    else if (k == "Rebroadcast") TRebroadcast
    else TFinalizeHeight

  pure val VOTE_TYPES: Set[str] = Set("Precommit", "Prevote")

  /// driver::Input<Ctx>, selected by tag so one pick names the variant and the
  /// payload picks stay independently pinnable from logged arguments.
  pure val ALL_TAGS: Set[str] =
    Set("NewRound", "ProposeValue", "Proposal", "Vote", "TimeoutElapsed",
        "WaitForValidExpired")

  //--------------------------------------------------------------------------
  // Thresholds — copied from quint-specs/fast-vote-keeper.qnt
  //--------------------------------------------------------------------------

  pure val QUORUM_NUM: int = 2
  pure val QUORUM_DEN: int = 5
  pure val DECISION_NUM: int = 4
  pure val DECISION_DEN: int = 5

  /// ThresholdParam::is_met — strict.
  pure def isMet(w: int, num: int, den: int, total: int): bool = w * den > total * num

  //--------------------------------------------------------------------------
  // Pure queries
  //--------------------------------------------------------------------------

  pure def validRound(s: SMState): Round =
    match s.valid { | NoRV => -1 | SomeRV(rv) => rv.round }

  pure def validIs(s: SMState, v: Value): bool =
    match s.valid { | NoRV => false | SomeRV(rv) => rv.value_id == v }

  pure def validIsNone(s: SMState): bool =
    match s.valid { | NoRV => true | SomeRV(_) => false }

  pure def isProposer(i: Info): bool = i.address == i.proposer
  pure def isDefined(r: Round): bool = r >= 0
  pure def isNil(r: Round): bool = r < 0

  pure def isTracked(k: TimeoutKind): bool = k == TPropose or k == TPrecommit
  pure def checkTimeout(s: SMState, k: TimeoutKind): bool =
    isTracked(k) and not(s.scheduled.contains(k))
  pure def recordTimeout(s: SMState, k: TimeoutKind): SMState =
    if (isTracked(k)) { ...s, scheduled: s.scheduled.union(Set(k)) } else s

  pure def updateRound(s: SMState, r: Round): SMState =
    if (s.round != r) { ...s, round: r, scheduled: Set() } else s

  pure def armPrecommit(s: SMState, r: Round): bool = not(s.armedPrecommit.contains(r))
  pure def recordArmed(s: SMState, r: Round): SMState =
    { ...s, armedPrecommit: s.armedPrecommit.union(Set(r)) }

  /// Refuses to leave Commit: a decided round is terminal.
  pure def withStep(s: SMState, st: Step): SMState =
    if (s.step == Commit) s else { ...s, step: st }

  /// Monotone: a no-op unless the new round is strictly above the recorded one.
  pure def setValid(s: SMState, r: Round, v: Value): SMState =
    if (validRound(s) < r) { ...s, valid: SomeRV({ round: r, value_id: v }) } else s

  /// Write-once — the paper treats `decision_p` as a latch (L56 reads it as one).
  pure def setDecision(s: SMState, r: Round, v: Value): SMState =
    if (s.decision != NoDec) s else { ...s, decision: SomeDec({ round: r, value: v }) }

  /// Output::vote — ALWAYS a precommit; the protocol has one voting step.
  pure def voteOutput(v: NilOrVal): ROut = OVote({ kind: KPrecommit, value: v })
  pure def scheduleTimeout(r: Round, k: TimeoutKind): ROut =
    OScheduleTimeout({ round: r, kind: k })

  //--------------------------------------------------------------------------
  // The round state machine — state_machine.rs apply()
  //--------------------------------------------------------------------------

  pure def vote(s: SMState, v: NilOrVal): Result =
    { st: withStep(s, Precommit), out: voteOutput(v), ok: true }

  pure def proposeNow(s0: SMState): Result = {
    val s = { ...s0, awaiting_valid: false }
    match s.valid {
      | SomeRV(rv) =>
          { st: s, out: ORepropose({ value_id: rv.value_id, valid_round: rv.round }), ok: true }
      | NoRV =>
          { st: s, out: OGetValueAndScheduleTimeout({ round: s.round, kind: TPropose }), ok: true }
    }
  }

  pure def startRound(s0: SMState, i: Info, round: Round): Result = {
    val s1 = withStep(updateRound(s0, round), Propose)
    if (not(isProposer(i)))
      if (checkTimeout(s1, TPropose))
        { st: recordTimeout(s1, TPropose), out: scheduleTimeout(round, TPropose), ok: true }
      else { st: s1, out: ONone, ok: true }
    else
      if (round > 0 and validRound(s1) < round - 1)
        { st: { ...s1, awaiting_valid: true },
          out: OWaitForValid({ round: round, kind: TPrecommit }), ok: true }
      else proposeNow(s1)
  }

  pure def applyInput(s: SMState, i: Info, input: RInput): Result = {
    val thisRound = s.round == i.input_round
    match input {
      | RNewRound(r) =>
          if (s.decision != NoDec) { st: s, out: ONone, ok: false }
          else if (s.step == Unstarted and s.round <= r) startRound(s, i, r)
          else if (s.round < r) startRound(s, i, r)
          else { st: s, out: ONone, ok: false }

      | RProposeValue(v) =>
          if (s.step == Propose and thisRound and isProposer(i) and not(s.awaiting_valid))
            { st: s, out: OProposal({ round: s.round, value: v, polRound: -1 }), ok: true }
          else { st: s, out: ONone, ok: false }

      | RProposal(p) =>
          if (s.step == Propose and thisRound and isNil(p.polRound))
            if (validIsNone(s) or validIs(s, p.value)) vote(s, VVal(p.value))
            else vote(s, VNil)
          else { st: s, out: ONone, ok: false }

      | RInvalidProposal =>
          if (s.step == Propose and thisRound) vote(s, VNil)
          else { st: s, out: ONone, ok: false }

      | RProposalAndVoteQuorumPrevious(p) =>
          if (s.step == Propose and thisRound)
            if (not(isDefined(p.polRound)) or p.polRound >= s.round)
              { st: s, out: ONone, ok: false }
            else if (validRound(s) <= p.polRound or validIs(s, p.value)) {
              // L29-L30. Note `<=`: at equality the paper REPLACES the value it
              // holds, so the write is direct rather than through the monotone
              // `set_valid`.
              val s2 =
                if (validRound(s) <= p.polRound)
                  { ...s, valid: SomeRV({ round: p.polRound, value_id: p.value }) }
                else s
              vote(s2, VVal(p.value))
            } else vote(s, VNil)
          else { st: s, out: ONone, ok: false }

      | RInvalidProposalAndVoteQuorumPrevious(_) =>
          if (s.step == Propose and thisRound) vote(s, VNil)
          else { st: s, out: ONone, ok: false }

      | RVoteQuorumForValue(q) =>
          if (q.round > s.round) { st: s, out: ONone, ok: false }
          else {
            val raised = validRound(s) < q.round
            val s2 = setValid(s, q.round, q.value_id)
            if (not(raised)) { st: s2, out: ONone, ok: false }
            else if (s2.awaiting_valid and isProposer(i)) proposeNow(s2)
            else { st: s2, out: ONone, ok: true }
          }

      | RQuorumAny(r) =>
          if (r >= s.round)
            if (armPrecommit(s, r))
              { st: recordArmed(s, r), out: scheduleTimeout(r, TPrecommit), ok: true }
            else { st: s, out: ONone, ok: false }
          else { st: s, out: ONone, ok: false }

      | RProposalAndDecisionQuorum(p) =>
          if (s.decision == NoDec)
            if (not(isNil(p.polRound))) { st: s, out: ONone, ok: false }
            else {
              val s2 = { ...s, awaiting_valid: false }
              { st: withStep(setDecision(s2, p.round, p.value), Commit),
                out: ODecision({ round: p.round, value: p.value }), ok: true }
            }
          else { st: s, out: ONone, ok: false }

      | RTimeoutPropose =>
          if (s.step == Propose and thisRound) vote(s, VNil)
          else { st: s, out: ONone, ok: false }

      | RWaitForValidExpired =>
          if (s.step == Propose and thisRound and s.awaiting_valid and isProposer(i))
            proposeNow(s)
          else { st: s, out: ONone, ok: false }

      | RTimeoutPrecommit =>
          if (i.input_round >= s.round and s.decision == NoDec)
            { st: s, out: ONewRound(i.input_round + 1), ok: true }
          else { st: s, out: ONone, ok: false }
    }
  }

  //--------------------------------------------------------------------------
  // The vote keeper — keeper.rs, transcribed from fast-vote-keeper.qnt
  //--------------------------------------------------------------------------

  pure def hasFirstVote(kv: KState, r: Round, a: Addr): bool =
    kv.votes.exists(x => x.round == r and x.voter == a)

  pure def firstVoteValue(kv: KState, r: Round, a: Addr): NilOrVal =
    kv.votes.filter(x => x.round == r and x.voter == a).fold(VNil, (_, x) => x.value)

  pure def countFor(kv: KState, r: Round, v: NilOrVal): int =
    kv.votes.filter(x => x.round == r and x.value == v).size()

  pure def countAny(kv: KState, r: Round): int =
    kv.votes.filter(x => x.round == r).size()

  /// FastVoteKeeper::has_vote_quorum — answered from `reached`.
  pure def hasVoteQuorum(kv: KState, r: Round, v: Value): bool =
    kv.reachedQuorum.contains((r, v))

  /// An INDEPENDENT recount of the same question, straight off the vote set.
  /// The L27 property compares the two.
  pure def recountVoteQuorum(kv: KState, r: Round, v: Value): bool =
    isMet(countFor(kv, r, VVal(v)), QUORUM_NUM, QUORUM_DEN, TOTAL)

  pure def hasAnyDecisionQuorum(kv: KState, v: Value): bool =
    kv.reachedDecision.exists(p => p._2 == v)

  /// FastVoteKeeper::decision_quorum_round — the BTreeMap is walked in
  /// ascending round order, so the lowest such round is the one returned.
  /// -1 stands for None; a real quorum round is always >= 0.
  pure def decisionQuorumRound(kv: KState, v: Value): Round =
    kv.reachedDecision.fold(-1, (acc, p) =>
      if (p._2 != v) acc else if (acc == -1 or p._1 < acc) p._1 else acc)

  /// FastVoteKeeper::apply_vote.
  pure def applyVoteK(kv: KState, v: SVote, vtype: str): { kv: KState, outs: List[KOut], tags: Set[str] } =
    if (vtype != "Precommit")
      // One voting step: a prevote is discarded rather than tallied.
      { kv: kv, outs: List(), tags: Set("prevote_discarded_by_the_keeper") }
    else if (not(VALIDATORS.contains(v.voter)))
      { kv: kv, outs: List(), tags: Set("vote_from_a_non_validator_discarded") }
    else if (not(isDefined(v.round)))
      { kv: kv, outs: List(), tags: Set("vote_at_a_nil_round_discarded") }
    else if (hasFirstVote(kv, v.round, v.voter))
      { kv: kv, outs: List(),
        tags: if (firstVoteValue(kv, v.round, v.voter) != v.value)
                Set("equivocating_vote_not_tallied")
              else Set("duplicate_vote_not_tallied") }
    else {
      val kv1 = { ...kv, votes: kv.votes.union(Set(v)) }
      val forValue = countFor(kv1, v.round, v.value)
      val anyWeight = countAny(kv1, v.round)
      val vid = match v.value { | VNil => "Nil" | VVal(x) => x }
      val isVal = match v.value { | VNil => false | VVal(_) => true }
      // L36 then L42, in that order, so a consumer acting on both sees `valid`
      // set before the decision that depends on it.
      val emitQ = isVal and isMet(forValue, QUORUM_NUM, QUORUM_DEN, TOTAL)
                    and not(kv1.reachedQuorum.contains((v.round, vid)))
      val emitD = isVal and isMet(forValue, DECISION_NUM, DECISION_DEN, TOTAL)
                    and not(kv1.reachedDecision.contains((v.round, vid)))
      val emitA = isMet(anyWeight, DECISION_NUM, DECISION_DEN, TOTAL)
                    and not(kv1.reachedAny.contains(v.round))
      val kv2 = {
        ...kv1,
        reachedQuorum: if (emitQ) kv1.reachedQuorum.union(Set((v.round, vid))) else kv1.reachedQuorum,
        reachedDecision: if (emitD) kv1.reachedDecision.union(Set((v.round, vid))) else kv1.reachedDecision,
        reachedAny: if (emitA) kv1.reachedAny.union(Set(v.round)) else kv1.reachedAny,
      }
      val l0: List[KOut] = List()
      val l1 = if (emitQ) l0.append(KVoteQuorum({ round: v.round, value: vid })) else l0
      val l2 = if (emitD) l1.append(KDecisionQuorum({ round: v.round, value: vid })) else l1
      val l3 = if (emitA) l2.append(KQuorumAny(v.round)) else l2
      { kv: kv2, outs: l3, tags: Set("vote_tallied") }
    }

  //--------------------------------------------------------------------------
  // FreshProposals — proposals.rs
  //--------------------------------------------------------------------------

  /// FreshProposals::keep — retains a proposal only if it is fresh and its
  /// identifier is not already held. Returns whether it was newly kept.
  pure def keepAllowed(props: Value -> Prop, p: Prop): bool =
    isNil(p.polRound) and not(props.keys().contains(p.value))

  pure def keepProp(props: Value -> Prop, p: Prop): Value -> Prop =
    if (keepAllowed(props, p)) props.put(p.value, p) else props

  pure def keepTag(props: Value -> Prop, p: Prop): str =
    if (not(isNil(p.polRound))) "reproposal_not_retained"
    else if (props.keys().contains(p.value)) "duplicate_fresh_proposal_not_rekept"
    else "fresh_proposal_retained"

  //--------------------------------------------------------------------------
  // The driver — driver.rs
  //--------------------------------------------------------------------------

  /// Driver::resolve. The only output that needs work is `Repropose`: the state
  /// machine holds an identifier, so the driver looks up the fresh proposal
  /// that carried the value. A missing original is ORDINARY — `valid` is set
  /// from vote quorums, and votes carry only id(v) — and is a KNOWN DIVERGENCE
  /// from L15-L16, which broadcasts the identifier and never needs the value.
  /// It must not stall the round, so a propose timeout goes out instead.
  pure def resolve(d: DState, out: ROut): { outs: List[DOut], tags: Set[str], bad: Set[str] } =
    match out {
      | ONone => { outs: List(), tags: Set(), bad: Set() }
      | ONewRound(r) => { outs: List(DNewRound(r)), tags: Set(), bad: Set() }
      | OProposal(p) => { outs: List(DProposal(p)), tags: Set(), bad: Set() }
      | OVote(v) => { outs: List(DVote(v)), tags: Set(), bad: Set() }
      | OScheduleTimeout(t) => { outs: List(DScheduleTimeout(t)), tags: Set(), bad: Set() }
      | OGetValueAndScheduleTimeout(t) =>
          { outs: List(DGetValueAndScheduleTimeout(t)), tags: Set(), bad: Set() }
      | OWaitForValid(t) => { outs: List(DWaitForValid(t)), tags: Set(), bad: Set() }
      | ODecision(dd) => { outs: List(DDecision(dd)), tags: Set(), bad: Set() }
      | ORepropose(rp) =>
          if (d.props.keys().contains(rp.value_id))
            { outs: List(DProposal({ round: d.rs.round,
                                     value: d.props.get(rp.value_id).value,
                                     polRound: rp.valid_round })),
              tags: Set("repropose_resolved_to_a_full_proposal"), bad: Set() }
          else
            { outs: List(DScheduleTimeout({ round: d.rs.round, kind: TPropose })),
              tags: Set("repropose_value_missing"), bad: Set() }
    }

  /// Driver::apply_round — apply one round input and resolve the output.
  /// `info.proposer` is the driver's own field, not something derived from the
  /// input's round.
  pure def applyRound(d: DState, input: RInput, inputRound: Round): DRes = {
    val info = { input_round: inputRound, address: ME, proposer: d.proposer }
    val r = applyInput(d.rs, info, input)
    val d1 = { ...d, rs: r.st }
    val res = resolve(d1, r.out)
    // L15-L16: a re-propose request must never produce nothing.
    val silent = match r.out { | ORepropose(_) => res.outs.length() == 0 | _ => false }
    { d: d1, outs: res.outs, tags: res.tags,
      bad: res.bad.union(if (silent) Set("silent_repropose") else Set()) }
  }

  pure def joinRes(a: DRes, b: DRes): DRes =
    { d: b.d, outs: a.outs.concat(b.outs),
      tags: a.tags.union(b.tags), bad: a.bad.union(b.bad) }

  /// Driver::apply_proposal — L20-L34. Route a proposal by whether it is fresh
  /// or a re-proposal, and in the latter case only once the keeper confirms the
  /// justification the proposal NAMES.
  pure def applyProposal(d0: DState, p: Prop, valid: bool): DRes = {
    val vid = p.value
    val pol = p.polRound
    // Only a proposal the application accepted may be retained: retaining a
    // rejected one would let an invalid value be decided at L42.
    val d1 = if (valid) { ...d0, props: keepProp(d0.props, p) } else d0
    val keepTags =
      if (valid) Set(keepTag(d0.props, p)) else Set("invalid_proposal_not_retained")
    // The retention itself is the safety-relevant act: the FIRST fresh proposal
    // for an identifier wins, so a rejected one that got in is the proposal a
    // later L42 would decide on, whatever arrives afterwards.
    val retainedInvalidly = not(valid) and d1.props != d0.props

    val justified = hasVoteQuorum(d1.kv, pol, vid)
    val routing =
      if (isNil(pol))
        { input: if (valid) RProposal(p) else RInvalidProposal,
          tag: if (valid) "fresh_proposal_routed_valid" else "fresh_proposal_routed_invalid",
          asJustified: false }
      else if (justified and valid)
        { input: RProposalAndVoteQuorumPrevious(p),
          tag: "reproposal_routed_as_justified", asJustified: true }
      else
        { input: RInvalidProposalAndVoteQuorumPrevious(p),
          tag: "reproposal_routed_as_unjustified", asJustified: false }

    // L27, judged against an independent recount for the round the proposal
    // names — not against the latch the routing itself consulted.
    val unjustified = routing.asJustified and not(recountVoteQuorum(d1.kv, pol, vid))

    val r1 = applyRound(d1, routing.input, p.round)
    val afterRoute =
      { ...r1, tags: r1.tags.union(keepTags).union(Set(routing.tag)),
        bad: r1.bad
               .union(if (unjustified) Set("unjustified_reproposal_forwarded") else Set())
               .union(if (retainedInvalidly) Set("retained_after_invalid_verdict") else Set()) }

    // L42 is a symmetric `upon`: both conjuncts persist and whichever arrives
    // SECOND fires it. Evaluating it only on the vote edge lost the decision
    // whenever the quorum arrived first — the keeper latches each threshold
    // once and never re-reports it, so nothing would have fired again.
    val d2 = afterRoute.d
    if (not(valid)) afterRoute
    else if (d2.rs.decision != NoDec)
      { ...afterRoute, tags: afterRoute.tags.union(Set("l42_skipped_because_already_decided")) }
    else {
      val qr = decisionQuorumRound(d2.kv, vid)
      if (qr == -1) afterRoute
      else if (not(d2.props.keys().contains(vid)))
        { ...afterRoute,
          tags: afterRoute.tags.union(Set("decision_quorum_waited_for_its_proposal")) }
      else {
        val retained = d2.props.get(vid)
        val r2 = applyRound(d2, RProposalAndDecisionQuorum(retained), qr)
        // L42: the decision carries the PROPOSAL's round, not the quorum's.
        val wrongRound =
          match r2.d.rs.decision {
            | NoDec => false
            | SomeDec(dd) => d2.rs.decision == NoDec and dd.round != retained.round
          }
        joinRes(afterRoute,
                { ...r2,
                  tags: r2.tags.union(Set("decision_fired_on_the_proposal_edge")),
                  bad: r2.bad.union(if (wrongRound) Set("decision_round_is_not_the_proposals") else Set()) })
      }
    }
  }

  /// The round a keeper output was reported FOR. The driver must carry this
  /// through rather than re-derive it from the round it happens to be at.
  /// A placeholder proposal for the arm that never applies one.
  pure val NO_PROP: Prop = { round: -1, value: "v", polRound: -1 }

  pure def roundOfKOut(o: KOut): Round =
    match o {
      | KVoteQuorum(q) => q.round
      | KDecisionQuorum(q) => q.round
      | KQuorumAny(r) => r
    }

  /// Driver::apply_vote's match: turn one keeper output into a round input plus
  /// the round to apply it for. `skip` models the `continue` arm — an `n - f`
  /// quorum with no retained proposal has nothing to decide on, so it waits.
  pure def routeKOut(d: DState, o: KOut): { input: RInput, round: Round, skip: bool, tag: str } =
    match o {
      | KVoteQuorum(q) =>
          { input: RVoteQuorumForValue({ round: q.round, value_id: q.value }),
            round: q.round, skip: false, tag: "vote_quorum_routed" }
      | KQuorumAny(r) =>
          { input: RQuorumAny(r), round: r, skip: false, tag: "quorum_any_routed" }
      | KDecisionQuorum(q) =>
          // L42. The votes decide, but the VALUE comes from the fresh proposal
          // that established it, which may be from an earlier round. Without
          // that proposal there is nothing to decide on, so the quorum waits.
          if (d.props.keys().contains(q.value))
            { input: RProposalAndDecisionQuorum(d.props.get(q.value)),
              round: q.round, skip: false, tag: "decision_fired_on_the_vote_edge" }
          else
            { input: RProposalAndDecisionQuorum(NO_PROP),
              round: q.round, skip: true, tag: "decision_quorum_waited_for_its_proposal" }
    }

  pure def stepKOut(acc: DRes, o: KOut): DRes = {
    val r = routeKOut(acc.d, o)
    if (r.skip) { ...acc, tags: acc.tags.union(Set(r.tag)) }
    else {
      val pre = acc.d
      val sub = applyRound(acc.d, r.input, r.round)
      // The round the keeper reported must survive the trip: the state machine
      // refuses a quorum for a round above its own, and can only do that if the
      // round is the one that was reported.
      val drifted = r.round != roundOfKOut(o)
      val hasRetained = pre.props.keys().contains(valueOfKOut(o))
      // L42: the decision carries the PROPOSAL's round, not the quorum's.
      val wrongRound =
        match sub.d.rs.decision {
          | NoDec => false
          | SomeDec(dd) =>
              pre.rs.decision == NoDec and hasRetained
                and dd.round != pre.props.get(valueOfKOut(o)).round
        }
      joinRes(acc, { ...sub, tags: sub.tags.union(Set(r.tag)),
                     bad: sub.bad
                            .union(if (drifted) Set("keeper_round_drifted") else Set())
                            .union(if (wrongRound) Set("decision_round_is_not_the_proposals") else Set()) })
    }
  }

  /// The value a keeper output names; "Nil" for QuorumAny, which names none.
  pure def valueOfKOut(o: KOut): Value =
    match o {
      | KVoteQuorum(q) => q.value
      | KDecisionQuorum(q) => q.value
      | KQuorumAny(_) => "Nil"
    }

  /// Driver::apply_vote — feed the vote to the keeper and turn each threshold
  /// it reports into a round input.
  pure def applyVote(d0: DState, v: SVote, vtype: str): DRes = {
    val k = applyVoteK(d0.kv, v, vtype)
    val d1 = { ...d0, kv: k.kv }
    val start: DRes = { d: d1, outs: List(), tags: k.tags, bad: Set() }
    k.outs.foldl(start, (acc, o) => stepKOut(acc, o))
  }

  /// Driver::process — the single entry point.
  pure def processInput(d: DState, tag: str, iround: Round, ivalue: str, ipol: Round,
                        ivalidity: bool, ivoter: Addr, ivtype: str, ikind: str): DRes = {
    val pvalue = if (ivalue == "Nil") "v" else ivalue
    if (tag == "NewRound") applyRound(d, RNewRound(iround), iround)
    else if (tag == "ProposeValue") applyRound(d, RProposeValue(pvalue), iround)
    else if (tag == "Proposal")
      applyProposal(d, { round: iround, value: pvalue, polRound: ipol }, ivalidity)
    else if (tag == "Vote")
      applyVote(d,
                { round: iround, voter: ivoter,
                  value: if (ivalue == "Nil") VNil else VVal(ivalue) },
                ivtype)
    else if (tag == "TimeoutElapsed")
      // The protocol has no prevote step, and the other kinds are not per-round.
      if (kindOf(ikind) == TPropose) applyRound(d, RTimeoutPropose, iround)
      else if (kindOf(ikind) == TPrecommit) applyRound(d, RTimeoutPrecommit, iround)
      else { d: d, outs: List(), tags: Set("timeout_kind_without_a_step_ignored"), bad: Set() }
    else applyRound(d, RWaitForValidExpired, d.rs.round)
  }

  //--------------------------------------------------------------------------
  // State
  //--------------------------------------------------------------------------

  pure val EMPTY_SM: SMState = {
    round: -1, step: Unstarted, valid: NoRV, decision: NoDec,
    awaiting_valid: false, scheduled: Set(), armedPrecommit: Set(),
  }

  pure val EMPTY_KV: KState =
    { votes: Set(), reachedQuorum: Set(), reachedDecision: Set(), reachedAny: Set() }

  pure def freshDriver(proposer: Addr): DState =
    { rs: EMPTY_SM, props: Map(), proposer: proposer, kv: EMPTY_KV }

  var d: DState
  /// The outputs the last call returned.
  var lastOutputs: List[DOut]
  /// How many outputs the last call returned — the conformance fact the
  /// instrumentation asserts against `process`'s real return value.
  var lastOutputCount: int
  /// The outcome classes the last call hit — what the observations read.
  var lastTags: Set[str]

  /// Ghost: the identifiers a proposal the application ACCEPTED ever carried.
  var validatedValues: Set[Value]
  /// Ghost: latched when a re-proposal was forwarded as justified without a
  /// 2f+1 recount backing it in the round the proposal named.
  var unjustifiedForwarded: bool
  /// Ghost: latched when a proposal the application rejected was retained.
  var retainedInvalid: bool
  /// Ghost: latched when a decision recorded a round other than the round of
  /// the fresh proposal that supplied the value.
  var decisionRoundWrong: bool
  /// Ghost: latched when a `Repropose` request produced no output at all.
  var silentRepropose: bool
  /// Ghost: latched when a round input derived from a keeper output was applied
  /// for a round other than the one the keeper reported.
  var keeperRoundDrifted: bool
  /// Ghost: latched when a recorded decision was changed.
  var decisionRevised: bool
  /// Ghost: latched when, at the END of a `process` call, some value held both
  /// an n-f decision quorum and a retained fresh proposal while nothing was
  /// decided — the second conjunct of L42 arrived and nothing fired.
  var pairedButUndecided: bool
  /// Ghost: the identifiers whose fresh proposal was retained THROUGH
  /// `Driver::process`. A proposal inserted by calling `FreshProposals::keep`
  /// directly is excluded: the code does not re-evaluate L42 on that path
  /// either, so counting it would report a bug the driver cannot commit.
  var processRetained: Set[Value]
  /// Ghost: latched when a non-precommit vote changed the keeper's tally.
  var prevoteTallied: bool

  action init = all {
    d' = freshDriver("b"),
    lastOutputs' = List(),
    lastOutputCount' = 0,
    lastTags' = Set(),
    validatedValues' = Set(),
    unjustifiedForwarded' = false,
    retainedInvalid' = false,
    decisionRoundWrong' = false,
    silentRepropose' = false,
    keeperRoundDrifted' = false,
    decisionRevised' = false,
    pairedButUndecided' = false,
    processRetained' = Set(),
    prevoteTallied' = false,
  }

  //--------------------------------------------------------------------------
  // Latch computations
  //--------------------------------------------------------------------------

  /// L42's symmetry, judged at the end of a driver call: both conjuncts persist,
  /// so a value that holds an n-f quorum AND a retained fresh proposal must have
  /// decided. The keeper never re-reports a latched threshold, so a miss here is
  /// permanent.
  pure def pairedAndUndecided(x: DState, retained: Set[Value]): bool =
    x.rs.decision == NoDec
      and retained.exists(v => x.props.keys().contains(v) and hasAnyDecisionQuorum(x.kv, v))

  pure def decisionChanged(pre: DState, post: DState): bool =
    pre.rs.decision != NoDec and post.rs.decision != pre.rs.decision

  //--------------------------------------------------------------------------
  // Actions
  //--------------------------------------------------------------------------

  /// Shared commit of one driver call.
  action commit(r: DRes, tallyGuarded: bool): bool = all {
    d' = r.d,
    lastOutputs' = r.outs,
    lastOutputCount' = r.outs.length(),
    lastTags' = r.tags,
    validatedValues' = validatedValues,
    unjustifiedForwarded' =
      (unjustifiedForwarded or r.bad.contains("unjustified_reproposal_forwarded")),
    retainedInvalid' = (retainedInvalid or r.bad.contains("retained_after_invalid_verdict")),
    decisionRoundWrong' =
      (decisionRoundWrong or r.bad.contains("decision_round_is_not_the_proposals")),
    silentRepropose' = (silentRepropose or r.bad.contains("silent_repropose")),
    keeperRoundDrifted' = (keeperRoundDrifted or r.bad.contains("keeper_round_drifted")),
    decisionRevised' = (decisionRevised or decisionChanged(d, r.d)),
    // L42 is re-evaluated only on the proposal and vote edges, so only
    // `Driverprocess` may latch the pairing.
    pairedButUndecided' = pairedButUndecided,
    processRetained' = processRetained.intersect(r.d.props.keys()),
    prevoteTallied' = (prevoteTallied or not(tallyGuarded)),
  }

  /// Driver::process(input) — the single entry point, routing NewRound /
  /// ProposeValue / Proposal / Vote / TimeoutElapsed / WaitForValidExpired.
  /// Call site: code/crates/core-driver/src/fast/driver.rs:111.
  /// Total: every branch returns, the ignored timeout kinds included.
  action Driverprocess(inputTag: str, iround: Round, ivalue: str, ipol: Round,
                       ivalidity: bool, ivoter: Addr, ivtype: str,
                       ikind: str): bool = {
    val r = processInput(d, inputTag, iround, ivalue, ipol, ivalidity, ivoter, ivtype, ikind)
    // A non-precommit vote must leave the tally untouched.
    val tallyGuarded =
      not(inputTag == "Vote" and ivtype != "Precommit") or r.d.kv == d.kv
    val newRetained =
      (if (r.tags.contains("fresh_proposal_retained"))
         processRetained.union(Set(if (ivalue == "Nil") "v" else ivalue))
       else processRetained).intersect(r.d.props.keys())
    all {
      d' = r.d,
      lastOutputs' = r.outs,
      lastOutputCount' = r.outs.length(),
      lastTags' = r.tags,
      validatedValues' =
        if (inputTag == "Proposal" and ivalidity and isNil(ipol))
          validatedValues.union(Set(if (ivalue == "Nil") "v" else ivalue))
        else validatedValues,
      unjustifiedForwarded' =
        (unjustifiedForwarded or r.bad.contains("unjustified_reproposal_forwarded")),
      retainedInvalid' = (retainedInvalid or r.bad.contains("retained_after_invalid_verdict")),
      decisionRoundWrong' =
        (decisionRoundWrong or r.bad.contains("decision_round_is_not_the_proposals")),
      silentRepropose' = (silentRepropose or r.bad.contains("silent_repropose")),
      keeperRoundDrifted' = (keeperRoundDrifted or r.bad.contains("keeper_round_drifted")),
      decisionRevised' = (decisionRevised or decisionChanged(d, r.d)),
      pairedButUndecided' =
        (pairedButUndecided or pairedAndUndecided(r.d, newRetained)),
      processRetained' = newRetained,
      prevoteTallied' = (prevoteTallied or not(tallyGuarded)),
    }
  }

  /// Driver::set_proposer(address) — sets the proposer for the round being
  /// entered. Unguarded.
  action Driverset_proposer(address: Addr): bool =
    commit({ d: { ...d, proposer: address }, outs: List(),
             tags: Set("proposer_set"), bad: Set() }, true)

  /// FreshProposals::keep(proposal) — retains a fresh proposal, reporting
  /// whether it was newly kept. Guarded by the code's two early returns: a
  /// re-proposal carries an identifier rather than a value, and the first fresh
  /// proposal for an identifier wins.
  action FreshProposalskeep(pround: Round, pvalue: Value, ppol: Round): bool = {
    val p = { round: pround, value: pvalue, polRound: ppol }
    all {
      keepAllowed(d.props, p),
      d' = { ...d, props: keepProp(d.props, p) },
      lastOutputs' = List(),
      lastOutputCount' = 0,
      lastTags' = Set(keepTag(d.props, p)),
      // The caller vouches for a proposal it hands straight to the store; the
      // application-validity gate lives in `Driver::apply_proposal`.
      validatedValues' = validatedValues.union(Set(pvalue)),
      unjustifiedForwarded' = unjustifiedForwarded,
      retainedInvalid' = retainedInvalid,
      decisionRoundWrong' = decisionRoundWrong,
      silentRepropose' = silentRepropose,
      keeperRoundDrifted' = keeperRoundDrifted,
      decisionRevised' = decisionRevised,
      pairedButUndecided' = pairedButUndecided,
      processRetained' = processRetained,
      prevoteTallied' = prevoteTallied,
    }
  }

  /// FreshProposals::clear() — forget everything, for use when the height
  /// changes. Deliberately not pruned by round.
  action FreshProposalsclear: bool =
    commit({ d: { ...d, props: Map() }, outs: List(),
             tags: Set("proposals_cleared"), bad: Set() }, true)

  /// Driver::new(ctx, height, validator_set, address, proposer) — the
  /// per-height constructor. Its whole payload is a parameter, so replay never
  /// searches for the baseline.
  action Drivernew(proposer: Addr): bool = all {
    d' = freshDriver(proposer),
    lastOutputs' = List(),
    lastOutputCount' = 0,
    lastTags' = Set("driver_constructed"),
    validatedValues' = Set(),
    unjustifiedForwarded' = unjustifiedForwarded,
    retainedInvalid' = retainedInvalid,
    decisionRoundWrong' = decisionRoundWrong,
    silentRepropose' = silentRepropose,
    keeperRoundDrifted' = keeperRoundDrifted,
    decisionRevised' = decisionRevised,
    pairedButUndecided' = pairedButUndecided,
    processRetained' = Set(),
    prevoteTallied' = prevoteTallied,
  }

  //--------------------------------------------------------------------------
  // step
  //--------------------------------------------------------------------------

  /// Values worth naming: the whole domain plus whatever we hold valid or have
  /// retained, so the branches that need a coincidence stay reachable.
  /// The identifier and round the L42 search arm concentrates on.
  pure val L42_VALUE: Value = "7"
  pure val L42_ROUND: Round = 0

  pure def focusValues(x: DState): Set[Value] =
    VALUES.union(x.props.keys())
          .union(match x.rs.valid { | NoRV => Set() | SomeRV(rv) => Set(rv.value_id) })

  action step = any {
    // Arm 1 — the replay-facing arm: every pick carries the name the
    // instrumentation logs, over the full domain, so a replayed event pins it.
    {
      nondet inputTag = ALL_TAGS.oneOf()
      nondet iround = ROUND_BAND.oneOf()
      nondet ivalue = VOTE_VALUES.oneOf()
      nondet ipol = ROUND_BAND.oneOf()
      nondet ivalidity = Set(false, true).oneOf()
      nondet ivoter = VOTERS.oneOf()
      nondet ivtype = VOTE_TYPES.oneOf()
      nondet ikind = KIND_NAMES.oneOf()
      Driverprocess(inputTag, iround, ivalue, ipol, ivalidity, ivoter, ivtype, ikind)
    },

    // Arm 2 — the SAME pick names, clustered around where the driver is: the
    // round it is at, the values it holds, precommits from real validators.
    // Pure search guidance; it never leaves a logged argument unpinned.
    {
      nondet inputTag = ALL_TAGS.oneOf()
      nondet iround = Set(d.rs.round, d.rs.round + 1).oneOf()
      nondet ivalue = focusValues(d).oneOf()
      nondet ipol = Set(-1, validRound(d.rs), d.rs.round - 1).oneOf()
      nondet ivalidity = Set(true).oneOf()
      nondet ivoter = VALIDATORS.oneOf()
      nondet ivtype = Set("Precommit").oneOf()
      nondet ikind = Set("Propose", "Precommit").oneOf()
      Driverprocess(inputTag, iround, ivalue, ipol, ivalidity, ivoter, ivtype, ikind)
    },

    // Arm 3 — the L42 arm, pure search guidance. n-f is FIVE distinct
    // validators voting for the SAME identifier in the SAME round, which a free
    // walk over three values, six voters and five rounds never stacks inside a
    // sampling budget. This arm fixes the identifier and the round and draws a
    // voter that has not yet voted there, so both arrival orders — quorum then
    // proposal, proposal then quorum — are reachable. Every pick keeps the name
    // the instrumentation logs; a replayed event that names other values simply
    // takes arm 1.
    {
      nondet inputTag = Set("Vote", "Proposal", "NewRound").oneOf()
      nondet ivalue = Set(L42_VALUE).oneOf()
      nondet ipol = Set(-1).oneOf()
      nondet ivalidity = Set(true).oneOf()
      nondet ivtype = Set("Precommit").oneOf()
      nondet ikind = Set("Propose").oneOf()
      nondet ivoter =
        VALIDATORS.filter(a => not(hasFirstVote(d.kv, L42_ROUND, a)))
                  .union(Set(ME)).oneOf()
      val iround =
        if (inputTag == "Vote") L42_ROUND
        else if (inputTag == "NewRound") d.rs.round + 1
        else d.rs.round
      Driverprocess(inputTag, iround, ivalue, ipol, ivalidity, ivoter, ivtype, ikind)
    },

    // Arm 3b — the QUORUM-FIRST lane. L42's two arrival orders are not equally
    // easy to walk into: a proposal for the identifier almost always lands
    // before the fifth vote, so the proposal edge — the order the code lost
    // entirely until the symmetric re-check was added — needs an arm that
    // withholds the proposal until the quorum is already latched.
    {
      nondet inputTag =
        (if (hasAnyDecisionQuorum(d.kv, L42_VALUE)) Set("Proposal") else Set("Vote")).oneOf()
      nondet ivalue = Set(L42_VALUE).oneOf()
      nondet ipol = Set(-1).oneOf()
      nondet ivalidity = Set(true).oneOf()
      nondet ivtype = Set("Precommit").oneOf()
      nondet ikind = Set("Propose").oneOf()
      nondet ivoter =
        VALIDATORS.filter(a => not(hasFirstVote(d.kv, L42_ROUND, a)))
                  .union(Set(ME)).oneOf()
      val iround = L42_ROUND
      Driverprocess(inputTag, iround, ivalue, ipol, ivalidity, ivoter, ivtype, ikind)
    },

    // Arm 4 — becoming the proposer. L15-L16's re-propose path is only reached
    // by the node that proposes the round it enters, so the walk has to pass
    // through here for `repropose_resolved_to_a_full_proposal` to exist.
    Driverset_proposer(ME),

    // The raw public operations, sharing an arm so `process` — what most
    // scenarios need — stays the likely choice.
    {
      nondet address = VALIDATORS.oneOf()
      nondet proposer = VALIDATORS.oneOf()
      nondet pround = ROUND_BAND.oneOf()
      nondet pvalue = VALUES.oneOf()
      nondet ppol = ROUND_BAND.oneOf()
      any {
        Driverset_proposer(address),
        FreshProposalskeep(pround, pvalue, ppol),
        FreshProposalsclear,
        Drivernew(proposer),
      }
    },
  }

  //--------------------------------------------------------------------------
  // Correctness properties — Algorithm 1 (arXiv:2608.13434)
  //--------------------------------------------------------------------------

  /// A re-proposal reaches the state machine as justified only when 2f+1 votes
  /// for that identifier exist in the round the proposal names.
  val justified_reproposal_needs_2f1_in_the_named_round: bool =
    not(unjustifiedForwarded)

  /// Whichever of the fresh proposal or the n-f quorum arrives second fires the
  /// decision, so no value ever holds both while nothing is decided.
  val l42_fires_on_whichever_arrives_second: bool = not(pairedButUndecided)

  /// A proposal the application rejected is never retained, so the decided
  /// value was carried by a proposal the application judged valid.
  val a_decided_value_was_judged_valid: bool =
    not(retainedInvalid)
      and match d.rs.decision {
            | NoDec => true
            | SomeDec(dd) => validatedValues.contains(dd.value)
          }

  /// A decision records the round of the fresh proposal that supplied the
  /// value, not the round of the quorum that decided it.
  val a_decision_carries_the_proposals_round: bool = not(decisionRoundWrong)

  /// A re-propose request yields either a proposal for that identifier or a
  /// propose timeout, never nothing.
  val a_repropose_request_is_never_silent: bool = not(silentRepropose)

  /// The round recorded as valid never exceeds the round the driver is at.
  val valid_never_records_a_round_above_our_own: bool =
    validRound(d.rs) <= d.rs.round

  /// Only precommits are tallied; a vote of any other type leaves the keeper
  /// unchanged.
  val only_precommits_are_tallied: bool = not(prevoteTallied)

  /// Every round input derived from a keeper output is applied for the round
  /// the keeper reported it for.
  val keeper_outputs_keep_their_reported_round: bool = not(keeperRoundDrifted)

  /// A decision is never changed once recorded.
  val a_decision_is_never_revised: bool = not(decisionRevised)

  /// Only fresh proposals are retained, so a re-proposal's identifier can never
  /// supply the payload of a decision.
  val only_fresh_proposals_are_retained: bool =
    d.props.keys().forall(v => isNil(d.props.get(v).polRound))

  //--------------------------------------------------------------------------
  // Observations — one per outcome class
  //--------------------------------------------------------------------------

  /// A re-proposal was forwarded to the state machine as justified.
  val reproposal_routed_as_justified: bool =
    lastTags.contains("reproposal_routed_as_justified")

  /// A re-proposal was refused the justification it named and routed as invalid.
  val reproposal_routed_as_unjustified: bool =
    lastTags.contains("reproposal_routed_as_unjustified")

  /// A fresh proposal the application accepted reached the state machine.
  val fresh_proposal_routed_valid: bool =
    lastTags.contains("fresh_proposal_routed_valid")

  /// A fresh proposal the application rejected reached the state machine as
  /// InvalidProposal.
  val fresh_proposal_routed_invalid: bool =
    lastTags.contains("fresh_proposal_routed_invalid")

  /// A proposal the application rejected was not retained.
  val invalid_proposal_not_retained: bool =
    lastTags.contains("invalid_proposal_not_retained")

  /// A fresh proposal for an identifier already held was not kept again.
  val duplicate_fresh_proposal_not_rekept: bool =
    lastTags.contains("duplicate_fresh_proposal_not_rekept")

  /// A re-proposal was not retained: it carries an identifier, not a value.
  val reproposal_not_retained: bool = lastTags.contains("reproposal_not_retained")

  /// The decision fired on the proposal edge: the quorum was already held and
  /// the proposal completed the rule.
  val decision_fired_on_the_proposal_edge: bool =
    lastTags.contains("decision_fired_on_the_proposal_edge")

  /// The decision fired on the vote edge: the proposal was already retained and
  /// the quorum completed the rule.
  val decision_fired_on_the_vote_edge: bool =
    lastTags.contains("decision_fired_on_the_vote_edge")

  /// An n-f quorum was reported for a value with no retained proposal, so the
  /// decision waited.
  val decision_quorum_waited_for_its_proposal: bool =
    lastTags.contains("decision_quorum_waited_for_its_proposal")

  /// A re-propose request was resolved back into a full-value proposal.
  val repropose_resolved_to_a_full_proposal: bool =
    lastTags.contains("repropose_resolved_to_a_full_proposal")

  /// A re-propose request named an identifier whose fresh proposal was never
  /// seen, so a propose timeout went out instead — the driver's known
  /// divergence from L15-L16.
  val repropose_value_missing: bool = lastTags.contains("repropose_value_missing")

  /// A timeout of a kind this protocol has no step for was ignored.
  val timeout_kind_without_a_step_ignored: bool =
    lastTags.contains("timeout_kind_without_a_step_ignored")

  /// The L42 re-check was skipped because the driver had already decided.
  val l42_skipped_because_already_decided: bool =
    lastTags.contains("l42_skipped_because_already_decided")

  /// A prevote reached the keeper and was discarded.
  val prevote_discarded_by_the_keeper: bool =
    lastTags.contains("prevote_discarded_by_the_keeper")

  /// A second, conflicting vote from a validator already counted was not
  /// tallied.
  val equivocating_vote_not_tallied: bool =
    lastTags.contains("equivocating_vote_not_tallied")

  /// A vote from an address outside the validator set was discarded.
  val vote_from_a_non_validator_discarded: bool =
    lastTags.contains("vote_from_a_non_validator_discarded")

  /// A fresh proposal was retained for later resolution.
  val fresh_proposal_retained: bool = lastTags.contains("fresh_proposal_retained")
}
