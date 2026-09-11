// Model of the Fast Tendermint per-round state machine (`n > 5f`) —
// `fast::state_machine::apply(ctx, state, info, input) -> Transition`.
//
// Code under model:
//   code/crates/core-state-machine/src/fast/state_machine.rs  (apply + start_round/propose_now/vote)
//   code/crates/core-state-machine/src/fast/state.rs          (State, RoundValueId, ScheduledTimeouts, Step)
//   code/crates/core-state-machine/src/fast/input.rs, output.rs
//
// ACTIONS, ARGUMENTS and OBSERVATIONS mirror the Rust — that is what the oracle
// replays. The PROPERTIES are derived from Algorithm 1 of Vander Vos & Cason,
// "Fast Tendermint" (arXiv:2608.13434), NOT from the implementation: the code is
// a hand transcription written alongside its own tests, so a property read off
// the code would only prove the code equals itself. Where a paper-derived
// property is violated, that is a finding to report, not something to model
// around.
//
// The paper's L45-L48 bounded busy-wait is represented by the code as
// `awaiting_valid` plus a synthetic `WaitForValidExpired` input. That
// representation is modelled as the code has it and NO property is stated over
// it — a property about `awaiting_valid` would test the representation against
// itself. Its faithfulness is the open question of this change.
module fast_round_state_machine {

  //--------------------------------------------------------------------------
  // Domain
  //--------------------------------------------------------------------------

  /// Round::Nil is modelled as -1; Round::Some(r) as r >= 0. This matches the
  /// `as_i64()` projection start_round uses for the L46 comparison.
  type Round = int
  type Value = str
  type Addr = str

  /// A Ctx::Proposal: its own round, the value, and its `pol_round` (the paper's `vr`).
  type Prop = { round: Round, value: Value, polRound: Round }

  /// state.rs Step — one voting step, named precommit (paper L2).
  type Step = Unstarted | Propose | Precommit | Commit

  /// state.rs RoundValueId: the paper's `valid_p = (round, id(value))` (L4).
  type RoundValueId = { round: Round, value_id: Value }

  /// Option[RoundValueId] for state.valid. NoRV is the paper's `(-1, nil)`.
  type MaybeRV = NoRV | SomeRV(RoundValueId)

  /// Option[(Round, Ctx::Value)] for state.decision.
  type MaybeDec = NoDec | SomeDec({ round: Round, value: Value })

  /// core_types::NilOrVal<ValueId>
  type NilOrVal = VNil | VVal(Value)

  /// core_types::TimeoutKind. Only Propose and Precommit are per-round here;
  /// the other three exist so ScheduledTimeouts::mask's `None` arm is reachable.
  type TimeoutKind = TPropose | TPrecommit | TPrevote | TRebroadcast | TFinalizeHeight

  /// The kind carried on a Vote output. The protocol has ONE voting step, so
  /// `Output::vote` must always build a precommit — carrying the kind
  /// explicitly is what keeps that property falsifiable rather than true by
  /// construction.
  type VoteKind = KPrevote | KPrecommit

  /// input.rs Input<Ctx>. NoInput is the model's idle placeholder at init.
  type Input =
    | NoInput
    | NewRound(Round)
    | ProposeValue(Value)
    | Proposal(Prop)
    | InvalidProposal
    | ProposalAndVoteQuorumPrevious(Prop)
    | InvalidProposalAndVoteQuorumPrevious(Prop)
    | VoteQuorumForValue({ round: Round, value_id: Value })
    | QuorumAny(Round)
    | ProposalAndDecisionQuorum(Prop)
    | TimeoutPropose
    | TimeoutPrecommit
    | WaitForValidExpired

  /// output.rs Output<Ctx>; ONone models `Transition.output == None`.
  type Output =
    | ONone
    | ONewRound(Round)
    | OProposal(Prop)
    | OVote({ kind: VoteKind, value: NilOrVal })
    | OScheduleTimeout({ round: Round, kind: TimeoutKind })
    | OGetValueAndScheduleTimeout({ round: Round, kind: TimeoutKind })
    | OWaitForValid({ round: Round, kind: TimeoutKind })
    | ORepropose({ value_id: Value, valid_round: Round })
    | ODecision({ round: Round, value: Value })

  /// state_machine.rs Info<'a, Ctx>
  type Info = { input_round: Round, address: Addr, proposer: Addr }

  /// state.rs State<Ctx>. Height is fixed — this component is per-height.
  type SMState = {
    round: Round,
    step: Step,
    valid: MaybeRV,
    decision: MaybeDec,
    awaiting_valid: bool,
    scheduled: Set[TimeoutKind],
    /// state.rs `armed_precommit_rounds`: the rounds whose L39 precommit timeout
    /// has been armed. Kept per round rather than in `scheduled`, because L39
    /// arms the timeout for the QUORUM's round, which may be above ours — the
    /// per-round bit would let a quorum for round 0 consume the only slot and
    /// leave round 1's timeout unarmed forever. It is per height, so a round
    /// change does not clear it.
    armedPrecommit: Set[Round],
  }

  /// The result of one `apply`: FastTransition plus the L-line tag.
  type Result = { st: SMState, out: Output, ok: bool, line: str }

  //--------------------------------------------------------------------------
  // Domains for the nondet picks
  //--------------------------------------------------------------------------

  /// The value ids the model reasons about: three abstract symbols, plus every
  /// concrete `ValueId` the fast-round test suite produces, rendered the way the
  /// code renders it (`ValueId`'s Display is lower-case hex).
  pure val VALUES: Set[Value] =
    Set("v", "w", "x", "1", "2", "5", "7", "8", "9", "2a", "4d", "63")
  pure val ADDRS: Set[Addr] = Set("a", "b")
  pure val ME: Addr = "a"

  /// Every round-shaped pick draws from here. -1 (Round::Nil) and rounds at or
  /// above the current round are deliberately included so `!vr.is_defined()`,
  /// `vr >= state.round` and a stale `input_round` all stay falsifiable.
  pure val ROUND_BAND: Set[Round] = Set(-1, 0, 1, 2, 3, 4, 5)

  pure val TIMEOUT_KINDS: Set[TimeoutKind] =
    Set(TPropose, TPrecommit, TPrevote, TRebroadcast, TFinalizeHeight)

  pure val STEPS: Set[Step] = Set(Unstarted, Propose, Precommit, Commit)

  /// The input constructors, selected by tag so one pick names the variant and
  /// the payload picks stay independently pinnable from logged arguments.
  pure val ALL_TAGS: Set[str] =
    Set("NewRound", "ProposeValue", "Proposal", "InvalidProposal",
        "ProposalAndVoteQuorumPrevious", "InvalidProposalAndVoteQuorumPrevious",
        "VoteQuorumForValue", "QuorumAny", "ProposalAndDecisionQuorum",
        "TimeoutPropose", "TimeoutPrecommit", "WaitForValidExpired")

  pure def mkInput(tag: str, p: Prop, v: Value, r: Round): Input =
    if (tag == "NewRound") NewRound(r)
    else if (tag == "ProposeValue") ProposeValue(v)
    else if (tag == "Proposal") Proposal(p)
    else if (tag == "InvalidProposal") InvalidProposal
    else if (tag == "ProposalAndVoteQuorumPrevious") ProposalAndVoteQuorumPrevious(p)
    else if (tag == "InvalidProposalAndVoteQuorumPrevious") InvalidProposalAndVoteQuorumPrevious(p)
    else if (tag == "VoteQuorumForValue") VoteQuorumForValue({ round: p.round, value_id: v })
    else if (tag == "QuorumAny") QuorumAny(r)
    else if (tag == "ProposalAndDecisionQuorum") ProposalAndDecisionQuorum(p)
    else if (tag == "TimeoutPropose") TimeoutPropose
    else if (tag == "TimeoutPrecommit") TimeoutPrecommit
    else WaitForValidExpired

  /// The four `Step` names, as the instrumentation renders them.
  pure val STEP_NAMES: Set[str] = Set("Unstarted", "Propose", "Precommit", "Commit")

  /// The ScheduledTimeouts bitset, as the two bits state.rs uses.
  pure val SCHEDULED_BITS: Set[int] = Set(0, 1, 2, 3)

  /// Rebuild the `State<Ctx>` a call to `apply` was handed, from the fields the
  /// instrumentation logs. `apply` is a pure function of (state, info, input),
  /// and callers — the test suite above all — hand it states they built
  /// themselves, so the state it operates on is a PARAMETER of the transition,
  /// not something the model can track on its own.
  ///
  /// `svround` / `sdround` of -1 mean "nothing valid" / "nothing decided":
  /// `set_valid` is only ever called with a real round, and a decision always
  /// carries the round of the proposal it came from.
  pure def mkPre(sround: Round, sstep: str, svround: Round, svalue: Value,
                 sdround: Round, sdvalue: Value, sawaiting: bool,
                 sscheduled: int, sarmed: int): SMState = {
    round: sround,
    step:
      if (sstep == "Unstarted") Unstarted
      else if (sstep == "Propose") Propose
      else if (sstep == "Precommit") Precommit
      else Commit,
    valid: if (svround >= 0) SomeRV({ round: svround, value_id: svalue }) else NoRV,
    decision: if (sdround >= 0) SomeDec({ round: sdround, value: sdvalue }) else NoDec,
    awaiting_valid: sawaiting,
    scheduled:
      (if (sscheduled == 1 or sscheduled == 3) Set(TPropose) else Set())
        .union(if (sscheduled >= 2) Set(TPrecommit) else Set()),
    armedPrecommit: ROUND_BAND.filter(r => armedBitSet(sarmed, r)),
  }

  /// `armed_precommit_rounds` travels as a bitmask over ROUND_BAND: bit 0 is
  /// round -1, bit i+1 is round i. Only rounds in the band are represented; a
  /// round armed outside it would fail replay loudly rather than pass wrongly.
  pure def armedBit(r: Round): int = 2^(r + 1)

  pure def armedBitSet(mask: int, r: Round): bool =
    mask / armedBit(r) % 2 == 1

  pure def armedMaskOf(s: SMState): int =
    ROUND_BAND.fold(0, (acc, r) => if (s.armedPrecommit.contains(r)) acc + armedBit(r) else acc)

  /// The reverse: the bitset of a state, for the continuity arm of `step`.
  pure def bitsOf(s: SMState): int =
    (if (s.scheduled.contains(TPropose)) 1 else 0)
      + (if (s.scheduled.contains(TPrecommit)) 2 else 0)

  pure def stepNameOf(s: SMState): str =
    match s.step {
      | Unstarted => "Unstarted"
      | Propose => "Propose"
      | Precommit => "Precommit"
      | Commit => "Commit"
    }

  //--------------------------------------------------------------------------
  // Pure queries — state.rs / state_machine.rs accessors
  //--------------------------------------------------------------------------

  /// state.rs State::valid_round(): Round::Nil when nothing is valid.
  pure def validRound(s: SMState): Round =
    match s.valid { | NoRV => -1 | SomeRV(rv) => rv.round }

  /// state.rs State::valid_is(value_id).
  pure def validIs(s: SMState, v: Value): bool =
    match s.valid { | NoRV => false | SomeRV(rv) => rv.value_id == v }

  pure def validIsNone(s: SMState): bool =
    match s.valid { | NoRV => true | SomeRV(_) => false }

  /// state_machine.rs Info::is_proposer().
  pure def isProposer(i: Info): bool = i.address == i.proposer

  /// Round::is_defined() — Round::Nil (-1) is not defined.
  pure def isDefined(r: Round): bool = r >= 0

  /// Round::is_nil()
  pure def isNil(r: Round): bool = r < 0

  /// state.rs ScheduledTimeouts::mask — only two kinds are tracked per round.
  pure def isTracked(k: TimeoutKind): bool = k == TPropose or k == TPrecommit

  /// state.rs ScheduledTimeouts::check — records the kind and reports whether
  /// it was NEWLY recorded. Untracked kinds are silently denied.
  pure def checkTimeout(s: SMState, k: TimeoutKind): bool =
    isTracked(k) and not(s.scheduled.contains(k))

  pure def recordTimeout(s: SMState, k: TimeoutKind): SMState =
    if (isTracked(k)) { ...s, scheduled: s.scheduled.union(Set(k)) } else s

  /// state.rs ScheduledTimeouts::clear()
  pure def clearTimeouts(s: SMState): SMState = { ...s, scheduled: Set() }

  /// state.rs State::update_round(round): moves round, clears the per-round
  /// bookkeeping. `valid` and `decision` are per-height and survive.
  ///
  /// The bits are cleared only when the round actually CHANGES. Clearing
  /// unconditionally re-armed a round we are already in — `apply` accepts
  /// `NewRound(r)` whenever `state.round <= r` — which defeated the
  /// at-most-once guard in `check_timeout` and made the L18 suppression branch
  /// dead code.
  pure def updateRound(s: SMState, r: Round): SMState =
    if (s.round != r) { ...s, round: r, scheduled: Set() } else s

  /// state.rs State::arm_precommit_timeout(round) — true the first time it is
  /// called for a round.
  pure def armPrecommit(s: SMState, r: Round): bool = not(s.armedPrecommit.contains(r))

  pure def recordArmed(s: SMState, r: Round): SMState =
    { ...s, armedPrecommit: s.armedPrecommit.union(Set(r)) }

  /// state.rs State::with_step(step).
  ///
  /// Refuses to leave `Commit`: a decided round is terminal, and letting a
  /// caller step back out of it is what allowed a finalized decision to be
  /// overwritten. The guard lives on the builder so it holds for every caller.
  pure def withStep(s: SMState, st: Step): SMState =
    if (s.step == Commit) s else { ...s, step: st }

  /// state.rs State::set_valid(round, value_id) — monotone: a no-op unless the
  /// new round is strictly above the recorded one.
  pure def setValid(s: SMState, r: Round, v: Value): SMState =
    if (validRound(s) < r) { ...s, valid: SomeRV({ round: r, value_id: v }) } else s

  /// state.rs State::set_decision(proposal_round, value).
  ///
  /// Write-once. A second call is a no-op: a height decides at most one value
  /// and the paper treats `decision_p` as a latch (L56 reads it as one).
  pure def setDecision(s: SMState, r: Round, v: Value): SMState =
    if (s.decision != NoDec) s else { ...s, decision: SomeDec({ round: r, value: v }) }

  /// output.rs Output::vote(..) — ALWAYS a precommit; the protocol has one
  /// voting step. The kind is carried explicitly so that stays checkable.
  pure def voteOutput(v: NilOrVal): Output = OVote({ kind: KPrecommit, value: v })

  /// output.rs Output::schedule_timeout(round, kind)
  pure def scheduleTimeout(r: Round, k: TimeoutKind): Output =
    OScheduleTimeout({ round: r, kind: k })

  //--------------------------------------------------------------------------
  // The transition function — state_machine.rs
  //--------------------------------------------------------------------------

  /// L22/L24/L31/L33/L52. Cast this round's single vote and move to the voting step.
  pure def vote(s: SMState, v: NilOrVal, line: str): Result =
    { st: withStep(s, Precommit), out: voteOutput(v), ok: true, line: line }

  /// L12-L16. Re-propose the identifier we hold valid, or ask the application
  /// for a fresh value.
  pure def proposeNow(s0: SMState): Result = {
    val s = { ...s0, awaiting_valid: false }
    match s.valid {
      | SomeRV(rv) =>
          { st: s,
            out: ORepropose({ value_id: rv.value_id, valid_round: rv.round }),
            ok: true, line: "L15Repropose" }
      | NoRV =>
          { st: s,
            out: OGetValueAndScheduleTimeout({ round: s.round, kind: TPropose }),
            ok: true, line: "L13GetValue" }
    }
  }

  /// L6-L18. Enter `round`.
  pure def startRound(s0: SMState, i: Info, round: Round): Result = {
    val s1 = withStep(updateRound(s0, round), Propose)
    if (not(isProposer(i)))
      // L18: a non-proposer arms the propose timeout.
      if (checkTimeout(s1, TPropose))
        { st: recordTimeout(s1, TPropose),
          out: scheduleTimeout(round, TPropose),
          ok: true, line: "L18ProposeTimeoutScheduled" }
      else
        { st: s1, out: ONone, ok: true, line: "L18ProposeTimeoutSuppressed" }
    else
      // L10-L11/L46: a proposer of a round above 0 that has not learned valid
      // from the round below waits first.
      if (round > 0 and validRound(s1) < round - 1)
        { st: { ...s1, awaiting_valid: true },
          out: OWaitForValid({ round: round, kind: TPrecommit }),
          ok: true, line: "L11WaitForValid" }
      else
        proposeNow(s1)
  }

  /// state_machine.rs apply(ctx, state, info, input).
  pure def applyInput(s: SMState, i: Info, input: Input): Result = {
    val thisRound = s.round == i.input_round
    match input {
      // L6-L18: start a round.
      //
      // The step guard matters: Algorithm 1 only ever calls StartRound(round+1),
      // so re-entering the round we are already in never happens. Without it, a
      // NewRound for the current round resets Precommit back to Propose and the
      // node can cast a SECOND vote in that round — equivocating against itself.
      | NewRound(r) =>
          if (s.step == Unstarted and s.round <= r) startRound(s, i, r)
          else if (s.round < r) startRound(s, i, r)
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L13/L16: the application produced a value and we are the proposer.
      | ProposeValue(v) =>
          if (s.step == Propose and thisRound and isProposer(i) and not(s.awaiting_valid))
            { st: s,
              out: OProposal({ round: s.round, value: v, polRound: -1 }),
              ok: true, line: "L13Propose" }
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L20-L25: a fresh proposal. Vote for it when nothing binds us, or when
      // it re-offers the identifier we already hold valid.
      | Proposal(p) =>
          if (s.step == Propose and thisRound and isNil(p.polRound))
            if (validIsNone(s) or validIs(s, p.value))
              vote(s, VVal(p.value),
                   if (validIsNone(s)) "L22VoteUnbound" else "L22VoteMatchesValid")
            else vote(s, VNil, "L21VoteNilBound")
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L23-L24: the value failed validation.
      | InvalidProposal =>
          if (s.step == Propose and thisRound) vote(s, VNil, "L24VoteNilInvalid")
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L27-L34: a re-proposal justified by 2f+1 votes from round `vr`.
      | ProposalAndVoteQuorumPrevious(p) =>
          if (s.step == Propose and thisRound)
            if (not(isDefined(p.polRound)) or p.polRound >= s.round)
              { st: s, out: ONone, ok: false, line: "L27MalformedValidRound" }
            else if (validRound(s) <= p.polRound or validIs(s, p.value)) {
              // L29-L30. Note `<=`: at equality the paper REPLACES the value it
              // holds. With n > 5f two 2f+1 quorums need not intersect
              // (2(2f+1) - (5f+1) = 1-f <= 0), so two different values can each
              // hold a quorum in the same round vr. `set_valid` is monotone and
              // no-ops at equality, so the code writes `valid` directly here.
              val s2 =
                if (validRound(s) <= p.polRound)
                  { ...s, valid: SomeRV({ round: p.polRound, value_id: p.value }) }
                else s
              vote(s2, VVal(p.value),
                   if (validRound(s) <= p.polRound) "L30ReproposalAcceptedRaised"
                   else "L30ReproposalAcceptedSameId")
            } else vote(s, VNil, "L28VoteNilStaleJustification")
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L33: the justification or the value was rejected.
      | InvalidProposalAndVoteQuorumPrevious(_) =>
          if (s.step == Propose and thisRound) vote(s, VNil, "L33VoteNilInvalidReproposal")
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L36-L37 and L47-L48: the observation rule. 2f+1 votes for a value in ANY
      // round above the one we hold valid raise `valid`. The round is carried on
      // the input rather than assumed to be ours: a proposer inside WaitForValid
      // sits at round_p while the quorum that ends its wait is for round_p - 1
      // (L46), so gating on the current round would make L47 unreachable and
      // force every wait to burn its full timeout.
      | VoteQuorumForValue(q) => {
          val raised = validRound(s) < q.round
          val s2 = setValid(s, q.round, q.value_id)
          if (not(raised)) { st: s2, out: ONone, ok: false, line: "L36NotRaised" }
          else if (s2.awaiting_valid and isProposer(i)) {
            val r = proposeNow(s2)
            { ...r, line: "L48WaitResolvedRepropose" }
          } else { st: s2, out: ONone, ok: true, line: "L37SetValid" }
        }

      // L39-L40: n - f votes for any value at a round at or above ours.
      // L39 latches per r ("for the first time with r >= round_p"), and the
      // timeout scheduled is for r, which may be ABOVE the round we are at.
      // Using the per-round bit would let a quorum for round 0 consume the only
      // slot and leave round 1's timeout unarmed forever.
      | QuorumAny(r) =>
          if (r >= s.round)
            if (armPrecommit(s, r))
              { st: recordArmed(s, r),
                out: scheduleTimeout(r, TPrecommit),
                ok: true, line: "L40PrecommitTimeoutScheduled" }
            else { st: s, out: ONone, ok: false, line: "L40PrecommitTimeoutSuppressed" }
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L42-L43: decide. Only a FRESH proposal establishes validity; its round
      // may differ from ours and from the votes'.
      //
      // The guard is on `decision`, NOT on the step: `NewRound` resets the step
      // to Propose while carrying the decision forward, so a step-only guard let
      // a second quorum overwrite a finalized value — two different values
      // decided at one height.
      | ProposalAndDecisionQuorum(p) =>
          if (s.decision == NoDec)
            if (not(isNil(p.polRound)))
              { st: s, out: ONone, ok: false, line: "L42ReproposalCannotDecide" }
            else
              { st: withStep(setDecision(s, p.round, p.value), Commit),
                out: ODecision({ round: p.round, value: p.value }),
                ok: true, line: "L43Decide" }
          else { st: s, out: ONone, ok: false, line: "CommitTerminal" }

      // L50-L53: no proposal arrived in time.
      | TimeoutPropose =>
          if (s.step == Propose and thisRound) vote(s, VNil, "L52VoteNilProposeTimeout")
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L46: the proposer's bounded wait ran out; propose with whatever we have.
      | WaitForValidExpired =>
          if (s.step == Propose and thisRound and s.awaiting_valid and isProposer(i)) {
            val r = proposeNow(s)
            { ...r, line: "L46WaitExpiredPropose" }
          } else { st: s, out: ONone, ok: false, line: "NoArm" }

      // L55-L57: give up on this round.
      | TimeoutPrecommit =>
          if (i.input_round >= s.round and s.decision == NoDec)
            { st: s, out: ONewRound(i.input_round + 1), ok: true, line: "L57NewRound" }
          else { st: s, out: ONone, ok: false, line: "NoArm" }

      | NoInput => { st: s, out: ONone, ok: false, line: "NoArm" }
    }
  }

  //--------------------------------------------------------------------------
  // Paper-derived rule recomputations (Algorithm 1, arXiv:2608.13434)
  //
  // These NEVER call applyInput. Each recomputes what the paper requires of a
  // transition and compares it with what the code produced, so a property can
  // fail when the transcription disagrees with the algorithm.
  //--------------------------------------------------------------------------

  /// L21. On a fresh proposal delivered for the current round in the propose
  /// step, the paper votes for id(v) iff valid_p.round = -1 or valid_p.value =
  /// id(v), and nil otherwise.
  pure def paperBindingVote(pre: SMState, p: Prop): NilOrVal =
    if (validRound(pre) == -1 or validIs(pre, p.value)) VVal(p.value) else VNil

  /// L27-L28. A re-proposal is applicable only when vr is a real earlier round
  /// of this height, and is then accepted iff valid_p.round <= vr or
  /// valid_p.value = id(v).
  pure def paperReproposalApplicable(pre: SMState, p: Prop): bool =
    isDefined(p.polRound) and p.polRound < pre.round

  pure def paperReproposalAccepted(pre: SMState, p: Prop): bool =
    validRound(pre) <= p.polRound or validIs(pre, p.value)

  /// L39-L40, L55-L57. The paper has no f+1 rule: these are the only inputs
  /// that may produce a round-advancing effect.
  pure def mayAdvanceRound(input: Input): bool =
    match input {
      | QuorumAny(_) => true
      | TimeoutPrecommit => true
      | NewRound(_) => true
      | _ => false
    }

  /// An output that moves, or arms the move to, a later round.
  pure def isRoundAdvancingOutput(o: Output): bool =
    match o {
      | ONewRound(_) => true
      | OScheduleTimeout(t) => t.kind == TPrecommit
      | _ => false
    }

  /// L18/L40: a per-round timeout is armed at most once per round.
  ///
  /// Stated PER TRANSITION, against the pre-state `apply` was handed: a
  /// `ScheduleTimeout` may only be emitted when that kind was not already
  /// recorded for the round the state stays in. A run-wide set of emitted
  /// (round, kind) pairs would be unsound here — each step may begin from an
  /// unrelated caller-built state, so two legitimate first-arms of round 0 in
  /// different states would collide.
  ///
  /// Only `OScheduleTimeout` is covered: the code emits it solely from the two
  /// `check_timeout`-guarded sites (L18 and L40). `GetValueAndScheduleTimeout`
  /// and `WaitForValid` are emitted unconditionally and are not guarded by the
  /// bitset at all.
  /// The timeout kinds THIS transition armed — exactly the one its
  /// `ScheduleTimeout` output names, since that output is emitted only when
  /// `check_timeout` granted the bit.
  pure def armedBy(o: Output): Set[TimeoutKind] =
    match o { | OScheduleTimeout(t) => Set(t.kind) | _ => Set() }

  /// L6/L18: entering a new round clears the previous round's timeout
  /// bookkeeping, so after a round change the scheduled set holds nothing
  /// beyond what this very transition armed.
  ///
  /// Comparing against `pre.scheduled` would be wrong: a round change clears
  /// the bits and the new round may immediately arm the SAME kind, which is
  /// indistinguishable from a bit that survived. Comparing against what the
  /// transition armed is not.
  pure def staleBitsSurvived(pre: SMState, r: Result): bool =
    r.st.round != pre.round and not(r.st.scheduled.subseteq(armedBy(r.out)))

  pure def timeoutRearmed(pre: SMState, r: Result): bool =
    match r.out {
      | OScheduleTimeout(t) => r.st.round == pre.round and pre.scheduled.contains(t.kind)
      | _ => false
    }

  /// The (round, kind) a timeout-bearing output claims, if any. Kept for trace
  /// readability; the at-most-once claim is `timeoutRearmed` above.
  pure def timeoutKeyOf(o: Output): Set[(Round, TimeoutKind)] =
    match o {
      | OScheduleTimeout(t) => Set((t.round, t.kind))
      | OGetValueAndScheduleTimeout(t) => Set((t.round, t.kind))
      | OWaitForValid(t) => Set((t.round, t.kind))
      | _ => Set()
    }

  //--------------------------------------------------------------------------
  // State
  //--------------------------------------------------------------------------

  pure val initial_state: SMState = {
    round: -1,
    step: Unstarted,
    valid: NoRV,
    decision: NoDec,
    awaiting_valid: false,
    scheduled: Set(),
    armedPrecommit: Set(),
  }

  var state: SMState
  /// The Transition's output.
  var output: Output
  /// The Transition's `valid` flag.
  var lastValid: bool
  /// Ghost: the L-line taken by the last transition.
  var lastLine: str
  /// Ghost: the state `apply` was last called on.
  var prev: SMState
  /// Ghost: the input of the last transition.
  var lastInput: Input
  /// Ghost: the `info.input_round` of the last transition.
  var lastInfoRound: Round
  /// Ghost: the highest round ever recorded in `valid`.
  var maxValidRound: Round
  /// Ghost: the first decision ever recorded.
  var firstDecision: MaybeDec
  /// Ghost: (round, kind) pairs a timeout output has already claimed.
  var emittedTimeouts: Set[(Round, TimeoutKind)]
  /// Ghost: latched when a timeout output repeats a (round, kind).
  var duplicateTimeout: bool
  /// Ghost: latched when a scheduled bit survived a round change.
  var staleTimeoutBits: bool
  /// Ghost: latched when the L21 binding rule was broken.
  var bindingRuleBroken: bool
  /// Ghost: latched when the L28 re-proposal rule was broken.
  var reproposalRuleBroken: bool
  /// Ghost: latched when a decision was not established by a fresh proposal.
  var decisionRuleBroken: bool
  /// Ghost: latched when the round advanced, or a round-advancing output was
  /// emitted, on an input the paper does not allow it for.
  var illegalRoundAdvance: bool
  /// Ghost: latched when an emitted vote was not a precommit.
  var nonPrecommitVote: bool
  /// Ghost: latched when `valid` fell.
  var validDecreased: bool
  /// Ghost: latched when a Repropose named something we did not hold.
  var reproposedWithoutValid: bool
  /// Ghost: latched when a transition of `apply` changed an already-recorded
  /// decision, or recorded one from the terminal Commit step.
  var decisionFinalityBroken: bool

  action init = all {
    state' = initial_state,
    output' = ONone,
    lastValid' = true,
    lastLine' = "init",
    prev' = initial_state,
    lastInput' = NoInput,
    lastInfoRound' = -1,
    maxValidRound' = -1,
    firstDecision' = NoDec,
    emittedTimeouts' = Set(),
    duplicateTimeout' = false,
    staleTimeoutBits' = false,
    bindingRuleBroken' = false,
    reproposalRuleBroken' = false,
    decisionRuleBroken' = false,
    illegalRoundAdvance' = false,
    nonPrecommitVote' = false,
    validDecreased' = false,
    reproposedWithoutValid' = false,
    decisionFinalityBroken' = false,
  }

  //--------------------------------------------------------------------------
  // Latch computations — the paper's rules judged against one transition
  //--------------------------------------------------------------------------

  /// L21: did the fresh-proposal vote match what Algorithm 1 requires?
  pure def bindingBroken(pre: SMState, i: Info, input: Input, r: Result): bool =
    match input {
      | Proposal(p) =>
          pre.step == Propose and pre.round == i.input_round and isNil(p.polRound)
            and (r.out != voteOutput(paperBindingVote(pre, p)))
      | _ => false
    }

  /// L27-L28: applicability and the acceptance condition, plus the L30 raise.
  pure def reproposalBroken(pre: SMState, i: Info, input: Input, r: Result): bool =
    match input {
      | ProposalAndVoteQuorumPrevious(p) =>
          if (not(pre.step == Propose and pre.round == i.input_round)) false
          else if (not(paperReproposalApplicable(pre, p)))
            // A malformed justification must not apply and must change nothing.
            r.ok or r.st != pre
          else if (paperReproposalAccepted(pre, p))
            // Accepted: vote for the identifier and hold it valid at vr or above.
            r.out != voteOutput(VVal(p.value))
              or not(r.ok)
              or validRound(r.st) < p.polRound
          else
            // Refused: vote nil, and nothing about valid moves.
            r.out != voteOutput(VNil) or r.st.valid != pre.valid
      | _ => false
    }

  /// L42-L43: a decision is established only by a fresh proposal, and carries
  /// THAT proposal's round and value — which the paper lets differ from ours.
  pure def decisionBroken(pre: SMState, input: Input, r: Result): bool =
    if (r.st.decision == pre.decision) false
    else
      match input {
        | ProposalAndDecisionQuorum(p) =>
            not(isNil(p.polRound))
              or r.st.decision != SomeDec({ round: p.round, value: p.value })
        | _ => true
      }

  /// L39-L40 / L55-L57: the only round-advancing paths the paper has.
  pure def roundAdvanceBroken(pre: SMState, input: Input, r: Result): bool =
    (r.st.round != pre.round or isRoundAdvancingOutput(r.out))
      and not(mayAdvanceRound(input))

  /// L15-L16: a Repropose names exactly the pair the machine holds valid.
  ///
  /// Judged against the POST-state: L36-L37 raises `valid_p` and, when the
  /// proposer is still waiting, L48 re-proposes the just-raised pair in the same
  /// transition. Comparing against the pre-state would flag that legal path.
  pure def reproposeBroken(r: Result): bool =
    match r.out {
      | ORepropose(rp) =>
          match r.st.valid {
            | NoRV => true
            | SomeRV(rv) => rp.value_id != rv.value_id or rp.valid_round != rv.round
          }
      | _ => false
    }

  /// L43/L56: once decided, Algorithm 1 never revisits the decision, and the
  /// Commit step records no further one.
  pure def decisionFinalityBrokenBy(pre: SMState, r: Result): bool =
    (pre.decision != NoDec and r.st.decision != pre.decision)
      or (pre.step == Commit and r.st.step != Commit)

  pure def votedNonPrecommit(o: Output): bool =
    match o { | OVote(v) => v.kind != KPrecommit | _ => false }

  //--------------------------------------------------------------------------
  // Actions
  //--------------------------------------------------------------------------

  /// Shared commit of one transition result, with every paper-rule latch.
  /// `pre` is the state `apply` was actually handed — the latches judge the
  /// transition against THAT, not against wherever the model happened to sit.
  action commitResult(r: Result, i: Info, input: Input, pre: SMState): bool = all {
    state' = r.st,
    output' = r.out,
    lastValid' = r.ok,
    lastLine' = r.line,
    prev' = pre,
    lastInput' = input,
    lastInfoRound' = i.input_round,
    maxValidRound' = if (validRound(r.st) > maxValidRound) validRound(r.st) else maxValidRound,
    firstDecision' = match firstDecision { | NoDec => r.st.decision | SomeDec(d) => SomeDec(d) },
    emittedTimeouts' = emittedTimeouts.union(timeoutKeyOf(r.out)),
    duplicateTimeout' = (duplicateTimeout or timeoutRearmed(pre, r)),
    staleTimeoutBits' =
      (staleTimeoutBits or staleBitsSurvived(pre, r)),
    bindingRuleBroken' = (bindingRuleBroken or bindingBroken(pre, i, input, r)),
    reproposalRuleBroken' = (reproposalRuleBroken or reproposalBroken(pre, i, input, r)),
    decisionRuleBroken' = (decisionRuleBroken or decisionBroken(pre, input, r)),
    illegalRoundAdvance' = (illegalRoundAdvance or roundAdvanceBroken(pre, input, r)),
    nonPrecommitVote' = (nonPrecommitVote or votedNonPrecommit(r.out)),
    validDecreased' = (validDecreased or (validRound(r.st) < validRound(pre))),
    reproposedWithoutValid' = (reproposedWithoutValid or reproposeBroken(r)),
    decisionFinalityBroken' = (decisionFinalityBroken or decisionFinalityBrokenBy(pre, r)),
  }

  /// Commit of a raw public mutator: no input, so only the state-shaped latches
  /// apply.
  action commitMutator(nxt: SMState, ok: bool, line: str): bool = all {
    state' = nxt,
    output' = ONone,
    lastValid' = ok,
    lastLine' = line,
    prev' = state,
    lastInput' = NoInput,
    lastInfoRound' = lastInfoRound,
    maxValidRound' = if (validRound(nxt) > maxValidRound) validRound(nxt) else maxValidRound,
    firstDecision' = match firstDecision { | NoDec => nxt.decision | SomeDec(d) => SomeDec(d) },
    emittedTimeouts' = emittedTimeouts,
    duplicateTimeout' = duplicateTimeout,
    staleTimeoutBits' =
      (staleTimeoutBits or (nxt.round != state.round and nxt.scheduled != Set())),
    bindingRuleBroken' = bindingRuleBroken,
    reproposalRuleBroken' = reproposalRuleBroken,
    decisionRuleBroken' = decisionRuleBroken,
    illegalRoundAdvance' = illegalRoundAdvance,
    nonPrecommitVote' = nonPrecommitVote,
    validDecreased' = (validDecreased or (validRound(nxt) < validRound(state))),
    reproposedWithoutValid' = reproposedWithoutValid,
    decisionFinalityBroken' = decisionFinalityBroken,
  }

  /// fast::state_machine::apply(ctx, state, info, input) — the transition function.
  /// Call site: code/crates/core-state-machine/src/fast/state_machine.rs:80.
  action faststate_machineapply(pre: SMState, info: Info, input: Input): bool =
    commitResult(applyInput(pre, info, input), info, input, pre)

  /// state.rs State::with_step(step) — unguarded public builder.
  action Statewith_step(step: Step): bool =
    commitMutator(withStep(state, step), true, "with_step")

  /// state.rs State::update_round(round) — unguarded; moves the round and
  /// clears the per-round timeout bookkeeping, keeping valid and decision.
  action Stateupdate_round(round: Round): bool =
    commitMutator(updateRound(state, round), true, "update_round")

  /// state.rs State::set_valid(round, value_id) — monotone; a no-op unless the
  /// new round is strictly above the recorded valid round.
  action Stateset_valid(round: Round, value_id: Value): bool =
    commitMutator(setValid(state, round, value_id), true,
                  if (validRound(state) < round) "set_valid_raised" else "set_valid_noop")

  /// state.rs State::set_decision(proposal_round, value) — unguarded overwrite.
  action Stateset_decision(proposal_round: Round, value: Value): bool =
    commitMutator(setDecision(state, proposal_round, value), true, "set_decision")

  /// state.rs State::check_timeout(kind) — guarded mutation on the scheduled set.
  action Statecheck_timeout(kind: TimeoutKind): bool =
    commitMutator(recordTimeout(state, kind), checkTimeout(state, kind),
                  if (not(isTracked(kind))) "check_timeout_untracked"
                  else if (checkTimeout(state, kind)) "check_timeout_granted"
                  else "check_timeout_denied")

  /// state.rs ScheduledTimeouts::check(kind) — the same bitset operation,
  /// reached directly rather than through State.
  action ScheduledTimeoutscheck(kind: TimeoutKind): bool =
    commitMutator(recordTimeout(state, kind), checkTimeout(state, kind),
                  if (not(isTracked(kind))) "scheduled_check_untracked"
                  else if (checkTimeout(state, kind)) "scheduled_check_granted"
                  else "scheduled_check_denied")

  /// state.rs ScheduledTimeouts::clear() — public, and the only thing that
  /// empties the bitset outside update_round.
  action ScheduledTimeoutsclear: bool =
    commitMutator(clearTimeouts(state), true, "scheduled_clear")

  /// Values worth trying: the whole domain plus whatever we currently hold, so
  /// the "re-offers what we hold valid" branches stay reachable.
  pure def focusValues(s: SMState): Set[Value] =
    match s.valid { | NoRV => VALUES | SomeRV(rv) => VALUES.union(Set(rv.value_id)) }

  action step = any {
    // Arm 1 — the replay-facing arm: every pick carries the name the
    // instrumentation logs, over the full domain, so a replayed event pins it.
    {
      nondet proposer = ADDRS.oneOf()
      nondet inputTag = ALL_TAGS.oneOf()
      nondet pvalue = VALUES.oneOf()
      nondet pround = ROUND_BAND.oneOf()
      nondet ppol = ROUND_BAND.oneOf()
      nondet input_round = ROUND_BAND.oneOf()
      nondet nround = ROUND_BAND.oneOf()
      nondet sround = ROUND_BAND.oneOf()
      nondet sstep = STEP_NAMES.oneOf()
      nondet svround = ROUND_BAND.oneOf()
      nondet svalue = VALUES.oneOf()
      nondet sdround = ROUND_BAND.oneOf()
      nondet sdvalue = VALUES.oneOf()
      nondet sawaiting = Set(false, true).oneOf()
      nondet sscheduled = SCHEDULED_BITS.oneOf()
      val info = { input_round: input_round, address: ME, proposer: proposer }
      val p = { round: pround, value: pvalue, polRound: ppol }
      faststate_machineapply(
        mkPre(sround, sstep, svround, svalue, sdround, sdvalue, sawaiting, sscheduled),
        info, mkInput(inputTag, p, pvalue, nround))
    },

    // Arm 2 — the same picks under the SAME NAMES, with the proposal carrying
    // the identifier we hold valid and the rounds clustered around ours. Pure
    // search guidance: it makes the rare binding branches reachable inside a
    // sampling budget without ever leaving a logged argument unpinned.
    {
      nondet proposer = ADDRS.oneOf()
      nondet inputTag = ALL_TAGS.oneOf()
      nondet pvalue = focusValues(state).oneOf()
      nondet pround = Set(state.round, state.round + 1).oneOf()
      nondet ppol = Set(-1, validRound(state), state.round - 1).oneOf()
      nondet input_round = Set(state.round, state.round + 1).oneOf()
      nondet nround = Set(state.round, state.round + 1).oneOf()
      nondet sround = Set(state.round).oneOf()
      nondet sstep = Set(stepNameOf(state)).oneOf()
      nondet svround = Set(validRound(state)).oneOf()
      nondet svalue = Set(match state.valid { | NoRV => "v" | SomeRV(rv) => rv.value_id }).oneOf()
      nondet sdround = Set(match state.decision { | NoDec => -1 | SomeDec(d) => d.round }).oneOf()
      nondet sdvalue = Set(match state.decision { | NoDec => "v" | SomeDec(d) => d.value }).oneOf()
      nondet sawaiting = Set(state.awaiting_valid).oneOf()
      nondet sscheduled = Set(bitsOf(state)).oneOf()
      val info = { input_round: input_round, address: ME, proposer: proposer }
      val p = { round: pround, value: pvalue, polRound: ppol }
      faststate_machineapply(
        mkPre(sround, sstep, svround, svalue, sdround, sdvalue, sawaiting, sscheduled),
        info, mkInput(inputTag, p, pvalue, nround))
    },

    // The raw public mutators, sharing an arm so the transition function — what
    // most scenarios need — stays the likely choice.
    {
      nondet step = STEPS.oneOf()
      nondet round = ROUND_BAND.oneOf()
      nondet value_id = VALUES.oneOf()
      nondet proposal_round = ROUND_BAND.oneOf()
      nondet value = VALUES.oneOf()
      nondet kind = TIMEOUT_KINDS.oneOf()
      any {
        Statewith_step(step),
        Stateupdate_round(round),
        Stateset_valid(round, value_id),
        Stateset_decision(proposal_round, value),
        Statecheck_timeout(kind),
        ScheduledTimeoutscheck(kind),
        ScheduledTimeoutsclear,
      }
    },
  }

  //--------------------------------------------------------------------------
  // Correctness properties — stated from Algorithm 1 (arXiv:2608.13434)
  //--------------------------------------------------------------------------

  /// The round recorded in valid never falls below a round it already reached.
  val valid_p_never_decreases: bool = not(validDecreased)

  /// A fresh proposal draws a vote for its value exactly when nothing binds us
  /// or it re-offers the identifier we hold valid, and a nil vote otherwise.
  val fresh_proposal_binding_rule: bool = not(bindingRuleBroken)

  /// A re-proposal applies only when its valid round is a real earlier round,
  /// and is accepted exactly when that round is at least ours or it re-offers
  /// the identifier we hold.
  val reproposal_acceptance_rule: bool = not(reproposalRuleBroken)

  /// Every decision is established by a fresh proposal and carries that
  /// proposal's own round and value.
  val decision_requires_a_fresh_proposal: bool = not(decisionRuleBroken)

  /// The round advances, and round-advancing outputs are emitted, only on
  /// NewRound, QuorumAny or the precommit timeout.
  val round_advances_only_by_quorum_any_or_timeout_precommit: bool =
    not(illegalRoundAdvance)

  /// A decision is never changed once recorded, and the Commit step is never
  /// left.
  val decision_is_final_and_commit_is_terminal: bool = not(decisionFinalityBroken)

  /// Every vote the state machine emits is a precommit.
  val every_vote_output_is_a_precommit: bool = not(nonPrecommitVote)

  /// A per-round timeout is armed at most once per round, and no scheduled bit
  /// survives a round change.
  val round_timeout_armed_at_most_once_per_round: bool =
    not(duplicateTimeout) and not(staleTimeoutBits)


  /// A re-proposal names exactly the identifier and round the state holds valid.
  val repropose_only_carries_a_value_we_hold: bool = not(reproposedWithoutValid)

  //--------------------------------------------------------------------------
  // Observations
  //--------------------------------------------------------------------------

  /// L12-L13: the round-0 proposer held nothing valid and asked the application.
  val round_zero_proposer_asked_for_value: bool =
    lastLine == "L13GetValue" and state.round == 0
  /// L15-L16: the proposer re-proposed the identifier it holds valid.
  val proposer_reproposed_held_identifier: bool = lastLine == "L15Repropose"
  /// L10-L11: a proposer above round 0 entered Propose waiting to learn valid.
  val later_round_proposer_waits_for_valid: bool = lastLine == "L11WaitForValid"
  /// L18: a non-proposer armed the propose timeout.
  val non_proposer_scheduled_propose_timeout: bool =
    lastLine == "L18ProposeTimeoutScheduled"
  /// L18: the propose timeout was already armed, so nothing was scheduled.
  ///
  /// This became LIVE with the fix recorded as F-20: `update_round` used to
  /// clear the timeout bits unconditionally, immediately before
  /// `check_timeout(Propose)`, so the check always succeeded and the branch was
  /// dead. The bits are now cleared only on a real round change, so re-entering
  /// the round we are already in — which `apply` accepts, since its NewRound
  /// guard is `state.round <= round` — reaches this arm.
  val non_proposer_propose_timeout_suppressed: bool =
    lastLine == "L18ProposeTimeoutSuppressed"

  /// L13: the application's value became a fresh proposal.
  val proposer_emitted_fresh_proposal: bool = lastLine == "L13Propose"
  /// L20-L22: nothing bound us, so we voted for the proposed identifier.
  val voted_for_unbound_fresh_proposal: bool = lastLine == "L22VoteUnbound"
  /// L21: the fresh proposal re-offered exactly what we hold valid.
  val voted_for_fresh_proposal_matching_valid: bool = lastLine == "L22VoteMatchesValid"
  /// L21: we hold a different identifier valid, so the vote was nil.
  val voted_nil_because_bound_to_another_value: bool = lastLine == "L21VoteNilBound"
  /// L23-L24: the application rejected the value.
  val voted_nil_on_invalid_proposal: bool = lastLine == "L24VoteNilInvalid"
  /// L50-L52: no proposal arrived in time.
  val voted_nil_on_propose_timeout: bool = lastLine == "L52VoteNilProposeTimeout"

  /// L29-L30: the justification was at least as recent as ours, raising valid.
  val reproposal_accepted_raising_valid: bool = lastLine == "L30ReproposalAcceptedRaised"
  /// L28: a stale justification was accepted because it re-offered our identifier.
  val reproposal_accepted_by_matching_identifier: bool =
    lastLine == "L30ReproposalAcceptedSameId"
  /// L28: the justification was older than ours and named another value.
  val reproposal_refused_on_stale_justification: bool =
    lastLine == "L28VoteNilStaleJustification"
  /// L27: the justifying round was nil or not below the current round.
  val reproposal_rejected_for_malformed_valid_round: bool =
    lastLine == "L27MalformedValidRound"
  /// L33: the justification or value was rejected upstream.
  val voted_nil_on_invalid_reproposal: bool = lastLine == "L33VoteNilInvalidReproposal"

  /// L36-L37: 2f+1 votes in this round made a value valid.
  val vote_quorum_raised_valid: bool = lastLine == "L37SetValid"
  /// L36: valid was already at this round, so nothing was raised.
  val vote_quorum_did_not_raise_valid: bool = lastLine == "L36NotRaised"
  /// L47-L48: the quorum ended the proposer's wait and it re-proposed.
  val waiting_proposer_reproposed_on_vote_quorum: bool =
    lastLine == "L48WaitResolvedRepropose"
  /// L39-L40: n-f votes for any value armed the precommit timeout.
  val precommit_timeout_armed_on_quorum_any: bool =
    lastLine == "L40PrecommitTimeoutScheduled"
  /// L40: a repeated quorum-any armed nothing.
  val quorum_any_repeat_armed_nothing: bool = lastLine == "L40PrecommitTimeoutSuppressed"
  /// L39: the quorum-any came from a round strictly above ours.
  val quorum_any_from_a_higher_round: bool = and {
    lastLine == "L40PrecommitTimeoutScheduled",
    match output { | OScheduleTimeout(t) => t.round > prev.round | _ => false },
  }

  /// L42-L43: a fresh proposal plus n-f votes decided a value.
  val decided_on_fresh_proposal: bool = lastLine == "L43Decide"
  /// L42: the decided proposal came from a round other than the one we are at.
  val decided_on_a_proposal_from_another_round: bool = and {
    lastLine == "L43Decide",
    match state.decision { | NoDec => false | SomeDec(d) => d.round != prev.round },
  }
  /// L42: a re-proposal carries only an identifier and cannot be decided on.
  val decision_refused_for_a_reproposal: bool = lastLine == "L42ReproposalCannotDecide"
  /// A decision is already recorded, so a second decision quorum did not apply.
  val decision_refused_in_commit_step: bool = lastLine == "CommitTerminal"

  /// L55-L57: the precommit timeout gave up on the round.
  val precommit_timeout_started_the_next_round: bool = lastLine == "L57NewRound"
  /// L56: once decided, the precommit timeout started nothing.
  val precommit_timeout_after_a_decision_ignored: bool = and {
    lastLine == "NoArm",
    lastInput == TimeoutPrecommit,
    prev.decision != NoDec,
  }
  /// L46: the proposer's bounded wait expired and it proposed anyway.
  val wait_for_valid_expired_and_proposed: bool = lastLine == "L46WaitExpiredPropose"
  /// A timeout kind this protocol does not track per round was denied silently.
  val untracked_timeout_kind_denied: bool =
    lastLine == "check_timeout_untracked" or lastLine == "scheduled_check_untracked"
  /// A round change emptied the scheduled-timeout bitset.
  val timeout_bits_cleared_by_round_change: bool = and {
    lastLine == "update_round",
    prev.scheduled != Set(),
    state.scheduled == Set(),
  }

  /// The input matched no arm of the transition table.
  val input_fell_through_to_invalid: bool = lastLine == "NoArm"
  /// An input arrived for a round strictly below the one we are at, and the
  /// round guards ignored it.
  val stale_input_for_an_older_round_ignored: bool = and {
    lastInfoRound < prev.round,
    not(lastValid),
    state == prev,
    match lastInput { | NoInput => false | _ => true },
  }
}
