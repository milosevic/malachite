// Model of `malachitebft-core-state-machine` — the pure per-round Tendermint
// algorithm (Unstarted -> Propose -> Prevote -> Precommit -> Commit) exposed as
// `apply(ctx, state, info, input) -> Transition { next_state, output, valid }`.
//
// Code under model:
//   code/crates/core-state-machine/src/state_machine.rs  (apply + all the L-line helpers)
//   code/crates/core-state-machine/src/state.rs          (State, ScheduledTimeouts, builders)
//   code/crates/core-state-machine/src/input.rs, output.rs, transition.rs
//
// The model MIRRORS the code, panics and all: `prevote_previous`'s
// `assert!(vr < proposal.round())` is modelled as a `panicked` latch rather than
// silently idealised into a rejection, and `debug_assert!(info.is_proposer())` on
// ProposeValue is modelled as the release build behaves (it proposes anyway) with
// a latch. The intent lives in the `invariants` below.
module round_state_machine {

  //--------------------------------------------------------------------------
  // Domain
  //--------------------------------------------------------------------------

  /// Round::Nil is modelled as -1; Round::Some(r) as r >= 0.
  type Round = int
  type Value = str
  type Addr = str

  /// A Ctx::Proposal: its own round, the value, and its proof-of-lock round.
  type Prop = { round: Round, value: Value, polRound: Round }

  /// state.rs Step
  type Step = Unstarted | Propose | Prevote | Precommit | Commit

  /// state.rs RoundValue<Value>
  type RoundValue = { value: Value, round: Round }

  /// Option[RoundValue] for state.locked / state.valid / state.decision.
  type MaybeRV = NoRV | SomeRV(RoundValue)

  /// core_types::NilOrVal<ValueId>
  type NilOrVal = VNil | VVal(Value)

  /// core_types::TimeoutKind, restricted to the kinds the round machine touches.
  /// TRebroadcast stands for the untracked kinds (Rebroadcast / FinalizeHeight).
  type TimeoutKind = TPropose | TPrevote | TPrecommit | TRebroadcast

  /// input.rs Input<Ctx>
  type Input =
    | NoInput
    | NewRound(Round)
    | ProposeValue(Value)
    | Proposal(Prop)
    | InvalidProposal
    | ProposalAndPolkaPrevious(Prop)
    | InvalidProposalAndPolkaPrevious(Prop)
    | PolkaAny
    | PolkaNil
    | ProposalAndPolkaCurrent(Prop)
    | PrecommitAny
    | ProposalAndPrecommitValue(Prop)
    | SkipRound(Round)
    | TimeoutPropose
    | TimeoutPrevote
    | TimeoutPrecommit

  /// output.rs Output<Ctx>; ONone models `Transition.output == None`.
  type Output =
    | ONone
    | ONewRound(Round)
    | OProposal(Prop)
    | OPrevote(NilOrVal)
    | OPrecommit(NilOrVal)
    | OScheduleTimeout({ round: Round, kind: TimeoutKind })
    | OGetValueAndScheduleTimeout({ round: Round, kind: TimeoutKind })
    | ODecision({ round: Round, proposal: Prop })

  /// state_machine.rs Info<'a, Ctx>
  type Info = { input_round: Round, address: Addr, proposer: Addr }

  /// state.rs State<Ctx> (height is fixed — this component is per-height).
  type SMState = {
    round: Round,
    step: Step,
    locked: MaybeRV,
    valid: MaybeRV,
    decision: MaybeRV,
    scheduled: Set[TimeoutKind],
  }

  /// The result of one `apply`: transition.rs Transition plus the abort case.
  type Result = { st: SMState, out: Output, ok: bool, panic: bool, line: str }

  /// The public builders of state.rs, as one operation family.
  type Builder =
    | BWithRound(Round)
    | BWithStep(Step)
    | BSetLocked(Value)
    | BSetValid(Value)
    | BSetDecision({ round: Round, value: Value })

  /// The value ids the model reasons about: two abstract symbols, plus every
  /// concrete `ValueId` the driver's integration suite produces (rendered the
  /// way the code renders them, lower-case hex).
  pure val VALUES: Set[Value] =
    Set("v", "w", "2a", "64", "c8", "1e61", "22b8", "270f")

  /// The values worth trying when steering the random search: the abstract pair
  /// plus whatever we currently hold, so the "same value as the lock" branches
  /// stay reachable within a sampling budget.
  pure def focusValues(s: SMState): Set[Value] =
    Set("v", "w", valueOf(s.locked), valueOf(s.valid))
  pure val ADDRS: Set[Addr] = Set("a", "b")
  pure val ME: Addr = "a"
  pure val ROUNDS: Set[Round] = Set(0, 1, 2)
  /// pol_round domain deliberately includes Nil (-1) and rounds at/above a
  /// proposal's own round, so the assert in prevote_previous is falsifiable.
  pure val POL_ROUNDS: Set[Round] = Set(-1, 0, 1, 2)

  /// The absolute rounds the driver's integration suite drives the machine
  /// through, so a replayed trace can name any of them regardless of where the
  /// model currently sits.
  pure val ROUND_BAND: Set[Round] = Set(-1, 0, 1, 2, 3, 4, 5)

  /// The rounds immediately around where the machine currently sits.
  pure def roundsAround(s: SMState): Set[Round] =
    Set(floorRound(s.round - 1), s.round, s.round + 1)

  /// pol_round candidates relative to the current round AND to our lock: the
  /// polka at, above, and strictly below the lock round are the three cases the
  /// locking rule distinguishes.
  pure def polRoundsAround(s: SMState): Set[Round] =
    Set(-1, floorRound(s.round - 1), s.round, roundOf(s.locked),
        floorRound(roundOf(s.locked) - 1))

  /// Rounds are floored at Nil so a rewind cannot go below Round::Nil.
  pure def floorRound(r: Round): Round = if (r < -1) -1 else r

  /// The Input constructors, named by tag. The tag is a primitive pick so a
  /// logged event can pin exactly which input the driver delivered.
  pure val ALL_TAGS: Set[str] = Set(
    "NoInput", "NewRound", "ProposeValue", "Proposal", "InvalidProposal",
    "ProposalAndPolkaPrevious", "InvalidProposalAndPolkaPrevious", "PolkaAny",
    "PolkaNil", "ProposalAndPolkaCurrent", "PrecommitAny",
    "ProposalAndPrecommitValue", "SkipRound", "TimeoutPropose", "TimeoutPrevote",
    "TimeoutPrecommit",
  )

  /// Build the Input the tag names, from the proposal / value / round picks.
  pure def mkInput(tag: str, p: Prop, v: Value, nr: Round): Input =
    if (tag == "NewRound") NewRound(nr)
    else if (tag == "ProposeValue") ProposeValue(v)
    else if (tag == "Proposal") Proposal(p)
    else if (tag == "InvalidProposal") InvalidProposal
    else if (tag == "ProposalAndPolkaPrevious") ProposalAndPolkaPrevious(p)
    else if (tag == "InvalidProposalAndPolkaPrevious") InvalidProposalAndPolkaPrevious(p)
    else if (tag == "PolkaAny") PolkaAny
    else if (tag == "PolkaNil") PolkaNil
    else if (tag == "ProposalAndPolkaCurrent") ProposalAndPolkaCurrent(p)
    else if (tag == "PrecommitAny") PrecommitAny
    else if (tag == "ProposalAndPrecommitValue") ProposalAndPrecommitValue(p)
    else if (tag == "SkipRound") SkipRound(nr)
    else if (tag == "TimeoutPropose") TimeoutPropose
    else if (tag == "TimeoutPrevote") TimeoutPrevote
    else if (tag == "TimeoutPrecommit") TimeoutPrecommit
    else NoInput

  /// The tags worth trying in a given step. Used only to steer the random
  /// search toward the deep lock/timeout scenarios — every tag stays available
  /// through the unrestricted `inputTag` pick.
  pure def focusTags(s: SMState): Set[str] =
    val generic = Set("TimeoutPrecommit", "SkipRound")
    val specific =
      match s.step {
        | Unstarted => Set("NewRound")
        | Propose => Set("Proposal", "ProposalAndPolkaPrevious",
                         "InvalidProposalAndPolkaPrevious", "TimeoutPropose")
        | Prevote => Set("PolkaAny", "PolkaNil", "ProposalAndPolkaCurrent", "TimeoutPrevote")
        | Precommit => Set("ProposalAndPolkaCurrent")
        | Commit => Set("NewRound")
      }
    generic.union(specific)

  /// with_round is omitted here: it is literally `update_round`, which has its
  /// own action.
  pure val BUILDERS: Set[Builder] =
    Set(Propose, Prevote, Precommit).map(s => BWithStep(s))
      .union(Set("v", "w").map(v => BSetLocked(v)))
      .union(Set("v", "w").map(v => BSetValid(v)))
      .union(Set("v", "w").map(v => BSetDecision({ round: 0, value: v })))

  //--------------------------------------------------------------------------
  // Pure helpers — state.rs
  //--------------------------------------------------------------------------

  /// state.rs State::new(height, Round::Nil)
  pure val initial_state: SMState = {
    round: -1,
    step: Unstarted,
    locked: NoRV,
    valid: NoRV,
    decision: NoRV,
    scheduled: Set(),
  }

  /// state.rs State::update_round — sets the round AND clears scheduled_timeouts.
  pure def updateRound(s: SMState, r: Round): SMState =
    { ...s, round: r, scheduled: Set() }

  /// state.rs ScheduledTimeouts::check — tracked kinds only; untracked kinds
  /// hit `debug_assert!(false)` and return false in release.
  pure def isTracked(k: TimeoutKind): bool = k != TRebroadcast

  pure def checkTimeout(s: SMState, k: TimeoutKind): bool =
    isTracked(k) and not(s.scheduled.contains(k))

  pure def recordTimeout(s: SMState, k: TimeoutKind): SMState =
    if (isTracked(k)) { ...s, scheduled: s.scheduled.union(Set(k)) } else s

  /// state_machine.rs is_valid_pol_round — the pol_round must be defined, below
  /// our round, AND below the proposal's own round.
  pure def isValidPolRound(s: SMState, p: Prop): bool =
    p.polRound >= 0 and p.polRound < s.round and p.polRound < p.round

  /// state_machine.rs Info::is_proposer
  pure def isProposer(i: Info): bool = i.address == i.proposer

  pure def valueOf(m: MaybeRV): Value =
    match m { | NoRV => "" | SomeRV(rv) => rv.value }

  pure def roundOf(m: MaybeRV): Round =
    match m { | NoRV => -1 | SomeRV(rv) => rv.round }

  pure def ok(s: SMState, o: Output, l: str): Result =
    { st: s, out: o, ok: true, panic: false, line: l }

  pure def invalid(s: SMState, l: str): Result =
    { st: s, out: ONone, ok: false, panic: false, line: l }

  //--------------------------------------------------------------------------
  // Pure helpers — the L-line functions of state_machine.rs
  //--------------------------------------------------------------------------

  /// L13-L16/L19 propose_valid_or_get_value
  pure def proposeValidOrGetValue(s: SMState): Result =
    match s.valid {
      | SomeRV(rv) =>
        ok({ ...s, step: Propose },
           OProposal({ round: s.round, value: rv.value, polRound: rv.round }),
           "L16ProposeValidValue")
      | NoRV =>
        // debug_assert!(state.check_timeout(Propose)) — always true right after
        // update_round cleared the bitset.
        ok({ ...recordTimeout(s, TPropose), step: Propose },
           OGetValueAndScheduleTimeout({ round: s.round, kind: TPropose }),
           "L18GetValue")
    }

  /// L13/L17-L18 propose
  pure def propose(s: SMState, v: Value): Result =
    ok({ ...s, step: Propose },
       OProposal({ round: s.round, value: v, polRound: -1 }),
       "L19Propose")

  /// L11/L20 schedule_timeout_propose
  pure def scheduleTimeoutPropose(s: SMState): Result =
    ok({ ...recordTimeout(s, TPropose), step: Propose },
       OScheduleTimeout({ round: s.round, kind: TPropose }),
       "L21ProposeTimeoutScheduled")

  /// L22-L26 prevote. The `assert_eq!(vr, Round::Nil)` is guaranteed by the
  /// caller's guard `proposal.pol_round().is_nil()`, so it cannot fire here.
  pure def prevote(s: SMState, p: Prop): Result =
    val v: NilOrVal =
      match s.locked {
        | NoRV => VVal(p.value)
        | SomeRV(l) => if (l.value == p.value) VVal(p.value) else VNil
      }
    val l: str =
      match s.locked {
        | NoRV => "L24ValidNoLockedRound"
        | SomeRV(lk) => if (lk.value == p.value) "L24ValidAndLockedValue" else "L26ValidAndLockedValue"
      }
    ok({ ...s, step: Prevote }, OPrevote(v), l)

  /// L28-L32 prevote_previous.
  /// `assert!(vr < proposal.round())` compares the pol_round against the
  /// PROPOSAL's round, while the caller's guard only compared it against
  /// state.round — so a proposal whose own round is stale aborts the process.
  pure def prevotePrevious(s: SMState, p: Prop): Result =
    if (not(p.polRound < p.round))
      { st: s, out: ONone, ok: false, panic: true, line: "PanicPolRoundAssert" }
    else
      val v: NilOrVal =
        match s.locked {
          | NoRV => VVal(p.value)
          | SomeRV(lk) =>
            if (lk.round <= p.polRound) VVal(p.value)
            else if (lk.value == p.value) VVal(p.value)
            else VNil
        }
      val l: str =
        match s.locked {
          | NoRV => "L30ValidNoLockedRound"
          | SomeRV(lk) =>
            if (lk.round <= p.polRound) "L30ValidLockedRound"
            else if (lk.value == p.value) "L30ValidLockedValue"
            else "L32InvalidValue"
        }
      ok({ ...s, step: Prevote }, OPrevote(v), l)

  /// L22/L25, L28/L31, L57 prevote_nil
  pure def prevoteNil(s: SMState, l: str): Result =
    ok({ ...s, step: Prevote }, OPrevote(VNil), l)

  /// L36/L37 precommit — locks and sets valid at the CURRENT state round.
  pure def precommit(s: SMState, p: Prop): Result =
    if (s.step != Prevote)
      ok(s, ONone, "L36NotInPrevote")
    else
      ok({ ...s,
           locked: SomeRV({ value: p.value, round: s.round }),
           valid: SomeRV({ value: p.value, round: s.round }),
           step: Precommit },
         OPrecommit(VVal(p.value)),
         "L36ValidProposal")

  /// L44, L61 precommit_nil
  pure def precommitNil(s: SMState, l: str): Result =
    ok({ ...s, step: Precommit }, OPrecommit(VNil), l)

  /// L34/L35 schedule_timeout_prevote — silently no-ops on the second call.
  pure def scheduleTimeoutPrevote(s: SMState): Result =
    if (checkTimeout(s, TPrevote))
      ok(recordTimeout(s, TPrevote), OScheduleTimeout({ round: s.round, kind: TPrevote }), "L35PrevoteTimeoutScheduled")
    else
      ok(s, ONone, "L35PrevoteTimeoutSuppressed")

  /// L47/L48 schedule_timeout_precommit — silently no-ops on the second call.
  pure def scheduleTimeoutPrecommit(s: SMState): Result =
    if (checkTimeout(s, TPrecommit))
      ok(recordTimeout(s, TPrecommit), OScheduleTimeout({ round: s.round, kind: TPrecommit }), "L48PrecommitTimeoutScheduled")
    else
      ok(s, ONone, "L48PrecommitTimeoutSuppressed")

  /// L36/L42 set_valid_value
  pure def setValidValue(s: SMState, p: Prop): Result =
    ok({ ...s, valid: SomeRV({ value: p.value, round: s.round }) }, ONone, "L42SetValidValue")

  /// L55, L65/L67 round_skip
  pure def roundSkip(s: SMState, r: Round, l: str): Result =
    ok({ ...updateRound(s, r), step: Unstarted }, ONewRound(r), l)

  /// L49 commit. The output round and the recorded decision round are both the
  /// proposal's own round.
  pure def commit(s: SMState, r: Round, p: Prop): Result =
    match s.decision {
      | SomeRV(d) =>
        if (d.value == p.value) ok(s, ONone, "L49DecisionRepeated")
        else invalid(s, "L49DecisionConflict")
      | NoRV =>
        ok({ ...s, decision: SomeRV({ value: p.value, round: p.round }), step: Commit },
           ODecision({ round: r, proposal: p }),
           "L49Decide")
    }

  //--------------------------------------------------------------------------
  // The transition table — state_machine::apply
  //--------------------------------------------------------------------------

  /// The tail arms of apply: `(_, PrecommitAny)`, `(_, TimeoutPrecommit)`,
  /// `(_, SkipRound)`, `(_, ProposalAndPrecommitValue)` and the invalid catch-all.
  pure def genericArms(s: SMState, i: Info, inp: Input, thisRound: bool): Result =
    match inp {
      | PrecommitAny => if (thisRound) scheduleTimeoutPrecommit(s) else invalid(s, "NoArm")
      | TimeoutPrecommit => if (thisRound) roundSkip(s, i.input_round + 1, "L67RoundSkip") else invalid(s, "NoArm")
      | SkipRound(r) => if (s.round < r) roundSkip(s, r, "L55RoundSkip") else invalid(s, "NoArm")
      // The decision output names the round the value was proposed in — the same
      // round recorded in state.decision.
      | ProposalAndPrecommitValue(p) => commit(s, p.round, p)
      | _ => invalid(s, "NoArm")
    }

  /// state_machine.rs apply(). `(Step::Commit, _) => Transition::invalid` is
  /// hoisted to the top: every step-specific arm above it requires a step
  /// other than Commit, so hoisting is behaviour-preserving.
  pure def applyInput(s: SMState, i: Info, inp: Input): Result =
    val thisRound = s.round == i.input_round
    if (s.step == Commit)
      invalid(s, "CommitTerminal")
    else
      match inp {
        | NewRound(r) =>
          // A NewRound for a round we already left is stale and must not rewind us.
          if (s.step == Unstarted and r >= s.round)
            val s2 = updateRound(s, r)
            if (isProposer(i)) proposeValidOrGetValue(s2) else scheduleTimeoutPropose(s2)
          else genericArms(s, i, inp, thisRound)

        | ProposeValue(v) =>
          // debug_assert!(info.is_proposer()) — in release the proposal is emitted
          // regardless of whether we are the proposer.
          if (s.step == Propose and thisRound) propose(s, v)
          else genericArms(s, i, inp, thisRound)

        | Proposal(p) =>
          if (s.step == Propose and thisRound and p.polRound < 0) prevote(s, p)
          else genericArms(s, i, inp, thisRound)

        | InvalidProposal =>
          if (s.step == Propose and thisRound) prevoteNil(s, "L26InvalidProposal")
          else genericArms(s, i, inp, thisRound)

        | ProposalAndPolkaPrevious(p) =>
          if (s.step == Propose and thisRound and isValidPolRound(s, p)) prevotePrevious(s, p)
          else genericArms(s, i, inp, thisRound)

        | InvalidProposalAndPolkaPrevious(p) =>
          if (s.step == Propose and thisRound and isValidPolRound(s, p))
            prevoteNil(s, "L32InvalidProposalAndPolkaPrevious")
          else genericArms(s, i, inp, thisRound)

        | TimeoutPropose =>
          if (s.step == Propose and thisRound) prevoteNil(s, "L59TimeoutPropose")
          else genericArms(s, i, inp, thisRound)

        | PolkaAny =>
          if (s.step == Prevote and thisRound) scheduleTimeoutPrevote(s)
          else genericArms(s, i, inp, thisRound)

        | PolkaNil =>
          if (s.step == Prevote and thisRound) precommitNil(s, "L45PrecommitNil")
          else genericArms(s, i, inp, thisRound)

        | ProposalAndPolkaCurrent(p) =>
          if (s.step == Prevote and thisRound) precommit(s, p)
          else if (s.step == Precommit and thisRound) setValidValue(s, p)
          else genericArms(s, i, inp, thisRound)

        | TimeoutPrevote =>
          if (s.step == Prevote and thisRound) precommitNil(s, "L61PrecommitNil")
          else genericArms(s, i, inp, thisRound)

        | _ => genericArms(s, i, inp, thisRound)
      }

  //--------------------------------------------------------------------------
  // State
  //--------------------------------------------------------------------------

  var state: SMState
  /// The Transition's output.
  var output: Output
  /// The Transition's `valid` flag.
  var lastValid: bool
  /// Ghost: the L-line taken by the last transition (the code's own debug traces).
  var lastLine: str
  /// Ghost: set once `prevote_previous`'s assert would abort the process.
  var panicked: bool
  /// Ghost: the highest round the state has ever held, sampled BEFORE each step.
  var maxRound: Round
  /// Ghost: latched when a Proposal output is emitted by a non-proposer.
  var nonProposerProposed: bool
  /// Ghost: the first decision ever recorded, to detect a later overwrite.
  var firstDecision: MaybeRV
  /// Ghost: (round, kind) pairs for which a timeout output was already emitted.
  var emittedTimeouts: Set[(Round, TimeoutKind)]
  /// Ghost: latched when a timeout output repeats a (round, kind) already emitted.
  var duplicateTimeout: bool

  pure def timeoutKeyOf(o: Output): Set[(Round, TimeoutKind)] =
    match o {
      | OScheduleTimeout(t) => Set((t.round, t.kind))
      | OGetValueAndScheduleTimeout(t) => Set((t.round, t.kind))
      | _ => Set()
    }

  action init = all {
    state' = initial_state,
    output' = ONone,
    lastValid' = true,
    lastLine' = "init",
    panicked' = false,
    maxRound' = initial_state.round,
    nonProposerProposed' = false,
    firstDecision' = NoRV,
    emittedTimeouts' = Set(),
    duplicateTimeout' = false,
  }

  /// Shared commit of one `apply` result to the model state.
  action commitResult(r: Result, i: Info): bool = all {
    state' = r.st,
    output' = r.out,
    lastValid' = r.ok,
    lastLine' = r.line,
    panicked' = (panicked or r.panic),
    maxRound' = if (state.round > maxRound) state.round else maxRound,
    nonProposerProposed' =
      (nonProposerProposed or
       (not(isProposer(i)) and (match r.out { | OProposal(_) => true | _ => false }))),
    firstDecision' = match firstDecision { | NoRV => r.st.decision | SomeRV(d) => SomeRV(d) },
    emittedTimeouts' = emittedTimeouts.union(timeoutKeyOf(r.out)),
    duplicateTimeout' =
      (duplicateTimeout or timeoutKeyOf(r.out).exists(k => emittedTimeouts.contains(k))),
  }

  /// state.rs State::apply(ctx, info, input) — delegates to state_machine::apply.
  /// Call site: `State::apply`, code/crates/core-state-machine/src/state.rs:196.
  action Stateapply(info: Info, input: Input): bool =
    all {
      not(panicked),
      commitResult(applyInput(state, info, input), info),
    }

  /// state_machine.rs apply(ctx, state, info, input) — the free transition function.
  /// Call site: code/crates/core-state-machine/src/state_machine.rs:71.
  action state_machineapply(info: Info, input: Input): bool =
    all {
      not(panicked),
      commitResult(applyInput(state, info, input), info),
    }

  /// state.rs State::update_round(round) — public mutator; also clears the
  /// scheduled-timeout bitset. No comparison against the current round.
  action Stateupdate_round(round: Round): bool = all {
    not(panicked),
    state' = updateRound(state, round),
    output' = ONone,
    lastValid' = true,
    lastLine' = "update_round",
    panicked' = panicked,
    maxRound' = if (state.round > maxRound) state.round else maxRound,
    nonProposerProposed' = nonProposerProposed,
    firstDecision' = firstDecision,
    emittedTimeouts' = emittedTimeouts,
    duplicateTimeout' = duplicateTimeout,
  }

  /// state.rs builders: with_round / with_step / set_locked / set_valid / set_decision.
  action Statewith_round__with_step__set_locked__set_valid__set_decision(builder: Builder): bool = all {
    not(panicked),
    state' =
      match builder {
        | BWithRound(r) => updateRound(state, r)
        | BWithStep(s) => { ...state, step: s }
        | BSetLocked(v) => { ...state, locked: SomeRV({ value: v, round: state.round }) }
        | BSetValid(v) => { ...state, valid: SomeRV({ value: v, round: state.round }) }
        | BSetDecision(d) => { ...state, decision: SomeRV({ value: d.value, round: d.round }) }
      },
    output' = ONone,
    lastValid' = true,
    lastLine' = "builder",
    panicked' = panicked,
    maxRound' = if (state.round > maxRound) state.round else maxRound,
    nonProposerProposed' = nonProposerProposed,
    firstDecision' =
      match firstDecision {
        | NoRV => match builder { | BSetDecision(d) => SomeRV({ value: d.value, round: d.round }) | _ => NoRV }
        | SomeRV(d) => SomeRV(d)
      },
    emittedTimeouts' = emittedTimeouts,
    duplicateTimeout' = duplicateTimeout,
  }

  /// state.rs State::check_timeout(kind) — guarded mutation on the scheduled
  /// bitset. Untracked kinds hit `debug_assert!(false)` and are denied.
  action Statecheck_timeout(kind: TimeoutKind): bool = all {
    not(panicked),
    state' = recordTimeout(state, kind),
    output' = ONone,
    lastValid' = checkTimeout(state, kind),
    lastLine' =
      if (not(isTracked(kind))) "check_timeout_untracked"
      else if (checkTimeout(state, kind)) "check_timeout_granted"
      else "check_timeout_denied",
    panicked' = panicked,
    maxRound' = if (state.round > maxRound) state.round else maxRound,
    nonProposerProposed' = nonProposerProposed,
    firstDecision' = firstDecision,
    emittedTimeouts' = emittedTimeouts,
    duplicateTimeout' = duplicateTimeout,
  }

  action step = any {
    // Arm 1 — the replay-facing arm: every pick carries the name the
    // instrumentation logs, over a domain wide enough to hold any value the real
    // suite produces, so a replayed event pins every pick.
    {
      nondet proposer = ADDRS.oneOf()
      nondet inputTag = ALL_TAGS.oneOf()
      nondet pvalue = VALUES.oneOf()
      nondet pround = ROUND_BAND.union(roundsAround(state)).oneOf()
      nondet ppol = ROUND_BAND.union(polRoundsAround(state)).oneOf()
      nondet ir = ROUND_BAND.union(roundsAround(state)).oneOf()
      nondet nround = ROUND_BAND.union(roundsAround(state)).oneOf()
      val info = { input_round: ir, address: ME, proposer: proposer }
      val p = { round: pround, value: pvalue, polRound: ppol }
      any {
        Stateapply(info, mkInput(inputTag, p, pvalue, nround)),
        state_machineapply(info, mkInput(inputTag, p, pvalue, nround)),
      }
    },

    // Arm 2 — the same picks under the SAME NAMES, narrowed to the
    // step-appropriate, state-relative values. Pure search guidance: it makes
    // the rare locking scenarios reachable within a sampling budget without
    // ever leaving a logged argument unpinned.
    {
      nondet proposer = ADDRS.oneOf()
      nondet inputTag = focusTags(state).oneOf()
      nondet pvalue = focusValues(state).oneOf()
      nondet pround = roundsAround(state).oneOf()
      nondet ppol = polRoundsAround(state).oneOf()
      nondet ir = roundsAround(state).oneOf()
      nondet nround = roundsAround(state).oneOf()
      val info = { input_round: ir, address: ME, proposer: proposer }
      val p = { round: pround, value: pvalue, polRound: ppol }
      any {
        Stateapply(info, mkInput(inputTag, p, pvalue, nround)),
        state_machineapply(info, mkInput(inputTag, p, pvalue, nround)),
      }
    },

    // Arm 3 — as arm 2, but the proposal carries the value we are locked on:
    // the "we already hold this value" branches only fire when the two coincide.
    {
      nondet proposer = ADDRS.oneOf()
      nondet inputTag = focusTags(state).oneOf()
      nondet pvalue = Set(valueOf(state.locked)).oneOf()
      nondet pround = roundsAround(state).oneOf()
      nondet ppol = polRoundsAround(state).oneOf()
      nondet ir = roundsAround(state).oneOf()
      nondet nround = roundsAround(state).oneOf()
      val info = { input_round: ir, address: ME, proposer: proposer }
      val p = { round: pround, value: pvalue, polRound: ppol }
      Stateapply(info, mkInput(inputTag, p, pvalue, nround))
    },

    {
      nondet builder = BUILDERS.oneOf()
      Statewith_round__with_step__set_locked__set_valid__set_decision(builder)
    },

    // The two remaining direct mutators share an arm so the transition
    // function, which is what most scenarios need, stays the likely choice.
    {
      nondet kind = Set(TPropose, TPrevote, TPrecommit, TRebroadcast).oneOf()
      nondet round = ROUNDS.oneOf()
      any {
        Stateupdate_round(round),
        Statecheck_timeout(kind),
      }
    },
  }

  //--------------------------------------------------------------------------
  // Correctness properties
  //--------------------------------------------------------------------------

  /// A mis-routed proposal is rejected as an invalid transition, never aborting
  /// the process: prevote_previous's `assert!(vr < proposal.round())` must not fire.
  val no_panic_on_proposal_round_mismatch: bool = not(panicked)

  /// The round reported in a Decision output is the round recorded in state.decision,
  /// so a consumer attributes the block to the round it was actually proposed in.
  val decision_output_round_matches_state: bool =
    match output {
      | ODecision(d) => d.round == roundOf(state.decision)
      | _ => true
    }

  /// The state's round never moves backwards: no input rewinds the node into a
  /// round it has already left while it still holds locks from a later round.
  val round_never_moves_backwards: bool = state.round >= maxRound

  /// Only the proposer for the round emits a Proposal output.
  val only_proposer_emits_proposal: bool = not(nonProposerProposed)

  /// Once a value is decided it is never replaced by a different one — the
  /// round-level agreement guarantee.
  val decision_is_never_overwritten: bool =
    match firstDecision {
      | NoRV => true
      | SomeRV(d) => state.decision == SomeRV(d)
    }

  /// A propose/prevote/precommit timeout is scheduled at most once per round, so
  /// a duplicate threshold cannot make the node arm the same timer twice.
  val timeout_scheduled_at_most_once_per_round: bool = not(duplicateTimeout)

  /// Step::Commit is terminal: no input applied in Commit yields a valid transition.
  val commit_step_is_terminal: bool =
    (lastLine == "CommitTerminal") implies (not(lastValid) and output == ONone)

  //--------------------------------------------------------------------------
  // Observations
  //--------------------------------------------------------------------------

  /// L16: the proposer re-proposed its stored valid value with that value's pol_round.
  val proposer_reproposed_valid_value: bool = lastLine == "L16ProposeValidValue"
  /// L18: the proposer had no valid value and asked the builder for one.
  val proposer_asked_for_value: bool = lastLine == "L18GetValue"
  /// L19: the proposer emitted a freshly built proposal with a nil pol_round.
  val proposer_emitted_fresh_proposal: bool = lastLine == "L19Propose"
  /// L21: a non-proposer entered Propose and armed the propose timeout.
  val non_proposer_scheduled_propose_timeout: bool = lastLine == "L21ProposeTimeoutScheduled"
  /// L24: not locked, so the proposed value was prevoted.
  val prevoted_proposal_value_unlocked: bool = lastLine == "L24ValidNoLockedRound"
  /// L24: locked on exactly this value, so it was prevoted again.
  val prevoted_locked_value: bool = lastLine == "L24ValidAndLockedValue"
  /// L26: locked on a different value, so nil was prevoted.
  val prevoted_nil_because_locked_elsewhere: bool = lastLine == "L26ValidAndLockedValue"
  /// L26/L32: the proposal itself was invalid, so nil was prevoted.
  val prevoted_nil_on_invalid_proposal: bool = lastLine == "L26InvalidProposal"
  /// L32: an invalid proposal carrying a previous polka, so nil was prevoted.
  val prevoted_nil_on_invalid_polka_previous: bool = lastLine == "L32InvalidProposalAndPolkaPrevious"
  /// L59: the propose timeout fired before any proposal arrived.
  val prevoted_nil_on_propose_timeout: bool = lastLine == "L59TimeoutPropose"
  /// L30: unlocked for a polka at or above the lock round — the value we are NOT
  /// locked on was prevoted.
  val unlocked_for_older_polka: bool =
    lastLine == "L30ValidLockedRound" and
    (match state.locked { | NoRV => false | SomeRV(l) => output != OPrevote(VVal(l.value)) })
  /// L30: a previous-polka proposal for the very value we are locked on.
  val prevoted_previous_locked_value: bool = lastLine == "L30ValidLockedValue"
  /// L30: a previous-polka proposal while not locked at all.
  val prevoted_previous_unlocked: bool = lastLine == "L30ValidNoLockedRound"
  /// L32: locked on a different value at a higher round, so nil was prevoted.
  val prevoted_nil_locked_higher_round: bool = lastLine == "L32InvalidValue"
  /// L35: the prevote timeout was armed on the first polka-any of the round.
  val prevote_timeout_scheduled: bool = lastLine == "L35PrevoteTimeoutScheduled"
  /// L35: a repeated polka-any silently armed nothing.
  val prevote_timeout_suppressed: bool = lastLine == "L35PrevoteTimeoutSuppressed"
  /// L36: a polka for a value produced a precommit and set both locked and valid.
  val precommitted_and_locked_value: bool = lastLine == "L36ValidProposal"
  /// L45: a polka for nil produced a nil precommit.
  val precommitted_nil_on_polka_nil: bool = lastLine == "L45PrecommitNil"
  /// L61: the prevote timeout produced a nil precommit.
  val precommitted_nil_on_prevote_timeout: bool = lastLine == "L61PrecommitNil"
  /// L42: a polka arriving after we already precommitted only refreshed valid.
  val valid_value_refreshed_after_precommit: bool = lastLine == "L42SetValidValue"
  /// L48: the precommit timeout was armed on the first precommit-any of the round.
  val precommit_timeout_scheduled: bool = lastLine == "L48PrecommitTimeoutScheduled"
  /// L48: a repeated precommit-any silently armed nothing.
  val precommit_timeout_suppressed: bool = lastLine == "L48PrecommitTimeoutSuppressed"
  /// L55: +1/3 from a higher round moved us forward.
  val round_skipped_on_higher_round: bool = lastLine == "L55RoundSkip"
  /// L67: the precommit timeout ended the round.
  val round_skipped_on_precommit_timeout: bool = lastLine == "L67RoundSkip"
  /// L49: a value was decided.
  val decided_a_value: bool = lastLine == "L49Decide"
  /// L49: a second, different decision was refused.
  val conflicting_decision_rejected: bool = lastLine == "L49DecisionConflict"
  /// Any input delivered in the terminal Commit step was rejected.
  val input_rejected_in_commit_step: bool = lastLine == "CommitTerminal"
  /// The input matched no arm of the transition table.
  val input_fell_through_to_invalid: bool = lastLine == "NoArm"
  /// prevote_previous's pol_round assert would have aborted the process.
  val aborted_on_pol_round_assert: bool = lastLine == "PanicPolRoundAssert"
  /// check_timeout granted a first-time timeout for the current round.
  val timeout_check_granted: bool = lastLine == "check_timeout_granted"
  /// check_timeout denied a timeout already scheduled this round.
  val timeout_check_denied: bool = lastLine == "check_timeout_denied"
  /// check_timeout was called with an untracked kind and denied it silently.
  val untracked_timeout_check_denied: bool = lastLine == "check_timeout_untracked"
  /// A Proposal output was emitted while we were not the proposer.
  val proposal_emitted_by_non_proposer: bool = nonProposerProposed

  //--------------------------------------------------------------------------
  // Grounding run for the "locked node unlocks for an older polka" goal
  //--------------------------------------------------------------------------

  /// Locked on `w` in round 0, then in round 2 a proposal for `v` carrying a polka
  /// from round 1 (>= our lock round) makes us prevote `v`, leaving the lock intact.
  run unlockOnOlderPolkaTest =
    init
      .then(Stateapply({ input_round: 0, address: "a", proposer: "b" }, NewRound(0)))
      .then(Stateapply({ input_round: 0, address: "a", proposer: "b" },
                       Proposal({ round: 0, value: "w", polRound: -1 })))
      .then(Stateapply({ input_round: 0, address: "a", proposer: "b" },
                       ProposalAndPolkaCurrent({ round: 0, value: "w", polRound: -1 })))
      .expect(state.locked == SomeRV({ value: "w", round: 0 }))
      .then(Stateapply({ input_round: 0, address: "a", proposer: "b" }, SkipRound(2)))
      .then(Stateapply({ input_round: 2, address: "a", proposer: "b" }, NewRound(2)))
      .then(Stateapply({ input_round: 2, address: "a", proposer: "b" },
                       ProposalAndPolkaPrevious({ round: 2, value: "v", polRound: 1 })))
      .expect(output == OPrevote(VVal("v")))
      .expect(state.locked == SomeRV({ value: "w", round: 0 }))
      .expect(state.step == Prevote)
}
