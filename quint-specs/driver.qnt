// Model of `malachitebft-core-driver` — the per-height Driver that owns the vote
// keeper, the proposal keeper and the round state, multiplexes votes / proposals /
// certificates into round-state-machine inputs, and gates the node's own outgoing
// votes before returning them as driver outputs.
//
// Code under model:
//   code/crates/core-driver/src/driver.rs          (Driver, process/apply/apply_input, lift_*)
//   code/crates/core-driver/src/mux.rs             (multiplex_proposal / _vote_threshold / _step_change)
//   code/crates/core-driver/src/proposal_keeper.rs (ProposalKeeper, PerRound, EvidenceMap)
//   code/crates/core-driver/src/input.rs, output.rs, error.rs
// Dependencies modelled inline at the fidelity the driver's own decisions need:
//   the vote keeper's tally / emitted-output dedup (core-votekeeper/src/keeper.rs)
//   the round state machine's transition table (core-state-machine/src/state_machine.rs)
//
// The model MIRRORS the code, bugs included. Notably:
//   * `process` returns early (with NO outputs and pending_inputs still queued) when
//     `apply` yields `None` even though a step change already queued pending inputs
//     (driver.rs:358-380). The intent lives in `pending_inputs_always_drained`.
//   * `store_precommit_any_round_certificate` / `store_skip_round_certificate` panic
//     when the per-round entry is missing (driver.rs:631-674): modelled as a `panicked`
//     latch, with `never_panics` stating the intent.
//   * `PerRound::add` panics on proposals from two different validators in one round
//     (proposal_keeper.rs:108-119): same treatment.
module driver {

  //--------------------------------------------------------------------------
  // Domain
  //--------------------------------------------------------------------------

  /// Round::Nil is modelled as -1; Round::Some(r) as r >= 0.
  type Round = int
  type Value = str
  type Addr = str
  type Height = int

  /// state.rs Step
  type Step = Unstarted | Propose | Prevote | Precommit | Commit

  /// core_types::VoteType
  type VoteType = VTPrevote | VTPrecommit

  /// core_types::TimeoutKind
  type TimeoutKind = TKPropose | TKPrevote | TKPrecommit | TKRebroadcast | TKFinalize

  /// core_types::NilOrVal<ValueId>
  type NilOrVal = NVNil | NVVal(Value)

  /// state.rs RoundValue<Value> and its Option.
  type RoundValue = { value: Value, round: Round }
  type MaybeRV = NoRV | SomeRV(RoundValue)

  /// A Ctx::Proposal, together with the proposer that signed it.
  type Prop = { height: Height, round: Round, value: Value, polRound: Round, proposer: Addr }

  /// A SignedVote<Ctx>.
  type SVote = { height: Height, round: Round, vtype: VoteType, value: NilOrVal, addr: Addr }
  type MaybeVote = NoVote | SomeVote(SVote)
  type MaybeAddr = NoAddr | SomeAddr(Addr)

  /// ExtendedCommitCertificate / PolkaCertificate (signatures abstracted to signers).
  type CCert = { height: Height, round: Round, valueId: Value, signers: Set[Addr] }
  type PCert = { height: Height, round: Round, valueId: Value, signers: Set[Addr] }

  /// EnterRoundCertificate: which round it justifies entering, over which round's
  /// votes, and whether it is a Skip or a Precommit certificate.
  type RCert = { enterRound: Round, round: Round, ctype: str }
  type MaybeRC = NoRC | SomeRC(RCert)

  /// core-state-machine input.rs Input<Ctx>
  type RInput =
    | NoInput
    | RNewRound(Round)
    | RProposeValue(Value)
    | RProposal(Prop)
    | RInvalidProposal
    | RProposalAndPolkaPrevious(Prop)
    | RInvalidProposalAndPolkaPrevious(Prop)
    | RPolkaAny
    | RPolkaNil
    | RProposalAndPolkaCurrent(Prop)
    | RPrecommitAny
    | RProposalAndPrecommitValue(Prop)
    | RSkipRound(Round)
    | RTimeoutPropose
    | RTimeoutPrevote
    | RTimeoutPrecommit

  /// core-state-machine output.rs Output<Ctx>; RONone models `Transition.output == None`.
  type ROutput =
    | RONone
    | RONewRound(Round)
    | ROProposal(Prop)
    | ROVote(SVote)
    | ROScheduleTimeout({ round: Round, kind: TimeoutKind })
    | ROGetValueAndScheduleTimeout({ height: Height, round: Round, kind: TimeoutKind })
    | RODecision({ round: Round, prop: Prop })

  /// core-driver output.rs Output<Ctx>
  type DOutput =
    | ONewRound({ height: Height, round: Round })
    | OPropose(Prop)
    | OVote(SVote)
    | ODecide({ round: Round, prop: Prop })
    | OScheduleTimeout({ round: Round, kind: TimeoutKind })
    | OGetValue({ height: Height, round: Round, kind: TimeoutKind })

  /// core-driver input.rs Input<Ctx>
  type DInput =
    | INewRound({ height: Height, round: Round, proposer: Addr })
    | IProposeValue({ round: Round, value: Value })
    | IProposal({ prop: Prop, valid: bool })
    | IVote(SVote)
    | ICommitCertificate(CCert)
    | IPolkaCertificate(PCert)
    | ITimeoutElapsed({ round: Round, kind: TimeoutKind })
    | ISyncDecision(Prop)

  /// core-votekeeper Threshold<ValueId>
  type Threshold = THValue(Value) | THNil | THAny | THUnreached

  /// The vote keeper's emitted-output identity, as stored in `emitted_outputs`.
  /// `value` is "" and `sround` is -1 for the variants that carry neither.
  type VKOut = { tag: str, value: Value, sround: Round }

  /// The vote keeper, at the fidelity the driver's multiplexing needs.
  /// `rounds` mirrors `per_round`'s key set: an entry is created for a vote's round
  /// BEFORE the unknown-validator check, so it exists even for discarded votes.
  type VK = {
    // The validator set with its voting powers, as installed at construction or
    // move_to_height. All threshold arithmetic is over these weights.
    weights: Addr -> int,
    rounds: Set[Round],
    votes: Set[SVote],
    emitted: Set[{ round: Round, out: VKOut }],
    evidence: Set[{ existing: SVote, conflicting: SVote }],
  }

  /// core-state-machine state.rs State<Ctx>
  type SMState = {
    height: Height,
    round: Round,
    step: Step,
    locked: MaybeRV,
    valid: MaybeRV,
    decision: MaybeRV,
    scheduled: Set[TimeoutKind],
  }

  /// state_machine.rs Info<'a, Ctx>
  type Info = { inputRound: Round, address: Addr, proposer: Addr }

  /// The result of one round-state-machine `apply`.
  type SMRes = { st: SMState, out: ROutput, ok: bool, panic: bool }

  /// Two abstract symbols plus every concrete ValueId the driver's integration
  /// suite produces, rendered the way the code renders them (lower-case hex).
  pure val VALUES: Set[Value] = Set("v", "w", "2a", "64", "c8", "1e61", "22b8", "270f")
  /// The four equal-power validators of the driver's integration suite, plus "e",
  /// an address that is NOT in the validator set (the Error::ValidatorNotFound and
  /// Error::ProposerNotFound surface).
  /// Validators are logged by their INDEX in the validator set, rendered as a
  /// letter; "e" is the address that is not in the set at all.
  pure val VSET: Set[Addr] = Set("a", "b", "c", "d")
  /// The voting-power configurations the driver's integration suite installs.
  pure val DEFAULT_VSET: Addr -> int = Map("a" -> 2, "b" -> 3, "c" -> 2)
  /// The per-validator voting powers, as three scalars (0 = the slot is absent),
  /// so the whole set travels as primitive picks a logged event can pin.
  /// Every voting power the driver's integration suite installs, plus 0 for an
  /// absent slot.
  pure val WEIGHTS: Set[int] = Set(0, 1, 2, 3, 5, 6, 7, 10, 20, 50)
  pure def mkVSet(w0: int, w1: int, w2: int, w3: int): Addr -> int =
    Set(("a", w0), ("b", w1), ("c", w2), ("d", w3))
      .filter(e => e._2 > 0)
      .fold(Map(), (m, e) => m.put(e._1, e._2))
  pure val ADDRS: Set[Addr] = Set("a", "b", "c", "d", "e")
  /// Vote senders: every validator (so a quorum is reachable) plus the outsider "e".
  pure val VOTERS: Set[Addr] = Set("a", "b", "c", "d", "e")
  pure val ME: Addr = "a"
  /// A full quorum of signers, as carried by a certificate.
  pure val QUORUM_SIGNERS: Set[Addr] = Set("a", "b", "c")

  pure val HEIGHTS: Set[Height] = Set(1, 2)
  pure val ROUNDS: Set[Round] = Set(0, 1, 2, 3, 5)
  /// Includes Round::Nil so a rewind / prune down to Nil stays expressible.
  pure val ROUND_BAND: Set[Round] = Set(-1, 0, 1, 2, 3, 4, 5, 6)
  /// pol_round domain deliberately includes Nil and rounds at/above the proposal's
  /// own round, so the pol-round branches of the multiplexer stay falsifiable.
  pure val POL_ROUNDS: Set[Round] = Set(-1, 0, 1, 2, 3)

  pure val INPUT_TAGS: Set[str] = Set(
    "NewRound", "ProposeValue", "Proposal", "Vote", "CommitCertificate",
    "PolkaCertificate", "TimeoutElapsed", "SyncDecision",
  )
  pure val TIMEOUT_KINDS: Set[str] = Set("Propose", "Prevote", "Precommit", "Rebroadcast")
  pure val VOTE_TYPES: Set[str] = Set("Prevote", "Precommit")
  /// "Nil" encodes NilOrVal::Nil in the single `ivalue` pick.
  pure val VOTE_VALUES: Set[Value] = VALUES.union(Set("Nil"))

  /// Round::increment(); Round::Nil increments to Round::Some(0).
  pure def inc(r: Round): Round = r + 1

  pure def stepRank(s: Step): int =
    match s { | Unstarted => 0 | Propose => 1 | Prevote => 2 | Precommit => 3 | Commit => 4 }

  pure def kindOf(s: str): TimeoutKind =
    if (s == "Propose") TKPropose
    else if (s == "Prevote") TKPrevote
    else if (s == "Precommit") TKPrecommit
    else TKRebroadcast

  pure def voteTypeOf(s: str): VoteType = if (s == "Precommit") VTPrecommit else VTPrevote
  pure def nilOrValOf(v: Value): NilOrVal = if (v == "Nil") NVNil else NVVal(v)

  pure def rvValue(m: MaybeRV): Value = match m { | NoRV => "" | SomeRV(rv) => rv.value }
  pure def rvRound(m: MaybeRV): Round = match m { | NoRV => -1 | SomeRV(rv) => rv.round }
  pure def isSome(m: MaybeRV): bool = match m { | NoRV => false | SomeRV(_) => true }

  //--------------------------------------------------------------------------
  // Vote keeper (core-votekeeper/src/keeper.rs), at driver fidelity
  //--------------------------------------------------------------------------

  pure def newVK(weights: Addr -> int): VK =
    { weights: weights, rounds: Set(), votes: Set(), emitted: Set(), evidence: Set() }

  pure def totalWeight(vk: VK): int =
    vk.weights.keys().fold(0, (acc, a) => acc + vk.weights.get(a))

  pure def votesIn(vk: VK, r: Round): Set[SVote] = vk.votes.filter(v => v.round == r)

  pure def sumWeights(vk: VK, addrs: Set[Addr]): int =
    addrs.fold(0, (acc, a) => acc + vk.weights.get(a))

  pure def weightFor(vk: VK, r: Round, t: VoteType, nv: NilOrVal): int =
    sumWeights(vk, votesIn(vk, r).filter(v => v.vtype == t and v.value == nv).map(v => v.addr))

  pure def weightSum(vk: VK, r: Round, t: VoteType): int =
    sumWeights(vk, votesIn(vk, r).filter(v => v.vtype == t).map(v => v.addr))

  /// `addresses_weights.sum()`: the weight of the addresses heard from in the round.
  pure def addressWeight(vk: VK, r: Round): int =
    sumWeights(vk, votesIn(vk, r).map(v => v.addr))

  /// ThresholdParams::quorum — strictly more than 2/3 of the total voting power.
  pure def quorumMet(vk: VK, w: int): bool = 3 * w > 2 * totalWeight(vk)
  /// ThresholdParams::honest — strictly more than 1/3 (f+1).
  pure def honestMet(vk: VK, w: int): bool = 3 * w > totalWeight(vk)

  /// keeper.rs is_threshold_met — false when the round has no per_round entry.
  pure def thresholdMet(vk: VK, r: Round, t: VoteType, th: Threshold): bool =
    if (not(vk.rounds.contains(r))) false
    else match th {
      | THValue(v) => quorumMet(vk, weightFor(vk, r, t, NVVal(v)))
      | THNil      => quorumMet(vk, weightFor(vk, r, t, NVNil))
      | THAny      => quorumMet(vk, weightSum(vk, r, t))
      | THUnreached => false
    }

  /// keeper.rs compute_threshold
  pure def computeThreshold(vk: VK, r: Round, t: VoteType, nv: NilOrVal): Threshold =
    match nv {
      | NVVal(v) =>
          if (quorumMet(vk, weightFor(vk, r, t, nv)) ) THValue(v)
          else if (quorumMet(vk, weightSum(vk, r, t))) THAny else THUnreached
      | NVNil =>
          if (quorumMet(vk, weightFor(vk, r, t, nv))) THNil
          else if (quorumMet(vk, weightSum(vk, r, t))) THAny else THUnreached
    }

  pure val noVKOut: VKOut = { tag: "None", value: "", sround: -1 }

  /// keeper.rs threshold_to_output
  pure def thresholdToOutput(t: VoteType, th: Threshold, futureRound: Round): VKOut =
    if (futureRound >= 0)
      // Only PrecommitValue(v) has larger priority than SkipRound(r).
      match th {
        | THValue(v) =>
            if (t == VTPrecommit) { tag: "PrecommitValue", value: v, sround: -1 }
            else { tag: "SkipRound", value: "", sround: futureRound }
        | _ => { tag: "SkipRound", value: "", sround: futureRound }
      }
    else
      match th {
        | THUnreached => noVKOut
        | THAny  => if (t == VTPrevote) { tag: "PolkaAny", value: "", sround: -1 }
                    else { tag: "PrecommitAny", value: "", sround: -1 }
        | THNil  => if (t == VTPrevote) { tag: "PolkaNil", value: "", sround: -1 }
                    else { tag: "PrecommitAny", value: "", sround: -1 }
        | THValue(v) => if (t == VTPrevote) { tag: "PolkaValue", value: v, sround: -1 }
                        else { tag: "PrecommitValue", value: v, sround: -1 }
      }

  /// The vote already recorded from this validator, for this round and vote type.
  pure def existingVote(vk: VK, v: SVote): MaybeVote =
    val same = votesIn(vk, v.round).filter(o => o.vtype == v.vtype and o.addr == v.addr)
    if (same.size() == 0) NoVote else SomeVote(same.fold(v, (_, o) => o))

  /// keeper.rs apply_vote: records the vote, returns the (deduplicated) output.
  pure def vkApplyVote(vk0: VK, v: SVote, curRound: Round): { vk: VK, out: VKOut } =
    // The per_round entry is created before the validator-set check.
    val vk1 = { ...vk0, rounds: vk0.rounds.union(Set(v.round)) }
    if (not(vk1.weights.keys().contains(v.addr)))
      { vk: vk1, out: noVKOut }
    else
      match existingVote(vk1, v) {
        | SomeVote(prev) =>
            if (prev.value != v.value)
              // Equivocating vote: recorded as evidence, no output.
              { vk: { ...vk1, evidence: vk1.evidence.union(Set({ existing: prev, conflicting: v })) },
                out: noVKOut }
            else
              // Exact duplicate: not re-tallied, but the threshold is recomputed.
              vkTally(vk1, v, curRound)
        | NoVote => vkTally({ ...vk1, votes: vk1.votes.union(Set(v)) }, v, curRound)
      }

  pure def vkTally(vk: VK, v: SVote, curRound: Round): { vk: VK, out: VKOut } =
    val th = computeThreshold(vk, v.round, v.vtype, v.value)
    val skipRound =
      if (v.round > curRound and honestMet(vk, addressWeight(vk, v.round))) v.round else -1
    val out = thresholdToOutput(v.vtype, th, skipRound)
    if (out.tag == "None" or vk.emitted.contains({ round: v.round, out: out }))
      { vk: vk, out: noVKOut }
    else
      { vk: { ...vk, emitted: vk.emitted.union(Set({ round: v.round, out: out })) }, out: out }

  /// keeper.rs prune_votes
  pure def vkPrune(vk: VK, minRound: Round): VK = {
    ...vk,
    rounds: vk.rounds.filter(r => r >= minRound),
    votes: vk.votes.filter(v => v.round >= minRound),
    emitted: vk.emitted.filter(e => e.round >= minRound),
  }

  /// driver.rs restore_precommits
  pure def restorePrecommits(vk: VK, r: Round, valueId: Value): Set[SVote] =
    if (not(vk.rounds.contains(r))) Set()
    else votesIn(vk, r).filter(v => v.vtype == VTPrecommit and v.value == NVVal(valueId))

  //--------------------------------------------------------------------------
  // Round state machine (core-state-machine/src/state_machine.rs)
  //--------------------------------------------------------------------------

  pure def smNew(h: Height, r: Round): SMState =
    { height: h, round: r, step: Unstarted, locked: NoRV, valid: NoRV, decision: NoRV,
      scheduled: Set() }

  /// state.rs update_round — clears the scheduled-timeout bits.
  pure def updateRound(s: SMState, r: Round): SMState = { ...s, round: r, scheduled: Set() }
  pure def withStep(s: SMState, st: Step): SMState = { ...s, step: st }
  pure def setLocked(s: SMState, v: Value): SMState =
    { ...s, locked: SomeRV({ value: v, round: s.round }) }
  pure def setValid(s: SMState, v: Value): SMState =
    { ...s, valid: SomeRV({ value: v, round: s.round }) }

  /// state.rs ScheduledTimeouts::check — true (and records) the first time only.
  pure def checkTimeout(s: SMState, k: TimeoutKind): bool = not(s.scheduled.contains(k))
  pure def markTimeout(s: SMState, k: TimeoutKind): SMState =
    { ...s, scheduled: s.scheduled.union(Set(k)) }

  /// state_machine.rs is_valid_pol_round
  pure def isValidPolRound(s: SMState, p: Prop): bool =
    p.polRound >= 0 and p.polRound < s.round and p.polRound < p.round

  pure def ok(s: SMState, o: ROutput): SMRes = { st: s, out: o, ok: true, panic: false }
  pure def invalidT(s: SMState): SMRes = { st: s, out: RONone, ok: false, panic: false }

  pure def mkVote(s: SMState, t: VoteType, nv: NilOrVal, a: Addr): SVote =
    { height: s.height, round: s.round, vtype: t, value: nv, addr: a }

  /// L13-L16, L19 — propose_valid_or_get_value.
  pure def proposeValidOrGetValue(s: SMState, a: Addr): SMRes =
    match s.valid {
      | SomeRV(rv) =>
          ok(withStep(s, Propose),
             ROProposal({ height: s.height, round: s.round, value: rv.value,
                          polRound: rv.round, proposer: a }))
      | NoRV =>
          // debug_assert!(state.check_timeout(Propose)) — under test builds the
          // assertion runs, so the Propose timeout IS recorded as scheduled.
          ok(withStep(markTimeout(s, TKPropose), Propose),
             ROGetValueAndScheduleTimeout({ height: s.height, round: s.round, kind: TKPropose }))
    }

  /// L13, L17-L18 — propose.
  pure def proposeValue(s: SMState, v: Value, a: Addr): SMRes =
    ok(withStep(s, Propose),
       ROProposal({ height: s.height, round: s.round, value: v, polRound: -1, proposer: a }))

  /// L22/L24 — prevote. `assert_eq!(vr, Round::Nil)`.
  pure def prevote(s: SMState, a: Addr, p: Prop): SMRes =
    val value = match s.locked {
      | SomeRV(l) => if (l.value == p.value) NVVal(p.value) else NVNil
      | NoRV => NVVal(p.value)
    }
    val r = ok(withStep(s, Prevote), ROVote(mkVote(s, VTPrevote, value, a)))
    if (p.polRound != -1) { ...r, panic: true } else r

  /// L28/L30 — prevote_previous. `assert!(vr >= 0)` and `assert!(vr < proposal.round())`.
  pure def prevotePrevious(s: SMState, a: Addr, p: Prop): SMRes =
    val value = match s.locked {
      | SomeRV(l) =>
          if (l.round <= p.polRound) NVVal(p.value)
          else if (l.value == p.value) NVVal(p.value)
          else NVNil
      | NoRV => NVVal(p.value)
    }
    val r = ok(withStep(s, Prevote), ROVote(mkVote(s, VTPrevote, value, a)))
    if (p.polRound < 0 or p.polRound >= p.round) { ...r, panic: true } else r

  /// L22/L25, L28/L31, L57 — prevote_nil.
  pure def prevoteNil(s: SMState, a: Addr): SMRes =
    ok(withStep(s, Prevote), ROVote(mkVote(s, VTPrevote, NVNil, a)))

  /// L36/L37 — precommit. A no-op transition when we are no longer at Prevote.
  pure def precommit(s: SMState, a: Addr, p: Prop): SMRes =
    if (s.step != Prevote) ok(s, RONone)
    else
      ok(withStep(setValid(setLocked(s, p.value), p.value), Precommit),
         ROVote(mkVote(s, VTPrecommit, NVVal(p.value), a)))

  /// L44, L61 — precommit_nil.
  pure def precommitNil(s: SMState, a: Addr): SMRes =
    ok(withStep(s, Precommit), ROVote(mkVote(s, VTPrecommit, NVNil, a)))

  /// L11/L20 — schedule_timeout_propose.
  pure def scheduleTimeoutPropose(s: SMState): SMRes =
    ok(withStep(markTimeout(s, TKPropose), Propose),
       ROScheduleTimeout({ round: s.round, kind: TKPropose }))

  /// L34/L35 — schedule_timeout_prevote (at most once per round).
  pure def scheduleTimeoutPrevote(s: SMState): SMRes =
    if (checkTimeout(s, TKPrevote))
      ok(markTimeout(s, TKPrevote), ROScheduleTimeout({ round: s.round, kind: TKPrevote }))
    else ok(s, RONone)

  /// L47/L48 — schedule_timeout_precommit (at most once per round).
  pure def scheduleTimeoutPrecommit(s: SMState): SMRes =
    if (checkTimeout(s, TKPrecommit))
      ok(markTimeout(s, TKPrecommit), ROScheduleTimeout({ round: s.round, kind: TKPrecommit }))
    else ok(s, RONone)

  /// L36/L42 — set_valid_value.
  pure def setValidValue(s: SMState, p: Prop): SMRes = ok(setValid(s, p.value), RONone)

  /// L55, L65 — round_skip.
  pure def roundSkip(s: SMState, r: Round): SMRes =
    ok(withStep(updateRound(s, r), Unstarted), RONewRound(r))

  /// L49 — commit.
  pure def commitOn(s: SMState, r: Round, p: Prop): SMRes =
    match s.decision {
      | SomeRV(dec) => if (dec.value == p.value) ok(s, RONone) else invalidT(s)
      | NoRV =>
          ok(withStep({ ...s, decision: SomeRV({ value: p.value, round: p.round }) }, Commit),
             RODecision({ round: r, prop: p }))
    }

  /// state_machine.rs apply — the transition table, arm order preserved.
  pure def smApply(s: SMState, info: Info, inp: RInput): SMRes =
    val thisRound = info.inputRound == s.round
    val isProposer = info.address == info.proposer
    match inp {
      | RNewRound(r) =>
          if (s.step == Unstarted and r >= s.round and isProposer)
            proposeValidOrGetValue(updateRound(s, r), info.address)
          else if (s.step == Unstarted and r >= s.round)
            scheduleTimeoutPropose(updateRound(s, r))
          else invalidT(s)
      | RProposeValue(v) =>
          if (s.step == Propose and thisRound and isProposer) proposeValue(s, v, info.address)
          else invalidT(s)
      | RProposal(p) =>
          if (s.step == Propose and thisRound and p.polRound == -1) prevote(s, info.address, p)
          else invalidT(s)
      | RInvalidProposal =>
          if (s.step == Propose and thisRound) prevoteNil(s, info.address) else invalidT(s)
      | RProposalAndPolkaPrevious(p) =>
          if (s.step == Propose and thisRound and isValidPolRound(s, p))
            prevotePrevious(s, info.address, p)
          else invalidT(s)
      | RInvalidProposalAndPolkaPrevious(p) =>
          if (s.step == Propose and thisRound and isValidPolRound(s, p))
            prevoteNil(s, info.address)
          else invalidT(s)
      | RTimeoutPropose =>
          if (s.step == Propose and thisRound) prevoteNil(s, info.address) else invalidT(s)
      | RPolkaAny =>
          if (s.step == Prevote and thisRound) scheduleTimeoutPrevote(s) else invalidT(s)
      | RPolkaNil =>
          if (s.step == Prevote and thisRound) precommitNil(s, info.address) else invalidT(s)
      | RProposalAndPolkaCurrent(p) =>
          if (s.step == Prevote and thisRound) precommit(s, info.address, p)
          else if (s.step == Precommit and thisRound) setValidValue(s, p)
          else invalidT(s)
      | RTimeoutPrevote =>
          if (s.step == Prevote and thisRound) precommitNil(s, info.address) else invalidT(s)
      | RPrecommitAny =>
          if (s.step != Commit and thisRound) scheduleTimeoutPrecommit(s) else invalidT(s)
      | RTimeoutPrecommit =>
          if (s.step != Commit and thisRound) roundSkip(s, inc(info.inputRound)) else invalidT(s)
      | RSkipRound(r) =>
          if (s.step != Commit and s.round < r) roundSkip(s, r) else invalidT(s)
      | RProposalAndPrecommitValue(p) =>
          if (s.step != Commit) commitOn(s, p.round, p) else invalidT(s)
      | NoInput => invalidT(s)
    }

  //--------------------------------------------------------------------------
  // The Driver itself
  //--------------------------------------------------------------------------

  type StoredProp = { prop: Prop, valid: bool }

  type Driver = {
    address: Addr,
    validatorSet: Addr -> int,
    proposer: MaybeAddr,
    // ProposalKeeper::per_round, flattened; insertion order is preserved so that
    // "the first proposal of a round" is well defined.
    props: List[StoredProp],
    propEvidence: Set[{ existing: Prop, conflicting: Prop }],
    vk: VK,
    commitCerts: List[CCert],
    polkaCerts: List[PCert],
    rs: SMState,
    pending: List[{ round: Round, input: RInput }],
    lastPrevote: MaybeVote,
    lastPrecommit: MaybeVote,
    roundCert: MaybeRC,

    // ---- ghosts (not code state; they make silent behaviour observable) ----
    // The driver outputs the most recent `process` call returned.
    outputs: List[DOutput],
    // The Error variant the most recent operation produced, "" for Ok.
    lastError: str,
    // True once a `process` call has returned Ok.
    processReturnedOk: bool,
    // Latched when an assert!/panic! in the modelled code would have fired.
    panicked: bool,
    // Latched when `lift_vote_output` suppressed one of our own votes,
    // split by which half of the gate rejected it.
    voteSuppressedMonotonic: bool,
    voteSuppressedValidMismatch: bool,
    // Latched when apply_new_round dropped a NewRound for an already-left round.
    staleNewRoundIgnored: bool,
    // Latched when the bounded drain of pending_inputs ran out of fuel.
    fuelExhausted: bool,
    // Latched when a prune actually dropped a round of votes or a polka certificate.
    prunedSomething: bool,
    // Latched when a stored proposal's validity was upgraded Invalid -> Valid.
    validityUpgraded: bool,
    // The number of driver outputs the most recent process call returned.
    outputCount: int,
    // stepRank of the current round-state step, as a scalar the oracle can pin.
    stepRankNow: int,
    // Every own vote we have ever emitted, in order.
    castVotes: List[SVote],
    // SyncDecision decisions we have taken: (round, value).
    syncDecided: Set[{ round: Round, value: Value }],
    // Lineage: the first decision ever recorded at the current height, and the
    // height it was recorded at.
    firstDecision: MaybeRV,
    firstDecisionHeight: Height,
    // Lineage: steps taken since the last move_to_height (0 == just reset).
    sinceMove: int,
    // Lineage: the step reached at the moment the current height first committed.
    everCommittedHeight: Height,
  }

  var d: Driver

  //--------------------------------------------------------------------------
  // Queries (driver.rs / proposal_keeper.rs read paths)
  //--------------------------------------------------------------------------

  pure def height(dr: Driver): Height = dr.rs.height
  pure def curRound(dr: Driver): Round = dr.rs.round

  /// ProposalKeeper::get_proposals_and_validities_for_round
  pure def propsForRound(dr: Driver, r: Round): List[StoredProp] =
    dr.props.select(sp => sp.prop.round == r)

  /// PerRound::get_first_proposal_and_validity — the FIRST match wins.
  pure def propForRoundValue(dr: Driver, r: Round, v: Value): List[StoredProp] =
    propsForRound(dr, r).select(sp => sp.prop.value == v)

  pure def hasPropForRoundValue(dr: Driver, r: Round, v: Value): bool =
    propForRoundValue(dr, r, v).length() > 0

  /// driver.rs valid_proposal_for_round_and_value
  pure def hasValidPropForRoundValue(dr: Driver, r: Round, v: Value): bool =
    val l = propForRoundValue(dr, r, v)
    l.length() > 0 and l.head().valid

  /// driver.rs commit_certificate / polka_certificate (height-scoped).
  pure def hasCommitCert(dr: Driver, r: Round, v: Value): bool =
    dr.commitCerts.select(c => c.round == r and c.valueId == v and c.height == height(dr)).length() > 0

  pure def hasPolkaCert(dr: Driver, r: Round, v: Value): bool =
    dr.polkaCerts.select(c => c.round == r and c.valueId == v and c.height == height(dr)).length() > 0

  /// driver.rs get_proposer: NoProposer when unset, ProposerNotFound when the
  /// stored address is not in the validator set.
  pure def proposerError(dr: Driver): str =
    match dr.proposer {
      | NoAddr => "NoProposer"
      | SomeAddr(a) => if (dr.validatorSet.keys().contains(a)) "" else "ProposerNotFound"
    }

  pure def proposerAddr(dr: Driver): Addr =
    match dr.proposer { | NoAddr => "" | SomeAddr(a) => a }

  //--------------------------------------------------------------------------
  // The multiplexer (mux.rs)
  //--------------------------------------------------------------------------

  type MaybeRI = NoRI | SomeRI(RInput)

  /// mux.rs multiplex_proposal
  pure def multiplexProposal(dr: Driver, p: Prop, valid: bool): MaybeRI =
    if (dr.rs.round == -1) NoRI
    else
      val polkaPrevious =
        p.polRound >= 0 and p.polRound < dr.rs.round and
        (hasPolkaCert(dr, p.polRound, p.value) or
         thresholdMet(dr.vk, p.polRound, VTPrevote, THValue(p.value)))
      if (not(valid))
        if (dr.rs.step == Propose)
          if (p.polRound == -1) SomeRI(RInvalidProposal)
          else if (polkaPrevious) SomeRI(RInvalidProposalAndPolkaPrevious(p))
          else NoRI
        else NoRI
      else if (not(isSome(dr.rs.decision)) and hasCommitCert(dr, p.round, p.value))
        SomeRI(RProposalAndPrecommitValue(p))
      else if (thresholdMet(dr.vk, p.round, VTPrecommit, THValue(p.value))
               and not(isSome(dr.rs.decision)))
        SomeRI(RProposalAndPrecommitValue(p))
      else if (dr.rs.round != p.round) NoRI
      else
        val polkaForCurrent =
          hasPolkaCert(dr, p.round, p.value) or
          thresholdMet(dr.vk, p.round, VTPrevote, THValue(p.value))
        val polkaCurrent = polkaForCurrent and stepRank(dr.rs.step) >= stepRank(Prevote)
        if (polkaCurrent) SomeRI(RProposalAndPolkaCurrent(p))
        else if (dr.rs.step == Propose and polkaPrevious) SomeRI(RProposalAndPolkaPrevious(p))
        else if (p.polRound == -1) SomeRI(RProposal(p))
        else NoRI

  /// mux.rs multiplex_vote_threshold
  pure def multiplexVoteThreshold(dr: Driver, out: VKOut, tRound: Round): { round: Round, input: RInput } =
    if (out.tag == "PolkaAny") { round: tRound, input: RPolkaAny }
    else if (out.tag == "PolkaNil") { round: tRound, input: RPolkaNil }
    else if (out.tag == "PrecommitAny") { round: tRound, input: RPrecommitAny }
    else if (out.tag == "SkipRound") { round: tRound, input: RSkipRound(out.sround) }
    else if (out.tag == "PrecommitValue")
      if (hasValidPropForRoundValue(dr, tRound, out.value))
        { round: tRound, input: RProposalAndPrecommitValue(propForRoundValue(dr, tRound, out.value).head().prop) }
      else if (tRound > curRound(dr)) { round: tRound, input: RSkipRound(tRound) }
      else { round: tRound, input: RPrecommitAny }
    else if (out.tag == "PolkaValue")
      // NOTE: the proposal is looked up at the CURRENT round, not the threshold round.
      val l = propForRoundValue(dr, curRound(dr), out.value)
      if (l.length() == 0) { round: tRound, input: RPolkaAny }
      else
        val sp = l.head()
        val p = sp.prop
        val polMatch = p.polRound == tRound
        val roundMatch = p.round == tRound
        if (p.polRound >= 0 and not(sp.valid) and polMatch)
          { round: p.round, input: RInvalidProposalAndPolkaPrevious(p) }
        else if (p.polRound >= 0 and sp.valid and polMatch)
          { round: p.round, input: RProposalAndPolkaPrevious(p) }
        else if (roundMatch and sp.valid)
          { round: tRound, input: RProposalAndPolkaCurrent(p) }
        else { round: tRound, input: RPolkaAny }
    else { round: tRound, input: NoInput }

  /// mux.rs find_non_value_threshold
  pure def nonValueThresholds(dr: Driver, r: Round): List[VKOut] =
    val polka =
      if (thresholdMet(dr.vk, r, VTPrevote, THNil)) List({ tag: "PolkaNil", value: "", sround: -1 })
      else if (thresholdMet(dr.vk, r, VTPrevote, THAny)) List({ tag: "PolkaAny", value: "", sround: -1 })
      else List()
    if (thresholdMet(dr.vk, r, VTPrecommit, THAny))
      polka.append({ tag: "PrecommitAny", value: "", sround: -1 })
    else polka

  /// mux.rs multiplex_step_change
  pure def multiplexStepChange(dr: Driver, r: Round): List[{ round: Round, input: RInput }] =
    val fromProposals =
      propsForRound(dr, r).foldl(List(), (acc, sp) =>
        if (dr.rs.step == Propose)
          match multiplexProposal(dr, sp.prop, sp.valid) {
            | SomeRI(i) => acc.append({ round: curRound(dr), input: i })
            | NoRI => acc
          }
        else if (dr.rs.step == Prevote and
                 (thresholdMet(dr.vk, r, VTPrevote, THValue(sp.prop.value))
                  or hasPolkaCert(dr, r, sp.prop.value)))
          acc.append(multiplexVoteThreshold(dr, { tag: "PolkaValue", value: sp.prop.value, sround: -1 }, r))
        else acc)
    val withThresholds =
      nonValueThresholds(dr, r).foldl(fromProposals, (acc, t) =>
        acc.append(multiplexVoteThreshold(dr, t, r)))
    val hasPolkaInput =
      withThresholds.select(e => match e.input {
        | RPolkaAny => true | RProposalAndPolkaCurrent(_) => true | _ => false
      }).length() > 0
    if (dr.rs.step == Prevote and not(hasPolkaInput)
        and dr.polkaCerts.select(c => c.round == r).length() > 0)
      withThresholds.append({ round: r, input: RPolkaAny })
    else withThresholds

  //--------------------------------------------------------------------------
  // Proposal keeper (proposal_keeper.rs)
  //--------------------------------------------------------------------------

  /// ProposalKeeper::store_proposal + PerRound::add.
  /// `equiv` mirrors StoreProposalResult::Equivocation.
  pure def storeProposal(dr: Driver, p: Prop, valid: bool): { d: Driver, equiv: bool } =
    val inRound = propsForRound(dr, p.round)
    if (inRound.select(sp => sp.prop == p and sp.valid == valid).length() > 0)
      // Exact duplicate: Stored, nothing changes.
      { d: dr, equiv: false }
    else
      // verify_same_validator: a proposal from a DIFFERENT validator in the same
      // round is a hard panic in the code.
      val wrongValidator = inRound.length() > 0 and inRound.head().prop.proposer != p.proposer
      val upgraded =
        inRound.select(sp => sp.prop == p and not(sp.valid)).length() > 0 and valid
      val dr1 =
        if (inRound.select(sp => sp.prop == p).length() > 0)
          // update_validity: Invalid -> Valid upgrades; Valid -> Invalid is refused.
          { ...dr, props: dr.props.foldl(List(), (acc, sp) =>
              if (sp.prop == p and not(sp.valid) and valid) acc.append({ ...sp, valid: true })
              else acc.append(sp)) }
        else { ...dr, props: dr.props.append({ prop: p, valid: valid }) }
      val equiv = propsForRound(dr1, p.round).length() > 1
      { d: { ...dr1, panicked: dr1.panicked or wrongValidator,
             validityUpgraded: dr1.validityUpgraded or upgraded }, equiv: equiv }

  /// ProposalKeeper::record_evidence (EvidenceMap::add deduplicates).
  pure def recordEvidence(dr: Driver, existing: Prop, conflicting: Prop): Driver =
    { ...dr, propEvidence: dr.propEvidence.union(Set({ existing: existing, conflicting: conflicting })) }

  //--------------------------------------------------------------------------
  // Certificate storage (driver.rs)
  //--------------------------------------------------------------------------

  pure def storePolkaCertificate(dr: Driver, voteRound: Round, valueId: Value): Driver =
    if (not(dr.vk.rounds.contains(voteRound))) dr
    else
      { ...dr, polkaCerts: dr.polkaCerts.append({
          height: height(dr), round: voteRound, valueId: valueId,
          signers: votesIn(dr.vk, voteRound)
                     .filter(v => v.vtype == VTPrevote and v.value == NVVal(valueId))
                     .map(v => v.addr) }) }

  /// PANICS when the per-round entry is missing (driver.rs:631-641).
  pure def storePrecommitAnyRoundCertificate(dr: Driver, voteRound: Round): Driver =
    if (not(dr.vk.rounds.contains(voteRound))) { ...dr, panicked: true }
    else { ...dr, roundCert: SomeRC({ enterRound: inc(voteRound), round: voteRound, ctype: "Precommit" }) }

  /// PANICS when the per-round entry is missing (driver.rs:656-666).
  pure def storeSkipRoundCertificate(dr: Driver, voteRound: Round): Driver =
    if (not(dr.vk.rounds.contains(voteRound))) { ...dr, panicked: true }
    else { ...dr, roundCert: SomeRC({ enterRound: voteRound, round: voteRound, ctype: "Skip" }) }

  /// driver.rs ensure_precommit_round_certificate
  pure def ensurePrecommitRoundCertificate(dr: Driver, r: Round): Driver =
    if (thresholdMet(dr.vk, r, VTPrecommit, THAny)) storePrecommitAnyRoundCertificate(dr, r)
    else if (dr.commitCerts.select(c => c.round == r and c.height == height(dr)).length() > 0)
      { ...dr, roundCert: SomeRC({ enterRound: inc(r), round: r, ctype: "Precommit" }) }
    else dr

  //--------------------------------------------------------------------------
  // apply_input / with_round_state (driver.rs)
  //--------------------------------------------------------------------------

  /// The result of one fallible driver step: the (possibly mutated) driver, the
  /// round-state-machine output if any, and the Error variant name ("" for Ok).
  type DRes = { d: Driver, out: ROutput, err: str }

  /// driver.rs apply_input — get_proposer() first (it can fail), then the
  /// atomic with_round_state swap, then the step-change multiplexing.
  pure def applyInput(dr: Driver, inputRound: Round, inp: RInput): DRes =
    val perr = proposerError(dr)
    if (perr != "") { d: { ...dr, lastError: perr }, out: RONone, err: perr }
    else
      val prevStep = dr.rs.step
      val res = smApply(dr.rs, { inputRound: inputRound, address: dr.address,
                                 proposer: proposerAddr(dr) }, inp)
      val dr1 = { ...dr, rs: res.st, panicked: dr.panicked or res.panic }
      val dr2 =
        if (prevStep != dr1.rs.step and dr1.rs.step != Unstarted)
          { ...dr1, pending: multiplexStepChange(dr1, inputRound) }
        else dr1
      { d: dr2, out: res.out, err: "" }

  //--------------------------------------------------------------------------
  // lift_output / lift_vote_output (driver.rs:382-436)
  //--------------------------------------------------------------------------

  /// driver.rs set_last_vote_cast — asserts the height matches; only records the
  /// vote when it is for the round we are currently at.
  pure def setLastVoteCast(dr: Driver, v: SVote): Driver =
    val dp = { ...dr, panicked: dr.panicked or (v.height != height(dr)) }
    if (v.round != curRound(dr)) dp
    else if (v.vtype == VTPrevote) { ...dp, lastPrevote: SomeVote(v) }
    else { ...dp, lastPrecommit: SomeVote(v) }

  pure def voteMonotonic(prev: MaybeVote, v: SVote): bool =
    match prev {
      | NoVote => true
      | SomeVote(p) => p.height < v.height or p.round < v.round or p == v
    }

  /// driver.rs lift_vote_output — the own-vote safety gate.
  pure def liftVoteOutput(dr: Driver, v: SVote, outs: List[DOutput]): { d: Driver, outs: List[DOutput] } =
    if (v.addr != dr.address) { d: dr, outs: outs }
    else
      val goodMonotonic =
        if (v.vtype == VTPrevote) voteMonotonic(dr.lastPrevote, v)
        else voteMonotonic(dr.lastPrecommit, v)
      val matchValid =
        if (v.vtype == VTPrecommit)
          match dr.rs.valid {
            | NoRV => true
            | SomeRV(valid) => match v.value { | NVVal(id) => valid.value == id | NVNil => true }
          }
        else true
      if (goodMonotonic and matchValid)
        { d: { ...setLastVoteCast(dr, v), castVotes: dr.castVotes.append(v) },
          outs: outs.append(OVote(v)) }
      else
        { d: { ...dr,
               voteSuppressedMonotonic: dr.voteSuppressedMonotonic or not(goodMonotonic),
               voteSuppressedValidMismatch: dr.voteSuppressedValidMismatch or not(matchValid) },
          outs: outs }

  /// driver.rs lift_output
  pure def liftOutput(dr: Driver, ro: ROutput, outs: List[DOutput]): { d: Driver, outs: List[DOutput] } =
    match ro {
      | RONone => { d: dr, outs: outs }
      | RONewRound(r) => { d: dr, outs: outs.append(ONewRound({ height: height(dr), round: r })) }
      | ROProposal(p) => { d: dr, outs: outs.append(OPropose(p)) }
      | ROVote(v) => liftVoteOutput(dr, v, outs)
      | ROScheduleTimeout(t) => { d: dr, outs: outs.append(OScheduleTimeout(t)) }
      | ROGetValueAndScheduleTimeout(g) =>
          { d: dr, outs: outs
              .append(OScheduleTimeout({ round: g.round, kind: g.kind }))
              .append(OGetValue({ height: g.height, round: g.round, kind: g.kind })) }
      | RODecision(dec) => { d: dr, outs: outs.append(ODecide(dec)) }
    }

  //--------------------------------------------------------------------------
  // apply (driver.rs:441-560) — one arm per Input variant
  //--------------------------------------------------------------------------

  pure def applyCommitCertificate(dr: Driver, c: CCert): DRes =
    if (height(dr) != c.height)
      { d: { ...dr, lastError: "InvalidCertificateHeight" }, out: RONone,
        err: "InvalidCertificateHeight" }
    else
      // A future-round commit certificate justifies entering that round; stored
      // BEFORE the mux consumes the certificate.
      val dr1 =
        if (c.round > curRound(dr))
          { ...dr, roundCert: SomeRC({ enterRound: c.round, round: c.round, ctype: "Skip" }) }
        else dr
      // apply_commit_certificate_votes: each precommit is fed to the vote keeper.
      val dr2 = { ...dr1, vk: c.signers.fold(dr1.vk, (vk, a) =>
          vkApplyVote(vk, { height: c.height, round: c.round, vtype: VTPrecommit,
                            value: NVVal(c.valueId), addr: a }, curRound(dr1)).vk) }
      val dr3 = { ...dr2, commitCerts: dr2.commitCerts.append(c) }
      val ri =
        if (hasValidPropForRoundValue(dr3, c.round, c.valueId))
          RProposalAndPrecommitValue(propForRoundValue(dr3, c.round, c.valueId).head().prop)
        else if (c.round > curRound(dr3)) RSkipRound(c.round)
        else RPrecommitAny
      applyInput(dr3, c.round, ri)

  pure def applyPolkaCertificate(dr: Driver, c: PCert): DRes =
    if (height(dr) != c.height)
      { d: { ...dr, lastError: "InvalidCertificateHeight" }, out: RONone,
        err: "InvalidCertificateHeight" }
    else
      val dr1 =
        if (c.round > curRound(dr))
          { ...dr, roundCert: SomeRC({ enterRound: c.round, round: c.round, ctype: "Skip" }) }
        else dr
      val dr2 = { ...dr1, vk: c.signers.fold(dr1.vk, (vk, a) =>
          vkApplyVote(vk, { height: c.height, round: c.round, vtype: VTPrevote,
                            value: NVVal(c.valueId), addr: a }, curRound(dr1)).vk) }
      val dr3 =
        if (dr2.polkaCerts.select(e => e.round == c.round and e.valueId == c.valueId).length() > 0) dr2
        else { ...dr2, polkaCerts: dr2.polkaCerts.append(c) }
      if (c.round > curRound(dr3)) applyInput(dr3, c.round, RSkipRound(c.round))
      else
        // NOTE: the proposal lookup uses the CURRENT round, not the certificate round.
        val l = propForRoundValue(dr3, curRound(dr3), c.valueId)
        if (l.length() == 0) applyInput(dr3, c.round, RPolkaAny)
        else
          val sp = l.head()
          val p = sp.prop
          if (sp.valid)
            if (p.polRound == c.round) applyInput(dr3, p.round, RProposalAndPolkaPrevious(p))
            else if (p.round == c.round) applyInput(dr3, p.round, RProposalAndPolkaCurrent(p))
            else { d: dr3, out: RONone, err: "" }
          else if (p.polRound == c.round)
            applyInput(dr3, p.round, RInvalidProposalAndPolkaPrevious(p))
          else { d: dr3, out: RONone, err: "" }

  pure def applyNewRound(dr: Driver, h: Height, r: Round, proposer: Addr): DRes =
    if (height(dr) == h and r < dr.rs.round)
      // Stale NewRound for a round we already left: silently ignored.
      { d: { ...dr, staleNewRoundIgnored: true }, out: RONone, err: "" }
    else
      val dr1 =
        if (height(dr) == h) { ...dr, rs: { ...dr.rs, round: r } }
        else { ...dr, rs: smNew(h, r) }
      applyInput({ ...dr1, proposer: SomeAddr(proposer) }, r, RNewRound(r))

  pure def applyProposal(dr: Driver, p: Prop, valid: bool): DRes =
    if (height(dr) != p.height)
      { d: { ...dr, lastError: "InvalidProposalHeight" }, out: RONone, err: "InvalidProposalHeight" }
    else
      val stored = storeProposal(dr, p, valid)
      val dr1 =
        if (stored.equiv)
          recordEvidence(stored.d, propsForRound(stored.d, p.round).head().prop, p)
        else stored.d
      match multiplexProposal(dr1, p, valid) {
        | SomeRI(ri) => applyInput(dr1, p.round, ri)
        | NoRI => { d: dr1, out: RONone, err: "" }
      }

  pure def applyVote(dr: Driver, v: SVote): DRes =
    if (height(dr) != v.height)
      { d: { ...dr, lastError: "InvalidVoteHeight" }, out: RONone, err: "InvalidVoteHeight" }
    else if (not(dr.validatorSet.keys().contains(v.addr)))
      { d: { ...dr, lastError: "ValidatorNotFound" }, out: RONone, err: "ValidatorNotFound" }
    else
      val thisRound = curRound(dr)
      val applied = vkApplyVote(dr.vk, v, thisRound)
      val dr1 = { ...dr, vk: applied.vk }
      val out = applied.out
      if (out.tag == "None") { d: dr1, out: RONone, err: "" }
      else
        val dr2 =
          if (out.tag == "PolkaValue") storePolkaCertificate(dr1, v.round, out.value)
          else if (out.tag == "PrecommitAny" and thisRound == v.round)
            storePrecommitAnyRoundCertificate(dr1, v.round)
          else if (out.tag == "SkipRound")
            val s = storeSkipRoundCertificate(dr1, out.sround)
            match v.value {
              | NVVal(id) =>
                  if (thresholdMet(s.vk, v.round, VTPrevote, THValue(id)))
                    storePolkaCertificate(s, v.round, id)
                  else s
              | NVNil => s
            }
          else if (out.tag == "PrecommitValue" and v.round > thisRound)
            storeSkipRoundCertificate(dr1, v.round)
          else dr1
        val muxed = multiplexVoteThreshold(dr2, out, v.round)
        if (muxed.input == NoInput) { d: dr2, out: RONone, err: "" }
        else applyInput(dr2, muxed.round, muxed.input)

  pure def applyTimeout(dr: Driver, r: Round, k: TimeoutKind): DRes =
    if (k == TKRebroadcast or k == TKFinalize) { d: dr, out: RONone, err: "" }
    else
      val ri = if (k == TKPropose) RTimeoutPropose
               else if (k == TKPrevote) RTimeoutPrevote
               else RTimeoutPrecommit
      val res = applyInput(dr, r, ri)
      if (res.err != "") res
      else if (k != TKPrecommit) res
      else
        match res.out {
          | RONewRound(nr) =>
              val needsRefresh =
                match res.d.roundCert { | NoRC => true | SomeRC(c) => c.enterRound != nr }
              if (needsRefresh) { ...res, d: ensurePrecommitRoundCertificate(res.d, r) } else res
          | _ => res
        }

  pure def applySyncDecision(dr: Driver, p: Prop): DRes =
    if (not(hasCommitCert(dr, p.round, p.value)))
      { d: { ...dr, lastError: "CertificateNotFound" }, out: RONone, err: "CertificateNotFound" }
    else
      val res = applyInput(dr, p.round, RProposalAndPrecommitValue(p))
      if (res.err != "") res
      else { ...res, d: { ...res.d,
               syncDecided: res.d.syncDecided.union(Set({ round: p.round, value: p.value })) } }

  pure def applyDInput(dr: Driver, inp: DInput): DRes =
    match inp {
      | ICommitCertificate(c) => applyCommitCertificate(dr, c)
      | IPolkaCertificate(c) => applyPolkaCertificate(dr, c)
      | INewRound(nr) => applyNewRound(dr, nr.height, nr.round, nr.proposer)
      | IProposeValue(pv) => applyInput(dr, pv.round, RProposeValue(pv.value))
      | IProposal(pp) => applyProposal(dr, pp.prop, pp.valid)
      | IVote(v) => applyVote(dr, v)
      | ITimeoutElapsed(t) => applyTimeout(dr, t.round, t.kind)
      | ISyncDecision(p) => applySyncDecision(dr, p)
    }

  //--------------------------------------------------------------------------
  // process (driver.rs:358-380)
  //--------------------------------------------------------------------------

  type Drain = { d: Driver, outs: List[DOutput], err: str }

  /// One iteration of the `while !self.pending_inputs.is_empty()` loop: take the
  /// queue, then apply each taken input in order. `apply_input` OVERWRITES
  /// `pending_inputs`, so a later input in the batch discards an earlier one's queue.
  pure def drainOnce(acc: Drain): Drain =
    if (acc.err != "" or acc.d.pending.length() == 0) acc
    else
      val taken = acc.d.pending
      taken.foldl({ ...acc, d: { ...acc.d, pending: List() } }, (a, pi) =>
        if (a.err != "") a
        else
          val r = applyInput(a.d, pi.round, pi.input)
          if (r.err != "") { d: r.d, outs: a.outs, err: r.err }
          else
            val lifted = liftOutput(r.d, r.out, a.outs)
            { d: lifted.d, outs: lifted.outs, err: "" })

  /// driver.rs process
  pure def processInput(dr: Driver, inp: DInput): Driver =
    val base = { ...dr, outputs: List(), lastError: "", processReturnedOk: false }
    val r = applyDInput(base, inp)
    if (r.err != "") { ...r.d, lastError: r.err, outputs: List() }
    else if (r.out == RONone)
      // Early `return Ok(Vec::new())`: pending_inputs are NOT drained here.
      { ...r.d, outputs: List(), processReturnedOk: true }
    else
      val lifted = liftOutput(r.d, r.out, List())
      // The `while` loop, unrolled to a bounded depth.
      val drained = 0.to(3).fold({ d: lifted.d, outs: lifted.outs, err: "" },
                                 (acc, _) => drainOnce(acc))
      if (drained.err != "")
        { ...drained.d, lastError: drained.err, outputs: List(),
          fuelExhausted: drained.d.fuelExhausted }
      else
        { ...drained.d, outputs: drained.outs, processReturnedOk: true,
          fuelExhausted: drained.d.fuelExhausted or drained.d.pending.length() > 0 }

  //--------------------------------------------------------------------------
  // Lineage bookkeeping (ghosts only)
  //--------------------------------------------------------------------------

  pure def withLineage(dr: Driver): Driver =
    val fd = match dr.firstDecision {
      | SomeRV(_) => dr.firstDecision
      | NoRV => dr.rs.decision
    }
    val fdh = match dr.firstDecision { | SomeRV(_) => dr.firstDecisionHeight | NoRV => height(dr) }
    { ...dr,
      firstDecision: fd,
      firstDecisionHeight: fdh,
      sinceMove: dr.sinceMove + 1,
      outputCount: dr.outputs.length(),
      stepRankNow: stepRank(dr.rs.step),
      everCommittedHeight: if (dr.rs.step == Commit) height(dr) else dr.everCommittedHeight }

  //--------------------------------------------------------------------------
  // Init — Driver::new(ctx, height, validator_set, address, threshold_params)
  //--------------------------------------------------------------------------

  action init = all {
    d' = {
      address: ME,
      validatorSet: DEFAULT_VSET,
      proposer: NoAddr,
      props: List(),
      propEvidence: Set(),
      vk: newVK(DEFAULT_VSET),
      commitCerts: List(),
      polkaCerts: List(),
      rs: smNew(1, -1),
      pending: List(),
      lastPrevote: NoVote,
      lastPrecommit: NoVote,
      roundCert: NoRC,
      outputs: List(),
      lastError: "",
      processReturnedOk: false,
      panicked: false,
      voteSuppressedMonotonic: false,
      voteSuppressedValidMismatch: false,
      staleNewRoundIgnored: false,
      fuelExhausted: false,
      prunedSomething: false,
      validityUpgraded: false,
      outputCount: 0,
      stepRankNow: 0,
      castVotes: List(),
      syncDecided: Set(),
      firstDecision: NoRV,
      firstDecisionHeight: 0,
      sinceMove: 0,
      everCommittedHeight: 0,
    },
  }

  //--------------------------------------------------------------------------
  // Actions
  //--------------------------------------------------------------------------

  /// Build the Input the tag names from the primitive picks, so a logged event can
  /// pin exactly which input the caller delivered.
  pure def mkInput(itag: str, ih: Height, iround: Round, ivalue: Value, ipol: Round,
                   iaddr: Addr, ivalid: bool, ivt: str, ikind: str): DInput =
    if (itag == "NewRound") INewRound({ height: ih, round: iround, proposer: iaddr })
    else if (itag == "ProposeValue") IProposeValue({ round: iround, value: ivalue })
    else if (itag == "Proposal")
      IProposal({ prop: { height: ih, round: iround, value: ivalue, polRound: ipol,
                          proposer: iaddr }, valid: ivalid })
    else if (itag == "Vote")
      IVote({ height: ih, round: iround, vtype: voteTypeOf(ivt), value: nilOrValOf(ivalue),
              addr: iaddr })
    else if (itag == "CommitCertificate")
      ICommitCertificate({ height: ih, round: iround, valueId: ivalue, signers: QUORUM_SIGNERS })
    else if (itag == "PolkaCertificate")
      IPolkaCertificate({ height: ih, round: iround, valueId: ivalue, signers: QUORUM_SIGNERS })
    else if (itag == "TimeoutElapsed") ITimeoutElapsed({ round: iround, kind: kindOf(ikind) })
    else ISyncDecision({ height: ih, round: iround, value: ivalue, polRound: ipol,
                         proposer: iaddr })

  /// driver.rs process(input) — the sole external entry point.
  action process(itag: str, ih: Height, iround: Round, ivalue: Value, ipol: Round,
                 iaddr: Addr, ivalid: bool, ivt: str, ikind: str): bool = all {
    d' = withLineage(processInput(d, mkInput(itag, ih, iround, ivalue, ipol, iaddr, ivalid,
                                             ivt, ikind))),
  }

  /// Driver::new(ctx, height, validator_set, address, threshold_params) — the
  /// baseline. The whole validator set with its voting powers travels as one
  /// parameter, so replay pins it at step 0 instead of searching for it.
  action Drivernew(height: Height, w0: int, w1: int, w2: int, w3: int,
                   address: Addr): bool = all {
    val validator_set = mkVSet(w0, w1, w2, w3)
    d' = withLineage({
      ...d,
      address: address,
      validatorSet: validator_set,
      proposer: NoAddr,
      vk: newVK(validator_set),
      rs: smNew(height, -1),
      roundCert: NoRC,
      props: List(),
      propEvidence: Set(),
      commitCerts: List(),
      polkaCerts: List(),
      pending: List(),
      lastPrevote: NoVote,
      lastPrecommit: NoVote,
      outputs: List(),
      lastError: "",
      processReturnedOk: false,
      castVotes: List(),
      syncDecided: Set(),
      firstDecision: NoRV,
      firstDecisionHeight: 0,
      everCommittedHeight: 0,
      sinceMove: -1,
    }),
  }

  /// driver.rs move_to_height — the full per-height reset. The whole replacement
  /// membership travels as one parameter, so replay never has to search it.
  action move_to_height(height: Height, w0: int, w1: int, w2: int, w3: int): bool = all {
    val validator_set = mkVSet(w0, w1, w2, w3)
    d' = withLineage({
      ...d,
      validatorSet: validator_set,
      proposer: NoAddr,
      vk: newVK(validator_set),
      rs: smNew(height, -1),
      roundCert: NoRC,
      props: List(),
      propEvidence: Set(),
      commitCerts: List(),
      polkaCerts: List(),
      pending: List(),
      lastPrevote: NoVote,
      lastPrecommit: NoVote,
      outputs: List(),
      lastError: "",
      processReturnedOk: false,
      sinceMove: -1,   // withLineage bumps it to 0
    }),
  }

  /// driver.rs prune_votes_and_certificates(min_round)
  action prune_votes_and_certificates(min_round: Round): bool = all {
    d' = withLineage({ ...d,
      polkaCerts: d.polkaCerts.select(c => c.round >= min_round),
      vk: vkPrune(d.vk, min_round),
      prunedSomething: d.prunedSomething
        or d.polkaCerts.select(c => c.round < min_round).length() > 0
        or d.vk.rounds.filter(r => r < min_round).size() > 0 }),
  }

  /// driver.rs take_proposal_evidence — drains the proposal-equivocation evidence.
  action take_proposal_evidence = all {
    d' = withLineage({ ...d, propEvidence: Set() }),
  }

  /// driver.rs take_vote_evidence — drains the vote-equivocation evidence.
  action take_vote_evidence = all {
    d' = withLineage({ ...d, vk: { ...d.vk, evidence: Set() } }),
  }

  /// ProposalKeeper::store_proposal, reached through the driver's own storage path,
  /// with the caller recording the surfaced equivocation as evidence.
  action ProposalKeeperstore_proposal(proposal: Prop, validity: bool): bool = all {
    val stored = storeProposal(d, proposal, validity)
    d' = withLineage(
      if (stored.equiv)
        recordEvidence(stored.d, propsForRound(stored.d, proposal.round).head().prop, proposal)
      else stored.d),
  }

  /// driver.rs record_proposal_evidence — the upstream path that records a pair the
  /// per-round store never saw.
  action record_proposal_evidence(existing: Prop, conflicting: Prop): bool = all {
    d' = withLineage(recordEvidence(d, existing, conflicting)),
  }

  /// driver.rs get_proposer() — a guarded read: NoProposer / ProposerNotFound.
  action get_proposer = all {
    d' = withLineage({ ...d, lastError: proposerError(d) }),
  }

  //--------------------------------------------------------------------------
  // step
  //--------------------------------------------------------------------------

  /// Tag-specific pick domains. A field an input variant does not carry gets a
  /// singleton domain, so its retry budget is 1.
  pure def heightDom(t: str): Set[Height] =
    if (t == "ProposeValue" or t == "TimeoutElapsed") Set(1) else HEIGHTS
  pure def roundDom(t: str): Set[Round] =
    if (t == "NewRound") ROUNDS else ROUND_BAND
  pure def valueDom(t: str): Set[Value] =
    if (t == "Vote") VOTE_VALUES
    else if (t == "NewRound" or t == "TimeoutElapsed") Set("v")
    else VALUES
  pure def polDom(t: str): Set[Round] =
    if (t == "Proposal" or t == "SyncDecision") POL_ROUNDS else Set(-1)
  pure def addrDom(t: str): Set[Addr] =
    if (t == "Vote") VOTERS
    else if (t == "NewRound" or t == "Proposal" or t == "SyncDecision") ADDRS
    else Set(ME)
  pure def validDom(t: str): Set[bool] = if (t == "Proposal") Set(true, false) else Set(true)
  pure def vtDom(t: str): Set[str] = if (t == "Vote") VOTE_TYPES else Set("Prevote")
  pure def kindDom(t: str): Set[str] = if (t == "TimeoutElapsed") TIMEOUT_KINDS else Set("Propose")

  /// The tags worth trying in the state we are in. Used ONLY to steer the random
  /// search toward the deep decide/skip scenarios — every tag stays reachable
  /// through the unrestricted arm below.
  pure def focusTags(dr: Driver): Set[str] =
    val generic = Set("Vote", "CommitCertificate", "SyncDecision")
    val specific =
      if (dr.proposer == NoAddr) Set("NewRound")
      else match dr.rs.step {
        | Unstarted => Set("NewRound")
        | Propose => Set("ProposeValue", "Proposal", "TimeoutElapsed")
        | Prevote => Set("Proposal", "PolkaCertificate", "TimeoutElapsed")
        | Precommit => Set("Proposal", "TimeoutElapsed")
        | Commit => Set("NewRound")
      }
    generic.union(specific)

  /// The rounds immediately around where the driver currently sits.
  pure def focusRounds(dr: Driver): Set[Round] =
    Set(0, curRound(dr), curRound(dr) + 1)

  action step = any {
    // Unrestricted: every input variant over its full domain.
    {
      nondet itag = INPUT_TAGS.oneOf()
      nondet ih = heightDom(itag).oneOf()
      nondet iround = roundDom(itag).oneOf()
      nondet ivalue = valueDom(itag).oneOf()
      nondet ipol = polDom(itag).oneOf()
      nondet iaddr = addrDom(itag).oneOf()
      nondet ivalid = validDom(itag).oneOf()
      nondet ivt = vtDom(itag).oneOf()
      nondet ikind = kindDom(itag).oneOf()
      process(itag, ih, iround, ivalue, ipol, iaddr, ivalid, ivt, ikind)
    },
    // Steered: the same action, with the picks that keep a round progressing.
    {
      nondet itag = focusTags(d).oneOf()
      nondet iround = focusRounds(d).oneOf()
      nondet ivalue = valueDom(itag).oneOf()
      nondet ipol = polDom(itag).oneOf()
      nondet iaddr = addrDom(itag).oneOf()
      nondet ivalid = validDom(itag).oneOf()
      nondet ivt = vtDom(itag).oneOf()
      nondet ikind = kindDom(itag).oneOf()
      process(itag, height(d), iround, ivalue, ipol, iaddr, ivalid, ivt, ikind)
    },
    {
      nondet height = HEIGHTS.oneOf()
      nondet w0 = WEIGHTS.oneOf()
      nondet w1 = WEIGHTS.oneOf()
      nondet w2 = WEIGHTS.oneOf()
      nondet w3 = WEIGHTS.oneOf()
      move_to_height(height, w0, w1, w2, w3)
    },
    {
      nondet height = HEIGHTS.oneOf()
      nondet w0 = WEIGHTS.oneOf()
      nondet w1 = WEIGHTS.oneOf()
      nondet w2 = WEIGHTS.oneOf()
      nondet w3 = WEIGHTS.oneOf()
      nondet address = VSET.oneOf()
      Drivernew(height, w0, w1, w2, w3, address)
    },
    {
      nondet min_round = ROUND_BAND.oneOf()
      prune_votes_and_certificates(min_round)
    },
    // The remaining maintenance / keeper operations, grouped so they do not
    // crowd out the input path in a random walk.
    any {
      take_proposal_evidence,
      take_vote_evidence,
      get_proposer,
      {
        nondet pround = ROUNDS.oneOf()
        nondet pvalue = VALUES.oneOf()
        nondet ppol = POL_ROUNDS.oneOf()
        nondet pproposer = ADDRS.oneOf()
        nondet validity = Set(true, false).oneOf()
        ProposalKeeperstore_proposal(
          { height: height(d), round: pround, value: pvalue, polRound: ppol,
            proposer: pproposer }, validity)
      },
      {
        nondet pround = ROUNDS.oneOf()
        nondet pvalue = VALUES.oneOf()
        nondet pother = VALUES.oneOf()
        nondet pproposer = ADDRS.oneOf()
        record_proposal_evidence(
          { height: height(d), round: pround, value: pvalue, polRound: -1, proposer: pproposer },
          { height: height(d), round: pround, value: pother, polRound: -1, proposer: pproposer })
      },
    },
  }

  //--------------------------------------------------------------------------
  // Correctness properties  (listed under `invariants`)
  //--------------------------------------------------------------------------

  /// `process` never returns while pending inputs are still queued: an input the
  /// step change produced must be applied before the caller sees the outputs,
  /// otherwise a vote or a decision the node owes the network is simply dropped.
  val pending_inputs_always_drained: bool =
    d.processReturnedOk implies d.pending.length() == 0

  /// We never sign two different votes of the same type for the same height and
  /// round. Emitting both is provable equivocation, and gets our stake slashed.
  val never_self_equivocate: bool =
    d.castVotes.indices().forall(i =>
      d.castVotes.indices().forall(j =>
        val a = d.castVotes.nth(i)
        val b = d.castVotes.nth(j)
        (a.height == b.height and a.round == b.round and a.vtype == b.vtype)
          implies a.value == b.value))

  /// `last_prevote` / `last_precommit` only ever hold a vote we actually emitted:
  /// the gate reads them to decide the next vote, so an entry for a vote we
  /// suppressed would block a vote we still owe the network.
  val last_vote_was_actually_emitted: bool = and {
    match d.lastPrevote {
      | NoVote => true
      | SomeVote(v) => d.castVotes.select(o => o == v).length() > 0
    },
    match d.lastPrecommit {
      | NoVote => true
      | SomeVote(v) => d.castVotes.select(o => o == v).length() > 0
    },
  }

  /// A wrong-height vote, proposal or certificate is reported as a typed error,
  /// never silently swallowed: the caller must be able to tell "rejected" from
  /// "accepted with nothing to do", or a stalled peer looks healthy.
  val height_mismatch_is_never_silent: bool =
    (d.lastError == "InvalidVoteHeight" or d.lastError == "InvalidProposalHeight"
     or d.lastError == "InvalidCertificateHeight")
      implies d.outputs.length() == 0

  /// `round_state` is never left at its `Default` value by the mem::take/replace
  /// swap in `with_round_state`: a default round state has height 0 and would make
  /// the node re-run a height it has already decided.
  val round_state_never_default: bool =
    d.rs.height > 0 and (d.rs.step == Unstarted or d.rs.round >= 0)

  /// Every decision reached through the sync path is backed by the commit
  /// certificate that justified it; deciding without one means committing a value
  /// no quorum ever precommitted.
  val sync_decision_backed_by_certificate: bool =
    d.syncDecided.forall(sd => hasCommitCert(d, sd.round, sd.value))

  /// A height decides at most one value. Two decisions at one height let a client
  /// be shown two different committed states and double-spend against one of them.
  val decision_is_unique_per_height: bool =
    (isSome(d.firstDecision) and d.firstDecisionHeight == height(d) and isSome(d.rs.decision))
      implies rvValue(d.firstDecision) == rvValue(d.rs.decision)

  /// Terminal permanence: once a height has committed, that height stays committed
  /// with the same decided value — no later input rewinds it out of Commit.
  val commit_is_permanent: bool =
    (d.everCommittedHeight == height(d) and d.everCommittedHeight > 0)
      implies (d.rs.step == Commit and isSome(d.rs.decision))

  /// Recorded equivocation evidence always names ONE validator. Evidence pairing
  /// two different validators would get an honest node slashed.
  val evidence_names_one_validator: bool =
    d.propEvidence.forall(e => e.existing.proposer == e.conflicting.proposer) and
    d.vk.evidence.forall(e => e.existing.addr == e.conflicting.addr)

  /// `move_to_height` really resets everything the previous height accumulated;
  /// a field left behind makes the new height inherit votes, certificates or a
  /// vote-gate entry from the old one, which is how a node double-signs.
  val move_to_height_resets_all_per_height_state: bool =
    (d.sinceMove == 0) implies and {
      d.rs.round == -1,
      d.rs.step == Unstarted,
      not(isSome(d.rs.decision)),
      not(isSome(d.rs.locked)),
      not(isSome(d.rs.valid)),
      d.props.length() == 0,
      d.commitCerts.length() == 0,
      d.polkaCerts.length() == 0,
      d.pending.length() == 0,
      d.lastPrevote == NoVote,
      d.lastPrecommit == NoVote,
      d.roundCert == NoRC,
      d.vk.rounds.size() == 0,
      d.vk.votes.size() == 0,
      d.vk.evidence.size() == 0,
      d.propEvidence.size() == 0,
    }

  /// No modelled assertion ever fires: the panics in the round-certificate stores
  /// and in the proposal keeper would take the whole node down mid-consensus.
  val never_panics: bool = not(d.panicked)

  /// Any round certificate we hold justifies entering a round we could actually be
  /// asked to enter — never a round below the one it was built from.
  val round_certificate_is_forward: bool =
    match d.roundCert { | NoRC => true | SomeRC(c) => c.enterRound >= c.round }

  //--------------------------------------------------------------------------
  // Observations — one per outcome class
  //--------------------------------------------------------------------------

  /// One external input cascaded into more than one driver output.
  val multi_output_cascade: bool = d.outputs.length() > 1

  /// A step change queued pending inputs that a later apply then consumed.
  val pending_inputs_queued: bool = d.pending.length() > 0

  /// `process` returned with no outputs at all even though it succeeded.
  val process_returned_no_outputs: bool = d.processReturnedOk and d.outputs.length() == 0

  /// The own-vote gate suppressed a vote because it would have regressed in
  /// height or round against our last vote of that type.
  val own_vote_suppressed_as_regressive: bool = d.voteSuppressedMonotonic

  /// The own-vote gate suppressed a precommit whose value did not match `valid`.
  val own_precommit_suppressed_as_value_mismatch: bool = d.voteSuppressedValidMismatch

  /// An input arrived for the wrong height and was rejected with a typed error.
  val height_mismatch_rejected: bool =
    d.lastError == "InvalidVoteHeight" or d.lastError == "InvalidProposalHeight"
    or d.lastError == "InvalidCertificateHeight"

  /// A vote from an address outside the validator set was rejected.
  val vote_from_unknown_validator_rejected: bool = d.lastError == "ValidatorNotFound"

  /// A SyncDecision arrived without the commit certificate that must back it.
  val sync_decision_without_certificate: bool = d.lastError == "CertificateNotFound"

  /// An input was applied while no proposer had been set for the round.
  val no_proposer_set: bool = d.lastError == "NoProposer"

  /// The stored proposer is not a member of the validator set.
  val proposer_not_in_validator_set: bool = d.lastError == "ProposerNotFound"

  /// A NewRound for a round we had already left was silently dropped.
  val stale_new_round_ignored: bool = d.staleNewRoundIgnored

  /// Proposal equivocation by one validator was recorded as evidence.
  val proposal_equivocation_recorded: bool = d.propEvidence.size() > 0

  /// Vote equivocation by one validator was recorded as evidence.
  val vote_equivocation_recorded: bool = d.vk.evidence.size() > 0

  /// A Skip round certificate is held, justifying entering a future round.
  val skip_round_certificate_held: bool =
    match d.roundCert { | NoRC => false | SomeRC(c) => c.ctype == "Skip" }

  /// A Precommit round certificate is held, justifying the next round.
  val precommit_round_certificate_held: bool =
    match d.roundCert { | NoRC => false | SomeRC(c) => c.ctype == "Precommit" }

  /// A polka certificate was stored for some round.
  val polka_certificate_stored: bool = d.polkaCerts.length() > 0

  /// Pruning actually removed a polka certificate or a round of votes.
  val pruning_removed_state: bool = d.prunedSomething

  /// The height reached a decision.
  val height_decided: bool = isSome(d.rs.decision)

  /// The decision was reached through the sync path rather than through votes.
  val decided_via_sync: bool = d.syncDecided.size() > 0

  /// The driver emitted a proposal of our own.
  val own_proposal_emitted: bool =
    d.outputs.select(o => match o { | OPropose(_) => true | _ => false }).length() > 0

  /// A stored proposal's validity was upgraded from Invalid to Valid.
  val proposal_validity_upgraded: bool = d.validityUpgraded
}
