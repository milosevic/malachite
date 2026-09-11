// Fast Tendermint Vote Keeper — model of `code/crates/core-votekeeper/src/fast/keeper.rs`.
//
// ACTIONS, ARGUMENTS and OBSERVATIONS mirror the Rust exactly (that is what the oracle
// replays). PROPERTIES are stated from Algorithm 1 of Vander Vos & Cason, "Fast Tendermint"
// (arXiv:2608.13434) — L27, L36, L39, L42 — not read off the implementation; where the code
// disagrees with them the check reports a finding.
//
// Validators are modelled by their INDEX in the validator set (`ValidatorSet::get_by_index`),
// with -1 standing for any address outside the set; the instrumentation normalises addresses
// the same way. `new` is a baseline action carrying the whole validator set as one payload
// (the list of voting powers, index-ordered), so replay pins it with zero unguided search.
module fast_vote_keeper {

  //// ------------------------------------------------------------------ domain

  /// A voted value id, rendered the way the code renders it, with "Nil" standing for a nil
  /// vote: nil has its own tally key and never reaches a value threshold. A plain string (not
  /// a sum type) because `ValueId` is generic and only `Display` is available to log.
  type VoteValue = str

  /// Fast Tendermint has ONE voting step, which the paper names precommit.
  type VType = str

  type Vote = { voter: int, round: int, value: VoteValue, voteType: VType }

  /// What `apply_vote` returns. Every variant carries its round deliberately.
  type Output =
    | VoteQuorumValue({ round: int, value: str })
    | DecisionQuorumValue({ round: int, value: str })
    | QuorumAny({ round: int })

  /// Classification of the last call — one per branch arm of `apply_vote`.
  type Outcome =
    | ONone
    | OCreated
    | ODiscardedPrevote
    | ODiscardedUnknownVoter
    | ODiscardedNilRound
    | ODiscardedDuplicate
    | OEvidenceRecorded
    | OEvidenceDuplicateDropped
    | OEvidenceCapped
    | OTallied
    | OPruned

  type Pair = { first: Vote, conflicting: Vote }

  type PerRound = {
    valuesWeights: VoteValue -> int,
    addressesWeights: int -> int,
    votesByAddress: int -> Vote,
  }

  type Emitted = { voteQuorum: Set[str], decisionQuorum: Set[str], quorumAny: bool }

  /// The keeper's real state. `reached` and `evidence` deliberately survive `prune_votes`.
  type Core = {
    weights: int -> int,
    perRound: int -> PerRound,
    reached: int -> Emitted,
    evidence: int -> List[Pair],
  }

  /// History the properties need; none of it exists in the Rust.
  type Ghost = {
    emittedLog: List[Output],
    lastOutputs: List[Output],
    lastOutcome: Outcome,
    justification: (int, str) -> int,
    decisionJustification: (int, str) -> int,
    anyJustification: int -> int,
    justificationTotal: int,
    tallied: List[Vote],
    pruneFloor: int,
    everQuorumAny: Set[int],
    everDecided: Set[(int, str)],
    everVoteQuorum: Set[(int, str)],
    evidencePairsAdded: int,
    missedEquivocation: bool,
    prunedSomething: bool,
    pruneViolation: bool,
    reEmitAfterPrune: int,
    retalliedAfterPrune: bool,
    suppressedByLatch: bool,
  }

  type World = { core: Core, ghost: Ghost }

  //// --------------------------------------------------------------- constants

  /// Any address outside the validator set.
  pure val UNKNOWN_VOTER: int = -1
  pure val NIL_ROUND: int = -1

  /// The validator-set shapes the suite constructs (lists of voting powers, index-ordered).
  pure val CONFIGS: Set[List[int]] = Set(
    List(1, 1, 1),
    List(1, 1, 1, 1, 1),
    List(1, 1, 1, 1, 1, 1),
    List(4, 5, 1),
    List(5, 3, 1, 1)
  )
  pure val TOTALS: Set[int] = Set(3, 5, 6, 10)

  pure val ROUNDS: Set[int] = (-1).to(9)
  pure val PRUNE_ROUNDS: Set[int] = (-1).to(10)
  pure val VALUE_IDS: Set[str] = Set("0", "1", "2", "3", "4", "5", "7", "9")
  pure val NIL_VALUE: str = "Nil"
  pure val VALUES: Set[VoteValue] = Set(NIL_VALUE).union(VALUE_IDS)
  /// The values the quorum-forming simulation arm starts from; the tally's own values are
  /// added to it, so a quorum can build up.
  pure val SEED_VALUES: Set[VoteValue] = Set(NIL_VALUE, "1", "2")
  pure val PRECOMMIT: str = "Precommit"
  pure val PREVOTE: str = "Prevote"
  pure val VOTE_TYPES: Set[VType] = Set(PRECOMMIT, PREVOTE)
  /// Bitmask of the outputs one apply_vote returns: 1 = VoteQuorumValue,
  /// 2 = DecisionQuorumValue, 4 = QuorumAny. Logged by the code as its conformance fact.
  pure val MASKS: Set[int] = 0.to(7)
  pure val ROUND_COUNTS: Set[int] = 0.to(12)

  /// FastThresholdParams::TWO_F_PLUS_ONE = 2/5, N_MINUS_F = 4/5.
  pure val QUORUM_NUM: int = 2
  pure val QUORUM_DEN: int = 5
  pure val DECISION_NUM: int = 4
  pure val DECISION_DEN: int = 5

  pure val MAX_EVIDENCE: int = 3

  /// ThresholdParam::is_met — strict.
  pure def isMet(w: int, num: int, den: int, total: int): bool = w * den > total * num

  //// ----------------------------------------------------------------- helpers

  pure def idOf(v: VoteValue): str = v
  pure def isVal(v: VoteValue): bool = v != NIL_VALUE

  pure val EMPTY_ROUND: PerRound =
    { valuesWeights: Map(), addressesWeights: Map(), votesByAddress: Map() }
  pure val EMPTY_EMITTED: Emitted =
    { voteQuorum: Set(), decisionQuorum: Set(), quorumAny: false }

  pure def roundOf(c: Core, r: int): PerRound =
    if (c.perRound.keys().contains(r)) c.perRound.get(r) else EMPTY_ROUND

  pure def reachedOf(c: Core, r: int): Emitted =
    if (c.reached.keys().contains(r)) c.reached.get(r) else EMPTY_EMITTED

  pure def valW(pr: PerRound, v: VoteValue): int =
    if (pr.valuesWeights.keys().contains(v)) pr.valuesWeights.get(v) else 0

  pure def sumAddr(m: int -> int): int = m.keys().fold(0, (a, k) => a + m.get(k))
  pure def sumValues(m: VoteValue -> int): int = m.keys().fold(0, (a, k) => a + m.get(k))
  pure def weightOfSet(c: Core, s: Set[int]): int =
    s.fold(0, (a, x) => a + (if (c.weights.keys().contains(x)) c.weights.get(x) else 0))

  /// FastVoteKeeper::total_weight.
  pure def totalOf(c: Core): int = sumAddr(c.weights)

  pure def listHas(l: List[Output], o: Output): bool =
    l.foldl(false, (a, x) => a or x == o)

  pure def firstIdx(l: List[Output], o: Output): int =
    l.foldl({ i: 0, found: -1 }, (a, x) =>
      if (a.found >= 0) { ...a, i: a.i + 1 }
      else if (x == o) { i: a.i + 1, found: a.i }
      else { ...a, i: a.i + 1 }).found

  pure def maskOf(l: List[Output]): int =
    l.foldl(0, (a, o) => a + match o {
      VoteQuorumValue(_) => 1 | DecisionQuorumValue(_) => 2 | QuorumAny(_) => 4
    })

  pure def evidenceCount(e: int -> List[Pair]): int =
    e.keys().fold(0, (a, k) => a + e.get(k).length())

  /// The distinct validators that ever had a vote for `v` in round `r` tallied.
  pure def talliedVoters(tl: List[Vote], r: int, v: VoteValue): Set[int] =
    tl.foldl(Set(), (a, t) => if (t.round == r and t.value == v) a.union(Set(t.voter)) else a)

  pure def talliedVotersAny(tl: List[Vote], r: int): Set[int] =
    tl.foldl(Set(), (a, t) => if (t.round == r) a.union(Set(t.voter)) else a)

  pure def hasVQ(l: List[Output]): bool =
    l.foldl(false, (a, o) => a or match o { VoteQuorumValue(_) => true | _ => false })
  pure def hasDQ(l: List[Output]): bool =
    l.foldl(false, (a, o) => a or match o { DecisionQuorumValue(_) => true | _ => false })
  pure def hasQA(l: List[Output]): bool =
    l.foldl(false, (a, o) => a or match o { QuorumAny(_) => true | _ => false })

  pure def setOutcome(s: World, o: Outcome): World =
    { ...s, ghost: { ...s.ghost, lastOutcome: o, lastOutputs: List() } }

  //// -------------------------------------------------------- the keeper logic

  /// The outputs `apply_vote` returns for this vote — empty on every discard path.
  pure def outsOf(s: World, v: Vote): List[Output] =
    if (v.voteType != PRECOMMIT) List()
    else if (not(s.core.weights.keys().contains(v.voter))) List()
    else if (v.round == NIL_ROUND) List()
    else {
      val pr = roundOf(s.core, v.round)
      if (pr.votesByAddress.keys().contains(v.voter)) List()
      else {
        val w = s.core.weights.get(v.voter)
        val total = totalOf(s.core)
        val forValue = valW(pr, v.value) + w
        val anyWeight = sumAddr(pr.addressesWeights) + w
        val em = reachedOf(s.core, v.round)
        val id = idOf(v.value)
        val emitQ = isVal(v.value)
          and isMet(forValue, QUORUM_NUM, QUORUM_DEN, total)
          and not(em.voteQuorum.contains(id))
        val emitD = isVal(v.value)
          and isMet(forValue, DECISION_NUM, DECISION_DEN, total)
          and not(em.decisionQuorum.contains(id))
        val emitA = isMet(anyWeight, DECISION_NUM, DECISION_DEN, total) and not(em.quorumAny)
        (if (emitQ) List(VoteQuorumValue({ round: v.round, value: id })) else List())
          .concat(if (emitD) List(DecisionQuorumValue({ round: v.round, value: id })) else List())
          .concat(if (emitA) List(QuorumAny({ round: v.round })) else List())
      }
    }

  /// EvidenceMap::add — the identical pair is not stored twice, and a validator holds at
  /// most MAX_EVIDENCE pairs.
  pure def recordEvidence(s: World, first: Vote, conflicting: Vote): World = {
    val a = conflicting.voter
    val pairs = if (s.core.evidence.keys().contains(a)) s.core.evidence.get(a) else List()
    val p = { first: first, conflicting: conflicting }
    val dup = pairs.foldl(false, (acc, q) =>
      acc or (q == p) or (q.first == conflicting and q.conflicting == first))
    if (dup) setOutcome(s, OEvidenceDuplicateDropped)
    else if (pairs.length() >= MAX_EVIDENCE) setOutcome(s, OEvidenceCapped)
    else {
      val s2 = setOutcome(s, OEvidenceRecorded)
      { core: { ...s2.core, evidence: s2.core.evidence.put(a, pairs.append(p)) },
        ghost: { ...s2.ghost, evidencePairsAdded: s2.ghost.evidencePairsAdded + 1 } }
    }
  }

  /// The tally path: set_once the weight, add to the value tally, then emit L36, L42, L39
  /// in that order, each latched per (round, kind, value).
  pure def tally(s: World, v: Vote, pr: PerRound): World = {
    val w = s.core.weights.get(v.voter)
    val total = totalOf(s.core)
    val pr2 = { valuesWeights: pr.valuesWeights.put(v.value, valW(pr, v.value) + w),
                addressesWeights: pr.addressesWeights.put(v.voter, w),
                votesByAddress: pr.votesByAddress.put(v.voter, v) }
    val forValue = valW(pr2, v.value)
    val anyWeight = sumAddr(pr2.addressesWeights)
    val em = reachedOf(s.core, v.round)
    val id = idOf(v.value)
    val metQ = isVal(v.value) and isMet(forValue, QUORUM_NUM, QUORUM_DEN, total)
    val metD = isVal(v.value) and isMet(forValue, DECISION_NUM, DECISION_DEN, total)
    val metA = isMet(anyWeight, DECISION_NUM, DECISION_DEN, total)
    val outs = outsOf(s, v)
    val emitQ = hasVQ(outs)
    val emitD = hasDQ(outs)
    val emitA = hasQA(outs)
    val em2 = { voteQuorum: if (metQ) em.voteQuorum.union(Set(id)) else em.voteQuorum,
                decisionQuorum: if (metD) em.decisionQuorum.union(Set(id)) else em.decisionQuorum,
                quorumAny: em.quorumAny or metA }
    val g = s.ghost
    // The pruning blind spot: a conflicting vote from a validator whose earlier vote for
    // this round was pruned away is tallied as a first vote and produces NO evidence.
    val missed = g.tallied.foldl(false, (acc, t) =>
      acc or (t.voter == v.voter and t.round == v.round and t.value != v.value))
    val reEmit = if (v.round < g.pruneFloor)
                   outs.foldl(0, (acc, o) => acc + (if (listHas(g.emittedLog, o)) 1 else 0))
                 else 0
    { core: { ...s.core,
              perRound: s.core.perRound.put(v.round, pr2),
              reached: s.core.reached.put(v.round, em2) },
      ghost: { ...g,
        lastOutcome: OTallied,
        lastOutputs: outs,
        emittedLog: g.emittedLog.concat(outs),
        tallied: g.tallied.append(v),
        justification:
          if (emitQ) g.justification.put((v.round, id), forValue) else g.justification,
        decisionJustification:
          if (emitD) g.decisionJustification.put((v.round, id), forValue)
          else g.decisionJustification,
        anyJustification:
          if (emitA) g.anyJustification.put(v.round, anyWeight) else g.anyJustification,
        everVoteQuorum:
          if (metQ) g.everVoteQuorum.union(Set((v.round, id))) else g.everVoteQuorum,
        everDecided:
          if (metD) g.everDecided.union(Set((v.round, id))) else g.everDecided,
        everQuorumAny:
          if (metA) g.everQuorumAny.union(Set(v.round)) else g.everQuorumAny,
        missedEquivocation: g.missedEquivocation or missed,
        reEmitAfterPrune: g.reEmitAfterPrune + reEmit,
        retalliedAfterPrune: g.retalliedAfterPrune or (v.round < g.pruneFloor),
        suppressedByLatch:
          g.suppressedByLatch or ((metQ or metD or metA) and outs.length() == 0),
      } }
  }

  /// FastVoteKeeper::apply_vote — the code's straight line. Every early return is a real
  /// transition the code accepts (it returns an empty Vec), never a disabled guard.
  pure def applyVoteW(s: World, v: Vote): World =
    if (v.voteType != PRECOMMIT) setOutcome(s, ODiscardedPrevote)
    else if (not(s.core.weights.keys().contains(v.voter)))
      setOutcome(s, ODiscardedUnknownVoter)
    else if (v.round == NIL_ROUND) setOutcome(s, ODiscardedNilRound)
    else {
      val pr = roundOf(s.core, v.round)
      if (pr.votesByAddress.keys().contains(v.voter))
        if (pr.votesByAddress.get(v.voter).value == v.value)
          setOutcome(s, ODiscardedDuplicate)
        else recordEvidence(s, pr.votesByAddress.get(v.voter), v)
      else tally(s, v, pr)
    }

  /// FastVoteKeeper::prune_votes — drops the tallies below `min_round`; `reached` and
  /// `evidence` are untouched.
  pure def pruneW(s: World, minRound: int): World = {
    val kept = s.core.perRound.keys().filter(r => r >= minRound)
    val np = kept.mapBy(r => s.core.perRound.get(r))
    val dropOk =
      not(s.core.perRound.keys().exists(r => r >= minRound and not(kept.contains(r))))
        and not(kept.exists(r => r < minRound))
    { core: { ...s.core, perRound: np },
      ghost: { ...s.ghost,
        lastOutcome: OPruned,
        lastOutputs: List(),
        pruneFloor: if (minRound > s.ghost.pruneFloor) minRound else s.ghost.pruneFloor,
        prunedSomething: s.ghost.prunedSomething or (kept != s.core.perRound.keys()),
        pruneViolation: s.ghost.pruneViolation or not(dropOk) } }
  }

  pure def weightsOf(ws: List[int]): int -> int =
    ws.foldl({ i: 0, m: Map() }, (a, w) => { i: a.i + 1, m: a.m.put(a.i, w) }).m

  //// ------------------------------------------------------------ state machine

  var st: World

  pure val EMPTY_GHOST: Ghost = {
    emittedLog: List(), lastOutputs: List(), lastOutcome: ONone,
    justification: Map(), decisionJustification: Map(), anyJustification: Map(),
    justificationTotal: 0,
    tallied: List(), pruneFloor: -1,
    everQuorumAny: Set(), everDecided: Set(), everVoteQuorum: Set(),
    evidencePairsAdded: 0, missedEquivocation: false,
    prunedSomething: false, pruneViolation: false, reEmitAfterPrune: 0,
    retalliedAfterPrune: false, suppressedByLatch: false,
  }

  action init = all {
    st' = { core: { weights: Map(), perRound: Map(), reached: Map(), evidence: Map() },
            ghost: EMPTY_GHOST },
  }

  /// FastVoteKeeper::new(validator_set, FastThresholdParams::default()) — keeper.rs:90.
  /// `validator_set` is the whole payload: the voting powers, index-ordered.
  /// `total_weight` is the conformance fact (FastVoteKeeper::total_weight).
  action FastVoteKeepernew(validator_set: List[int], total_weight: int): bool = all {
    total_weight == validator_set.foldl(0, (a, x) => a + x),
    st' = { core: { weights: weightsOf(validator_set), perRound: Map(), reached: Map(),
                    evidence: Map() },
            ghost: { ...EMPTY_GHOST, lastOutcome: OCreated } },
  }

  /// FastVoteKeeper::apply_vote(signed_vote) — keeper.rs:126.
  /// `outputs` is the conformance fact: the bitmask of the returned Vec.
  action FastVoteKeeperapply_vote(voter: int, round: int, value: VoteValue,
                                  vote_type: VType, outputs: int): bool = all {
    outputs == maskOf(outsOf(st, { voter: voter, round: round, value: value,
                                   voteType: vote_type })),
    st' = applyVoteW(st, { voter: voter, round: round, value: value, voteType: vote_type }),
  }

  /// FastVoteKeeper::prune_votes(min_round) — keeper.rs:226.
  /// `rounds_left` is the conformance fact: how many rounds still hold tallies.
  action FastVoteKeeperprune_votes(min_round: int, rounds_left: int): bool = all {
    rounds_left == st.core.perRound.keys().filter(r => r >= min_round).size(),
    st' = pruneW(st, min_round),
  }

  //// ---------------------------------------------------------------- queries

  /// FastVoteKeeper::has_vote_quorum — answers from `reached`, so it survives pruning.
  def has_vote_quorum(round: int, value_id: str): bool =
    st.core.reached.keys().contains(round)
      and st.core.reached.get(round).voteQuorum.contains(value_id)

  /// FastVoteKeeper::has_decision_quorum — answers from `reached`, so it survives pruning.
  def has_decision_quorum(round: int, value_id: str): bool =
    st.core.reached.keys().contains(round)
      and st.core.reached.get(round).decisionQuorum.contains(value_id)

  /// FastVoteKeeper::total_weight.
  def total_weight: int = totalOf(st.core)

  //// ------------------------------------------------------------------- step

  def knownVoters: Set[int] = st.core.weights.keys()
  def votedIn(r: int): Set[int] = roundOf(st.core, r).votesByAddress.keys()
  def notYetVoted(r: int): Set[int] = knownVoters.exclude(votedIn(r))
  def nonEmptyVoters(s: Set[int]): Set[int] = if (s == Set()) Set(UNKNOWN_VOTER) else s
  def seedValues(r: int): Set[VoteValue] =
    SEED_VALUES.union(roundOf(st.core, r).valuesWeights.keys())

  action step = any {
    {
      nondet validator_set = CONFIGS.oneOf()
      nondet total_weight = TOTALS.oneOf()
      FastVoteKeepernew(validator_set, total_weight)
    },
    // A fresh vote in round 0 — the productive arm that forms quorums.
    {
      nondet voter = nonEmptyVoters(notYetVoted(0)).oneOf()
      nondet value = seedValues(0).oneOf()
      nondet outputs = MASKS.oneOf()
      FastVoteKeeperapply_vote(voter, 0, value, PRECOMMIT, outputs)
    },
    // A second vote in round 0 from a validator that already voted: duplicate or equivocation.
    {
      nondet voter = nonEmptyVoters(votedIn(0)).oneOf()
      nondet value = VALUES.oneOf()
      nondet outputs = MASKS.oneOf()
      FastVoteKeeperapply_vote(voter, 0, value, PRECOMMIT, outputs)
    },
    // The adversarial arm: any voter (including one outside the set), any round (including
    // the undefined round), any value, either vote type.
    {
      nondet voter = knownVoters.union(Set(UNKNOWN_VOTER)).oneOf()
      nondet round = ROUNDS.oneOf()
      nondet value = VALUES.oneOf()
      nondet vote_type = VOTE_TYPES.oneOf()
      nondet outputs = MASKS.oneOf()
      FastVoteKeeperapply_vote(voter, round, value, vote_type, outputs)
    },
    {
      nondet min_round = PRUNE_ROUNDS.oneOf()
      nondet rounds_left = ROUND_COUNTS.oneOf()
      FastVoteKeeperprune_votes(min_round, rounds_left)
    },
  }

  //// ------------------------------------------------------- correctness properties

  /// Crossing 2f+1 for a value never suppresses the n-f report for that same value and round.
  val both_thresholds_are_reported_independently: bool =
    st.ghost.everDecided.forall(p =>
      listHas(st.ghost.emittedLog, VoteQuorumValue({ round: p._1, value: p._2 }))
        and listHas(st.ghost.emittedLog, DecisionQuorumValue({ round: p._1, value: p._2 })))

  /// A value is reported valid before it is reported decided, never the other way round.
  val decision_quorum_implies_its_vote_quorum: bool =
    st.ghost.everDecided.forall(p => {
      val vi = firstIdx(st.ghost.emittedLog, VoteQuorumValue({ round: p._1, value: p._2 }))
      val di = firstIdx(st.ghost.emittedLog, DecisionQuorumValue({ round: p._1, value: p._2 }))
      and { vi >= 0, di >= 0, vi < di }
    })

  /// A validator's weight is counted at most once in a round, so equivocation adds no weight
  /// to any tally, and no address outside the validator set holds any.
  val equivocation_never_manufactures_a_quorum: bool =
    st.core.perRound.keys().forall(r => {
      val pr = st.core.perRound.get(r)
      and {
        sumValues(pr.valuesWeights) == sumAddr(pr.addressesWeights),
        pr.addressesWeights.keys() == pr.votesByAddress.keys(),
        pr.addressesWeights.keys().forall(a =>
          st.core.weights.keys().contains(a)
            and pr.addressesWeights.get(a) == st.core.weights.get(a)),
      }
    })

  /// Each output fires at most once per round, kind and value.
  val each_output_fires_at_most_once_per_round_kind_value: bool = {
    val l = st.ghost.emittedLog
    0.to(l.length() - 1).forall(i =>
      0.to(l.length() - 1).forall(j => (i != j) implies (l.nth(i) != l.nth(j))))
  }

  /// Only precommits are tallied or recorded as evidence.
  val only_precommits_are_tallied: bool = and {
    st.ghost.tallied.foldl(true, (a, v) => a and v.voteType == PRECOMMIT),
    st.core.perRound.keys().forall(r => {
      val pr = st.core.perRound.get(r)
      pr.votesByAddress.keys().forall(a => pr.votesByAddress.get(a).voteType == PRECOMMIT)
    }),
    st.core.evidence.keys().forall(a =>
      st.core.evidence.get(a).foldl(true, (acc, p) =>
        acc and p.first.voteType == PRECOMMIT and p.conflicting.voteType == PRECOMMIT)),
  }

  /// No vote at an undefined round is tallied and no state is created for one.
  val no_vote_at_an_undefined_round_is_tallied: bool = and {
    st.ghost.tallied.foldl(true, (a, v) => a and v.round != NIL_ROUND),
    not(st.core.perRound.keys().contains(NIL_ROUND)),
    not(st.core.reached.keys().contains(NIL_ROUND)),
  }

  /// Every output is justified by votes of the very round it names.
  val every_output_carries_the_round_of_its_votes: bool = and {
    st.ghost.justification.keys().forall(p =>
      st.ghost.justification.get(p)
        <= weightOfSet(st.core, talliedVoters(st.ghost.tallied, p._1, p._2))),
    st.ghost.decisionJustification.keys().forall(p =>
      st.ghost.decisionJustification.get(p)
        <= weightOfSet(st.core, talliedVoters(st.ghost.tallied, p._1, p._2))),
    st.ghost.anyJustification.keys().forall(r =>
      st.ghost.anyJustification.get(r)
        <= weightOfSet(st.core, talliedVotersAny(st.ghost.tallied, r))),
  }

  /// A threshold once reached is still reported after the round's votes are pruned, and
  /// evidence is never pruned.
  val threshold_answers_survive_pruning: bool = and {
    st.ghost.everVoteQuorum.forall(p => has_vote_quorum(p._1, p._2)),
    st.ghost.everDecided.forall(p => has_decision_quorum(p._1, p._2)),
    st.ghost.everQuorumAny.forall(r =>
      st.core.reached.keys().contains(r) and st.core.reached.get(r).quorumAny),
    evidenceCount(st.core.evidence) == st.ghost.evidencePairsAdded,
  }

  /// A pruned round never reports a threshold it has already reported.
  val a_pruned_round_never_re_reports_its_thresholds: bool =
    st.ghost.reEmitAfterPrune == 0

  /// Pruning drops every round below min_round and keeps every round at or above it.
  val pruning_drops_exactly_the_rounds_below_min_round: bool =
    not(st.ghost.pruneViolation)

  /// Every value that reaches 2f+1 in a round is reported, including two disjoint quorums
  /// in the same round.
  val two_disjoint_vote_quorums_are_both_reported: bool =
    st.ghost.everVoteQuorum.forall(p =>
      listHas(st.ghost.emittedLog, VoteQuorumValue({ round: p._1, value: p._2 })))

  /// Weight exactly at a threshold does not meet it.
  /// The fractions are written out here rather than through `isMet`, so that a non-strict
  /// comparison in the model's threshold test cannot hide inside both sides at once.
  val threshold_is_strict_at_the_boundary: bool = {
    val total = totalOf(st.core)
    and {
      st.ghost.justification.keys().forall(p => st.ghost.justification.get(p) * 5 > total * 2),
      st.ghost.decisionJustification.keys().forall(p =>
        st.ghost.decisionJustification.get(p) * 5 > total * 4),
      st.ghost.anyJustification.keys().forall(r =>
        st.ghost.anyJustification.get(r) * 5 > total * 4),
    }
  }

  //// ------------------------------------------------------------- observations

  /// A vote was tallied and crossed nothing.
  val vote_tallied_without_output: bool =
    st.ghost.lastOutcome == OTallied and st.ghost.lastOutputs.length() == 0

  /// A 2f+1 vote quorum was reported for a value.
  val vote_quorum_emitted: bool = hasVQ(st.ghost.lastOutputs)

  /// An n-f decision quorum was reported for a value.
  val decision_quorum_emitted: bool = hasDQ(st.ghost.lastOutputs)

  /// One vote crossed 2f+1 and n-f at once and both were reported.
  val both_quorums_from_one_vote: bool =
    hasVQ(st.ghost.lastOutputs) and hasDQ(st.ghost.lastOutputs)

  /// The round-advancing n-f quorum-any was reported.
  val quorum_any_emitted: bool = hasQA(st.ghost.lastOutputs)

  /// Quorum-any was reached in a round where no value reached any threshold.
  val quorum_any_without_any_value_quorum: bool =
    st.core.reached.keys().exists(r => {
      val em = st.core.reached.get(r)
      em.quorumAny and em.voteQuorum == Set() and em.decisionQuorum == Set()
    })

  /// Two different values each hold a 2f+1 quorum in the same round.
  val two_disjoint_value_quorums_in_one_round: bool =
    st.core.reached.keys().exists(r => st.core.reached.get(r).voteQuorum.size() >= 2)

  /// A value sits at exactly 2/5 of the total weight and has not met the quorum.
  val value_at_exact_quorum_boundary: bool =
    st.core.perRound.keys().exists(r => {
      val pr = st.core.perRound.get(r)
      pr.valuesWeights.keys().exists(v =>
        isVal(v) and valW(pr, v) * QUORUM_DEN == totalOf(st.core) * QUORUM_NUM)
    })

  /// A value sits at exactly 4/5 of the total weight and has not met the decision threshold.
  val value_at_exact_decision_boundary: bool =
    st.core.perRound.keys().exists(r => {
      val pr = st.core.perRound.get(r)
      pr.valuesWeights.keys().exists(v =>
        isVal(v) and valW(pr, v) * DECISION_DEN == totalOf(st.core) * DECISION_NUM)
    })

  /// A prevote was discarded — this protocol has one voting step.
  val prevote_discarded: bool = st.ghost.lastOutcome == ODiscardedPrevote

  /// A vote from an address outside the validator set was discarded.
  val unknown_voter_discarded: bool = st.ghost.lastOutcome == ODiscardedUnknownVoter

  /// A vote at the undefined round was discarded.
  val nil_round_discarded: bool = st.ghost.lastOutcome == ODiscardedNilRound

  /// A validator's identical vote was replayed and ignored.
  val duplicate_vote_ignored: bool = st.ghost.lastOutcome == ODiscardedDuplicate

  /// A conflicting second vote was recorded as evidence instead of being tallied.
  val equivocation_recorded: bool = st.ghost.lastOutcome == OEvidenceRecorded

  /// The same equivocation pair arrived twice and was stored once.
  val equivocation_pair_deduplicated: bool =
    st.ghost.lastOutcome == OEvidenceDuplicateDropped

  /// A validator reached the per-validator evidence cap and a further pair was dropped.
  val equivocation_cap_reached: bool = st.ghost.lastOutcome == OEvidenceCapped

  /// A prune actually dropped a round's tallies.
  val round_pruned: bool = st.ghost.prunedSomething

  /// A vote for an already-pruned round rebuilt that round's tally.
  val vote_retallied_after_prune: bool = st.ghost.retalliedAfterPrune

  /// A vote crossed a threshold whose latch was already set, so nothing was reported again.
  val pruned_round_emits_nothing_again: bool = st.ghost.suppressedByLatch

  /// A validator equivocated across a prune and it was tallied rather than caught: the first
  /// vote it conflicts with was pruned, so no evidence exists for it.
  val equivocation_missed_after_prune: bool = st.ghost.missedEquivocation
}
