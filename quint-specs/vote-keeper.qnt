// Vote Keeper — models code/crates/core-votekeeper (keeper.rs, round_votes.rs,
// count.rs, value_weights.rs, round_weights.rs, evidence.rs).
// The model MIRRORS the code, quirks included; intent is stated as properties.
//
// Encoding notes (chosen so real traces can be logged):
//   · a validator address is its INDEX in the validator set; -1 (or any index
//     past the set) is a sender the keeper does not know.
//   · a vote value is a value id, with -1 standing for NilOrVal::Nil.
//   · the validator set is state: VoteKeeper::new installs it once.
module vote_keeper {

  // ══════════════ types ══════════════

  type Address = int

  /// Round::Nil is modelled as -1, Round::Some(r) as r.
  type Vote = { voteType: str, src: Address, round: int, value: str }

  type Output =
    | PolkaAny
    | PolkaNil
    | PolkaValue(str)
    | PrecommitAny
    | PrecommitValue(str)
    | SkipRound(int)

  type Threshold = Unreached | ThNil | ThAny | ThValue(str)

  type MaybeOutput = NoOutput | SomeOutput(Output)
  type MaybeRound  = NoRound  | SomeRound(int)

  /// count.rs::VoteCount — per-value weights plus the addresses already counted.
  type VoteCount = { valuesWeights: str -> int, voted: Set[Address] }

  /// keeper.rs::PerRound.
  type PerRound = {
    prevotes: VoteCount,
    precommits: VoteCount,
    addressesWeights: Address -> int,
    receivedVotes: List[Vote],
    emittedOutputs: Set[Output],
  }

  /// One emission of apply_vote, recorded for the history-based properties.
  type Emission = { round: int, currentRound: int, output: Output }

  type Ghost = {
    // keeper.rounds() — what the code reports after the last operation.
    roundsCount: int,
    // the number of validators the evidence map holds evidence against.
    evidenceCount: int,
    // the Output apply_vote returned, split into loggable scalars.
    lastOutputName: str,
    lastOutputValue: str,
    lastOutputRound: int,
    emittedLog: List[Emission],
    prunedRounds: Set[int],
    unknownDiscarded: bool,
    equivocationRecorded: bool,
    duplicateIgnored: bool,
    outputSuppressed: bool,
    evidenceDrained: bool,
    prunedEmitted: bool,
    zeroWeightCounted: bool,
    scratchConflict: bool,
    scratchDuplicate: bool,
  }

  // ══════════════ domains ══════════════

  /// NilOrVal::Nil, as the code renders it in a logged vote.
  pure val NIL: str = "Nil"

  /// VoteType, as the code's discriminants are logged.
  pure val PREVOTE: str = "Prevote"
  pure val PRECOMMIT: str = "Precommit"

  /// The validator sets the suite builds, plus one with a zero-power validator.
  pure val VOTING_POWER_SETS: Set[List[int]] =
    Set(List(1, 1, 1), List(1, 1, 1, 1), List(2, 3, 2), List(1, 1), List(1, 1, 2),
        List(0, 1, 1, 1))

  /// Validator indices, including -1 for a sender outside the set.
  pure val SENDERS: Set[Address] = Set(-1, 0, 1, 2, 3)
  pure val VOTE_TYPES: Set[str] = Set(PREVOTE, PRECOMMIT)
  pure val VOTE_ROUNDS: Set[int] = Set(0, 1)
  pure val CURRENT_ROUNDS: Set[int] = Set(-1, 0, 1)
  pure val PRUNE_ROUNDS: Set[int] = Set(0, 1, 2)
  /// The value ids the suite forms quorums on.
  pure val VOTE_VALUES: Set[str] = Set(NIL, "0", "1", "2")

  /// The long tail of distinct ids an equivocation flood produces. ValueId
  /// renders in HEX ({:x}), so ids 10..50 log as "a".."32". Kept in a step arm
  /// of its own so it does not dilute the quorum-forming picks above.
  pure val WIDE_VOTE_VALUES: Set[str] =
    Set("3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f",
        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a",
        "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25",
        "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", "30",
        "31", "32")

  /// Stand-in for u64::MAX: the machine bound the Rust tally's checked
  /// arithmetic aborts on (scaled down so the model stays inside i64).
  pure val MAX_WEIGHT: int = 1000000
  /// A voting power large enough that the quorum comparison's `weight * 3`
  /// crosses MAX_WEIGHT — the shape of the real overflow panic.
  pure val HUGE_WEIGHT: int = 400000

  pure val WEIGHTS: Set[int] = Set(0, 1, 2, HUGE_WEIGHT)

  // ══════════════ functional layer ══════════════

  pure def weightOf(m: str -> int, v: str): int =
    if (m.keys().contains(v)) m.get(v) else 0

  pure def sumWeights(m: str -> int): int =
    m.keys().fold(0, (acc, k) => acc + m.get(k))

  pure def sumAddrWeights(m: Address -> int): int =
    m.keys().fold(0, (acc, k) => acc + m.get(k))

  /// ThresholdParams::quorum = 2/3 — is_met is strict: weight * 3 > total * 2.
  pure def isQuorum(weight: int, total: int): bool = 3 * weight > 2 * total

  /// ThresholdParams::honest = 1/3 — f+1 of the voting power.
  pure def isHonest(weight: int, total: int): bool = 3 * weight > total

  pure val emptyVoteCount: VoteCount = { valuesWeights: Map(), voted: Set() }

  pure val emptyPerRound: PerRound = {
    prevotes: emptyVoteCount,
    precommits: emptyVoteCount,
    addressesWeights: Map(),
    receivedVotes: List(),
    emittedOutputs: Set(),
  }

  /// count.rs::VoteCount::add — one vote per validator per type; later ones ignored.
  pure def countAdd(vc: VoteCount, vote: Vote, weight: int): VoteCount =
    if (vc.voted.contains(vote.src)) vc
    else {
      valuesWeights: vc.valuesWeights.put(vote.value, weightOf(vc.valuesWeights, vote.value) + weight),
      voted: vc.voted.union(Set(vote.src)),
    }

  /// The tally half of PerRound::add (the dedupe/equivocation half lives in the action).
  pure def perRoundTally(pr: PerRound, vote: Vote, weight: int): PerRound =
    val addrW =
      if (pr.addressesWeights.keys().contains(vote.src)) pr.addressesWeights
      else pr.addressesWeights.put(vote.src, weight)
    val pv = if (vote.voteType == PREVOTE) countAdd(pr.prevotes, vote, weight) else pr.prevotes
    val pc = if (vote.voteType == PRECOMMIT) countAdd(pr.precommits, vote, weight) else pr.precommits
    { ...pr, prevotes: pv, precommits: pc,
             addressesWeights: addrW,
             receivedVotes: pr.receivedVotes.append(vote) }

  /// PerRound::get_vote — the first received vote of this type from this address.
  pure def existingVotes(pr: PerRound, vt: str, addr: Address): List[Vote] =
    pr.receivedVotes.select(v => v.voteType == vt and v.src == addr)

  pure def countFor(pr: PerRound, vt: str): VoteCount =
    if (vt == PREVOTE) pr.prevotes else pr.precommits

  /// keeper.rs::compute_threshold
  pure def computeThreshold(vt: str, pr: PerRound, value: str, total: int): Threshold =
    val vc = countFor(pr, vt)
    if (isQuorum(weightOf(vc.valuesWeights, value), total))
      (if (value == NIL) ThNil else ThValue(value))
    else if (isQuorum(sumWeights(vc.valuesWeights), total)) ThAny
    else Unreached

  /// keeper.rs::threshold_to_output — PrecommitValue is the only output that
  /// outranks SkipRound for a future round.
  pure def thresholdToOutput(vt: str, th: Threshold, skip: MaybeRound): MaybeOutput =
    match skip {
      | SomeRound(fr) =>
        match th {
          | ThValue(v) => if (vt == PRECOMMIT) SomeOutput(PrecommitValue(v)) else SomeOutput(SkipRound(fr))
          | ThNil      => SomeOutput(SkipRound(fr))
          | ThAny      => SomeOutput(SkipRound(fr))
          | Unreached  => SomeOutput(SkipRound(fr))
        }
      | NoRound =>
        match th {
          | Unreached  => NoOutput
          | ThNil      => if (vt == PREVOTE) SomeOutput(PolkaNil) else SomeOutput(PrecommitAny)
          | ThAny      => if (vt == PREVOTE) SomeOutput(PolkaAny) else SomeOutput(PrecommitAny)
          | ThValue(v) => if (vt == PREVOTE) SomeOutput(PolkaValue(v)) else SomeOutput(PrecommitValue(v))
        }
    }

  /// The Output variant's name, as the code's Debug discriminant.
  pure def outputName(o: MaybeOutput): str =
    match o {
      | NoOutput => "None"
      | SomeOutput(out) =>
        match out {
          | PolkaAny          => "PolkaAny"
          | PolkaNil          => "PolkaNil"
          | PolkaValue(_)     => "PolkaValue"
          | PrecommitAny      => "PrecommitAny"
          | PrecommitValue(_) => "PrecommitValue"
          | SkipRound(_)      => "SkipRound"
        }
    }

  /// The value id an Output carries, or "" when it carries none.
  pure def outputValue(o: MaybeOutput): str =
    match o {
      | NoOutput => ""
      | SomeOutput(out) =>
        match out {
          | PolkaValue(v)     => v
          | PrecommitValue(v) => v
          | _                 => ""
        }
    }

  /// The round a SkipRound carries, or -1 for every other Output.
  pure def outputRound(o: MaybeOutput): int =
    match o {
      | NoOutput => -1
      | SomeOutput(out) =>
        match out { | SkipRound(r) => r | _ => -1 }
    }

  /// evidence.rs::MAX_EVIDENCE_PER_VALIDATOR — pairs retained per validator.
  pure val MAX_EVIDENCE_PER_VALIDATOR: int = 3

  /// evidence.rs::EvidenceMap::add — pair-deduped in either order, and capped at
  /// MAX_EVIDENCE_PER_VALIDATOR pairs per validator; further pairs are dropped.
  pure def addEvidence(ev: Address -> List[(Vote, Vote)], existing: Vote, conflicting: Vote):
      Address -> List[(Vote, Vote)] =
    val addr = conflicting.src
    if (ev.keys().contains(addr)) {
      val lst = ev.get(addr)
      val dup = lst.select(p =>
        (p._1 == existing and p._2 == conflicting) or (p._1 == conflicting and p._2 == existing))
      if (dup.length() > 0 or lst.length() >= MAX_EVIDENCE_PER_VALIDATOR) ev
      else ev.put(addr, lst.append((existing, conflicting)))
    } else ev.put(addr, List((existing, conflicting)))

  // ══════════════ state ══════════════

  /// The installed validator set: voting power by validator index.
  var weights: List[int]
  var perRound: int -> PerRound
  var evidence: Address -> List[(Vote, Vote)]
  /// A caller-owned PerRound, the only way PerRound::add is reachable directly.
  var scratch: PerRound
  var ghost: Ghost

  pure val initialGhost: Ghost = {
    roundsCount: 0,
    evidenceCount: 0,
    lastOutputName: "None",
    lastOutputValue: "",
    lastOutputRound: -1,
    emittedLog: List(),
    prunedRounds: Set(),
    unknownDiscarded: false,
    equivocationRecorded: false,
    duplicateIgnored: false,
    outputSuppressed: false,
    evidenceDrained: false,
    prunedEmitted: false,
    zeroWeightCounted: false,
    scratchConflict: false,
    scratchDuplicate: false,
  }

  /// No keeper yet — VoteKeeper::new installs the validator set.
  action init = all {
    weights' = List(),
    perRound' = Map(),
    evidence' = Map(),
    scratch' = emptyPerRound,
    ghost' = initialGhost,
  }

  // ══════════════ queries (no transition) ══════════════

  pure def perRoundOf(m: int -> PerRound, r: int): PerRound =
    if (m.keys().contains(r)) m.get(r) else emptyPerRound

  /// validator_set.total_voting_power()
  val totalWeight: int = weights.foldl(0, (acc, w) => acc + w)

  /// validator_set.get_by_address(..).is_some()
  def known(a: Address): bool = a >= 0 and a < weights.length()

  /// validator.voting_power()
  def powerOf(a: Address): int = if (known(a)) weights.nth(a) else 0

  /// keeper.rs::is_threshold_met
  def isThresholdMet(r: int, vt: str, th: Threshold): bool =
    perRound.keys().contains(r) and {
      val vc = countFor(perRound.get(r), vt)
      match th {
        | ThValue(v) => isQuorum(weightOf(vc.valuesWeights, v), totalWeight)
        | ThNil      => isQuorum(weightOf(vc.valuesWeights, NIL), totalWeight)
        | ThAny      => isQuorum(sumWeights(vc.valuesWeights), totalWeight)
        | Unreached  => false
      }
    }

  /// keeper.rs::has_vote
  def hasVote(vote: Vote): bool =
    perRound.keys().contains(vote.round) and
    perRound.get(vote.round).receivedVotes.select(v => v == vote).length() > 0

  /// keeper.rs::max_round
  val maxRound: int =
    if (perRound.keys().size() == 0) -1
    else perRound.keys().fold(-1, (a, r) => if (r > a) r else a)

  def emittedOutputsOf(r: int): Set[Output] = perRoundOf(perRound, r).emittedOutputs

  // ══════════════ actions ══════════════

  /// keeper.rs::VoteKeeper::new — installs the validator set for this height.
  action VoteKeeperNew(voting_powers: List[int]): bool = all {
    weights.length() == 0,
    voting_powers.length() > 0,
    weights' = voting_powers,
    perRound' = Map(),
    evidence' = Map(),
    scratch' = scratch,
    ghost' = { ...initialGhost, scratchConflict: ghost.scratchConflict,
                                scratchDuplicate: ghost.scratchDuplicate },
  }

  /// keeper.rs::apply_vote (keeper.rs:249). Note the per_round entry is created
  /// BEFORE the validator-set lookup, so an unknown sender still creates a round.
  action apply_vote(vote_type: str, src: Address, vote_round: int, value: str,
                    current_round: int): bool = {
    val vote: Vote = { voteType: vote_type, src: src, round: vote_round, value: value }
    val pr0 = perRoundOf(perRound, vote.round)
    if (not(known(vote.src))) {
      // Vote from unknown validator: entry inserted, vote discarded, no output.
      val nextRounds = perRound.put(vote.round, pr0)
      all {
        weights.length() > 0,
        weights' = weights,
        perRound' = nextRounds,
        evidence' = evidence,
        scratch' = scratch,
        ghost' = { ...ghost, lastOutputName: "None", lastOutputValue: "", lastOutputRound: -1,
                             roundsCount: nextRounds.keys().size(),
                             evidenceCount: evidence.keys().size(),
                             unknownDiscarded: true },
      }
    } else {
      val w = powerOf(vote.src)
      val prior = existingVotes(pr0, vote.voteType, vote.src)
      val hasPrior = prior.length() > 0
      if (hasPrior and prior.head().value != vote.value) {
        // Equivocation: recorded as evidence, never tallied, no output.
        val nextRounds = perRound.put(vote.round, pr0)
        val nextEvidence = addEvidence(evidence, prior.head(), vote)
        all {
          weights.length() > 0,
          weights' = weights,
          perRound' = nextRounds,
          evidence' = nextEvidence,
          scratch' = scratch,
          ghost' = { ...ghost, lastOutputName: "None", lastOutputValue: "", lastOutputRound: -1,
                               roundsCount: nextRounds.keys().size(),
                               evidenceCount: nextEvidence.keys().size(),
                               equivocationRecorded: true },
        }
      } else {
        // Exact duplicate returns Ok(()) WITHOUT tallying, then falls through
        // to the threshold computation just like a fresh vote.
        val pr1 = if (hasPrior) pr0 else perRoundTally(pr0, vote, w)
        val th = computeThreshold(vote.voteType, pr1, vote.value, totalWeight)
        val skip =
          if (vote.round > current_round and isHonest(sumAddrWeights(pr1.addressesWeights), totalWeight))
            SomeRound(vote.round)
          else NoRound
        val cand = thresholdToOutput(vote.voteType, th, skip)
        val alreadyEmitted =
          match cand { | NoOutput => false | SomeOutput(o) => pr1.emittedOutputs.contains(o) }
        val emitted = if (alreadyEmitted) NoOutput else cand
        val pr2 =
          match emitted {
            | NoOutput => pr1
            | SomeOutput(o) => { ...pr1, emittedOutputs: pr1.emittedOutputs.union(Set(o)) }
          }
        val nextRounds = perRound.put(vote.round, pr2)
        val nextLog =
          match emitted {
            | NoOutput => ghost.emittedLog
            | SomeOutput(o) =>
              ghost.emittedLog.append({ round: vote.round, currentRound: current_round, output: o })
          }
        all {
          weights.length() > 0,
          weights' = weights,
          perRound' = nextRounds,
          evidence' = evidence,
          scratch' = scratch,
          ghost' = { ...ghost, lastOutputName: outputName(emitted),
                               lastOutputValue: outputValue(emitted),
                               lastOutputRound: outputRound(emitted),
                               roundsCount: nextRounds.keys().size(),
                               evidenceCount: evidence.keys().size(),
                               emittedLog: nextLog,
                               outputSuppressed: ghost.outputSuppressed or alreadyEmitted,
                               duplicateIgnored: ghost.duplicateIgnored or hasPrior,
                               zeroWeightCounted: ghost.zeroWeightCounted or (not(hasPrior) and w == 0) },
        }
      }
    }
  }

  /// keeper.rs::take_evidence — drains the evidence map.
  action take_evidence = all {
    weights.length() > 0,
    weights' = weights,
    perRound' = perRound,
    evidence' = Map(),
    scratch' = scratch,
    ghost' = { ...ghost, evidenceCount: 0,
                         evidenceDrained: ghost.evidenceDrained or evidence.keys().size() > 0 },
  }

  /// keeper.rs::prune_votes — retains rounds >= min_round; the emitted-output
  /// dedup state of the dropped rounds goes with them.
  action prune_votes(min_round: int): bool = {
    val dropped = perRound.keys().filter(r => r < min_round)
    val nextRounds = perRound.keys().filter(r => r >= min_round).mapBy(r => perRound.get(r))
    all {
      weights.length() > 0,
      weights' = weights,
      perRound' = nextRounds,
      evidence' = evidence,
      scratch' = scratch,
      ghost' = { ...ghost, roundsCount: nextRounds.keys().size(),
                           prunedRounds: ghost.prunedRounds.union(dropped),
                           prunedEmitted: ghost.prunedEmitted or
                             dropped.exists(r => perRound.get(r).emittedOutputs.size() > 0) },
    }
  }

  /// keeper.rs::PerRound::add, called directly on a caller-owned PerRound.
  action PerRoundadd(vote: Vote, weight: int): bool = {
    val prior = existingVotes(scratch, vote.voteType, vote.src)
    val hasPrior = prior.length() > 0
    if (hasPrior and prior.head().value != vote.value) all {
      // ConflictingVote error: nothing recorded.
      weights' = weights, perRound' = perRound, evidence' = evidence, scratch' = scratch,
      ghost' = { ...ghost, scratchConflict: true },
    } else if (hasPrior) all {
      // Duplicate: Ok(()), nothing recorded.
      weights' = weights, perRound' = perRound, evidence' = evidence, scratch' = scratch,
      ghost' = { ...ghost, scratchDuplicate: true },
    } else all {
      weights' = weights, perRound' = perRound, evidence' = evidence,
      scratch' = perRoundTally(scratch, vote, weight),
      ghost' = ghost,
    }
  }

  action step = any {
    {
      nondet voting_powers = VOTING_POWER_SETS.oneOf()
      VoteKeeperNew(voting_powers)
    },
    {
      nondet vote_type = VOTE_TYPES.oneOf()
      nondet src = SENDERS.oneOf()
      nondet vote_round = VOTE_ROUNDS.oneOf()
      nondet value = VOTE_VALUES.oneOf()
      nondet current_round = CURRENT_ROUNDS.oneOf()
      apply_vote(vote_type, src, vote_round, value, current_round)
    },
    {
      nondet vote_type = VOTE_TYPES.oneOf()
      nondet src = SENDERS.oneOf()
      nondet vote_round = VOTE_ROUNDS.oneOf()
      nondet value = WIDE_VOTE_VALUES.oneOf()
      nondet current_round = CURRENT_ROUNDS.oneOf()
      apply_vote(vote_type, src, vote_round, value, current_round)
    },
    take_evidence,
    {
      nondet min_round = PRUNE_ROUNDS.oneOf()
      prune_votes(min_round)
    },
    {
      nondet vote_type = VOTE_TYPES.oneOf()
      nondet src = SENDERS.oneOf()
      nondet vote_round = VOTE_ROUNDS.oneOf()
      nondet value = VOTE_VALUES.oneOf()
      nondet weight = WEIGHTS.oneOf()
      PerRoundadd({ voteType: vote_type, src: src, round: vote_round, value: value }, weight)
    },
  }

  // ══════════════ correctness properties ══════════════

  /// An output already emitted for a round is never emitted again for that same
  /// round, so the driver never sees a duplicate threshold event.
  val emit_at_most_once_per_round: bool =
    ghost.emittedLog.indices().forall(i =>
      ghost.emittedLog.indices().forall(j =>
        val a = ghost.emittedLog.nth(i)
        val b = ghost.emittedLog.nth(j)
        (i < j and a.round == b.round and a.output == b.output)
          implies ghost.prunedRounds.contains(a.round)))

  /// The tallied weight of a round equals the voting power of exactly the
  /// validators recorded as having voted — a re-tallied or double-counted
  /// validator would let a minority reach a quorum.
  val tally_matches_voters: bool =
    perRound.keys().forall(r =>
      VOTE_TYPES.forall(vt =>
        val vc = countFor(perRound.get(r), vt)
        sumWeights(vc.valuesWeights) == vc.voted.fold(0, (acc, a) => acc + powerOf(a))))

  /// PolkaValue(v) is only ever reported for a round where strictly more than
  /// 2/3 of the total voting power prevoted v; otherwise a validator could lock
  /// on a value that never polka'd.
  val polka_value_needs_quorum: bool =
    perRound.keys().forall(r =>
      VOTE_VALUES.forall(v =>
        (v != NIL and perRound.get(r).emittedOutputs.contains(PolkaValue(v)))
          implies isQuorum(weightOf(perRound.get(r).prevotes.valuesWeights, v), totalWeight)))

  /// SkipRound(r) is only reported for a round strictly above the current round,
  /// and only once f+1 of the voting power has voted in it — a skip triggered by
  /// less than that lets a single faulty validator drag the node forward.
  val skip_round_only_from_future_rounds: bool =
    ghost.emittedLog.indices().forall(i =>
      val e = ghost.emittedLog.nth(i)
      match e.output {
        | SkipRound(r) => r == e.round and e.round > e.currentRound
        | _ => true
      })

  /// A precommit quorum on a value is always reported as PrecommitValue for that
  /// round, even when the round is ahead of the current one — PrecommitValue is
  /// the one output that outranks SkipRound.
  val precommit_value_reported_on_quorum: bool =
    perRound.keys().forall(r =>
      VOTE_VALUES.forall(v =>
        (v != NIL and isQuorum(weightOf(perRound.get(r).precommits.valuesWeights, v), totalWeight))
          implies perRound.get(r).emittedOutputs.contains(PrecommitValue(v))))

  /// A round that holds a 2f+1 prevote quorum has reported PolkaAny for it —
  /// a driver arming its prevote timeout on PolkaAny must not be starved.
  val polka_any_reported_on_prevote_quorum: bool =
    perRound.keys().forall(r =>
      isThresholdMet(r, PREVOTE, ThAny) implies emittedOutputsOf(r).contains(PolkaAny))

  /// Equivocation evidence is only ever recorded against a validator that
  /// actually cast two differing votes of the same type in the same round.
  val evidence_is_real_equivocation: bool =
    evidence.keys().forall(a =>
      evidence.get(a).indices().forall(i =>
        val p = evidence.get(a).nth(i)
        p._1.src == a and p._2.src == a and
        p._1.voteType == p._2.voteType and p._1.round == p._2.round and
        p._1.value != p._2.value))

  /// A single validator's equivocation evidence never accumulates more than the
  /// retention cap, so a flooding equivocator cannot grow the keeper's memory.
  val evidence_bounded_per_validator: bool =
    evidence.keys().forall(a =>
      evidence.get(a).length() <= MAX_EVIDENCE_PER_VALIDATOR)

  /// A precommit quorum on nil is reported with an output of its own, never the
  /// PrecommitAny that a quorum split across different values reports.
  val precommit_nil_distinguishable_from_split: bool =
    perRound.keys().forall(r =>
      isThresholdMet(r, PRECOMMIT, ThNil)
        implies not(perRound.get(r).emittedOutputs.contains(PrecommitAny)))

  /// Accumulating votes never pushes a tallied weight, or the quorum comparison
  /// computed from it, past the machine maximum where the tally aborts the node.
  val tally_never_overflows: bool =
    VOTE_TYPES.forall(vt =>
      val vc = countFor(scratch, vt)
      and {
        vc.valuesWeights.keys().forall(v => weightOf(vc.valuesWeights, v) <= MAX_WEIGHT),
        sumWeights(vc.valuesWeights) <= MAX_WEIGHT,
        3 * sumWeights(vc.valuesWeights) <= MAX_WEIGHT,
      })

  // ══════════════ scenario runs ══════════════

  /// A precommit quorum for a round ahead of the current one is reported as
  /// PrecommitValue, even though SkipRound for that round was already emitted.
  run futurePrecommitValueRun =
    init
      .then(VoteKeeperNew(List(2, 1, 1)))
      .then(apply_vote(PRECOMMIT, 0, 1, "1", 0))
      .expect(perRoundOf(perRound, 1).emittedOutputs.contains(SkipRound(1)))
      .then(apply_vote(PRECOMMIT, 1, 1, "1", 0))
      .expect(ghost.lastOutputName == "PrecommitValue" and ghost.lastOutputValue == "1")

  // ══════════════ observations ══════════════

  /// A vote from a validator outside the validator set was discarded.
  val vote_from_unknown_validator_discarded: bool = ghost.unknownDiscarded

  /// A round entry exists that holds no received vote at all (created by a
  /// discarded vote, or emptied by nothing else).
  val ghost_round_created: bool =
    perRound.keys().exists(r => perRound.get(r).receivedVotes.length() == 0)

  /// A conflicting second vote was absorbed into the evidence map.
  val equivocation_recorded: bool = ghost.equivocationRecorded

  /// An exact duplicate vote was accepted without being re-tallied.
  val duplicate_vote_ignored: bool = ghost.duplicateIgnored

  /// A threshold was reached again but the output had already been emitted.
  val output_suppressed_as_duplicate: bool = ghost.outputSuppressed

  /// A validator with zero voting power had its vote tallied.
  val zero_weight_vote_counted: bool = ghost.zeroWeightCounted

  /// A prevote quorum spread over several values reported PolkaAny.
  val polka_any_emitted: bool =
    perRound.keys().exists(r => perRound.get(r).emittedOutputs.contains(PolkaAny))

  /// A prevote quorum on nil reported PolkaNil.
  val polka_nil_emitted: bool =
    perRound.keys().exists(r => perRound.get(r).emittedOutputs.contains(PolkaNil))

  /// A prevote quorum on a specific value reported PolkaValue.
  val polka_value_emitted: bool =
    perRound.keys().exists(r => perRound.get(r).emittedOutputs.exists(o =>
      match o { | PolkaValue(_) => true | _ => false }))

  /// A precommit quorum on nil or spread over values reported PrecommitAny.
  val precommit_any_emitted: bool =
    perRound.keys().exists(r => perRound.get(r).emittedOutputs.contains(PrecommitAny))

  /// A precommit quorum on a specific value reported PrecommitValue.
  val precommit_value_emitted: bool =
    perRound.keys().exists(r => perRound.get(r).emittedOutputs.exists(o =>
      match o { | PrecommitValue(_) => true | _ => false }))

  /// f+1 of the voting power voted in a round above the current one, reporting SkipRound.
  val skip_round_emitted: bool =
    perRound.keys().exists(r => perRound.get(r).emittedOutputs.exists(o =>
      match o { | SkipRound(_) => true | _ => false }))

  /// take_evidence drained a non-empty evidence map.
  val evidence_drained: bool = ghost.evidenceDrained

  /// prune_votes dropped a round that had already emitted outputs, losing its
  /// dedup state.
  val pruned_round_with_emitted_outputs: bool = ghost.prunedEmitted

  /// PerRound::add rejected a vote with ConflictingVote.
  val per_round_add_conflicting: bool = ghost.scratchConflict

  /// PerRound::add silently ignored an exact duplicate.
  val per_round_add_duplicate: bool = ghost.scratchDuplicate
}
