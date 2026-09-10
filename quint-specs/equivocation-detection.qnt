// Equivocation Detection — cross-cutting evidence collection in Malachite.
//
// Mirrors:
//   code/crates/core-votekeeper/src/evidence.rs        EvidenceMap<DoubleVote>, capped at 3
//   code/crates/core-votekeeper/src/keeper.rs:93-441   PerRound::add + apply_vote
//   code/crates/core-driver/src/proposal_keeper.rs     PerRound::add, ProposalKeeper,
//                                                      EvidenceMap<DoubleProposal> (UNCAPPED)
//   code/crates/core-driver/src/driver.rs:283-325      take_*_evidence, record_proposal_evidence
//   code/crates/core-consensus/src/handle/proposal.rs  the proposer gate
//   code/crates/core-consensus/src/state.rs:209-235    the upstream-filtered evidence path
//   code/crates/core-consensus/src/handle/finalize.rs  log_and_finalize, the single drain/emit
//
// The model mirrors the code, bugs included. Intent is stated in `invariants`.
//
// Action signatures are FLAT and their parameter names match the names the
// instrumentation logs, so every replay pick is pinned from a logged argument.
module equivocation_detection {

  type Vote     = { src: int, voteType: str, round: int, value: str }
  type Proposal = { validator: int, round: int, value: str, polRound: int }

  /// evidence.rs:14 — MAX_EVIDENCE_PER_VALIDATOR
  pure val MAX_EVIDENCE_PER_VALIDATOR: int = 3

  pure val VALIDATORS: Set[int] = Set(0, 1, 2, 3)
  pure val POWER: int -> int = VALIDATORS.mapBy(_ => 10)
  /// 2f+1 with f = 1 over four equal validators.
  pure val QUORUM: int = 30

  /// Simulation bound on how far a height's rounds advance. The code itself
  /// bounds nothing — `per_round.entry(round).or_insert(..)` accepts any round —
  /// so this is sim machinery, not a contract guard.
  pure val MAX_ROUND: int = 3

  // ── logged-argument domains (names match the `domain` tags in the code) ───
  /// Vote senders by validator-set index; -1 is a sender outside the set.
  pure val SENDERS: Set[int] = Set(-1, 0, 1, 2, 3)
  pure val VOTE_TYPES: Set[str] = Set("Prevote", "Precommit")
  // ── narrow sim sets: small enough that a random walk repeats a value ──
  pure val SIM_ROUNDS: Set[int] = Set(0, 1)
  pure val SIM_VOTE_VALUES: Set[str] = Set("Nil", "64", "c8")
  pure val SIM_PROPOSAL_VALUES: Set[str] = Set("64", "c8")
  pure val SIM_POL_ROUNDS: Set[int] = Set(-1, 0)

  /// Rounds a vote can carry: MAX_FUTURE_ROUND_LOOKAHEAD is 10, and the
  /// lookahead window slides with the consensus round.
  pure val VOTE_ROUNDS: Set[int] = Set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20)
  pure val CURRENT_ROUNDS: Set[int] = Set(-1).union(VOTE_ROUNDS)
  /// Value ids as the code renders them (lowercase hex), plus Nil.
  pure val VOTE_VALUES: Set[str] = Set("Nil", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", "30", "31", "32", "64", "c8", "12c", "190", "3e7", "1e61", "22b8", "270f", "37a5")
  /// Proposal senders by validator-set index; -1 is outside the set.
  pure val PROPOSERS: Set[int] = Set(-1, 0, 1, 2, 3)
  pure val PROPOSAL_ROUNDS: Set[int] = VOTE_ROUNDS
  pure val PROPOSAL_VALUES: Set[str] = Set("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "2f", "30", "31", "32", "64", "c8", "12c", "190", "3e7", "1e61", "22b8", "270f", "37a5")
  pure val POL_ROUNDS: Set[int] = Set(-1, 0, 1, 2)
  pure val VALIDITIES: Set[str] = Set("Valid", "Invalid")

  /// Round-robin proposer, as `state.get_proposer(height, round)` resolves it here.
  pure def proposerOf(r: int): int = r % 4

  type VoteKeeper = {
    // PerRound.received_votes, per round.
    received: int -> Set[Vote],
    // PerRound.votes weights, per round, per (vote type, value).
    tally: int -> ((str, str) -> int),
    // EvidenceMap<DoubleVote>.map, per validator index.
    evidence: int -> List[(Vote, Vote)],
  }

  type ProposalKeeper = {
    // PerRound.proposals, per round.
    stored: int -> List[(Proposal, str)],
    // EvidenceMap<DoubleProposal>.map, per validator index. No cap in the code.
    evidence: int -> List[(Proposal, Proposal)],
  }

  type Node = {
    round: int,
    stepIsCommit: bool,
    finalizationPeriod: bool,
    // Latched where verify_same_validator's assert_eq! fires. The real process
    // stops there, so this is observational only — it gates no other operation.
    aborted: bool,
  }

  type Ghost = {
    // (round, validator) -> the value its power was credited to at tally time; "" = none.
    creditedValue: (int, int) -> str,
    // ── conformance mirrors, asserted by the instrumentation ──
    votePairs: int,
    proposalPairs: int,
    voteAddrs: int,
    proposalAddrs: int,
    finalizeCount: int,
    abortedFlag: int,
    // What the take_*_evidence drains removed, so log_and_finalize can report
    // the height's evidence even though the drains ran first.
    drainedVotePairs: int,
    drainedProposalPairs: int,
    // (round, validator index) pairs apply_vote detected as equivocating.
    equivocators: Set[(int, int)],
    // ── outcome latches ──
    surfacedMidRound: bool,
    voteDedupAbsorbed: bool,
    proposalDedupAbsorbed: bool,
    capDropped: bool,
    validityUpgraded: bool,
    validityDowngradeRefused: bool,
    duplicateVoteIgnored: bool,
    unknownValidatorDropped: bool,
    nonProposerDropped: bool,
    thresholdReached: bool,
  }

  var vk: VoteKeeper
  var pk: ProposalKeeper
  var node: Node
  /// One entry per Effect::Finalize(_, _, MisbehaviorEvidence{proposals, votes}, _).
  var emitted: List[{ proposalPairs: int, votePairs: int }]
  var ghost: Ghost

  // ── pure helpers ──────────────────────────────────────────────────────────

  // Every keeper map grows on demand, mirroring BTreeMap::entry(..).or_insert(..):
  // a key the code has not created yet reads as its empty value.
  pure def receivedAt(m: int -> Set[Vote], r: int): Set[Vote] =
    if (m.keys().contains(r)) m.get(r) else Set()

  pure def tallyAt(m: int -> ((str, str) -> int), r: int): (str, str) -> int =
    if (m.keys().contains(r)) m.get(r) else Map()

  pure def weightAt(t: (str, str) -> int, k: (str, str)): int =
    if (t.keys().contains(k)) t.get(k) else 0

  pure def storedAt(m: int -> List[(Proposal, str)], r: int): List[(Proposal, str)] =
    if (m.keys().contains(r)) m.get(r) else List()

  pure def voteEvAt(m: int -> List[(Vote, Vote)], a: int): List[(Vote, Vote)] =
    if (m.keys().contains(a)) m.get(a) else List()

  pure def propEvAt(m: int -> List[(Proposal, Proposal)], a: int): List[(Proposal, Proposal)] =
    if (m.keys().contains(a)) m.get(a) else List()

  pure def creditedAt(g: (int, int) -> str, r: int, a: int): str =
    if (g.keys().contains((r, a))) g.get((r, a)) else ""

  pure def votePairCount(m: int -> List[(Vote, Vote)]): int =
    m.keys().fold(0, (acc, a) => acc + m.get(a).length())

  pure def voteAddrCount(m: int -> List[(Vote, Vote)]): int =
    m.keys().filter(a => m.get(a).length() > 0).size()

  pure def proposalPairCount(m: int -> List[(Proposal, Proposal)]): int =
    m.keys().fold(0, (acc, a) => acc + m.get(a).length())

  pure def proposalAddrCount(m: int -> List[(Proposal, Proposal)]): int =
    m.keys().filter(a => m.get(a).length() > 0).size()

  /// EvidenceMap::add's "already exists (in either order)" check.
  pure def votePairKnown(l: List[(Vote, Vote)], e: Vote, c: Vote): bool =
    l.indices().exists(i =>
      (l.nth(i)._1 == e and l.nth(i)._2 == c) or (l.nth(i)._1 == c and l.nth(i)._2 == e))

  pure def proposalPairKnown(l: List[(Proposal, Proposal)], e: Proposal, c: Proposal): bool =
    l.indices().exists(i =>
      (l.nth(i)._1 == e and l.nth(i)._2 == c) or (l.nth(i)._1 == c and l.nth(i)._2 == e))

  /// PerRound::add's existing-vote lookup: same vote type, same validator.
  pure def priorVotes(vs: Set[Vote], v: Vote): Set[Vote] =
    vs.filter(o => o.voteType == v.voteType and o.src == v.src)

  /// PerRound::proposal_validity_mut — the index of an entry equal to this proposal.
  pure def storedIndex(l: List[(Proposal, str)], p: Proposal): Set[int] =
    l.indices().filter(i => l.nth(i)._1 == p)

  pure def containsExact(l: List[(Proposal, str)], p: Proposal, v: str): bool =
    l.indices().exists(i => l.nth(i)._1 == p and l.nth(i)._2 == v)

  /// PerRound::get_first_proposal.
  pure def firstProposalValidator(l: List[(Proposal, str)]): int =
    if (l.length() == 0) -1 else l.nth(0)._1.validator

  // ── init ──────────────────────────────────────────────────────────────────

  pure val initialGhost: Ghost = {
    creditedValue: Map(),
    votePairs: 0,
    proposalPairs: 0,
    voteAddrs: 0,
    proposalAddrs: 0,
    finalizeCount: 0,
    abortedFlag: 0,
    drainedVotePairs: 0,
    drainedProposalPairs: 0,
    equivocators: Set(),
    surfacedMidRound: false,
    voteDedupAbsorbed: false,
    proposalDedupAbsorbed: false,
    capDropped: false,
    validityUpgraded: false,
    validityDowngradeRefused: false,
    duplicateVoteIgnored: false,
    unknownValidatorDropped: false,
    nonProposerDropped: false,
    thresholdReached: false,
  }

  action init = all {
    vk' = { received: Map(), tally: Map(), evidence: Map() },
    pk' = { stored: Map(), evidence: Map() },
    node' = { round: 0, stepIsCommit: false, finalizationPeriod: false, aborted: false },
    emitted' = List(),
    ghost' = initialGhost,
  }

  // ── EvidenceMap::add (evidence.rs:52-72) ──────────────────────────────────

  /// EvidenceMap::add — the direct entry the votekeeper evidence tests drive.
  /// Its guards are the documented precondition: both votes from the same
  /// validator (debug-asserted), one (round, vote type), conflicting values.
  action vote_evidence_add(src: int, vote_type: str, vote_round: int,
                           existing_value: str, conflicting_value: str): bool = all {
    VALIDATORS.contains(src),
    existing_value != conflicting_value,
    val existing = { src: src, voteType: vote_type, round: vote_round, value: existing_value }
    val conflicting = { src: src, voteType: vote_type, round: vote_round, value: conflicting_value }
    val l = voteEvAt(vk.evidence, src)
    val known = votePairKnown(l, existing, conflicting)
    val newEvidence =
      if (not(known) and l.length() < MAX_EVIDENCE_PER_VALIDATOR)
        vk.evidence.put(src, l.append((existing, conflicting)))
      else vk.evidence
    all {
      vk' = { ...vk, evidence: newEvidence },
      ghost' = { ...ghost,
        voteDedupAbsorbed: ghost.voteDedupAbsorbed or known,
        capDropped: ghost.capDropped
                    or (not(known) and l.length() >= MAX_EVIDENCE_PER_VALIDATOR),
        votePairs: votePairCount(newEvidence),
        voteAddrs: voteAddrCount(newEvidence),
      },
    },
    pk' = pk,
    node' = node,
    emitted' = emitted,
  }

  // ── apply_vote (keeper.rs:314-441, PerRound::add at keeper.rs:93-135) ──────

  /// VoteKeeper::apply_vote. The equivocation branch calls evidence.add and
  /// returns before any tally happens; the conflicting vote is never counted.
  action apply_vote(vote_type: str, src: int, vote_round: int,
                    value: str, current_round: int): bool = all {
    val vote = { src: src, voteType: vote_type, round: vote_round, value: value }
    val unknown = not(VALIDATORS.contains(src))
    val prior = priorVotes(receivedAt(vk.received, vote_round), vote)
    val conflicting = prior.exists(o => o.value != value)
    val duplicate = prior.exists(o => o.value == value)
    val newWeight =
      weightAt(tallyAt(vk.tally, vote_round), (vote_type, value))
        + (if (unknown) 0 else POWER.get(src))
    val newVk =
      if (unknown) vk
      // keeper.rs:397-441 — the conflicting vote is never tallied. The evidence
      // write itself is EvidenceMap::add, modelled as `vote_evidence_add`.
      else if (conflicting) vk
      else if (duplicate) vk
      else {
        received: vk.received.put(vote_round,
                    receivedAt(vk.received, vote_round).union(Set(vote))),
        tally: vk.tally.put(vote_round,
                 tallyAt(vk.tally, vote_round).put((vote_type, value), newWeight)),
        evidence: vk.evidence,
      }
    val tallied = not(unknown) and not(conflicting) and not(duplicate)
    all {
      vk' = newVk,
      ghost' = { ...ghost,
        unknownValidatorDropped: ghost.unknownValidatorDropped or unknown,
        duplicateVoteIgnored: ghost.duplicateVoteIgnored or (not(unknown) and duplicate),
        equivocators: if (not(unknown) and conflicting)
                        ghost.equivocators.union(Set((vote_round, src)))
                      else ghost.equivocators,
        creditedValue: if (tallied) ghost.creditedValue.put((vote_round, src), value)
                       else ghost.creditedValue,
        thresholdReached: ghost.thresholdReached or (tallied and newWeight >= QUORUM),
        votePairs: votePairCount(newVk.evidence),
        voteAddrs: voteAddrCount(newVk.evidence),
      },
      pk' = pk,
      node' = node,
      emitted' = emitted,
    },
  }

  // ── ProposalKeeper::store_proposal (proposal_keeper.rs:78-176, 239-247) ────

  /// The driver-level ProposalKeeper::store_proposal — no proposer gate on this
  /// entry point. verify_same_validator's assert_eq! is mirrored as `aborted`.
  action store_proposal(validator: int, proposal_round: int, value: str,
                        pol_round: int, validity: str): bool = all {
    VALIDATORS.contains(validator),
    val proposal = { validator: validator, round: proposal_round,
                     value: value, polRound: pol_round }
    val l = storedAt(pk.stored, proposal_round)
    val exact = containsExact(l, proposal, validity)
    val crossValidator = l.length() > 0 and firstProposalValidator(l) != validator
    val idx = storedIndex(l, proposal)
    val present = idx.size() > 0
    val at = idx.fold(0, (_, i) => i)
    val currentValidity = if (present) l.nth(at)._2 else validity
    val upgrade = present and currentValidity == "Invalid" and validity == "Valid"
    val downgrade = present and currentValidity == "Valid" and validity == "Invalid"
    val newStored =
      if (exact or crossValidator) l
      else if (upgrade) l.replaceAt(at, (proposal, "Valid"))
      else if (present) l
      else l.append((proposal, validity))
    all {
      node' = { ...node, aborted: node.aborted or crossValidator },
      // ProposalKeeper::store_proposal only STORES; check_equivocation reports the
      // pair to the caller, which records it via record_evidence.
      pk' = { ...pk, stored: pk.stored.put(proposal_round, newStored) },
      ghost' = { ...ghost,
        validityUpgraded: ghost.validityUpgraded or upgrade,
        validityDowngradeRefused: ghost.validityDowngradeRefused or downgrade,
        abortedFlag: if (node.aborted or crossValidator) 1 else 0,
      },
      vk' = vk,
      emitted' = emitted,
    },
  }

  /// The network path: handle_proposal gates on the expected proposer
  /// (proposal.rs:201-213) and on the current round before the keeper sees it.
  action handle_proposal(validator: int, proposal_round: int, value: str,
                         pol_round: int, validity: str): bool = all {
    proposal_round == node.round,
    validator == proposerOf(node.round),
    store_proposal(validator, proposal_round, value, pol_round, validity),
  }

  /// verify_signed_proposal rejecting a non-proposer (proposal.rs:203-213):
  /// the proposal is silently dropped before any keeper sees it.
  action drop_non_proposer(validator: int, proposal_round: int): bool = all {
    proposal_round == node.round,
    validator != proposerOf(node.round),
    ghost' = { ...ghost, nonProposerDropped: true },
    vk' = vk,
    pk' = pk,
    node' = node,
    emitted' = emitted,
  }

  // ── ProposalKeeper::record_evidence (proposal_keeper.rs:257-269) ───────────

  /// The upstream-filtered path from state.rs:226-233: the full-proposal keeper
  /// filtered the conflicting proposal, so evidence is recorded directly.
  action record_proposal_evidence(validator: int, proposal_round: int,
                                  existing_value: str, existing_pol_round: int,
                                  conflicting_value: str, conflicting_pol_round: int): bool = all {
    VALIDATORS.contains(validator),
    not(existing_value == conflicting_value and existing_pol_round == conflicting_pol_round),
    // Reports the surfaced pair; EvidenceMap::add performs the write.
    pk' = pk,
    ghost' = ghost,
    vk' = vk,
    node' = node,
    emitted' = emitted,
  }

  /// EvidenceMap::add on the proposal side (proposal_keeper.rs:308-327) — the
  /// write itself: dedup in either order, and NO per-validator cap, unlike the
  /// vote EvidenceMap.
  action proposal_evidence_add(validator: int, proposal_round: int,
                               existing_value: str, existing_pol_round: int,
                               conflicting_value: str,
                               conflicting_pol_round: int): bool = all {
    VALIDATORS.contains(validator),
    not(existing_value == conflicting_value and existing_pol_round == conflicting_pol_round),
    val existing = { validator: validator, round: proposal_round,
                     value: existing_value, polRound: existing_pol_round }
    val conflicting = { validator: validator, round: proposal_round,
                        value: conflicting_value, polRound: conflicting_pol_round }
    val el = propEvAt(pk.evidence, validator)
    val known = proposalPairKnown(el, existing, conflicting)
    val newEvidence = if (known) pk.evidence
                      else pk.evidence.put(validator, el.append((existing, conflicting)))
    all {
      pk' = { ...pk, evidence: newEvidence },
      ghost' = { ...ghost,
        proposalDedupAbsorbed: ghost.proposalDedupAbsorbed or known,
        proposalPairs: proposalPairCount(newEvidence),
        proposalAddrs: proposalAddrCount(newEvidence),
      },
    },
    vk' = vk,
    node' = node,
    emitted' = emitted,
  }

  // ── evidence queries (evidence.rs:34-45, proposal_keeper.rs:226-228) ───────

  /// VoteKeeper::evidence() — a read of the vote evidence map that holds evidence.
  /// A read hands out a reference; only a drain moves evidence out of the keeper.
  action read_vote_evidence = all {
    votePairCount(vk.evidence) > 0,
    ghost' = ghost,
    vk' = vk,
    pk' = pk,
    node' = node,
    emitted' = emitted,
  }

  /// ProposalKeeper::evidence() — a read of the proposal evidence map that holds evidence.
  /// A read hands out a reference; only a drain moves evidence out of the keeper.
  action read_proposal_evidence = all {
    proposalPairCount(pk.evidence) > 0,
    ghost' = ghost,
    vk' = vk,
    pk' = pk,
    node' = node,
    emitted' = emitted,
  }

  // ── the drains (driver.rs:283-325) ────────────────────────────────────────

  action take_vote_evidence = all {
    vk' = { ...vk, evidence: Map() },
    ghost' = { ...ghost,
      surfacedMidRound: ghost.surfacedMidRound
                        or (not(node.finalizationPeriod) and votePairCount(vk.evidence) > 0),
      drainedVotePairs: ghost.drainedVotePairs + votePairCount(vk.evidence),
      votePairs: 0,
      voteAddrs: 0,
    },
    pk' = pk,
    node' = node,
    emitted' = emitted,
  }

  action take_proposal_evidence = all {
    pk' = { ...pk, evidence: Map() },
    ghost' = { ...ghost,
      surfacedMidRound: ghost.surfacedMidRound
                        or (not(node.finalizationPeriod) and proposalPairCount(pk.evidence) > 0),
      proposalPairs: 0,
      proposalAddrs: 0,
    },
    vk' = vk,
    node' = node,
    emitted' = emitted,
  }

  // ── log_and_finalize (finalize.rs:50-82) ──────────────────────────────────

  /// Effect::Finalize with MisbehaviorEvidence{proposals, votes} — the single
  /// point where a height's evidence reaches the application.
  /// `finalize_height` asserts Commit step + finalization period before calling
  /// this; `log_and_finalize` itself is also reached from the sync and
  /// start-height flush paths, which carry no such precondition.
  action log_and_finalize = all {
    emitted' = emitted.append({
      proposalPairs: proposalPairCount(pk.evidence) + ghost.drainedProposalPairs,
      votePairs: votePairCount(vk.evidence) + ghost.drainedVotePairs,
    }),
    vk' = { ...vk, evidence: Map() },
    pk' = { ...pk, evidence: Map() },
    node' = { ...node, finalizationPeriod: false },
    ghost' = { ...ghost,
      votePairs: 0, voteAddrs: 0, proposalPairs: 0, proposalAddrs: 0,
      drainedVotePairs: 0, drainedProposalPairs: 0,
      finalizeCount: ghost.finalizeCount + 1 },
  }

  // ── round / step progress (unlogged: replay fills these from its budget) ───

  /// Driver::apply_new_round (driver.rs:803-826): the round advances and the
  /// keepers carry over untouched, so evidence accumulates across rounds.
  action new_round(round: int): bool = all {
    round >= node.round,
    node' = { ...node, round: round },
    vk' = vk,
    pk' = pk,
    emitted' = emitted,
    ghost' = ghost,
  }

  action enter_commit = all {
    not(node.stepIsCommit),
    node' = { ...node, stepIsCommit: true, finalizationPeriod: true },
    vk' = vk,
    pk' = pk,
    emitted' = emitted,
    ghost' = ghost,
  }

  // ── step ──────────────────────────────────────────────────────────────────

  action step = any {
    // narrow (sim) arms
    {
      nondet src = SENDERS.oneOf()
      nondet vote_type = VOTE_TYPES.oneOf()
      nondet vote_round = SIM_ROUNDS.oneOf()
      nondet existing_value = SIM_VOTE_VALUES.oneOf()
      nondet conflicting_value = SIM_VOTE_VALUES.oneOf()
      vote_evidence_add(src, vote_type, vote_round, existing_value, conflicting_value)
    },
    {
      nondet vote_type = VOTE_TYPES.oneOf()
      nondet src = SENDERS.oneOf()
      nondet vote_round = SIM_ROUNDS.oneOf()
      nondet value = SIM_VOTE_VALUES.oneOf()
      nondet current_round = SIM_ROUNDS.oneOf()
      apply_vote(vote_type, src, vote_round, value, current_round)
    },
    {
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = SIM_ROUNDS.oneOf()
      nondet value = SIM_PROPOSAL_VALUES.oneOf()
      nondet pol_round = SIM_POL_ROUNDS.oneOf()
      nondet validity = VALIDITIES.oneOf()
      store_proposal(validator, proposal_round, value, pol_round, validity)
    },
    {
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = SIM_ROUNDS.oneOf()
      nondet existing_value = SIM_PROPOSAL_VALUES.oneOf()
      nondet conflicting_value = SIM_PROPOSAL_VALUES.oneOf()
      nondet existing_pol_round = SIM_POL_ROUNDS.oneOf()
      nondet conflicting_pol_round = SIM_POL_ROUNDS.oneOf()
      record_proposal_evidence(validator, proposal_round, existing_value, existing_pol_round,
                               conflicting_value, conflicting_pol_round)
    },
    {
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = SIM_ROUNDS.oneOf()
      nondet existing_value = SIM_PROPOSAL_VALUES.oneOf()
      nondet conflicting_value = SIM_PROPOSAL_VALUES.oneOf()
      nondet existing_pol_round = SIM_POL_ROUNDS.oneOf()
      nondet conflicting_pol_round = SIM_POL_ROUNDS.oneOf()
      proposal_evidence_add(validator, proposal_round, existing_value, existing_pol_round,
                            conflicting_value, conflicting_pol_round)
    },
    // wide (replay) arms — accept every value the real suite logs
    {
      nondet src = SENDERS.oneOf()
      nondet vote_type = VOTE_TYPES.oneOf()
      nondet vote_round = VOTE_ROUNDS.oneOf()
      nondet existing_value = VOTE_VALUES.oneOf()
      nondet conflicting_value = VOTE_VALUES.oneOf()
      vote_evidence_add(src, vote_type, vote_round, existing_value, conflicting_value)
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
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = PROPOSAL_ROUNDS.oneOf()
      nondet value = PROPOSAL_VALUES.oneOf()
      nondet pol_round = POL_ROUNDS.oneOf()
      nondet validity = VALIDITIES.oneOf()
      store_proposal(validator, proposal_round, value, pol_round, validity)
    },
    {
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = PROPOSAL_ROUNDS.oneOf()
      nondet value = PROPOSAL_VALUES.oneOf()
      nondet pol_round = POL_ROUNDS.oneOf()
      nondet validity = VALIDITIES.oneOf()
      handle_proposal(validator, proposal_round, value, pol_round, validity)
    },
    {
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = PROPOSAL_ROUNDS.oneOf()
      drop_non_proposer(validator, proposal_round)
    },
    {
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = PROPOSAL_ROUNDS.oneOf()
      nondet existing_value = PROPOSAL_VALUES.oneOf()
      nondet conflicting_value = PROPOSAL_VALUES.oneOf()
      nondet existing_pol_round = POL_ROUNDS.oneOf()
      nondet conflicting_pol_round = POL_ROUNDS.oneOf()
      record_proposal_evidence(validator, proposal_round, existing_value, existing_pol_round,
                               conflicting_value, conflicting_pol_round)
    },
    {
      nondet validator = PROPOSERS.oneOf()
      nondet proposal_round = PROPOSAL_ROUNDS.oneOf()
      nondet existing_value = PROPOSAL_VALUES.oneOf()
      nondet conflicting_value = PROPOSAL_VALUES.oneOf()
      nondet existing_pol_round = POL_ROUNDS.oneOf()
      nondet conflicting_pol_round = POL_ROUNDS.oneOf()
      proposal_evidence_add(validator, proposal_round, existing_value, existing_pol_round,
                            conflicting_value, conflicting_pol_round)
    },
    read_vote_evidence,
    read_proposal_evidence,
    take_vote_evidence,
    take_proposal_evidence,
    log_and_finalize,
    { nondet round = VOTE_ROUNDS.oneOf()
      new_round(round) },
    enter_commit,
  }

  // ── correctness properties ────────────────────────────────────────────────

  /// A value's tallied weight in a round is exactly the summed power of the
  /// validators whose recorded vote of that type is for that value.
  val equivocating_vote_is_absorbed_not_tallied: bool =
    vk.tally.keys().forall(r =>
      tallyAt(vk.tally, r).keys().forall(k =>
        weightAt(tallyAt(vk.tally, r), k)
          == receivedAt(vk.received, r)
               .filter(v => v.voteType == k._1 and v.value == k._2)
               .fold(0, (acc, v) => acc + POWER.get(v.src))))

  /// A validator with recorded vote equivocation in a round has none of its
  /// voting power credited to any value in that round.
  val no_value_credited_by_arrival_order: bool =
    ghost.equivocators.forall(e =>
      creditedAt(ghost.creditedValue, e._1, e._2) == "")

  /// No validator's evidence holds the same conflicting pair twice, in either order.
  val evidence_pair_is_deduped_in_both_orderings: bool =
    and {
      vk.evidence.keys().forall(a =>
        val l = voteEvAt(vk.evidence, a)
        l.indices().forall(i => l.indices().forall(j =>
          (i != j) implies
            not((l.nth(i)._1 == l.nth(j)._1 and l.nth(i)._2 == l.nth(j)._2)
                or (l.nth(i)._1 == l.nth(j)._2 and l.nth(i)._2 == l.nth(j)._1))))),
      pk.evidence.keys().forall(a =>
        val l = propEvAt(pk.evidence, a)
        l.indices().forall(i => l.indices().forall(j =>
          (i != j) implies
            not((l.nth(i)._1 == l.nth(j)._1 and l.nth(i)._2 == l.nth(j)._2)
                or (l.nth(i)._1 == l.nth(j)._2 and l.nth(i)._2 == l.nth(j)._1))))),
    }

  /// Every recorded pair is two distinct messages from the one validator it is
  /// filed under, for a single round and, for votes, a single vote type.
  val evidence_pairs_are_same_validator_conflicts: bool =
    and {
      vk.evidence.keys().forall(a =>
        val l = voteEvAt(vk.evidence, a)
        l.indices().forall(i => and {
          l.nth(i)._1.src == a,
          l.nth(i)._2.src == a,
          l.nth(i)._1.round == l.nth(i)._2.round,
          l.nth(i)._1.voteType == l.nth(i)._2.voteType,
          l.nth(i)._1 != l.nth(i)._2,
        })),
      pk.evidence.keys().forall(a =>
        val l = propEvAt(pk.evidence, a)
        l.indices().forall(i => and {
          l.nth(i)._1.validator == a,
          l.nth(i)._2.validator == a,
          l.nth(i)._1.round == l.nth(i)._2.round,
          l.nth(i)._1 != l.nth(i)._2,
        })),
    }

  /// Recorded evidence is never drained outside the finalization period, and a
  /// height's evidence reaches the application at most once.
  val evidence_surfaces_only_at_finalize: bool =
    and { not(ghost.surfacedMidRound), ghost.finalizeCount <= 1 }

  /// No validator's evidence list exceeds MAX_EVIDENCE_PER_VALIDATOR.
  val evidence_per_validator_is_bounded: bool =
    and {
      vk.evidence.keys().forall(a => voteEvAt(vk.evidence, a).length() <= MAX_EVIDENCE_PER_VALIDATOR),
      pk.evidence.keys().forall(a => propEvAt(pk.evidence, a).length() <= MAX_EVIDENCE_PER_VALIDATOR),
    }

  /// The node never aborts on a proposal whose validator differs from the one
  /// that sent the round's first proposal.
  val node_never_aborts_on_cross_validator_proposal: bool = not(node.aborted)

  // ── observations ──────────────────────────────────────────────────────────

  /// A conflicting-vote pair was recorded in the vote evidence map.
  val vote_equivocation_recorded: bool = votePairCount(vk.evidence) > 0

  /// A conflicting-proposal pair was recorded in the proposal evidence map.
  val proposal_equivocation_recorded: bool = proposalPairCount(pk.evidence) > 0

  /// A vote pair already present was offered again and absorbed by the same-pair check.
  val vote_evidence_deduped: bool = ghost.voteDedupAbsorbed

  /// A proposal pair already present was offered again and absorbed.
  val proposal_evidence_deduped: bool = ghost.proposalDedupAbsorbed

  /// A further distinct vote pair was dropped because the per-validator cap was full.
  val vote_evidence_cap_dropped: bool = ghost.capDropped

  /// One validator's proposal evidence grew past the vote map's per-validator cap.
  val proposal_evidence_exceeds_vote_cap: bool =
    pk.evidence.keys().exists(a => propEvAt(pk.evidence, a).length() > MAX_EVIDENCE_PER_VALIDATOR)

  /// Evidence is held against two different validators at once.
  val evidence_from_two_validators: bool =
    vk.evidence.keys().union(pk.evidence.keys()).filter(a =>
      voteEvAt(vk.evidence, a).length() > 0
        or propEvAt(pk.evidence, a).length() > 0).size() >= 2

  /// An equivocator's voting power is still credited to a value in that round.
  val equivocator_power_still_tallied: bool =
    ghost.equivocators.exists(e =>
      creditedAt(ghost.creditedValue, e._1, e._2) != "")

  /// A Finalize effect carried a non-empty MisbehaviorEvidence.
  val evidence_drained_at_finalize: bool =
    emitted.indices().exists(i =>
      emitted.nth(i).proposalPairs + emitted.nth(i).votePairs > 0)

  /// A Finalize effect carried an empty MisbehaviorEvidence.
  val evidence_empty_at_finalize: bool =
    emitted.indices().exists(i =>
      emitted.nth(i).proposalPairs + emitted.nth(i).votePairs == 0)

  /// Evidence was drained while the node was not in its finalization period.
  val evidence_surfaced_mid_round: bool = ghost.surfacedMidRound

  /// A proposal recorded Invalid was later accepted as Valid.
  val proposal_validity_upgraded: bool = ghost.validityUpgraded

  /// A proposal recorded Valid was offered as Invalid and the downgrade was refused.
  val proposal_validity_downgrade_refused: bool = ghost.validityDowngradeRefused

  /// A repeated vote with the same value from the same validator was ignored.
  val duplicate_vote_ignored: bool = ghost.duplicateVoteIgnored

  /// A vote from an address outside the validator set was discarded.
  val unknown_validator_vote_dropped: bool = ghost.unknownValidatorDropped

  /// A proposal from a validator that is not the round's proposer was dropped.
  val non_proposer_proposal_dropped: bool = ghost.nonProposerDropped

  /// The node aborted on proposals from two different validators in one round.
  val node_aborted_on_cross_validator_proposal: bool = node.aborted

  /// A threshold was reached on the tallied votes of a round.
  val vote_threshold_reached: bool = ghost.thresholdReached

  /// Evidence accumulated across more than one round of the same height.
  val evidence_spans_multiple_rounds: bool =
    node.round > 0 and votePairCount(vk.evidence) + proposalPairCount(pk.evidence) > 0
}
