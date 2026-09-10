// Core Types & Quorum Domain — the shared consensus vocabulary (height, round, vote,
// validator set, certificates, timeouts) and the quorum arithmetic every consensus
// component depends on.
//
// Code:
//   code/crates/core-types/src/threshold.rs:52-88      ThresholdParam::new / is_met / min_expected
//   code/crates/core-types/src/validator_set.rs:37-64  the ValidatorSet trait + its documented ordering
//   code/crates/test/src/validator_set.rs:73-84        ValidatorSet::new (assert non-empty, power overflow)
//   code/crates/core-types/src/context.rs:47           Context::select_proposer
//   code/crates/test/src/proposer_selector.rs:31-43    RotateProposer::select_proposer
//   code/crates/core-types/src/height.rs:22-36         Height::increment / decrement / *_by
//   code/crates/test/src/height.rs:50-57               the concrete impl (saturating_sub!)
//   code/crates/core-types/src/round.rs:67-98          Round::increment / or
//   code/crates/core-types/src/timeouts.rs:96-130      LinearTimeouts::duration_for
//   code/crates/core-types/src/certificate.rs          the four certificate constructors
//   code/crates/signing/src/ext.rs:272-326, :478-520   the certificate verifier's power accumulation
//
// GRANULARITY: a domain workbench, not a state machine. A caller installs a baseline
// (validator set, threshold param, timeout configuration) and drives the queries and
// constructors. Queries are silent in Rust, so every one latches its result into a
// ghost field — the only way an observation or a logged assertion can see what a query
// returned.
//
// RESILIENCE ASSUMPTION: the one the code implements today — n > 3f, quorum
// TWO_F_PLUS_ONE = 2/3, honest F_PLUS_ONE = 1/3, per ThresholdParams::default().
//
// CONCRETE vs TRAIT-BASED: threshold.rs is a concrete struct, so its arithmetic is
// checked against the shipped code. ValidatorSet, Height, Timeouts and Context are
// traits; for those the model mirrors the in-repo implementation in code/crates/test/src
// and promotes each trait doc-contract to an invariant the simulator can break.
//
// ---------------------------------------------------------------------------------
// WHY THE SHAPE IS WHAT IT IS — the replay constraint.
//
// The oracle pins an action parameter from a logged argument ONLY when that value is a
// MEMBER of the set the parameter's `nondet` draws from. Domain tags do not extend that
// set. An earlier revision of this spec passed whole payloads as single arguments (the
// validator set, the timeout config, the certificates' vote lists) and 191 of 214 tests
// were rejected, because those payloads are seed-derived addresses and arbitrary powers
// that no enumerable domain can hold. Hence, throughout:
//
//   * every argument is a SCALAR from an enumerable domain — never a list or a record;
//   * a payload arrives as PER-ITEM EVENTS: a `*_begin` event clears a staging list, one
//     small event follows per element, then the operation that consumes it;
//   * identities and values are ENCODED, not passed through — a validator is its
//     address's lexicographic rank, a vote's value is one of three tokens.
//
// This is also the idiom core-votekeeper/src/keeper.rs:320-348 already uses in this repo.
// ---------------------------------------------------------------------------------

module core_types_domain_core {
  import basicSpells.* from "./spells/basicSpells"

  // ---------------------------------------------------------------- types

  /// A validator identity: the LEXICOGRAPHIC RANK of its address within its own set.
  /// The real addresses are seed-derived hex strings, which no enumerable domain can
  /// hold, and Quint has no ordering on strings anyway. The rank is order-preserving
  /// for exactly the comparison the documented ordering is defined by — rank ascending
  /// iff address ascending — and it is a plain int, so it replays.
  type Address = int

  /// A validator: its identity and its voting power (validator_set.rs:17-30).
  type Validator = { address: Address, power: int }

  /// ThresholdParam, a numerator/denominator pair (threshold.rs:42-49). 2/3 and 1/3 are
  /// merely the TWO_F_PLUS_ONE / F_PLUS_ONE constants, so they are data here.
  type Param = { numerator: int, denominator: int }

  /// LinearTimeouts (timeouts.rs:35-66), in milliseconds. Every field is `pub` and
  /// nothing validates any of them.
  type TimeoutCfg = {
    propose: int,
    propose_delta: int,
    prevote: int,
    prevote_delta: int,
    precommit: int,
    precommit_delta: int,
    rebroadcast: int,
    max_timeout: int,
  }

  /// A signed vote, its signature abstracted to "produced by this voter". `round` is -1
  /// for Round::Nil (exactly Round::as_i64). `value` is "Match" when the vote is for the
  /// certificate's own value, "Other" for a different id, "Nil" for a nil vote — which
  /// is the whole distinction the constructors' filter makes.
  ///
  /// NOTE ON `voter`: inside a certificate constructor there is no validator set, so a
  /// voter is its rank among the distinct voters of THAT CALL's vote list (repeats share
  /// a rank, which is what the dedupe check keys on). In the verifier there IS a set, so
  /// a signer is its rank within the validator set, -1 when absent. The two rank spaces
  /// never meet: certificate actions only use voters to build the signer list and to spot
  /// repeats, and the verify actions read their own staged signer list.
  type SignedVote = {
    voter: Address,
    height: int,
    round: int,
    value: str,
    vote_type: str,
  }

  /// A built certificate. `signers` is a LIST, not a Set: the constructors keep the vote
  /// order and do NOT dedupe. `source` is the vote list it was built from, so a property
  /// can recompute the filter and compare against what was stored.
  type Cert = {
    kind: str,
    height: int,
    round: int,
    value_id: str,
    signers: List[Address],
    enter_round: int,
    source: List[SignedVote],
  }

  /// One duration `duration_for` produced, with the cap configured at the time, so the
  /// clamping claim stays checkable after the configuration changes.
  type Computed = { ms: int, per_round: bool, cap: int }

  type State = {
    // --- the installed baseline
    vset: List[Validator],
    threshold: Param,
    timeouts: TimeoutCfg,
    certs: int -> Cert,
    next_cert_id: int,

    // --- staging lists the per-item events fill before the consuming operation
    staged_votes: List[SignedVote],
    staged_signers: List[Address],

    // --- ghosts: what the silent queries returned
    vset_installed: bool,
    last_is_met: Option[bool],
    // The same verdict as a plain int (-1 unset / 0 not met / 1 met). The oracle client
    // cannot log a payload-carrying variant, so this is what a logged post-state
    // assertion can pin.
    last_is_met_code: int,
    last_is_met_weight: int,
    last_is_met_total: int,
    last_min_expected: Option[int],
    last_min_expected_value: int,
    last_total_power: Option[int],
    last_count: Option[int],
    last_lookup_hit: Option[bool],
    last_lookup_code: int,
    last_index_in_range: Option[bool],
    last_index_code: int,
    last_proposer: Option[Address],
    last_proposer_address: int,
    last_proposer_height: int,
    last_proposer_round: int,
    last_decrement_from: int,
    last_decrement_by: int,
    last_decrement_result: Option[int],
    last_increment: Option[int],
    last_round: Option[int],
    round_from_nil: bool,
    computed_timeouts: Set[Computed],
    timeout_clamped: bool,
    finalize_above_cap: bool,
    last_signed_power: Option[int],
    last_signed_power_value: int,
    last_signed_power_total: int,
    last_signed_power_met: Option[bool],
    signer_unknown_to_set: bool,
    duplicate_vote_rejected: bool,
    signed_power_overflowed: bool,
    dropped_votes: bool,
    kept_all_votes: bool,
    round_cert_kept_foreign: bool,
    lifted_enter_round_cert: bool,

    // --- ghosts: the panic arms
    panic_threshold_overflow: bool,
    panic_min_expected_div0: bool,
    panic_vset_empty: bool,
    panic_vset_power_overflow: bool,
    panic_proposer_nil_round: bool,
    panic_proposer_zero_height: bool,
    panic_timeout_nil_round: bool,
  }

  // ------------------------------------------------------------ constants

  /// The machine-word ceiling the code's checked_mul / checked_add compare against.
  /// Quint ints are unbounded, so every u64 overflow is modeled against this bound. The
  /// value is SCALED DOWN from 2^64-1, which the evaluator cannot hold: nothing here
  /// depends on the exact width, only on "the product left the word".
  pure val U64_MAX: int = 1000000

  /// Big enough that one validator fits under the ceiling but two do not.
  pure val NEAR_MAX: int = 500001

  /// ThresholdParam::TWO_F_PLUS_ONE (threshold.rs:54).
  pure val TWO_F_PLUS_ONE: Param = { numerator: 2, denominator: 3 }

  /// ThresholdParam::F_PLUS_ONE (threshold.rs:57).
  pure val F_PLUS_ONE: Param = { numerator: 1, denominator: 3 }

  /// Height::ZERO (height.rs:22).
  pure val MIN_HEIGHT: int = 0

  /// Round::Nil, as Round::as_i64 renders it.
  pure val NIL_ROUND: int = -1

  // Domains are enumerable RANGES, not listings of the values a run happened to show:
  // the oracle reports only each test's FIRST rejection, so a listing invites another
  // round with new values.

  /// Validator ranks. The largest set in these tests has 7 validators.
  pure val ADDRESSES: Set[Address] = 0.to(8)

  /// A signer's rank in the validator set, or -1 when it is not a member.
  pure val SIGNER_RANKS: Set[Address] = Set(-1).union(0.to(8))

  /// Voting powers, plus the two word-boundary values.
  pure val POWERS: Set[int] = 0.to(100).union(Set(NEAR_MAX, U64_MAX))

  pure val HEIGHTS: Set[int] = 0.to(20)
  pure val ROUNDS: Set[int] = Set(NIL_ROUND).union(0.to(120))
  pure val INDICES: Set[int] = 0.to(8)
  pure val VOTE_VALUES: Set[str] = Set("Nil", "Match", "Other")
  pure val VOTE_TYPES: Set[str] = Set("Prevote", "Precommit")

  /// A certificate's own value is the "Match" token by construction.
  pure val VALUE_IDS: Set[str] = Set("Match")

  /// RoundCertificateType has exactly two variants.
  pure val CERT_ROUND_KINDS: Set[str] = Set("Skip", "Precommit")

  /// Weights and totals for the arithmetic actions, plus the values that overflow.
  pure val SMALL_NUMBERS: Set[int] = 0.to(300)
  pure val BIG_NUMBERS: Set[int] = Set(NEAR_MAX, U64_MAX)
  pure val ARITH_NUMBERS: Set[int] = SMALL_NUMBERS.union(BIG_NUMBERS)

  // The domains above are ranges so that any value a real test logs is a member and
  // therefore replays. That width, though, dilutes the interesting regions to nearly
  // zero sampling probability — the 2/3 boundary is ~100 pairs out of 90_000, a zero
  // timeout needs particular fields out of 120_001 values, and "every vote matched"
  // needs a vote's height/round/value to coincide with the certificate's by chance. The
  // battery reported exactly that: four observations unreachable in 1000 samples.
  //
  // So each of those actions also gets a DENSE arm in `step`, drawing from the small
  // sets below. Guards and updates are untouched; only the simulator's sampling changes,
  // and replay is unaffected because a logged argument pins its pick whichever arm it
  // came from.

  /// Small enough that the exact 1/3 and 2/3 boundaries are dense: (2,3), (4,6), (6,9).
  pure val DENSE_NUMBERS: Set[int] = 0.to(12)

  /// Includes 0, so a zero base or a zero cap — the operator mistake that collapses a
  /// timeout to "expires immediately" — actually gets sampled.
  pure val DENSE_TIMEOUT_MS: Set[int] = Set(0, 500, 1000, 3000, 5000, 60000)

  /// One height and one round, so a certificate's scope and its votes' scope coincide.
  pure val DENSE_HEIGHTS: Set[int] = Set(1)
  pure val DENSE_ROUNDS: Set[int] = Set(0)

  /// Ranks a small installed set actually contains, so signers are known and their
  /// summed power can reach a quorum.
  pure val DENSE_RANKS: Set[int] = 0.to(3)

  /// Powers that let a couple of signers clear a 2/3 quorum, so
  /// certificate_signed_power_meets_quorum is reachable in a short chain rather than
  /// needing three specific distinct signers.
  pure val DENSE_POWERS: Set[int] = Set(10, 40)

  /// The domain the arithmetic invariants quantify over. Deliberately small: they sweep
  /// param x weight x total in EVERY state, so each extra element multiplies the cost of
  /// an on-demand simulator run. 0..6 still carries both 2/3 boundary cases, (2,3) and (4,6).
  pure val INV_NUMBERS: Set[int] = 0.to(6)

  /// ThresholdParam::new takes any pair, a zero denominator included — which is what
  /// makes min_expected's checked_div `expect` fire.
  pure val PARAM_NUMERATORS: Set[int] = Set(1, 2)
  pure val PARAM_DENOMINATORS: Set[int] = Set(0, 3)

  /// Timeout values in ms, and the duration a FinalizeHeight timeout carries. Ranges,
  /// because any application's middleware supplies its own values (a run logged 938ms).
  pure val TIMEOUT_MS: Set[int] = 0.to(120000)
  pure val FINALIZE_DURATIONS: Set[int] = 0.to(120000)

  /// TimeoutKind (timeout.rs:8-22), by name. FinalizeHeight's own duration travels as
  /// the separate `finalize_ms` argument.
  pure val TIMEOUT_KINDS: Set[str] =
    Set("Propose", "Prevote", "Precommit", "Rebroadcast", "FinalizeHeight")

  /// LinearTimeouts::default (timeouts.rs:72-88), in ms.
  pure val DEFAULT_TIMEOUTS: TimeoutCfg = {
    propose: 3000,
    propose_delta: 500,
    prevote: 1000,
    prevote_delta: 500,
    precommit: 1000,
    precommit_delta: 500,
    rebroadcast: 5000,
    max_timeout: 60000,
  }

  // -------------------------------------------------------- pure functions

  /// `a * b` leaves the machine word.
  pure def mul_overflows(a: int, b: int): bool = a * b > U64_MAX

  /// ThresholdParam::is_met (threshold.rs:68-78): cross-multiply, then STRICT >.
  pure def is_met_pure(p: Param, weight: int, total: int): bool =
    weight * p.denominator > total * p.numerator

  /// Whether is_met would panic on these arguments (threshold.rs:71, 74).
  pure def is_met_overflows(p: Param, weight: int, total: int): bool =
    mul_overflows(weight, p.denominator) or mul_overflows(total, p.numerator)

  /// ThresholdParam::min_expected (threshold.rs:81-87): 1 + floor(total*num/den).
  pure def min_expected_pure(p: Param, total: int): int =
    1 + (total * p.numerator) / p.denominator

  /// Whether min_expected would panic: the multiply overflows, or the divide is by zero.
  pure def min_expected_panics(p: Param, total: int): bool =
    mul_overflows(total, p.numerator) or p.denominator == 0

  /// ValidatorSet::total_voting_power — a checked_add fold (test/src/validator_set.rs:105).
  pure def vset_total(vs: List[Validator]): int =
    vs.foldl(0, (acc, v) => acc + v.power)

  /// ValidatorSet::get_by_address — the FIRST validator with this identity
  /// (test/src/validator_set.rs:118).
  pure def vset_find(vs: List[Validator], a: Address): Option[Validator] =
    vs.foldl(None, (acc, v) =>
      match acc {
      | Some(_) => acc
      | None => if (v.address == a) Some(v) else None
      })

  /// The power a verifier credits to a signature from this signer.
  pure def power_of(vs: List[Validator], a: Address): int =
    match vset_find(vs, a) {
    | Some(v) => v.power
    | None => 0
    }

  pure def to_set(l: List[Address]): Set[Address] =
    l.foldl(Set(), (acc, a) => acc.union(Set(a)))

  /// Whether a signature list names the same validator twice. The constructors never
  /// check this; the verifier does, and rejects.
  pure def has_duplicate(l: List[Address]): bool = l.length() != to_set(l).size()

  /// The votes CommitCertificate::new / PolkaCertificate::new keep: same height, round,
  /// value and vote type as the certificate itself (certificate.rs:54-60).
  pure def matching_votes(source: List[SignedVote], vt: str,
                          h: int, r: int, vid: str): List[SignedVote] =
    source.select(v => v.vote_type == vt and v.height == h and v.round == r
                       and v.value == vid)

  pure def voters_of(l: List[SignedVote]): List[Address] =
    l.foldl(List(), (acc, v) => acc.append(v.voter))

  /// How many of a certificate's signers are not in the validator set.
  pure def unknown_signers(vs: List[Validator], signers: List[Address]): int =
    signers.select(a => vset_find(vs, a) == None).length()

  /// The power the verifier accumulates over a certificate's signers.
  pure def signed_power(vs: List[Validator], signers: List[Address]): int =
    signers.foldl(0, (acc, a) => acc + power_of(vs, a))

  /// The documented ordering (validator_set.rs:37-42): power descending, then address
  /// ascending.
  pure def in_documented_order(vs: List[Validator]): bool =
    0.to(vs.length() - 2).forall(i => {
      val a = vs.nth(i)
      val b = vs.nth(i + 1)
      a.power > b.power or (a.power == b.power and a.address < b.address)
    })

  pure def addresses_unique(vs: List[Validator]): bool =
    vs.length() == vs.foldl(Set(), (acc, v) => acc.union(Set(v.address))).size()

  /// How many validators strictly precede this one in the documented order — the
  /// position the contract requires, computed WITHOUT relying on the list's actual
  /// order, which is what makes the determinism property falsifiable.
  pure def documented_rank(vs: List[Validator], v: Validator): int =
    vs.select(u => u.power > v.power
                     or (u.power == v.power and u.address < v.address)).length()

  /// RotateProposer::select_proposer (test/src/proposer_selector.rs:37-42):
  /// (height - 1 + round) % count, indexing the list positionally.
  pure def proposer_index(vs: List[Validator], h: int, r: int): int =
    (h - 1 + r) % vs.length()

  /// The address the documented ordering would make proposer for (h, r), whatever order
  /// the list happens to be stored in.
  pure def canonical_proposers(vs: List[Validator], h: int, r: int): Set[Address] =
    vs.select(v => documented_rank(vs, v) == proposer_index(vs, h, r))
      .foldl(Set(), (acc, v) => acc.union(Set(v.address)))

  /// Every kind but FinalizeHeight is extrapolated per round and clamped.
  pure def is_per_round(kind: str): bool = kind != "FinalizeHeight"

  /// LinearTimeouts::duration_for (timeouts.rs:96-130). The Rust side saturates the
  /// add/mul then clamps to max_timeout; with unbounded ints the clamp alone is
  /// indistinguishable from that, exactly as the code's own comment says.
  pure def duration_for_pure(t: TimeoutCfg, kind: str, finalize_ms: int, r: int): int =
    if (kind == "Propose") min(t.propose + t.propose_delta * r, t.max_timeout)
    else if (kind == "Prevote") min(t.prevote + t.prevote_delta * r, t.max_timeout)
    else if (kind == "Precommit") min(t.precommit + t.precommit_delta * r, t.max_timeout)
    else if (kind == "Rebroadcast")
      min(t.rebroadcast + (t.propose_delta + t.prevote_delta + t.precommit_delta) * r,
          t.max_timeout)
    else finalize_ms

  /// The unclamped per-round value, so "was it clamped" stays distinguishable.
  pure def duration_unclamped(t: TimeoutCfg, kind: str, finalize_ms: int, r: int): int =
    if (kind == "Propose") t.propose + t.propose_delta * r
    else if (kind == "Prevote") t.prevote + t.prevote_delta * r
    else if (kind == "Precommit") t.precommit + t.precommit_delta * r
    else if (kind == "Rebroadcast")
      t.rebroadcast + (t.propose_delta + t.prevote_delta + t.precommit_delta) * r
    else finalize_ms

  pure val initial_state: State = {
    vset: List({ address: 0, power: 40 }, { address: 1, power: 40 },
               { address: 2, power: 10 }, { address: 3, power: 10 }),
    threshold: TWO_F_PLUS_ONE,
    timeouts: DEFAULT_TIMEOUTS,
    certs: Map(),
    next_cert_id: 0,

    staged_votes: List(),
    staged_signers: List(),

    vset_installed: false,
    last_is_met: None,
    last_is_met_code: -1,
    last_is_met_weight: 0,
    last_is_met_total: 0,
    last_min_expected: None,
    last_min_expected_value: -1,
    last_total_power: None,
    last_count: None,
    last_lookup_hit: None,
    last_lookup_code: -1,
    last_index_in_range: None,
    last_index_code: -1,
    last_proposer: None,
    last_proposer_address: -1,
    last_proposer_height: 1,
    last_proposer_round: 0,
    last_decrement_from: 0,
    last_decrement_by: 0,
    last_decrement_result: None,
    last_increment: None,
    last_round: None,
    round_from_nil: false,
    computed_timeouts: Set(),
    timeout_clamped: false,
    finalize_above_cap: false,
    last_signed_power: None,
    last_signed_power_value: -1,
    last_signed_power_total: 0,
    last_signed_power_met: None,
    signer_unknown_to_set: false,
    duplicate_vote_rejected: false,
    signed_power_overflowed: false,
    dropped_votes: false,
    kept_all_votes: false,
    round_cert_kept_foreign: false,
    lifted_enter_round_cert: false,

    panic_threshold_overflow: false,
    panic_min_expected_div0: false,
    panic_vset_empty: false,
    panic_vset_power_overflow: false,
    panic_proposer_nil_round: false,
    panic_proposer_zero_height: false,
    panic_timeout_nil_round: false,
  }
}

module core_types_domain {
  import basicSpells.* from "./spells/basicSpells"
  import core_types_domain_core.*

  var state: State

  action init = all {
    state' = initial_state,
  }

  // ------------------------------------------------------- the validator set

  /// ValidatorSet::new starting to collect its validators (test/src/validator_set.rs:73).
  /// The vector it is handed cannot travel as one logged argument, so the constructor
  /// reports the collection it performs: this clears the set, one add follows per
  /// validator, then the finalize arm runs the two checks.
  action ValidatorSetnew_begin: bool = all {
    state' = { ...state, vset: List() },
  }

  /// One validator being collected. `addr_rank` is its address's lexicographic rank
  /// within the set — the identity the documented ordering compares.
  action ValidatorSetnew_add(power: int, addr_rank: int): bool = all {
    state' = { ...state,
               vset: state.vset.append({ address: addr_rank, power: power }) },
  }

  /// The constructor returning: both checks passed (test/src/validator_set.rs:75-80).
  action ValidatorSetnew: bool = all {
    state.vset.length() > 0,
    vset_total(state.vset) <= U64_MAX,
    state' = { ...state, vset_installed: true },
  }

  /// The `assert!(!validators.is_empty())` firing.
  action ValidatorSetnew_empty_panics: bool = all {
    state.vset.length() == 0,
    state' = { ...state, panic_vset_empty: true },
  }

  /// The `expect("total voting power overflow")` firing.
  action ValidatorSetnew_power_overflow_panics: bool = all {
    state.vset.length() > 0,
    vset_total(state.vset) > U64_MAX,
    state' = { ...state, panic_vset_power_overflow: true },
  }

  /// ValidatorSet::get_by_address (test/src/validator_set.rs:118) — a linear find. The
  /// domain includes -1, because `lookup_by_address_missed` is one of this action's own
  /// outcome classes.
  action ValidatorSetget_by_address(address: Address): bool = all {
    state' = { ...state,
               last_lookup_hit: Some(vset_find(state.vset, address) != None),
               last_lookup_code: if (vset_find(state.vset, address) != None) 1 else 0 },
  }

  /// ValidatorSet::get_by_index (test/src/validator_set.rs:113). The domain runs one past
  /// the end, so the None arm is reachable.
  action ValidatorSetget_by_index(index: int): bool = all {
    state' = { ...state,
               last_index_in_range: Some(index >= 0 and index < state.vset.length()),
               last_index_code: if (index >= 0 and index < state.vset.length()) 1 else 0 },
  }

  /// ValidatorSet::total_voting_power (test/src/validator_set.rs:105) — guarded by the
  /// same checked_add fold as the constructor.
  action ValidatorSettotal_voting_power: bool = all {
    vset_total(state.vset) <= U64_MAX,
    state' = { ...state, last_total_power: Some(vset_total(state.vset)) },
  }

  /// ValidatorSet::count (test/src/validator_set.rs:132).
  action ValidatorSetcount: bool = all {
    state' = { ...state, last_count: Some(state.vset.length()) },
  }

  // --------------------------------------------------------- quorum arithmetic

  /// ThresholdParam::new (threshold.rs:60-65) — a const fn with no checks, so a zero
  /// denominator gets installed too. There is no constructor to instrument (it is a
  /// `const fn`, and the two shipped values are `const`s), so this is reported from
  /// is_met / min_expected, where `self` IS the installed param.
  action ThresholdParamnew(numerator: int, denominator: int): bool = all {
    state' = { ...state, threshold: { numerator: numerator, denominator: denominator } },
  }

  /// ThresholdParam::is_met (threshold.rs:68-78). The guards are the two checked_mul
  /// sites; the comparison itself is strictly greater-than.
  action ThresholdParamis_met(weight: int, total: int): bool = all {
    not(is_met_overflows(state.threshold, weight, total)),
    state' = { ...state,
               last_is_met: Some(is_met_pure(state.threshold, weight, total)),
               last_is_met_code: if (is_met_pure(state.threshold, weight, total)) 1 else 0,
               last_is_met_weight: weight,
               last_is_met_total: total },
  }

  /// Either checked_mul in is_met returning None, so the `expect` panics.
  action ThresholdParamis_met_overflow_panics(weight: int, total: int): bool = all {
    is_met_overflows(state.threshold, weight, total),
    state' = { ...state, panic_threshold_overflow: true },
  }

  /// ThresholdParam::min_expected (threshold.rs:81-87).
  action ThresholdParammin_expected(total: int): bool = all {
    not(min_expected_panics(state.threshold, total)),
    state' = { ...state,
               last_min_expected: Some(min_expected_pure(state.threshold, total)),
               last_min_expected_value: min_expected_pure(state.threshold, total) },
  }

  /// min_expected's checked_mul or checked_div `expect` firing — the latter on the zero
  /// denominator ThresholdParam::new happily accepts.
  action ThresholdParammin_expected_panics(total: int): bool = all {
    min_expected_panics(state.threshold, total),
    state' = { ...state,
               panic_threshold_overflow:
                 state.panic_threshold_overflow
                   or mul_overflows(total, state.threshold.numerator),
               panic_min_expected_div0:
                 state.panic_min_expected_div0 or state.threshold.denominator == 0 },
  }

  // ------------------------------------------------------- proposer selection

  /// Context::select_proposer, as RotateProposer implements it
  /// (test/src/proposer_selector.rs:31-43). Guards: the `assert!(round != Round::Nil)`,
  /// the `height - 1` that underflows on a usize at height 0, and a non-empty set —
  /// the code indexes `validators[proposer_index]`, and modelling the collection item by
  /// item makes the empty set transiently reachable.
  action Contextselect_proposer(height: int, round: int): bool = all {
    round >= 0,
    height >= 1,
    state.vset.length() > 0,
    state' = { ...state,
               last_proposer:
                 Some(state.vset.nth(proposer_index(state.vset, height, round)).address),
               last_proposer_address:
                 state.vset.nth(proposer_index(state.vset, height, round)).address,
               last_proposer_height: height,
               last_proposer_round: round },
  }

  /// The `assert!(round != Round::Nil)` firing.
  action Contextselect_proposer_nil_round_panics(height: int, round: int): bool = all {
    round == NIL_ROUND,
    state' = { ...state, panic_proposer_nil_round: true },
  }

  /// `height - 1` underflowing at height 0, before the modulo is reached.
  action Contextselect_proposer_zero_height_panics(height: int, round: int): bool = all {
    round >= 0,
    height == 0,
    state' = { ...state, panic_proposer_zero_height: true },
  }

  // ---------------------------------------------------------- height and round

  /// Height::decrement_by, through the trait's `decrement` default (height.rs:27). The
  /// trait documents "Returns None if the height would be decremented below its minimum"
  /// (height.rs:34-36); the concrete impl is `saturating_sub` wrapped in Some
  /// (test/src/height.rs:55). The model mirrors the impl, and
  /// decrement_below_minimum_returns_none states the contract.
  action Heightdecrement_by(from: int, by: int): bool = all {
    state' = { ...state,
               last_decrement_from: from,
               last_decrement_by: by,
               last_decrement_result: Some(max(MIN_HEIGHT, from - by)) },
  }

  /// Height::increment_by, through the trait's `increment` default (height.rs:22).
  action Heightincrement_by(from: int, by: int): bool = all {
    state' = { ...state, last_increment: Some(from + by) },
  }

  /// Round::increment (round.rs:67-72) — a nil round becomes round 0.
  action Roundincrement(round: int): bool = all {
    state' = { ...state,
               last_round: Some(if (round == NIL_ROUND) 0 else round + 1),
               round_from_nil: state.round_from_nil or round == NIL_ROUND },
  }

  /// Round::or (round.rs:93-98).
  action Roundor(round: int, fallback: int): bool = all {
    state' = { ...state,
               last_round: Some(if (round == NIL_ROUND) fallback else round) },
  }

  // ---------------------------------------------------------------- timeouts

  /// Installing a LinearTimeouts configuration. Every field is `pub` and nothing
  /// validates any of them, so there is no guard: a zero propose timeout or a zero
  /// max_timeout is accepted as written. Eight scalar parameters rather than one record,
  /// so each PINS its own pick — a single `cfg` record argument matched no parameter at
  /// all, replay left all eight unguided, and the oracle caught it as an assertion
  /// mismatch on max_timeout. There is no constructor to instrument (the configuration is
  /// a struct literal), so this is reported from duration_for, where `self` IS it.
  action LinearTimeoutsset(propose: int, propose_delta: int, prevote: int,
                           prevote_delta: int, precommit: int, precommit_delta: int,
                           rebroadcast: int, max_timeout: int): bool = all {
    state' = { ...state,
               timeouts: { propose: propose, propose_delta: propose_delta,
                           prevote: prevote, prevote_delta: prevote_delta,
                           precommit: precommit, precommit_delta: precommit_delta,
                           rebroadcast: rebroadcast, max_timeout: max_timeout } },
  }

  /// Timeouts::duration_for (timeouts.rs:96-130). The guard is the documented `# Panics`
  /// precondition — `timeout.round.as_u32().expect("Round must be defined")`.
  action Timeoutsduration_for(kind: str, finalize_ms: int, round: int): bool = all {
    round >= 0,
    state' = {
      val ms = duration_for_pure(state.timeouts, kind, finalize_ms, round)
      val raw = duration_unclamped(state.timeouts, kind, finalize_ms, round)
      { ...state,
        computed_timeouts: state.computed_timeouts.union(Set({
          ms: ms,
          per_round: is_per_round(kind),
          cap: state.timeouts.max_timeout })),
        timeout_clamped:
          state.timeout_clamped or (is_per_round(kind) and raw > ms),
        finalize_above_cap:
          state.finalize_above_cap
            or (not(is_per_round(kind)) and ms > state.timeouts.max_timeout) }
    },
  }

  /// The documented panic: a nil round reaching duration_for (timeouts.rs:26-29).
  action Timeoutsduration_for_nil_round_panics(kind: str, finalize_ms: int,
                                               round: int): bool = all {
    round == NIL_ROUND,
    state' = { ...state, panic_timeout_nil_round: true },
  }

  // ------------------------------------------------------------- certificates

  /// A certificate constructor starting to filter its votes: clears the staging list, one
  /// add_vote follows per vote handed in.
  action certificate_votes_begin: bool = all {
    state' = { ...state, staged_votes: List() },
  }

  /// One vote handed to a certificate constructor.
  action add_vote(voter: int, height: int, round: int, value: str,
                  vote_type: str): bool = all {
    state' = { ...state,
               staged_votes: state.staged_votes.append({
                 voter: voter, height: height, round: round,
                 value: value, vote_type: vote_type }) },
  }

  /// CommitCertificate::new (certificate.rs:45-73): keeps the precommits matching the
  /// certificate's own height/round/value, in vote order, WITHOUT deduping.
  action CommitCertificatenew(height: int, round: int, value_id: str): bool = all {
    state' = {
      val commits = state.staged_votes
      val kept = matching_votes(commits, "Precommit", height, round, value_id)
      { ...state,
        certs: state.certs.put(state.next_cert_id, {
          kind: "Commit", height: height, round: round, value_id: value_id,
          signers: voters_of(kept), enter_round: NIL_ROUND, source: commits }),
        next_cert_id: state.next_cert_id + 1,
        dropped_votes: state.dropped_votes or kept.length() < commits.length(),
        kept_all_votes:
          state.kept_all_votes
            or (commits.length() > 0 and kept.length() == commits.length()) }
    },
  }

  /// PolkaCertificate::new (certificate.rs:276-304) — the same filter over prevotes.
  action PolkaCertificatenew(height: int, round: int, value_id: str): bool = all {
    state' = {
      val commits = state.staged_votes
      val kept = matching_votes(commits, "Prevote", height, round, value_id)
      { ...state,
        certs: state.certs.put(state.next_cert_id, {
          kind: "Polka", height: height, round: round, value_id: value_id,
          signers: voters_of(kept), enter_round: NIL_ROUND, source: commits }),
        next_cert_id: state.next_cert_id + 1,
        dropped_votes: state.dropped_votes or kept.length() < commits.length(),
        kept_all_votes:
          state.kept_all_votes
            or (commits.length() > 0 and kept.length() == commits.length()) }
    },
  }

  /// RoundCertificate::new_from_votes (certificate.rs:441-467). Unlike the commit and
  /// polka constructors this applies NO filter at all: every vote handed in becomes a
  /// signature, whatever its type, height or round.
  ///
  /// No guard on cert_type: RoundCertificateType has exactly two variants, so a
  /// "Commit"/"Polka" kind is not a value any caller can construct. Excluding it here
  /// would be an invented guard, and the oracle's scenario pass rightly flagged such a
  /// conjunct as never falsifiable.
  action RoundCertificatenew_from_votes(height: int, round: int,
                                        cert_type: str): bool = all {
    state' = { ...state,
               certs: state.certs.put(state.next_cert_id, {
                 kind: cert_type, height: height, round: round, value_id: "Nil",
                 signers: voters_of(state.staged_votes), enter_round: round,
                 source: state.staged_votes }),
               next_cert_id: state.next_cert_id + 1,
               round_cert_kept_foreign:
                 state.round_cert_kept_foreign
                   or state.staged_votes
                        .select(v => v.height != height or v.round != round).length() > 0 },
  }

  /// EnterRoundCertificate::from_commit_certificate (certificate.rs:502-533): lifts a
  /// commit certificate's precommit signatures, the caller choosing cert_type and
  /// enter_round. Same reasoning as above: the cert_type is compile-time restricted.
  action EnterRoundCertificatefrom_commit_certificate(height: int, round: int,
                                                      value_id: str, cert_type: str,
                                                      enter_round: int): bool = all {
    state' = { ...state,
               certs: state.certs.put(state.next_cert_id, {
                 kind: cert_type, height: height, round: round, value_id: value_id,
                 signers: state.staged_signers, enter_round: enter_round,
                 source: List() }),
               next_cert_id: state.next_cert_id + 1,
               lifted_enter_round_cert: true },
  }

  // The certificate verifier's power accumulation (signing/src/ext.rs:272-326 for commit
  // and extended-commit certificates, :478-520 for polka). The loop ABORTS on the first
  // problem rather than summing through it, so each exit is its own arm. Signature
  // verification itself is out of scope; what is modeled is the dedupe/membership/
  // threshold arithmetic that decides whether a certificate carries a quorum.

  /// A verifier starting to walk a certificate's signatures.
  action certificate_signers_begin: bool = all {
    state' = { ...state, staged_signers: List() },
  }

  /// One signature's signer, as its rank in the validator set (-1 when the set does not
  /// contain it — the UnknownValidator case).
  action add_signer(signer: int): bool = all {
    state' = { ...state, staged_signers: state.staged_signers.append(signer) },
  }

  /// The `seen_validators` check firing: a repeated address is rejected as DuplicateVote
  /// before any voting power is added (ext.rs:288-290).
  action verify_certificate_power_duplicate_vote: bool = all {
    has_duplicate(state.staged_signers),
    state' = { ...state, duplicate_vote_rejected: true },
  }

  /// get_by_address returning None: the certificate names a validator the set does not
  /// contain, rejected as UnknownValidator (ext.rs:292-295).
  action verify_certificate_power_unknown_validator: bool = all {
    not(has_duplicate(state.staged_signers)),
    unknown_signers(state.vset, state.staged_signers) > 0,
    state' = { ...state, signer_unknown_to_set: true },
  }

  /// The `checked_add` accumulator overflowing (ext.rs:300-305), rejected as
  /// VotingPowerOverflow.
  ///
  /// This arm carries NO conjunct over the model's own recomputed sum, deliberately.
  /// `ValidatorSet`'s `validators` field is public, so a caller can build the struct
  /// directly and skip ValidatorSet::new's total-power check entirely — which is exactly
  /// what certificates::commit::invalid_commit_certificate_signed_voting_power_overflow
  /// does with `[u64::MAX, 1]`. For such a set the model never saw the validators at all
  /// (no ValidatorSetnew_add events fired), so it cannot recompute the sum, and the code's
  /// own checked_add is the authority. The oracle caught this: an earlier revision guarded
  /// this arm on a recomputed sum and those two tests replayed as guard-contract violations.
  action verify_certificate_power_overflow: bool = all {
    not(has_duplicate(state.staged_signers)),
    state' = { ...state, signed_power_overflowed: true },
  }

  /// The loop running to completion: unique signers, all of them known, so the credited
  /// power is summed and compared against the quorum threshold (ext.rs:308-325).
  action verify_certificate_power: bool = all {
    not(has_duplicate(state.staged_signers)),
    unknown_signers(state.vset, state.staged_signers) == 0,
    signed_power(state.vset, state.staged_signers) <= U64_MAX,
    not(is_met_overflows(state.threshold,
                         signed_power(state.vset, state.staged_signers),
                         vset_total(state.vset))),
    state' = {
      val signed = signed_power(state.vset, state.staged_signers)
      val total = vset_total(state.vset)
      { ...state,
        last_signed_power: Some(signed),
        last_signed_power_value: signed,
        last_signed_power_total: total,
        last_signed_power_met: Some(is_met_pure(state.threshold, signed, total)) }
    },
  }

  // -------------------------------------------------------------------- step

  action step = any {
    ValidatorSetnew_begin,
    { nondet power = POWERS.oneOf()
      nondet addr_rank = ADDRESSES.oneOf()
      ValidatorSetnew_add(power, addr_rank) },
    // dense arm: builds a small set whose signers can reach a quorum
    { nondet power = DENSE_POWERS.oneOf()
      nondet addr_rank = DENSE_RANKS.oneOf()
      ValidatorSetnew_add(power, addr_rank) },
    ValidatorSetnew,
    ValidatorSetnew_empty_panics,
    ValidatorSetnew_power_overflow_panics,
    { nondet address = SIGNER_RANKS.oneOf()
      ValidatorSetget_by_address(address) },
    { nondet index = INDICES.oneOf()
      ValidatorSetget_by_index(index) },
    ValidatorSettotal_voting_power,
    ValidatorSetcount,
    { nondet numerator = PARAM_NUMERATORS.oneOf()
      nondet denominator = PARAM_DENOMINATORS.oneOf()
      ThresholdParamnew(numerator, denominator) },
    { nondet weight = ARITH_NUMBERS.oneOf()
      nondet total = ARITH_NUMBERS.oneOf()
      ThresholdParamis_met(weight, total) },
    // dense arm: reaches the exact-boundary weights
    { nondet weight = DENSE_NUMBERS.oneOf()
      nondet total = DENSE_NUMBERS.oneOf()
      ThresholdParamis_met(weight, total) },
    { nondet weight = ARITH_NUMBERS.oneOf()
      nondet total = ARITH_NUMBERS.oneOf()
      ThresholdParamis_met_overflow_panics(weight, total) },
    { nondet total = ARITH_NUMBERS.oneOf()
      ThresholdParammin_expected(total) },
    { nondet total = ARITH_NUMBERS.oneOf()
      ThresholdParammin_expected_panics(total) },
    { nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      Contextselect_proposer(height, round) },
    { nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      Contextselect_proposer_nil_round_panics(height, round) },
    { nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      Contextselect_proposer_zero_height_panics(height, round) },
    { nondet from = HEIGHTS.oneOf()
      nondet by = Set(1, 2).oneOf()
      Heightdecrement_by(from, by) },
    { nondet from = HEIGHTS.oneOf()
      nondet by = Set(1, 2).oneOf()
      Heightincrement_by(from, by) },
    { nondet round = ROUNDS.oneOf()
      Roundincrement(round) },
    { nondet round = ROUNDS.oneOf()
      nondet fallback = ROUNDS.oneOf()
      Roundor(round, fallback) },
    { nondet propose = TIMEOUT_MS.oneOf()
      nondet propose_delta = TIMEOUT_MS.oneOf()
      nondet prevote = TIMEOUT_MS.oneOf()
      nondet prevote_delta = TIMEOUT_MS.oneOf()
      nondet precommit = TIMEOUT_MS.oneOf()
      nondet precommit_delta = TIMEOUT_MS.oneOf()
      nondet rebroadcast = TIMEOUT_MS.oneOf()
      nondet max_timeout = TIMEOUT_MS.oneOf()
      LinearTimeoutsset(propose, propose_delta, prevote, prevote_delta,
                        precommit, precommit_delta, rebroadcast, max_timeout) },
    // dense arm: samples zero bases and zero caps, so a timeout that expires
    // immediately is reachable
    { nondet propose = DENSE_TIMEOUT_MS.oneOf()
      nondet propose_delta = DENSE_TIMEOUT_MS.oneOf()
      nondet prevote = DENSE_TIMEOUT_MS.oneOf()
      nondet prevote_delta = DENSE_TIMEOUT_MS.oneOf()
      nondet precommit = DENSE_TIMEOUT_MS.oneOf()
      nondet precommit_delta = DENSE_TIMEOUT_MS.oneOf()
      nondet rebroadcast = DENSE_TIMEOUT_MS.oneOf()
      nondet max_timeout = DENSE_TIMEOUT_MS.oneOf()
      LinearTimeoutsset(propose, propose_delta, prevote, prevote_delta,
                        precommit, precommit_delta, rebroadcast, max_timeout) },
    { nondet kind = TIMEOUT_KINDS.oneOf()
      nondet finalize_ms = FINALIZE_DURATIONS.oneOf()
      nondet round = ROUNDS.oneOf()
      Timeoutsduration_for(kind, finalize_ms, round) },
    { nondet kind = TIMEOUT_KINDS.oneOf()
      nondet finalize_ms = FINALIZE_DURATIONS.oneOf()
      nondet round = ROUNDS.oneOf()
      Timeoutsduration_for_nil_round_panics(kind, finalize_ms, round) },
    certificate_votes_begin,
    { nondet voter = ADDRESSES.oneOf()
      nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      nondet value = VOTE_VALUES.oneOf()
      nondet vote_type = VOTE_TYPES.oneOf()
      add_vote(voter, height, round, value, vote_type) },
    // dense arm: votes whose scope can coincide with a certificate's
    { nondet voter = DENSE_RANKS.oneOf()
      nondet height = DENSE_HEIGHTS.oneOf()
      nondet round = DENSE_ROUNDS.oneOf()
      nondet value = Set("Match", "Nil").oneOf()
      nondet vote_type = VOTE_TYPES.oneOf()
      add_vote(voter, height, round, value, vote_type) },
    { nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      nondet value_id = VALUE_IDS.oneOf()
      CommitCertificatenew(height, round, value_id) },
    // dense arm: same scope as the dense votes, so "kept every vote" is reachable
    { nondet height = DENSE_HEIGHTS.oneOf()
      nondet round = DENSE_ROUNDS.oneOf()
      CommitCertificatenew(height, round, "Match") },
    { nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      nondet value_id = VALUE_IDS.oneOf()
      PolkaCertificatenew(height, round, value_id) },
    { nondet height = DENSE_HEIGHTS.oneOf()
      nondet round = DENSE_ROUNDS.oneOf()
      PolkaCertificatenew(height, round, "Match") },
    { nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      nondet cert_type = CERT_ROUND_KINDS.oneOf()
      RoundCertificatenew_from_votes(height, round, cert_type) },
    { nondet height = HEIGHTS.oneOf()
      nondet round = ROUNDS.oneOf()
      nondet value_id = VALUE_IDS.oneOf()
      nondet cert_type = CERT_ROUND_KINDS.oneOf()
      nondet enter_round = ROUNDS.oneOf()
      EnterRoundCertificatefrom_commit_certificate(height, round, value_id, cert_type,
                                                   enter_round) },
    certificate_signers_begin,
    { nondet signer = SIGNER_RANKS.oneOf()
      add_signer(signer) },
    // dense arm: signers a small installed set knows, so the accumulated power can
    // reach the quorum threshold
    { nondet signer = DENSE_RANKS.oneOf()
      add_signer(signer) },
    verify_certificate_power,
    verify_certificate_power_duplicate_vote,
    verify_certificate_power_unknown_validator,
    verify_certificate_power_overflow,
  }

  // ------------------------------------------------------------ observations

  /// A threshold evaluation returned "met".
  val quorum_met: bool = state.last_is_met == Some(true)

  /// A threshold evaluation returned "not met".
  val quorum_not_met: bool = state.last_is_met == Some(false)

  /// A threshold was evaluated with the weight exactly on the boundary.
  val quorum_boundary_exactly_at_threshold: bool =
    state.last_is_met != None
      and state.last_is_met_weight * state.threshold.denominator
            == state.last_is_met_total * state.threshold.numerator

  /// A threshold multiplication overflowed the machine word and panicked.
  val threshold_multiply_overflow_panicked: bool = state.panic_threshold_overflow

  /// min_expected divided by a zero denominator and panicked.
  val min_expected_divide_by_zero_panicked: bool = state.panic_min_expected_div0

  /// min_expected returned a minimum weight.
  val min_expected_computed: bool = state.last_min_expected != None

  /// A caller installed a validator set through ValidatorSet::new.
  val validator_set_installed: bool = state.vset_installed

  /// ValidatorSet::new was called with an empty set and panicked.
  val validator_set_empty_panicked: bool = state.panic_vset_empty

  /// ValidatorSet::new panicked because the total voting power overflowed.
  val validator_set_power_overflow_panicked: bool = state.panic_vset_power_overflow

  /// The installed validator set names the same validator twice.
  val validator_set_has_duplicate_address: bool = not(addresses_unique(state.vset))

  /// The installed validator set is not in the order its documentation requires.
  val validator_set_out_of_documented_order: bool = not(in_documented_order(state.vset))

  /// The installed validator set has zero total voting power.
  val validator_set_total_power_is_zero: bool = vset_total(state.vset) == 0

  /// An address lookup found no validator.
  val lookup_by_address_missed: bool = state.last_lookup_hit == Some(false)

  /// An index lookup ran past the end of the validator set.
  val lookup_by_index_out_of_range: bool = state.last_index_in_range == Some(false)

  /// A proposer was selected for a height and round.
  val proposer_selected: bool = state.last_proposer != None

  /// Proposer selection was asked for a nil round and panicked.
  val proposer_selection_nil_round_panicked: bool = state.panic_proposer_nil_round

  /// Proposer selection was asked for height zero, underflowing `height - 1`.
  val proposer_selection_zero_height_panicked: bool = state.panic_proposer_zero_height

  /// A height was decremented past its minimum.
  val height_decremented_below_minimum: bool =
    state.last_decrement_result != None
      and state.last_decrement_from - state.last_decrement_by < MIN_HEIGHT

  /// A height was incremented.
  val height_incremented: bool = state.last_increment != None

  /// A nil round was incremented, producing round zero.
  val round_incremented_from_nil: bool = state.round_from_nil

  /// A computed timeout was clamped down to max_timeout.
  val timeout_clamped_at_max: bool = state.timeout_clamped

  /// A computed per-round timeout came out below the cap, unclamped.
  val timeout_below_cap: bool =
    state.computed_timeouts.exists(c => c.per_round and c.ms < c.cap)

  /// A FinalizeHeight timeout passed through above the cap, which does not apply to it.
  val finalize_height_timeout_exceeds_cap: bool = state.finalize_above_cap

  /// duration_for produced a timeout of zero, which expires immediately.
  val zero_timeout_computed: bool = state.computed_timeouts.exists(c => c.ms == 0)

  /// duration_for was called with a nil round and panicked.
  val timeout_nil_round_panicked: bool = state.panic_timeout_nil_round

  /// A commit or polka certificate dropped votes that did not match its scope.
  val commit_certificate_dropped_votes: bool = state.dropped_votes

  /// A commit or polka certificate kept every vote it was handed.
  val commit_certificate_kept_all_votes: bool = state.kept_all_votes

  /// A certificate carries the same validator's signature twice.
  val commit_certificate_has_duplicate_signer: bool =
    state.certs.keys().exists(id => has_duplicate(state.certs.get(id).signers))

  /// A round certificate kept a vote from a different height or round, because it
  /// applies no filter.
  val round_certificate_kept_foreign_vote: bool = state.round_cert_kept_foreign

  /// An enter-round certificate was lifted from an existing commit certificate.
  val enter_round_certificate_lifted_from_commit: bool = state.lifted_enter_round_cert

  /// A certificate was rejected because it named a validator outside the set.
  val certificate_signer_unknown_to_set: bool = state.signer_unknown_to_set

  /// A certificate was rejected because it named the same validator twice.
  val certificate_rejected_as_duplicate_vote: bool = state.duplicate_vote_rejected

  /// Accumulating a certificate's signed voting power overflowed the machine word.
  val certificate_signed_power_overflowed: bool = state.signed_power_overflowed

  /// A certificate's signed voting power met the quorum threshold.
  val certificate_signed_power_meets_quorum: bool = state.last_signed_power_met == Some(true)

  /// A certificate's signed voting power fell below the quorum threshold.
  val certificate_signed_power_below_quorum: bool = state.last_signed_power_met == Some(false)

  // -------------------------------------------------- correctness properties

  /// The params the arithmetic properties sweep: the two shipped constants plus whatever
  /// a caller installed, skipping the degenerate ones min_expected cannot be evaluated on.
  val CHECKABLE_PARAMS: Set[Param] =
    Set(TWO_F_PLUS_ONE, F_PLUS_ONE, state.threshold)
      .filter(p => p.denominator > 0 and p.numerator > 0)

  /// A weight sitting exactly on a threshold boundary never meets that threshold.
  val quorum_boundary_is_not_met: bool =
    CHECKABLE_PARAMS.forall(p =>
      INV_NUMBERS.forall(w =>
        INV_NUMBERS.forall(t =>
          (w * p.denominator == t * p.numerator) implies not(is_met_pure(p, w, t)))))

  /// A threshold is met by exactly the weights that reach its own minimum expected weight.
  val is_met_agrees_with_min_expected: bool =
    CHECKABLE_PARAMS.forall(p =>
      INV_NUMBERS.forall(w =>
        INV_NUMBERS.forall(t =>
          is_met_pure(p, w, t) iff w >= min_expected_pure(p, t))))

  /// Two weights that each meet the quorum threshold against the same total always sum to
  /// more than that total, so no two quorums can be disjoint.
  val quorums_always_intersect: bool =
    INV_NUMBERS.forall(a =>
      INV_NUMBERS.forall(b =>
        INV_NUMBERS.forall(t =>
          (is_met_pure(TWO_F_PLUS_ONE, a, t) and is_met_pure(TWO_F_PLUS_ONE, b, t))
            implies a + b > t)))

  /// Every quorum check against a validator set built by ValidatorSet::new stays within
  /// the machine word, so the comparison cannot panic.
  ///
  /// Scoped to `vset_installed` on purpose: `ValidatorSet`'s `validators` field is public,
  /// so the constructor's total-power check is not an invariant of the type. A caller that
  /// builds the struct directly gets no overflow protection at all — the certificate tests
  /// do exactly that with `[u64::MAX, 1]`, and the verifier's VotingPowerOverflow branch is
  /// what catches it there.
  val quorum_check_never_overflows_for_an_installed_set: bool =
    state.vset_installed
      implies CHECKABLE_PARAMS.forall(p =>
                not(mul_overflows(vset_total(state.vset), p.numerator)))

  /// Decrementing a height below its minimum returns no height.
  val decrement_below_minimum_returns_none: bool =
    (state.last_decrement_from - state.last_decrement_by < MIN_HEIGHT)
      implies state.last_decrement_result == None

  /// Every computed timeout is strictly positive, and every per-round timeout is at most
  /// the configured maximum.
  val computed_timeouts_are_positive_and_capped: bool =
    state.computed_timeouts.forall(c => c.ms > 0 and (c.per_round implies c.ms <= c.cap))

  /// A validator set has unique validators and is ordered by voting power descending,
  /// then by address ascending.
  val validator_set_is_deterministically_ordered: bool =
    addresses_unique(state.vset) and in_documented_order(state.vset)

  /// Every signature in a commit or polka certificate comes from a vote for that
  /// certificate's own height, round, value and vote type.
  val certificate_keeps_only_matching_votes: bool =
    state.certs.keys().forall(id => {
      val c = state.certs.get(id)
      and {
        c.kind == "Commit" implies c.signers
          == voters_of(matching_votes(c.source, "Precommit", c.height, c.round, c.value_id)),
        c.kind == "Polka" implies c.signers
          == voters_of(matching_votes(c.source, "Prevote", c.height, c.round, c.value_id)),
      }
    })

  /// No certificate carries the same validator's signature twice.
  val certificate_has_no_duplicate_signers: bool =
    state.certs.keys().forall(id => not(has_duplicate(state.certs.get(id).signers)))

  /// The voting power credited to a certificate never exceeds the validator set's total
  /// voting power.
  val signed_power_never_exceeds_total: bool =
    match state.last_signed_power {
    | None => true
    | Some(signed) => signed <= state.last_signed_power_total
    }

  /// A selected proposer is a validator in the current set.
  val proposer_is_a_member: bool =
    match state.last_proposer {
    | None => true
    | Some(a) => state.vset.select(v => v.address == a).length() > 0
    }

  /// Proposer selection depends only on the validators, the height and the round — never
  /// on the order the validator set happens to be stored in.
  val proposer_independent_of_set_order: bool =
    match state.last_proposer {
    | None => true
    | Some(a) =>
        // canonical_proposers indexes modulo the set size, so it is only meaningful
        // while a set is installed.
        state.vset.length() == 0
          or canonical_proposers(state.vset, state.last_proposer_height,
                                 state.last_proposer_round).contains(a)
    }
}
