use bytes::Bytes;
use malachitebft_core_types::{
    NilOrVal, Round, SignedExtension, SignedVote, Threshold, Vote as _, VoteType,
};

use arc_malachitebft_core_votekeeper::evidence::MAX_EVIDENCE_PER_VALIDATOR;
use arc_malachitebft_core_votekeeper::keeper::{Output, VoteKeeper};

use malachitebft_test::{
    Address, Height, PrivateKey, Signature, TestContext, Validator, ValidatorSet, ValueId, Vote,
};

fn setup<const N: usize>(vp: [u64; N]) -> ([Address; N], VoteKeeper<TestContext>) {
    let mut addrs = [Address::new([0; 20]); N];
    let mut vals = Vec::with_capacity(N);
    for i in 0..N {
        let pk = PrivateKey::from([i as u8; 32]);
        addrs[i] = Address::from_public_key(&pk.public_key());
        vals.push(Validator::new(pk.public_key(), vp[i]));
    }
    let keeper = VoteKeeper::new(ValidatorSet::new(vals), Default::default());
    (addrs, keeper)
}

fn new_signed_prevote(
    height: Height,
    round: Round,
    value: NilOrVal<ValueId>,
    addr: Address,
) -> SignedVote<TestContext> {
    SignedVote::new(
        Vote::new_prevote(height, round, value, addr),
        Signature::test(),
    )
}

fn new_signed_precommit(
    height: Height,
    round: Round,
    value: NilOrVal<ValueId>,
    addr: Address,
) -> SignedVote<TestContext> {
    SignedVote::new(
        Vote::new_precommit(height, round, value, addr),
        Signature::test(),
    )
}

fn new_signed_precommit_with_extension(
    height: Height,
    round: Round,
    value: NilOrVal<ValueId>,
    addr: Address,
    extension: SignedExtension<TestContext>,
) -> SignedVote<TestContext> {
    SignedVote::new(
        Vote::new_precommit(height, round, value, addr).extend(extension),
        Signature::test(),
    )
}

fn test_extension(data: &'static [u8]) -> SignedExtension<TestContext> {
    SignedExtension::new(Bytes::from_static(data), Signature::test())
}

#[test]
fn prevote_apply_nil() {
    let ([addr1, addr2, addr3], mut keeper) = setup([1, 1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);

    let vote = new_signed_prevote(height, round, NilOrVal::Nil, addr1);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, round, NilOrVal::Nil, addr2);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, round, NilOrVal::Nil, addr3);
    let msg = keeper.apply_vote(vote, round);
    assert_eq!(msg, Some(Output::PolkaNil));
}

#[test]
fn precommit_apply_nil() {
    let ([addr1, addr2, addr3], mut keeper) = setup([1, 1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);

    let vote = new_signed_precommit(height, round, NilOrVal::Nil, addr1);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, Round::new(0), NilOrVal::Nil, addr2);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, Round::new(0), NilOrVal::Nil, addr3);
    let msg = keeper.apply_vote(vote, round);
    assert_eq!(msg, Some(Output::PrecommitAny));
}

#[test]
fn prevote_apply_single_value() {
    let ([addr1, addr2, addr3, addr4], mut keeper) = setup([1, 1, 1, 1]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let round = Round::new(0);

    let vote = new_signed_prevote(height, Round::new(0), val, addr1);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, Round::new(0), val, addr2);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote_nil = new_signed_prevote(height, Round::new(0), NilOrVal::Nil, addr3);
    let msg = keeper.apply_vote(vote_nil, round);
    assert_eq!(msg, Some(Output::PolkaAny));

    let vote = new_signed_prevote(height, Round::new(0), val, addr4);
    let msg = keeper.apply_vote(vote, round);
    assert_eq!(msg, Some(Output::PolkaValue(id)));
}

#[test]
fn precommit_apply_single_value() {
    let ([addr1, addr2, addr3, addr4], mut keeper) = setup([1, 1, 1, 1]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let round = Round::new(0);

    let vote = new_signed_precommit(height, Round::new(0), val, addr1);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    // Duplicated
    let vote = new_signed_precommit(height, Round::new(0), val, addr1);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, Round::new(0), val, addr2);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    // Duplicated
    let vote = new_signed_precommit(height, Round::new(0), val, addr2);
    let msg = keeper.apply_vote(vote.clone(), round);
    assert_eq!(msg, None);

    let vote_nil = new_signed_precommit(height, Round::new(0), NilOrVal::Nil, addr3);
    let msg = keeper.apply_vote(vote_nil, round);
    assert_eq!(msg, Some(Output::PrecommitAny));

    let vote = new_signed_precommit(height, Round::new(0), val, addr4);
    let msg = keeper.apply_vote(vote, round);
    assert_eq!(msg, Some(Output::PrecommitValue(id)));

    let per_round = keeper.per_round(round);

    match per_round {
        Some(per_round) => {
            // Build a commit certificate for (round, val)
            let cert = per_round.precommits_for_value(&id);
            assert_eq!(cert.len(), 3);
        }
        None => panic!("Per round not found"),
    }
}

#[test]
fn skip_round_small_quorum_prevotes_two_vals() {
    let ([addr1, addr2, addr3, _], mut keeper) = setup([1, 1, 1, 1]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let cur_round = Round::new(0);
    let fut_round = Round::new(1);

    let vote = new_signed_prevote(height, cur_round, val, addr1);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, fut_round, val, addr3);
    let msg = keeper.apply_vote(vote, cur_round);
    assert_eq!(msg, Some(Output::SkipRound(Round::new(1))));
}

#[test]
fn skip_round_small_quorum_with_prevote_precommit_two_vals() {
    let ([addr1, addr2, addr3, _], mut keeper) = setup([1, 1, 1, 1]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let cur_round = Round::new(0);
    let fut_round = Round::new(1);

    let vote = new_signed_prevote(height, cur_round, val, addr1);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, fut_round, val, addr3);
    let msg = keeper.apply_vote(vote, cur_round);
    assert_eq!(msg, Some(Output::SkipRound(Round::new(1))));
}

#[test]
fn skip_round_full_quorum_with_prevote_precommit_two_vals() {
    let ([addr1, addr2, addr3], mut keeper) = setup::<3>([1, 1, 2]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let cur_round = Round::new(0);
    let fut_round = Round::new(1);

    let vote = new_signed_prevote(height, cur_round, val, addr1);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, fut_round, val, addr3);
    let msg = keeper.apply_vote(vote, cur_round);
    assert_eq!(msg, Some(Output::SkipRound(Round::new(1))));
}

#[test]
fn no_skip_round_small_quorum_with_same_val() {
    let ([addr1, addr2, ..], mut keeper) = setup([1, 1, 1, 1]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let cur_round = Round::new(0);
    let fut_round = Round::new(1);

    let vote = new_signed_prevote(height, cur_round, val, addr1);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote, cur_round);
    assert_eq!(msg, None);
}

#[test]
fn no_skip_round_full_quorum_with_same_val() {
    let ([addr1, addr2, ..], mut keeper) = setup([1, 1, 1, 1]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let cur_round = Round::new(0);
    let fut_round = Round::new(1);

    let vote = new_signed_prevote(height, cur_round, val, addr1);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_prevote(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote.clone(), cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote, cur_round);
    assert_eq!(msg, None);
}

#[test]
fn skip_round_and_precommit_value_future_round() {
    let ([addr1, addr2, ..], mut keeper) = setup([2, 3, 2]);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);
    let height = Height::new(1);
    let cur_round = Round::new(0);
    let fut_round = Round::new(1);

    let vote = new_signed_precommit(height, fut_round, val, addr1);
    let msg = keeper.apply_vote(vote, cur_round);
    assert_eq!(msg, None);

    let vote = new_signed_precommit(height, fut_round, val, addr2);
    let msg = keeper.apply_vote(vote, cur_round);
    assert_eq!(msg, Some(Output::PrecommitValue(id)));
}

#[test]
fn same_votes() {
    let ([addr1, ..], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);

    let vote1 = new_signed_prevote(height, round, val, addr1);
    let msg = keeper.apply_vote(vote1.clone(), round);
    assert_eq!(msg, None);

    let vote2 = new_signed_prevote(height, round, val, addr1);
    let msg = keeper.apply_vote(vote2.clone(), round);
    assert_eq!(msg, None);

    assert!(keeper.evidence().is_empty());
    assert_eq!(keeper.evidence().get(&addr1), None);
}

#[test]
fn equivocation() {
    let ([addr1, addr2, ..], mut keeper) = setup([1, 1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);

    let id1 = ValueId::new(1);
    let val1 = NilOrVal::Val(id1);

    let vote11 = new_signed_prevote(height, round, val1, addr1);
    let msg = keeper.apply_vote(vote11.clone(), round);
    assert_eq!(msg, None);

    let vote12 = new_signed_prevote(height, round, NilOrVal::Nil, addr1);
    let msg = keeper.apply_vote(vote12.clone(), round);
    assert_eq!(msg, None);

    assert!(!keeper.evidence().is_empty());
    assert_eq!(keeper.evidence().get(&addr1), Some(&vec![(vote11, vote12)]));

    let vote21 = new_signed_prevote(height, round, val1, addr2);
    let msg = keeper.apply_vote(vote21.clone(), round);
    assert_eq!(msg, None);

    let id2 = ValueId::new(2);
    let val2 = NilOrVal::Val(id2);

    let vote22 = new_signed_prevote(height, round, val2, addr2);
    let msg = keeper.apply_vote(vote22.clone(), round);
    assert_eq!(msg, None);

    assert_eq!(keeper.evidence().get(&addr2), Some(&vec![(vote21, vote22)]));
}

#[test]
fn precommit_with_extension_replaces_stored_precommit_without_extension() {
    let ([addr1, _], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);
    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);

    let bare = new_signed_precommit(height, round, val, addr1);
    assert_eq!(keeper.apply_vote(bare, round), None);

    let extension = test_extension(b"app-data");
    let extended =
        new_signed_precommit_with_extension(height, round, val, addr1, extension.clone());
    assert_eq!(keeper.apply_vote(extended, round), None);

    let per_round = keeper.per_round(round).expect("per-round entry exists");
    let stored = per_round
        .get_vote(VoteType::Precommit, &addr1)
        .expect("precommit stored for validator");
    assert_eq!(stored.extension(), Some(&extension));
}

#[test]
fn has_vote_true_for_same_value_bare_duplicate() {
    let ([addr1, _], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);
    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);

    let vote = new_signed_precommit(height, round, val, addr1);
    keeper.apply_vote(vote.clone(), round);

    assert!(keeper.has_vote(&vote));
}

#[test]
fn has_vote_false_for_extension_upgrade() {
    let ([addr1, _], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);
    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);

    let bare = new_signed_precommit(height, round, val, addr1);
    keeper.apply_vote(bare, round);

    let extended =
        new_signed_precommit_with_extension(height, round, val, addr1, test_extension(b"app-data"));
    assert!(!keeper.has_vote(&extended));
}

#[test]
fn has_vote_true_for_bare_duplicate_after_extension_upgrade() {
    let ([addr1, _], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);
    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);

    let bare = new_signed_precommit(height, round, val, addr1);
    keeper.apply_vote(bare.clone(), round);

    let extended =
        new_signed_precommit_with_extension(height, round, val, addr1, test_extension(b"app-data"));
    keeper.apply_vote(extended, round);

    assert!(keeper.has_vote(&bare));
}

#[test]
fn has_vote_false_for_equivocating_value() {
    let ([addr1, _], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);

    let first = new_signed_precommit(height, round, NilOrVal::Val(ValueId::new(1)), addr1);
    keeper.apply_vote(first, round);

    let conflicting = new_signed_precommit(height, round, NilOrVal::Val(ValueId::new(2)), addr1);
    assert!(!keeper.has_vote(&conflicting));
}

#[test]
fn has_vote_true_for_signature_variant_duplicate() {
    let ([addr1, _], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);
    let val = NilOrVal::Val(ValueId::new(1));

    let vote = Vote::new_prevote(height, round, val, addr1);

    let stored = SignedVote::new(vote.clone(), Signature::from_bytes([1; 64]));
    keeper.apply_vote(stored, round);

    let variant = SignedVote::new(vote, Signature::from_bytes([2; 64]));
    assert!(keeper.has_vote(&variant));
}

#[test]
fn precommit_without_extension_does_not_clear_stored_extension() {
    let ([addr1, _], mut keeper) = setup([1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);
    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);

    let extension = test_extension(b"app-data");
    let extended =
        new_signed_precommit_with_extension(height, round, val, addr1, extension.clone());
    assert_eq!(keeper.apply_vote(extended, round), None);

    let bare = new_signed_precommit(height, round, val, addr1);
    assert_eq!(keeper.apply_vote(bare, round), None);

    let per_round = keeper.per_round(round).expect("per-round entry exists");
    let stored = per_round
        .get_vote(VoteType::Precommit, &addr1)
        .expect("precommit stored for validator");
    assert_eq!(stored.extension(), Some(&extension));
}

/// Characterization test for the weight-overflow hazard: a validator set whose
/// total voting power leaves no headroom for `total * 2` turns any well-formed
/// vote into a panic inside `ThresholdParam::is_met`, taking the node down.
/// `VoteKeeper::new` accepts such a validator set without complaint.
#[test]
#[should_panic(expected = "attempt to multiply with overflow")]
fn apply_vote_panics_on_total_weight_overflow() {
    let huge = 3_100_000_000_000_000_000; // 3 x this overflows u64 when doubled
    let ([addr1, ..], mut keeper) = setup([huge, huge, huge]);
    assert_eq!(keeper.total_weight(), huge * 3);

    let vote = new_signed_prevote(
        Height::new(1),
        Round::new(0),
        NilOrVal::Val(ValueId::new(1)),
        addr1,
    );

    keeper.apply_vote(vote, Round::new(0));
}

/// Pins the `evidence_bounded_per_validator` violation: the model asserts a
/// single validator's evidence never accumulates more than one proven pair, so
/// a flooding equivocator cannot grow the keeper's memory. Driving the
/// counterexample through the public `apply_vote` API — one validator
/// equivocating on its precommit and then on its prevote in the same round —
/// records two entries for that validator, so this test FAILS on current code
/// and pins the unbounded-evidence bug.
// reproduces evidence_bounded_per_validator — fails on current code
#[test]
#[ignore]
fn evidence_stays_bounded_per_validator() {
    let ([addr1, ..], mut keeper) = setup([1, 1, 1, 1]);

    let height = Height::new(1);
    let round = Round::new(1);

    // First equivocation: two precommits for different values.
    let pc1 = new_signed_precommit(height, round, NilOrVal::Val(ValueId::new(0)), addr1);
    assert_eq!(keeper.apply_vote(pc1, round), None);
    let pc2 = new_signed_precommit(height, round, NilOrVal::Val(ValueId::new(2)), addr1);
    assert_eq!(keeper.apply_vote(pc2, round), None);

    // Second equivocation from the same validator, on its prevote this time.
    let pv1 = new_signed_prevote(height, round, NilOrVal::Val(ValueId::new(2)), addr1);
    assert_eq!(keeper.apply_vote(pv1, round), None);
    let pv2 = new_signed_prevote(height, round, NilOrVal::Nil, addr1);
    assert_eq!(keeper.apply_vote(pv2, round), None);

    let recorded = keeper.evidence().get(&addr1).map(|e| e.len()).unwrap_or(0);
    assert!(
        recorded <= 1,
        "evidence for a single validator must stay bounded at one proven pair, got {recorded}"
    );
}

/// Pins the `polka_any_reported_on_prevote_quorum` violation: a round holding a
/// 2f+1 prevote quorum must have reported PolkaAny for it, or a driver arming
/// its prevote timeout on PolkaAny is starved. Driving the counterexample
/// through the public `apply_vote` API — every validator prevoting in round 1
/// while the node is still driving round 0 — reaches the quorum with only
/// SkipRound(1) reported, and no prevote is left to ever trigger PolkaAny.
/// This test FAILS on current code and pins that starvation. Note the driver
/// compensates: on entering the round it re-derives thresholds through
/// `is_threshold_met`, so PolkaAny is not lost system-wide.
// reproduces polka_any_reported_on_prevote_quorum — fails on current code
#[test]
#[ignore]
fn polka_any_reported_once_prevote_quorum_reached() {
    let ([addr1, addr2, addr3], mut keeper) = setup([1, 1, 2]);

    let height = Height::new(1);
    let current = Round::new(0);
    let future = Round::new(1);

    // The whole validator set has moved on to round 1 while we still drive
    // round 0, so every round-1 prevote arrives as a future-round vote.
    let mut outputs = Vec::new();
    for (addr, value) in [
        (addr2, NilOrVal::Val(ValueId::new(1))),
        (addr3, NilOrVal::Val(ValueId::new(2))),
        (addr1, NilOrVal::Val(ValueId::new(1))),
    ] {
        let vote = new_signed_prevote(height, future, value, addr);
        if let Some(output) = keeper.apply_vote(vote, current) {
            outputs.push(output);
        }
    }

    // Round 1 now holds a prevote quorum and no prevote is left to arrive.
    assert!(keeper.is_threshold_met(&future, VoteType::Prevote, Threshold::Any));
    assert!(
        outputs.contains(&Output::PolkaAny),
        "round holding a prevote quorum never reported PolkaAny, got {outputs:?}"
    );
}

/// A future-round `SkipRound` is emitted first, and the later `2f+1`
/// `PrecommitValue` for that same future round is still reported: the
/// `emitted_outputs` dedup only suppresses the repeated `SkipRound`, not the
/// stronger `PrecommitValue`, which `threshold_to_output` special-cases inside
/// the future-round branch.
#[test]
fn precommit_value_after_skip_round_in_future_round() {
    let ([addr1, addr2, addr3, _addr4], mut keeper) = setup([1, 1, 1, 1]);

    let height = Height::new(1);
    let cur_round = Round::new(0);
    let fut_round = Round::new(1);

    let id = ValueId::new(1);
    let val = NilOrVal::Val(id);

    // First precommit for the future round: below both thresholds.
    let msg = keeper.apply_vote(new_signed_precommit(height, fut_round, val, addr1), cur_round);
    assert_eq!(msg, None);

    // Second one crosses f+1 but not 2f+1: only the skip is reported.
    let msg = keeper.apply_vote(new_signed_precommit(height, fut_round, val, addr2), cur_round);
    assert_eq!(msg, Some(Output::SkipRound(fut_round)));

    // Third one reaches the 2f+1 quorum on the value. The skip threshold is
    // still met, but `PrecommitValue` outranks it and `SkipRound` is not
    // re-emitted.
    let msg = keeper.apply_vote(new_signed_precommit(height, fut_round, val, addr3), cur_round);
    assert_eq!(msg, Some(Output::PrecommitValue(id)));

    let emitted = keeper.per_round(fut_round).unwrap().emitted_outputs();
    assert!(emitted.contains(&Output::SkipRound(fut_round)));
    assert!(emitted.contains(&Output::PrecommitValue(id)));
    assert_eq!(emitted.len(), 2);
}

/// Characterization test for the `PolkaAny` hazard: in a unanimous round the
/// keeper reaches a prevote quorum but never emits `PolkaAny`.
///
/// `compute_threshold` returns `Threshold::Value` as soon as the quorum is on
/// the voted value and never falls through to the `Any` branch, and `apply_vote`
/// emits at most one output per call. So a consumer keyed on `PolkaAny` (e.g. to
/// arm the prevote timeout) never sees it here, even though
/// `is_threshold_met(.., Threshold::Any)` answers `true`.
#[test]
fn prevote_unanimous_value_quorum_never_emits_polka_any() {
    let ([addr1, addr2, addr3, addr4], mut keeper) = setup([1, 1, 1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);

    let id = ValueId::new(1);
    let value = NilOrVal::Val(id);

    let msg = keeper.apply_vote(new_signed_prevote(height, round, value, addr1), round);
    assert_eq!(msg, None);

    let msg = keeper.apply_vote(new_signed_prevote(height, round, value, addr2), round);
    assert_eq!(msg, None);

    // The quorum is crossed on the value: only the stronger `PolkaValue` is reported.
    let msg = keeper.apply_vote(new_signed_prevote(height, round, value, addr3), round);
    assert_eq!(msg, Some(Output::PolkaValue(id)));

    // A further prevote for the same value emits nothing at all.
    let msg = keeper.apply_vote(new_signed_prevote(height, round, value, addr4), round);
    assert_eq!(msg, None);

    // The `Any` threshold is met ...
    assert!(keeper.is_threshold_met(&round, VoteType::Prevote, Threshold::Any));

    // ... yet `PolkaAny` was never emitted for this round.
    let emitted = keeper.per_round(round).unwrap().emitted_outputs();
    assert!(
        !emitted.contains(&Output::PolkaAny),
        "expected no PolkaAny in a unanimous round, got {emitted:?}"
    );
    assert!(emitted.contains(&Output::PolkaValue(id)));
}

/// Characterization test for the per-validator evidence cap: a flooding
/// equivocator's entries stop accumulating at `MAX_EVIDENCE_PER_VALIDATOR`,
/// `add` dedupes exact repeats of the same ordered pair, and `prune_votes`
/// never touches the evidence map.
///
/// Before the cap was introduced, growth was unbounded in the number of
/// equivocations — one entry per fresh conflicting value — which is the
/// memory-exhaustion hazard this cap closes.
#[test]
fn repeated_equivocation_is_capped_and_survives_prune() {
    let ([addr1, ..], mut keeper) = setup([1, 1, 1, 1]);

    let height = Height::new(1);
    let round = Round::new(0);

    // First vote, then a stream of conflicting ones from the same validator.
    let first = new_signed_prevote(height, round, NilOrVal::Val(ValueId::new(0)), addr1);
    assert_eq!(keeper.apply_vote(first, round), None);

    const CONFLICTS: u64 = 50;
    for i in 1..=CONFLICTS {
        let vote = new_signed_prevote(height, round, NilOrVal::Val(ValueId::new(i)), addr1);
        assert_eq!(keeper.apply_vote(vote, round), None);
    }

    // Growth stops at the cap, however many fresh conflicting values arrive.
    assert!(CONFLICTS as usize > MAX_EVIDENCE_PER_VALIDATOR);
    assert_eq!(
        keeper.evidence().get(&addr1).map(|e| e.len()),
        Some(MAX_EVIDENCE_PER_VALIDATOR)
    );

    // An exact repeat of an already recorded pair is deduped as well.
    let repeat = new_signed_prevote(height, round, NilOrVal::Val(ValueId::new(1)), addr1);
    assert_eq!(keeper.apply_vote(repeat, round), None);
    assert_eq!(
        keeper.evidence().get(&addr1).map(|e| e.len()),
        Some(MAX_EVIDENCE_PER_VALIDATOR)
    );

    // Pruning the round drops the per-round votes but leaves the evidence.
    keeper.prune_votes(Round::new(1));
    assert_eq!(keeper.rounds(), 0);
    assert_eq!(
        keeper.evidence().get(&addr1).map(|e| e.len()),
        Some(MAX_EVIDENCE_PER_VALIDATOR)
    );

    // Only the caller taking the evidence releases it.
    let taken = keeper.take_evidence();
    assert_eq!(
        taken.get(&addr1).map(|e| e.len()),
        Some(MAX_EVIDENCE_PER_VALIDATOR)
    );
    assert!(keeper.evidence().is_empty());
}

/// Pins the `tally_never_overflows` violation: accumulating votes must never
/// push a tallied weight, or the quorum comparison computed from it, past the
/// machine maximum where the tally aborts the node. Here the total voting power
/// itself is small enough that `total * 2` fits in a u64 — it is the accumulated
/// tally of a single large validator that overflows `weight * 3` inside
/// `ThresholdParam::is_met`, which uses `.expect("attempt to multiply with
/// overflow")`. `VoteKeeper::new` accepts the validator set without complaint
/// and the first well-formed prevote takes the node down, so this test FAILS on
/// current code and pins the tally-overflow abort.
// reproduces tally_never_overflows — fails on current code
#[test]
#[ignore]
fn tally_never_overflows_on_accumulated_weight() {
    // total * 2 fits in a u64; weight * 3 for the first validator does not.
    let big = 6_500_000_000_000_000_000;
    let small = 2_500_000_000_000_000_000;
    let ([addr1, _addr2], mut keeper) = setup([big, small]);
    assert_eq!(keeper.total_weight(), big + small);

    let vote = new_signed_prevote(
        Height::new(1),
        Round::new(0),
        NilOrVal::Val(ValueId::new(1)),
        addr1,
    );

    // Tallying this vote must not abort the node.
    keeper.apply_vote(vote, Round::new(0));
}

/// Real network noise around the keeper's main job: a vote from a validator
/// outside the set is discarded, a future-round vote reports SkipRound, a second
/// future-round vote from the same round is suppressed as a duplicate output,
/// and a genuine prevote quorum in that round still reports PolkaAny.
#[test]
fn unknown_vote_discarded_then_skip_round_suppressed_then_polka_any() {
    let ([addr1, addr2, addr3], mut keeper) = setup([1, 1, 2]);

    // An address that is not part of the validator set.
    let outsider = Address::from_public_key(&PrivateKey::from([9; 32]).public_key());

    let height = Height::new(1);
    let round0 = Round::new(0);
    let round1 = Round::new(1);

    // Nothing to prune and no evidence yet.
    keeper.prune_votes(round0);
    assert!(keeper.take_evidence().is_empty());
    assert!(keeper.take_evidence().is_empty());

    // A vote from outside the validator set is discarded.
    let vote = new_signed_prevote(height, round0, NilOrVal::Val(ValueId::new(1)), outsider);
    assert_eq!(keeper.apply_vote(vote, round0), None);

    // The heaviest validator prevotes in the next round: f+1 honest weight for a
    // future round, so the keeper tells the driver to skip to it.
    let vote = new_signed_prevote(height, round1, NilOrVal::Val(ValueId::new(1)), addr3);
    assert_eq!(keeper.apply_vote(vote, round0), Some(Output::SkipRound(round1)));

    // A second future-round vote would report SkipRound(1) again; it is suppressed.
    let vote = new_signed_precommit(height, round1, NilOrVal::Nil, addr1);
    assert_eq!(keeper.apply_vote(vote, round0), None);

    // Now driving round 1, a prevote quorum spread over two values is PolkaAny.
    let vote = new_signed_prevote(height, round1, NilOrVal::Val(ValueId::new(2)), addr2);
    assert_eq!(keeper.apply_vote(vote, round1), Some(Output::PolkaAny));
}
