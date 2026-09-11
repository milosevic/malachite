use malachitebft_core_types::{Round, SignedProposal, Validity};
use malachitebft_test::{Address, Height, PrivateKey, Proposal, TestContext, Value};

use arc_malachitebft_core_driver::proposal_keeper::{
    EvidenceMap, ProposalKeeper, StoreProposalResult,
};

fn pk(id: &str) -> PrivateKey {
    let mut seed = [0u8; 32];
    for (i, b) in id.bytes().enumerate() {
        seed[i % 32] = b;
    }
    PrivateKey::from(seed)
}

fn addr(id: &str) -> Address {
    Address::from_public_key(&pk(id).public_key())
}

fn make_proposal_pair(
    addr_id: &str,
    round: u32,
    values: [u64; 2],
) -> (SignedProposal<TestContext>, SignedProposal<TestContext>) {
    let pk = pk(addr_id);
    let addr = addr(addr_id);
    let round = Round::new(round);

    let p1 = Proposal::new(
        Height::new(1),
        round,
        Value::new(values[0]),
        Round::Nil,
        addr,
    );
    let p2 = Proposal::new(
        Height::new(1),
        round,
        Value::new(values[1]),
        Round::Nil,
        addr,
    );

    (
        SignedProposal::new(p1.clone(), pk.sign(&p1.to_sign_bytes())),
        SignedProposal::new(p2.clone(), pk.sign(&p2.to_sign_bytes())),
    )
}

struct TestCase {
    name: &'static str,
    evidence: &'static [(&'static str, u32, [u64; 2])], // (addr, round, [v1, v2])
    expected: &'static [(&'static str, usize)],         // (addr, count)
}

#[test]
fn test_proposal_evidence_deduplication() {
    let cases: &[TestCase] = &[
        TestCase {
            name: "single proposal equivocation",
            evidence: &[("Alice", 0, [100, 200])],
            expected: &[("Alice", 1)],
        },
        TestCase {
            name: "duplicate same order",
            evidence: &[("Alice", 0, [100, 200]), ("Alice", 0, [100, 200])],
            expected: &[("Alice", 1)],
        },
        TestCase {
            name: "duplicate reversed order",
            evidence: &[("Alice", 0, [100, 200]), ("Alice", 0, [200, 100])],
            expected: &[("Alice", 1)],
        },
        TestCase {
            name: "different rounds not deduped",
            evidence: &[("Alice", 0, [100, 200]), ("Alice", 1, [100, 200])],
            expected: &[("Alice", 2)],
        },
        TestCase {
            name: "multiple validators",
            evidence: &[
                ("Alice", 0, [100, 200]),
                ("Bob", 0, [100, 200]),
                ("Alice", 0, [100, 200]), // duplicate
            ],
            expected: &[("Alice", 1), ("Bob", 1)],
        },
    ];

    for case in cases {
        // Oracle test boundary: a fresh EvidenceMap per case means a fresh run.
        let _oracle_case = quint_oracle::register_test("test_proposal_evidence_deduplication");
        let mut evidence = EvidenceMap::<TestContext>::new();

        for &(addr_id, round, values) in case.evidence {
            let (p1, p2) = make_proposal_pair(addr_id, round, values);
            evidence.add(p1, p2);
        }

        for &(addr_id, expected_count) in case.expected {
            let actual = evidence.get(&addr(addr_id)).map(|v| v.len()).unwrap_or(0);
            assert_eq!(
                actual, expected_count,
                "Test '{}' failed for {}: expected {}, got {}",
                case.name, addr_id, expected_count, actual
            );
        }
    }
}

#[test]
fn test_proposal_evidence_into_iterator_and_len() {
    let mut evidence = EvidenceMap::<TestContext>::new();

    let (p1_alice, p2_alice) = make_proposal_pair("Alice", 0, [100, 200]);
    let (p1_bob, p2_bob) = make_proposal_pair("Bob", 0, [300, 400]);
    evidence.add(p1_alice.clone(), p2_alice.clone());
    evidence.add(p1_bob.clone(), p2_bob.clone());

    // Test len()
    assert_eq!(evidence.len(), 2);

    // Test IntoIterator for &EvidenceMap
    let mut ref_count = 0;
    for (a, proposals) in &evidence {
        assert!(*a == addr("Alice") || *a == addr("Bob"));
        assert_eq!(proposals.len(), 1);
        ref_count += 1;
    }
    assert_eq!(ref_count, 2);

    // Test IntoIterator for EvidenceMap (owned)
    let mut owned_count = 0;
    for (a, proposals) in evidence {
        assert!(a == addr("Alice") || a == addr("Bob"));
        assert_eq!(proposals.len(), 1);
        owned_count += 1;
    }
    assert_eq!(owned_count, 2);
}

#[test]
fn test_proposal_evidence_len_empty() {
    let evidence = EvidenceMap::<TestContext>::new();
    assert_eq!(evidence.len(), 0);
    assert!(evidence.is_empty());
}

#[test]
fn store_proposal_surfaces_equivocation_to_caller() {
    let mut keeper = ProposalKeeper::<TestContext>::new();
    let (first, conflicting) = make_proposal_pair("Alice", 0, [100, 200]);

    // First proposal from the validator is stored without equivocation.
    assert!(matches!(
        keeper.store_proposal(first.clone(), Validity::Valid),
        StoreProposalResult::Stored
    ));

    // An exact duplicate is ignored, still reported as stored.
    assert!(matches!(
        keeper.store_proposal(first.clone(), Validity::Valid),
        StoreProposalResult::Stored
    ));

    // A second, distinct proposal for the same round surfaces the equivocating pair.
    match keeper.store_proposal(conflicting.clone(), Validity::Valid) {
        StoreProposalResult::Equivocation {
            existing,
            conflicting: returned,
        } => {
            assert_eq!(existing, first);
            assert_eq!(returned, conflicting);
        }
        StoreProposalResult::Stored => panic!("expected an equivocation to be surfaced"),
    }

    // The keeper does not record evidence on its own; the caller drives that.
    assert!(keeper.evidence().is_empty());

    keeper.record_evidence(first, conflicting);
    assert_eq!(keeper.evidence().len(), 1);
}

/// reproduces obs:proposal_evidence_exceeds_vote_cap — fails on current code.
///
/// The vote-side `EvidenceMap` (core-votekeeper) caps each validator's evidence
/// list at `MAX_EVIDENCE_PER_VALIDATOR`; the proposal-side `EvidenceMap` applies
/// the same either-order dedup but no bound at all. Evidence only drains once
/// per height (`log_and_finalize`), so a proposer that equivocates in every round
/// of one undecided height grows its list without limit.
///
/// Driven through the real driver entry point: `Driver::process` with `NewRound`
/// and two conflicting `Proposal` inputs per round, exactly as the consensus
/// layer feeds it, then the production drain `Driver::take_proposal_evidence`.
#[test]
#[ignore = "reproduces obs:proposal_evidence_exceeds_vote_cap"]
fn proposal_evidence_per_validator_stays_within_the_vote_cap() {
    use malachitebft_core_votekeeper::evidence::MAX_EVIDENCE_PER_VALIDATOR;
    use malachitebft_test::utils::validators::make_validators;
    use malachitebft_test::ValidatorSet;

    use arc_malachitebft_core_driver::{Driver, Input};

    let [(v1, _sk1), (v2, sk2), (v3, _sk3), (v4, _sk4)] = make_validators([10, 10, 10, 10]);
    let validator_set = ValidatorSet::new(vec![v1.clone(), v2.clone(), v3, v4]);

    let ctx = TestContext::new();
    let height = Height::new(1);
    let mut driver = Driver::new(ctx, height, validator_set, v1.address, Default::default());

    // One more round than the vote map would ever keep pairs for.
    let rounds = MAX_EVIDENCE_PER_VALIDATOR + 1;

    for r in 0..rounds {
        let round = Round::new(r as u32);

        driver
            .process(Input::NewRound(height, round, v2.address))
            .expect("NewRound accepted");

        // The round's proposer sends two conflicting proposals.
        for value in [Value::new(100 + r as u64), Value::new(200 + r as u64)] {
            let proposal = Proposal::new(height, round, value, Round::Nil, v2.address);
            let signed = SignedProposal::new(proposal.clone(), sk2.sign(&proposal.to_sign_bytes()));
            driver
                .process(Input::Proposal(signed, Validity::Valid))
                .expect("Proposal accepted");
        }
    }

    // The height drains its evidence exactly once, at finalization.
    let evidence = driver.take_proposal_evidence();
    let pairs = evidence
        .get(&v2.address)
        .map(|pairs| pairs.len())
        .unwrap_or(0);

    assert_eq!(
        rounds, 4,
        "the scenario must offer more distinct pairs than the cap"
    );
    assert!(
        pairs <= MAX_EVIDENCE_PER_VALIDATOR,
        "one validator's proposal evidence grew to {pairs} pairs, past the \
         per-validator cap of {MAX_EVIDENCE_PER_VALIDATOR} the vote evidence map enforces"
    );
}
