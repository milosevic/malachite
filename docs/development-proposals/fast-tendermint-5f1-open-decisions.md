# Fast Tendermint (5f+1) — decisions waiting on Zarko

Batch queue. Each item states the decision, why it is blocked on a human, and my
recommendation so you can say "yes to all" where you agree. Last updated 2026-09-10.

Nothing here has been acted on. Nothing has been pushed to any remote.

---

## A. Blocking — work cannot proceed without these

### A1. Studio's native UI prompts are blocking two pipelines
Studio raises confirmation prompts in its own desktop UI that the operator MCP cannot
answer (`operator_resolvable: false`). Two are outstanding:

- **`signing`, task 16** — stuck at `refine` for over an hour. The MCP reported
  *"the adapter is waiting for a human in its native permission UI"*. It cleared once by
  itself, then did not. `advance_component` has dropped out of its allowed actions, so I
  cannot reach it.
- **`core-types-domain`** — my `restart_component` at stage `generate` returned
  `operator cancel the elicitation`. It cleared the artifacts anyway (spec deleted, config
  gone) but did not start the worker.

**Needed:** open Quint Studio and clear/approve the pending prompts.
**Also worth knowing:** three consecutive `request_review` calls on `core-types-domain`
timed out with no decision recorded. That looks like a Studio transport problem, not a
modelling one, and it may be worth reporting upstream.

### A2. Did the `core-types-domain` scope reduction take?
You asked to cut its observations to a minimum. The worker re-submitted **34 actions /
12 invariants / 35 observations** — wider than the 34 that failed before. I rejected with a
hard scope, but the gate re-presented unchanged with `addressed_feedback: []`, so the
rejection probably never reached the worker.

The scope I asked for, which I still recommend:

- **9 observations:** `quorum_met`, `quorum_not_met`,
  `quorum_boundary_exactly_at_threshold`, `min_expected_computed`,
  `certificate_signed_power_meets_quorum`, `certificate_signed_power_below_quorum`,
  `certificate_signed_power_overflowed`, `certificate_signer_unknown_to_set`,
  `certificate_rejected_as_duplicate_vote`
- **5 invariants:** `quorum_boundary_is_not_met`, `is_met_agrees_with_min_expected`,
  `quorums_always_intersect`, `signed_power_never_exceeds_total`,
  `certificate_has_no_duplicate_signers`
- **Dropped:** proposer selection, height arithmetic, `Round::increment`, timeout
  computation/clamping, validator-set ordering and duplicate-address arms, index/address
  lookups, the round/enter-round certificate lifts, and the nil-round panic arms.

Rationale: this component is needed for exactly one thing downstream — the threshold
arithmetic and certificate signed-power accumulation that the 5f+1 change rewrites. The
rest is what produced 10,660 behavior classes, 20.7 ms/step and 191 spec gaps with nothing
confirmed.

**Needed:** confirm the narrow scope, and if the gate stays unreachable, whether to let the
worker proceed at its own width or leave the component parked.

---

## B. Findings needing your verdict (`set_finding` requires it, in every mode)

I have not decided any of these. Two are named because they look real; the rest need the
evidence read properly.

### B1. `equivocation-detection` — 11 product bugs, 18 findings
Component is `ready`: 19/19 observations and 7 properties confirmed, 167 tests matched.

- **Uncapped proposal evidence.** Vote evidence is capped at
  `MAX_EVIDENCE_PER_VALIDATOR = 3`; the proposal side has **no bound at all** —
  `EvidenceMap::add` is guarded only by `if !already_exists`. In one undecided height that
  keeps opening rounds, a single equivocating validator adds a fresh pair every round,
  unbounded. Violates `evidence_per_validator_is_bounded`. The asymmetry looks like an
  oversight rather than a decision. **Recommend: accept as a real bug.**
- **Release-mode abort.** `proposal_keeper.rs:112` is `assert_eq!`, not
  `debug_assert_eq!` — "BUG: Received proposals from different validators in the same
  round" — so it aborts in release too. **Not** network-reachable: `verify_signed_proposal`'s
  proposer check protects that path, so it is an internal-API hazard only. This answers the
  open question Studio's own component map carried on that row.
  **Recommend: accept, but as low severity given it is unreachable from the network.**
- **Two further property violations:** `no_value_credited_by_arrival_order` (arrival order
  decides which conflicting value gets tallied) and `evidence_surfaces_only_at_finalize`.

**Honesty caveat, important:** three properties were never violated even with guards off,
so they may hold by model construction rather than being genuinely exercised — and one of
them is `equivocating_vote_is_absorbed_not_tallied`, i.e. exactly the "equivocation cannot
manufacture a quorum" guarantee. **Treat that as weak evidence, not proof.**

### B2. `signing` — 4 properties showing violated, 10 findings
`accepted_certificate_meets_its_threshold`,
`accepted_certificate_has_distinct_known_signers`,
`verification_accepts_only_signed_preimages`, `consensus_preimages_are_network_scoped`.

Only the last is intentional — a documented domain-separation obligation
(`signing/src/lib.rs:60`) that the test provider does not carry. The other three are most
likely artifacts of `refine` being mid-flight (88 open requests), **not** code bugs.
The first would matter a great deal if real, since certificate threshold verification is
exactly what Stage 1 changes.

**Recommend: do not decide these until `signing` finishes refine (blocked by A1).**

### B3. `driver` — 4 findings, `core-types-domain` — 18 findings
Not yet read in detail.

---

## C. Direction

### C1. Is the 5x replica cost acceptable?
`n > 5f` means **6 validators to tolerate 1**, and **11 to tolerate 2**. This decides
whether the branch is a research exercise or a shipping path, and it should be answered
before Stage 1 writes code. Still unanswered from the original plan.

### C2. How should `WaitForValid` be modelled?
The paper's proposer of any round > 0 performs a bounded wait to learn `valid` from the
previous round before choosing fresh-propose vs re-propose (L45-L48). Malachite has no
analogue, and a pure transition function cannot block. My parked draft surfaces it as an
`Output::WaitForValid(Timeout)` plus an `awaiting_valid` flag and its own expiry input.
**This is the main open design question of the whole change** and is worth settling in the
Quint model before Rust.

### C3. Keep or discard the parked 5f+1 draft?
676 lines in `git stash@{0}` — `fast/{mod,state,input,output,state_machine}.rs`. Written
before your "3f+1 baseline first" instruction, never compiled, never committed. Contains
the step collapse, the merged `valid` holding an identifier, both thresholds as distinct
inputs, no `SkipRound`, and the `WaitForValid` representation above.
**Recommend: keep as a labelled draft; the first honest step when it is restored is
compiling it.**

---

## D. Permissions

### D1. Push approval
**3 commits unpushed** on `zm_5f+1`. Nothing will go to `fork`
(`github.com/milosevic/malachite`) without your explicit yes.

### D2. Tool access
You confirmed `cargo`. I also rely on `git` (local only; `git push` withheld) and
`grep`/`sed`/`python3` for repo edits.

One narrow request: **read access to Studio's oracle logs in `$TMPDIR`**. That is how the
~97-minute non-termination got diagnosed — the log line `simulation done in 1036893ms:
10660 behavior class(es)` is what proved the runs were working rather than hung. Studio's
MCP insights do not surface it. Without it, when a run goes quiet for an hour I can only
report "Studio shows an active task" and cannot tell you whether it is progressing.

`ps`/`pgrep` served the same purpose; Studio's `activeTask` field covers most of it, so
that one I can live without.

### D3. An always-present field landed in a production struct
`ProposalKeeper` now carries `oracle_addresses: Vec<Ctx::Address>`, **not** cfg-gated —
private, empty when the oracle is off, excluded from equality and the public API, but
always present. Studio's instrumentation put it there. Benign, but it deserves a conscious
decision before this branch goes anywhere.

---

## E. Answered already — recorded so they are not re-asked

- Authors' Quint spec is **requirements input only**, not reconciled. Studio produces our
  model; `test/mbt` is inspiration only.
- All behavior cards reverted to `not_sure`; the acceptance checklist is each model's
  **properties and observations**, not the deck.
- One component through the oracle at a time.
- Build the 3f+1 baseline first, then make 5f+1 changes, then verify with Studio.
- `core-types-domain` is not critical; constrain it rather than perfect it.
