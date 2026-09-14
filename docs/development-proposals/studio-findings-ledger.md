# Findings ledger — unexpected behavior by code version

Every unexpected behavior found while building the Quint Studio baseline and the
`n > 5f` variant, anchored to the code it was found against so it can be re-inspected
later. Append-only: entries are amended with decisions, never deleted.

**Maintenance rule.** Add an entry the moment something unexpected appears — a violated
property, a failing or `#[ignore]`d test, a doc-vs-code divergence, a Studio finding, a
compiler-caught design error. Record: the code anchor (commit, or `HEAD` at the time plus
the working-tree state), the component, the named property/observation/test, and how to get
back to it. Update `Status` when a verdict is recorded; do not rewrite the original
observation.

**Nothing in here has been decided.** No `set_finding` verdict has been recorded for any
Studio finding; that needs the owner. Statuses below are mine, not Studio's.

## Index — every bug, its source, and its fix

Sorted by severity. **Source** says who found it, which is the most interesting column:
no single check caught everything, and the two most severe bugs were found by the
independent reviewer, not by Studio or by the tests.

| ID | Bug | Source | Severity | Found against | Fixed in | Status |
| --- | --- | --- | --- | --- | --- | --- |
| F-24 | Decided value overwritten after a round change — **agreement violation** | Studio (property + generated test) | critical | `85d486e2` | `e600629e`, `99c8468c` | **fixed** |
| F-22a | A node could **vote twice in one round** (self-equivocation) | reviewer | critical | `99c8468c` | `7dbe76b6` | **fixed** |
| F-22b | `set_valid` used `<` where L29-L30 needs `≤`; node votes for values the paper forbids | reviewer | high (safety) | `99c8468c` | `7dbe76b6` | **fixed** |
| F-22c | L39 precommit timeout never armable for a later round | reviewer | high (liveness) | `99c8468c` | `7dbe76b6` | **fixed** |
| F-22d | `WaitForValid` unimplementable; every wait burned its full timeout | reviewer | medium (liveness) | `99c8468c` | `7dbe76b6` | **fixed** |
| F-25 | `State` invariants bypassable through public mutators | Studio (model read) | high | `85d486e2` | `99c8468c` | **fixed**, partially — fields still `pub` |
| F-26 | Three of four "property violations" were MODEL defects, not code | Studio (self-diagnosis) | — | `7dbe76b6` | four spec fixes **offered**, need the desktop | open |
| F-27a | My F-22d fix over-widened: a quorum for a FUTURE round set `valid` there, locking the node to nil votes | reviewer (round 2) | high | `51c77153` | next commit | **fixed** |
| F-27b | `Commit` not terminal — a decided node scheduled timeouts and emitted proposals | reviewer (round 2) | medium-high | `51c77153` | next commit | **fixed** |
| F-27c | Keeper: outputs lacked their round; `prune_votes` destroyed L27/L42 justification and reset latches; `Round::Nil` tallied; no params ordering check | reviewer (round 2) | medium | `51c77153` | `b245fa86` | **fixed** |
| F-28 | Pruning blinds equivocation detection for the pruned round — a late conflicting vote goes undetected | Studio (design worker, then triaged `data-loss-or-corruption`) | medium-high | `b245fa86` | `9dc95d3d` | **fixed** in the fast keeper; the classic keeper still has it |
| F-29a | My fault-budget check rejected `[2,3,2]` and every n<=3 set — would have **broken the classic path** | reviewer (round 3) | critical | `26553e1a` | next commit | **fixed** (now advisory) |
| F-29b | My doc comment's justifying example was false and its test never exercised it | reviewer (round 3) | medium | `26553e1a` | next commit | **fixed** |
| F-29c | Three uncross-checked copies of the same threshold fractions | reviewer (round 3) | medium | `26553e1a` | next commit | **fixed** |
| F-29d | `saturating_mul` reported a malformed set as an intolerance verdict | reviewer (round 3) | low | `26553e1a` | `073ed7e0` | **fixed** |
| F-30a | A public `protocol` field let the fast-protocol panic escape into a logging statement | reviewer (round 4) | medium | `bf6ac554` | next commit | **fixed** — third instance of "method guard on a public field" |
| F-30c | The Driver keeps its own threshold copy, outside the single source | reviewer (round 4) | low | `bf6ac554` | — | recorded; cannot diverge now |
| F-30d | No operator-facing protocol selection; `config` lacks the dependency and the serde feature | reviewer (round 4) | medium | `bf6ac554` | next commit | **fixed** |
| F-31 | The fast driver (L27 justification, L42 cross-round decide, L15-L16 resolution) | — | — | — | `1d51e828` | added; reviewed, **not yet modelled** |
| F-32a | An unbuildable re-proposal stalled the proposer — no proposal, no timeout, no wait | reviewer (round 5) | high | `1d51e828` | next commit | **fixed** (interim; needs the id-carrying proposal type) |
| F-32b | An unpairable decision quorum was lost forever, and my test pinned it as intended | reviewer (round 5) | high | `1d51e828` | next commit | **fixed** |
| F-32c | Proposals the application rejected were retained and could supply a decision | reviewer (round 5) | medium | `1d51e828` | next commit | **fixed** |
| F-32d | One `proposer` field answers for every input round | reviewer (round 5) | medium | `1d51e828` | next commit | **fixed** — proposer folded into `Input::NewRound` |
| F-33a | Oracle address→letter mapping aliases two validators onto `a` when the node is outside its own validator set | me (gate review) | low | `ac4916df` | — | **open** — instrumentation-only, unreachable in current tests |
| F-33b | Five decision-path observations were unreachable in the fast-driver validation battery | studio (fast-driver, instrumentation) | low | `ac4916df` | `ac4916df`+ | **fixed by Studio** — two search-guidance arms added |
| F-33c | `keeper_outputs_keep_their_reported_round` is a tautology — it compares a value with itself | me (ran the check the worker owed) | medium | `ac4916df` | — | **confirmed vacuous; must be dropped** |
| F-34a | Studio's two generated tests were vacuity-prone: every assertion negative | me (mutation check) | medium | `c796d359` | `c796d359` | **fixed** — controls added |
| F-34b | Equivocating vote untested at the driver boundary | studio (fast-driver, coverage) | medium | `ac4916df` | `c796d359` | **fixed** — test adopted |
| F-34c | Vote from a non-validator untested at the driver boundary | studio (fast-driver, coverage) | medium | `ac4916df` | `c796d359` | **fixed** — test adopted |
| F-34d | `get_component_insights` cannot return coverage: report indexes an observation outside an empty confirmed contract | studio (tooling) | low | `ac4916df` | — | **open** — Studio-side |
| F-35a | New public config field undocumented in `BREAKING_CHANGES.md`; semver CI likely to fail | reviewer (round 6) | medium | `59038473` | next commit | **fixed** |
| F-35b | Generated configs emit `protocol` but no reference config or doc mentions it | reviewer (round 6) | medium | `59038473` | next commit | **fixed** |
| F-35c | The `fast` refusal fired after the network listener and WAL were already open | reviewer (round 6) | low | `59038473` | next commit | **fixed** |
| F-35d | Nothing tested the refusal itself — the whole no-silent-downgrade guarantee was unguarded | reviewer (round 6) | low | `59038473` | next commit | **fixed** |
| F-20 | Propose timeout re-armed; suppression branch dead code | Studio (reachability) | medium | `85d486e2` | `e600629e` | **fixed** |
| F-22e | Vote keeper tallied **prevotes** toward `2f+1`/`n-f` | reviewer | medium | `99c8468c` | `7dbe76b6` | **fixed** |
| F-11 | Fast state machine draft never re-proposed | compiler | medium | draft | `e6e07b6f` | **fixed** |
| F-07 | Instrumentation could manufacture a preimage collision (`Nil` shared an index) | Studio gate review | medium | pre-landing | at the gate | **fixed** |
| F-09 | `driver` oracle exited 127 for the component's entire life — 0 tests ever | me (oracle run) | high (process) | pre-`ab36a137` | re-wire | **fixed** |

### Open — in Malachite's existing code, not the 5f+1 work

| ID | Bug | Source | Severity | Found against | Status |
| --- | --- | --- | --- | --- | --- |
| F-01 | Proposal evidence **unbounded** (vote evidence capped at 3) | Studio | high | `ab36a137` | open, undecided |
| F-02 | Cross-validator proposal `assert_eq!` aborts in **release** (not network-reachable) | Studio | medium | `ab36a137` | open, undecided |
| F-18 | `ValidatorSet::new`'s overflow check bypassable — public field | Studio | medium | `e237290b` | open, undecided |
| F-08 | The two `Height` impls disagree with each other and the docs | Studio | medium | `ab36a137` | open |
| F-14 | Four `#[ignore]`d WAL tests assert a contract the code lacks (no-amnesia) | pre-existing | medium | `b9c3f555` | open, pre-existing |
| F-04 | Arrival order decides which conflicting value is tallied | Studio | medium | `ab36a137` | open, undecided |
| F-05 | Evidence surfaces before finalize | Studio | low | `ab36a137` | open, undecided |
| F-06 | Four `signing` properties violated (one intentional) | Studio | unknown | `ab36a137` | open — `signing` still mid-refine |
| F-10 | Doc-vs-code divergences in `core-types` | Studio | low | `ab36a137` | open |
| F-15 | `ProposalKeeper` gained an always-present `oracle_addresses` field | instrumentation | low | `c3e28655` | open, needs a call |
| F-03 | Three `equivocation-detection` properties may hold **vacuously** | Studio | — | `ab36a137` | open — weak evidence, not a proof |

### Open — from the reviewer, on the 5f+1 code

| Item | Description | Severity |
| --- | --- | --- |
| F-22 open 1 | Every `State` field is `pub`, so F-25's guards are advisory | medium |
| F-22 open 2 | `WaitForValid` and the L39 timeout emit an identical `Timeout`; caller cannot tell which input to feed back | medium |
| F-22 open 3 | `ProposeValue` accepted while `valid` is `Some` — would send a fresh proposal where L14-L15 needs a re-proposal | question |
| F-22 open 4 | Nothing checks the validator set can support `f < n/5` | low |

### Process findings, not code defects

F-12 (a spec at 196/214 destroyed by my reset), F-13 (oracle runs look hung but are not),
F-16 (concurrent pipelines broke the build), F-17 (re-sync proved the classic machine
intact), F-19 (Studio's review queue swallowed a scope instruction), F-21 (Studio adopted
mutation testing unprompted), F-23 (accepting a finding offers test generation).

---

## Code anchors on `zm_5f+1`

| Commit | When | What it is |
| --- | --- | --- |
| `72143f6c` | — | `origin/main` tip, the v0.8.0 sync. Baseline. |
| `c3e28655` | 09-09 09:22 | Studio oracle instrumentation snapshot + in-flight fixes |
| `b9c3f555` | 09-09 09:25 | merge of `quint-studio-main` |
| `e6e07b6f` | 09-10 21:53 | **Fast Tendermint round state machine added** (`core-state-machine/src/fast/`) |
| `e237290b` | 09-10 23:47 | 22 behavior tests for the fast round machine |

---

## F-01 — Proposal evidence is unbounded (vote evidence is capped)

- **Anchor:** found against the tree at `ab36a137`; code path unchanged since `72143f6c`.
- **Component:** `equivocation-detection` (reached `ready`)
- **Violated property:** `evidence_per_validator_is_bounded`
- **Where:** `code/crates/core-votekeeper/src/evidence.rs` — the proposal-side
  `EvidenceMap::add` push is guarded only by `if !already_exists`, with no length bound.
  The vote side caps at `MAX_EVIDENCE_PER_VALIDATOR = 3`.
- **Behavior:** within one undecided height that keeps opening rounds, a single
  equivocating validator adds a fresh distinct pair every round, without limit. Memory
  growth driven by a Byzantine validator.
- **Evidence strength:** property violated in simulation; Studio suggested generating a
  test. The asymmetry with the vote side looks like an oversight, not a decision.
- **Status:** undecided. My recommendation: accept as a real bug.

## F-02 — Cross-validator proposal abort fires in release builds

- **Anchor:** tree at `ab36a137`; unchanged since `72143f6c`.
- **Components:** `equivocation-detection`, `driver`
- **Where:** `code/crates/core-driver/src/proposal_keeper.rs:112`
- **Behavior:** `assert_eq!`, **not** `debug_assert_eq!` — "BUG: Received proposals from
  different validators in the same round" — so it aborts the process in release too.
- **Reachability, resolved:** **not** reachable from the network.
  `verify_signed_proposal`'s proposer check protects that path; it is reachable only by
  calling `ProposalKeeper::store_proposal` or `Driver` directly. This answers the open
  question Studio's component map carried on that adversary row.
- **Related:** `driver`'s oracle test command now skips `driver_conflicting_proposal_panic`,
  the test that exercises it.
- **Status:** undecided. Recommendation: accept, low severity — internal-API hazard.

## F-03 — Three properties may hold vacuously, including the one that matters most

- **Anchor:** tree at `ab36a137`
- **Component:** `equivocation-detection`
- **Behavior:** three properties were never violated *even with guards off*, so they may
  hold by model construction rather than being genuinely exercised. One of them is
  **`equivocating_vote_is_absorbed_not_tallied`** — the "equivocation cannot manufacture a
  quorum" guarantee.
- **Evidence strength:** **weak. Not a proof.** Treat the guarantee as unverified.
- **Note:** three other properties flagged for vacuity at submit *were* violated in the
  final run, so their concern resolved.
- **Status:** open — needs a deliberate check that these are genuinely reachable.

## F-04 — Arrival order decides which conflicting value gets tallied

- **Anchor:** tree at `ab36a137`
- **Component:** `equivocation-detection`
- **Violated property:** `no_value_credited_by_arrival_order`
- **Status:** undecided.

## F-05 — Evidence surfaces before finalize

- **Anchor:** tree at `ab36a137`
- **Component:** `equivocation-detection`
- **Violated property:** `evidence_surfaces_only_at_finalize`
- **Status:** undecided.

## F-06 — Four `signing` properties violated; one is intentional

- **Anchor:** tree at `ab36a137`; `signing` still at `refine`, mid-flight
- **Component:** `signing`
- **Violated properties:** `accepted_certificate_meets_its_threshold`,
  `accepted_certificate_has_distinct_known_signers`,
  `verification_accepts_only_signed_preimages`, `consensus_preimages_are_network_scoped`
- **Assessment:** only the last is intentional — a documented domain-separation obligation
  (`code/crates/signing/src/lib.rs:60`) that the test provider does not carry. The other
  three are most likely artifacts of `refine` being mid-flight (88 open requests) rather
  than code bugs.
- **Why it matters:** `accepted_certificate_meets_its_threshold` is exactly the contract the
  5f+1 change rewrites (certificate quorum moves from `2f+1` to `n-f`). If it is real, it
  matters a great deal.
- **Status:** do not decide until `signing` finishes refine. Currently blocked on a Studio
  UI prompt (task 16).

## F-07 — Instrumentation projection could manufacture a preimage collision

- **Anchor:** caught at the `instrumentation_result` gate, before landing
- **Component:** `signing`
- **Behavior:** `NilOrVal::Nil` was mapped to the same index a first-seen concrete
  `ValueId` takes, which could mask or manufacture a preimage collision in the logged
  trace.
- **Resolution:** rejected at the gate; fixed by reserving `NIL_VALUE = -2`.
- **Status:** fixed. Recorded because it is a class of error worth watching for in other
  components' projections.

## F-08 — The two `Height` implementations disagree with each other and with the docs

- **Anchor:** tree at `ab36a137`
- **Component:** `core-types-domain`
- **Behavior:** the test crate's `Height::decrement_by` **saturates and returns `Some`**;
  `core-types`' own `TestHeight` returns **`None`**. The trait docs say `None`.
- **Consequence for modelling:** the worker deliberately declined to assert on the
  decrement result, because an assertion would fire as a false replay violation. The
  contract was left on an invariant instead.
- **Status:** open — a real inconsistency in shipped code, independent of 5f+1.

## F-09 — `driver`'s oracle never ran for the component's whole life

- **Anchor:** discovered at `ab36a137`; fixed by a `restart_component` at `wire`
- **Component:** `driver`
- **Behavior:** the recorded oracle test command began with bare `cargo`, which is not on
  PATH in the environment Studio spawns runs in. Every run exited **127** with **0 tests**.
  `specGaps: 0` therefore meant "never measured", not "healthy" — a reading I initially got
  wrong.
- **Resolution:** re-wire recorded the absolute path
  `/Users/zarkomilosevic/.cargo/bin/cargo` and widened the scope to include
  `-p arc-malachitebft-core-consensus`. Now **132 tests logged**, component `ready`.
- **Status:** fixed. Lesson: check `loggedTests` before trusting `specGaps: 0`.

## F-10 — Doc-vs-code divergences in `core-types`

- **Anchor:** tree at `ab36a137`
- **Component:** `core-types-domain` (design predicted these before the run)
- **Behaviors:** certificate constructors do not dedupe signers; `ValidatorSet::new` does
  not enforce its documented ordering and uniqueness; `Height::decrement_by` saturates
  (see F-08).
- **Status:** open. The component is now wedged (see F-12), so these are unmeasured.

## F-11 — Fast state machine draft never re-proposed (found by the compiler, not Studio)

- **Anchor:** introduced in the draft, fixed in **`e6e07b6f`**
- **Component:** the new `fast/` module (not yet a Studio component)
- **Behavior:** the re-proposal branch scheduled a timeout and emitted no proposal. Cause is
  structural: the fast state machine holds only a value **identifier**, so it cannot
  construct a `Proposal` (Algorithm 1 L15 — re-proposals carry `id(v)`).
- **Resolution:** added `Output::Repropose { value_id, valid_round }`; the caller resolves
  the identifier against the retained fresh proposal.
- **Status:** fixed. Recorded because it shows the class of error the paper's
  identifier-vs-value distinction creates, and because **Studio did not find it** — the
  compiler did.

## F-12 — `core-types-domain` pipeline wedged, and a spec with 196/214 matched was destroyed

- **Anchor:** tree at `ab36a137`
- **Component:** `core-types-domain`
- **What happened:** a `restart_component` at stage `generate` (my choice of stage) deleted
  `quint-specs/core-types-domain.qnt`, which had never been committed, so git cannot
  recover it. The worker reported it had reached **196/214 tests matched** with 16 failures
  left and had just fixed the last three classes when the reset landed.
- **Then:** three consecutive `request_review` calls timed out with no decision recorded,
  leaving three orphaned review requests. Every later `restart_component` returns
  `operator decline the elicitation`.
- **Status:** wedged; needs the owner in the Studio UI. Lesson: prefer the narrowest
  restart stage, and commit generated specs before resetting anything.

## F-13 — Oracle runs look hung but are not

- **Anchor:** observed 09-09 and 09-10
- **Behavior:** a full exhaustiveness run is ~97 minutes and the phase that dominates it
  (`confirmCap = 8` single-conjunct confirms) **prints nothing at all**. Measured: phase-1
  simulation 1,036,893 ms producing 10,660 behavior classes, then 514,013 ms for the
  all-soft guard run. Roughly 95% of CPU is in `serde_json` -> `fs::File`; about 4 samples
  in `simulate`. Cost is disk serialization of one ~35 KB ITF file per behavior class, not
  search.
- **Corrections to earlier claims of mine:** there is **no** serialised oracle slot
  (five daemons ran concurrently), and the runs I killed at ~50 minutes **were** working.
- **Worker count scales with free CPU** — `workers=1` under contention, 3-6 when idle — so
  running one component at a time buys parallelism on the dominant phase.
- **Side effect:** ~4.85 GB of trace directories leak into `$TMPDIR` when a run is killed.
- **Status:** understood, not a defect to fix here. Full analysis was written to a session
  scratchpad outside the repo and is not preserved.

## F-14 — WAL: four `#[ignore]`d tests assert behavior the code does not have

- **Anchor:** present at `b9c3f555`, arrived via the `quint-studio-main` merge
- **Component:** `wal`
- **Tests:** `code/crates/test/tests/unit/wal_append.rs`,
  `wal_replay.rs` (two), `wal_started_height.rs` — all `#[ignore]`d with
  "Ignored because it fails on current code".
- **Behavior asserted but absent:** an append the WAL does not write **must not be
  acknowledged as written**. Today a mismatched-height append is answered `Ok(())` and
  never written, so consensus is told its vote is durable and goes on to broadcast it.
- **Why it matters:** this is the **no-amnesia** bridge check in Studio's interaction map.
  `wal_actor.rs` (unignored) characterizes today's behavior; these four record the intended
  contract.
- **Status:** open, parked by whoever wrote them. Not introduced by this work.

## F-15 — Instrumentation added an always-present field to a production struct

- **Anchor:** `c3e28655` and later Studio edits
- **Component:** `equivocation-detection` / `driver`
- **Behavior:** `ProposalKeeper` carries `oracle_addresses: Vec<Ctx::Address>`, **not**
  cfg-gated — private, empty when the oracle is off, excluded from equality and the public
  API, but always present. A `pub(crate) evidence_counts()` accessor was also added.
- **Status:** open — benign, but deserves a conscious decision before this branch merges.

## F-16 — Concurrent pipelines on one worktree broke the build

- **Anchor:** during the 09-10 session, transient
- **Behavior:** `core-types-domain` and `signing` pipelines edited the same files
  (`signing/src/ext.rs`, `test/src/validator_set.rs`, `test/src/proposer_selector.rs`);
  `cargo check --tests` failed at one point with errors confined to
  `signing/src/ext.rs` and `wal/src/log.rs`, from an optional `quint-oracle` feature dep
  whose call sites were not `cfg`-gated. Later edits fixed it; the workspace is clean at
  `e237290b`.
- **Status:** resolved. Lesson recorded in the plan: never parallelise components whose
  paths or instrumentation overlap.

## F-17 — Re-sync confirms the fast module did not perturb the classic machine

- **Anchor:** `e237290b` (fast module + its 22 tests present)
- **Component:** `round-state-machine`
- **Action:** `restart_component` with no stage (re-sync), after `drift.code: true` appeared
  from adding `core-state-machine/src/fast/`.
- **Result:** drift cleared, component back to `ready`, snapshot current at revision 1,
  **89 tests replayed**, all 7 properties and 33 observations still confirmed,
  `specGaps: 0`, `modelIssues: 0`, `productBugs: 0`, no pending review.
- **What this is evidence of:** the fork-not-a-flag design holds — adding the fast state
  machine changed nothing observable about the classic one. This is measured, not asserted.
- **What it is NOT evidence of:** anything about the fast protocol. Studio did **not**
  propose modelling `fast/`, and by design cannot: a re-sync reconciles against the
  component's declared `paths` and `testCommand`, and the command is
  `-p arc-malachitebft-core-driver --test it`, which never runs
  `core-state-machine/tests/fast_round.rs`. My 22 tests produced zero traces.
- **Consequence:** verifying the fast protocol needs a **separate component** with its own
  spec of Algorithm 1, its own observations, and a test command covering `fast_round.rs`.
  That needs `survey_components` to pick up `fast/`.
- **Status:** understood. The verification gap below is unchanged.

## F-18 — `ValidatorSet::new`'s overflow check is not an invariant of the type

- **Anchor:** found by the `core-types-domain` worker at `e237290b`
- **Component:** `core-types-domain`
- **Where:** `code/crates/core-types/src/validator_set.rs` (test-crate impl)
- **Behavior:** the `validators` field is **public**, so `ValidatorSet::new`'s total-power
  overflow check can be bypassed entirely by constructing the struct directly. The existing
  test `invalid_commit_certificate_signed_voting_power_overflow` does exactly that with
  `[u64::MAX, 1]`, and the constructor never runs. Any caller doing the same gets no
  overflow protection; only the verifier's defensive `checked_add` catches it.
- **Why it matters:** the constructor reads like a validated entry point and is not one.
  It also forced a modelling concession — the invariant had to be scoped to sets actually
  built through `new`.
- **Status:** open, undecided. Worth a look independent of whether this component finishes
  wiring.

## F-19 — Studio's review queue is the wall-clock bottleneck, not the modelling

- **Anchor:** observed across 09-10/09-11
- **Behavior:** review requests time out without recording a decision, and duplicates queue
  up behind them. On `core-types-domain` the worker reported **six** timed-out
  `request_review` calls; the design review took four attempts. Separately, my own
  `advance_component` rejections were consumed by **orphaned queued copies** rather than
  reaching the live worker — three consecutive calls re-presented the same artifact with
  `addressed_feedback: []` and different artifact ids, so a scope instruction never landed.
- **Consequence:** a scope reduction the owner asked for could not be delivered, and the
  component proceeded at its original width (34 actions / 35 observations).
- **Not a code defect.** Recorded because it distorts any measurement of how much Studio
  speeds development up: the modelling, instrumentation and validation all ran fine.
- **Status:** worth reporting upstream.

## F-20 — **Studio's first finding on 5f+1 code**: dead suppression branch, and a latent double-schedule

- **Anchor:** `85d486e2` (fast state machine + vote keeper, 32 tests passing)
- **Component:** `fast-round-state-machine` (created by `survey_components` on 09-11)
- **Found by:** the validation battery's reachability check, which reported the observation
  `non_proposer_propose_timeout_suppressed` as **unreachable**. The worker deliberately
  kept it rather than deleting it, on the grounds that it is dead code in the Rust and
  belongs in an investigate verdict.
- **Where:** `code/crates/core-state-machine/src/fast/state_machine.rs`, `start_round`

```
323:    state.update_round(round);                       // calls scheduled_timeouts.clear()
328:    if state.check_timeout(TimeoutKind::Propose) {   // therefore always true
329:        ... schedule the propose timeout
330:    } else {                                         // UNREACHABLE
```

- **Confirmed behavior:** `update_round` clears the per-round timeout bits, and
  `check_timeout` is called immediately afterwards, so it can never return false. The
  suppression branch is dead.
- **The latent part, which is worse than the dead code.** `apply` accepts
  `Input::NewRound(r)` whenever `state.round <= r`, so **re-entering the same round is
  allowed**. Each re-entry clears the timeout bits and schedules the propose timeout
  again. The guard that exists to stop double-scheduling is defeated by the `clear()` that
  precedes it. Worth checking whether the classic machine shares this shape — it has the
  same `state.round <= round` guard and the same clearing `update_round`, and it carries a
  **confirmed** property `timeout_scheduled_at_most_once_per_round`.
- **Why this entry matters beyond the bug:** it is the first thing Studio has told us about
  the 5f+1 implementation that we did not already believe. My 22 hand-written tests did not
  catch it, which is exactly the blind spot predicted when tests and code share an author
  and a reading of the paper (see the verification-gaps section).
- **Status:** open, undecided. Two candidate fixes — drop the dead `else`, or stop clearing
  timeouts when re-entering a round already in progress. The second is only correct if
  re-entering the same round should be idempotent, which is a protocol question.

## F-21 — Studio applied the anti-vacuity lesson unprompted

- **Anchor:** `85d486e2`, at the `fast-round-state-machine` design gate
- **Not a defect** — recorded because it is evidence about the process.
- After I asked that properties be derived from the paper rather than the Rust, and noted
  that three `equivocation-detection` properties had held vacuously (F-03), the worker
  committed to **mutation testing**: every property carries "the single wrong write that
  falsifies it", each is checked against a deliberately mutated copy of the model before
  submission, and the design reports which ones actually failed.
- It also declined to state any property over `awaiting_valid`, reasoning that such a
  property "would test the representation, not the paper" — so the faithfulness of the
  `WaitForValid` representation is recorded as the change's open question rather than
  quietly assumed. That is the right call and it is the one part of the fast state machine
  with no counterpart in the paper's structure.

## F-22 — Independent reviewer: four definite bugs the model and the tests both missed

- **Found against:** `99c8468c` · **Fixed in:** `7dbe76b6` · **Source:** independent reviewer subagent
- **Found by:** an independent adversarial reviewer subagent, given the verbatim Algorithm 1
  transcription as ground truth and barred from reading the implementation's own tests as
  authority. None of these duplicate F-01..F-21.

### F-22a — A node could vote TWICE in one round (self-equivocation) — SEVERE
`fast/state_machine.rs`, the `NewRound` arm. It matched `(_, Input::NewRound(round)) if
state.round <= round`, so a `NewRound` for the round already in progress ran `start_round`
and reset the step from `Precommit` back to `Propose`. A second proposal then drew a
**second vote for the same round**. The classic machine guards this with
`(Step::Unstarted, Input::NewRound(round))`; the fast one had dropped the step guard.
Algorithm 1 only ever calls `StartRound(round+1)`, so same-round re-entry never occurs in
the protocol. **Fixed:** the `Unstarted` arm handles entry, and every other step requires
`state.round < round`. This is the severe half of F-20, which recorded only the timeout
symptom.

### F-22b — `set_valid` used `<` where L29-L30 uses `≤`, so a node voted for values the paper forbids
`fast/state.rs::set_valid` is monotone and no-ops at equality, but L29-L30 reads
`if valid_p.round ≤ vr then valid_p ← (vr, id(v))`. The `≤` is deliberate: when `n > 5f`,
two `2f+1` quorums need **not** intersect — `2(2f+1) - (5f+1) = 1-f ≤ 0` — so two different
values can each hold a quorum in the same round, and the rule replaces the *value* while
keeping the round. Because the code no-oped, `valid.value` went stale, and a later fresh
proposal for the stale value passed the L21 binding check that should have rejected it.
**Fixed:** the L27 arm writes `(vr, value_id)` directly when `valid_round() <= vr`;
`set_valid` keeps its strict `<` for the L36/L47 callers.

### F-22c — The L39 precommit timeout could never be armed for a later round — LIVENESS
The arm used the single per-round `check_timeout(Precommit)` bit, but L39 arms the timeout
for the **quorum's** round `r`, which may be above the round we are at. A `QuorumAny(0)`
consumed the only slot, so `QuorumAny(1)` returned invalid and round 1's timeout was never
armed — and the keeper had already latched its own quorum-any for that round, so it would
never re-emit. The node sits in round 1 with no timeout. **Fixed:** `State` now carries
`armed_precommit_rounds: BTreeSet<Round>` and latches per `r`, matching L39's "for the
first time with `r >= round_p`".

### F-22d — L47-L48 was unimplementable; every `WaitForValid` burned its full timeout
`Input::VoteQuorumForValue` was gated on `this_round`. A proposer inside `WaitForValid` is
at `round_p` waiting to learn `valid` from `round_p - 1` (L46), so the quorum that should
end the wait had no accepting arm and was dropped. **Fixed:** the input now carries the
round — `VoteQuorumForValue(Round, ValueId)` — and is accepted for any round above
`valid_p.round`, which covers L36 and L47 together.

### F-22e — The vote keeper tallied prevotes
`fast/keeper.rs::apply_vote` accepted any `SignedVote`. This protocol has one voting step;
a prevote is not part of it. A prevote for `v` landed in the same weight bucket as a
precommit for `v` and counted toward `2f+1`/`n-f`, and a validator's prevote followed by a
precommit was misrecorded as equivocation. **Fixed:** non-precommit votes are discarded.

### Still open from the same review
- **Every `State` field is `pub`**, so the `with_step` / `set_decision` guards added in
  `99c8468c` are advisory — a caller can write `s.decision = None` directly. Same class as
  F-18. The tests themselves write fields directly, so closing this needs a test refactor.
- **`WaitForValid` and the L39 timeout emit the identical `Timeout{round, Precommit}`**, so
  a caller cannot tell which input to feed back — the conflation `input.rs` claims to
  avoid. Needs its own `TimeoutKind` or tag.
- **`ProposeValue` is accepted while `valid` is `Some`**, which would broadcast a fresh
  proposal where L14-L15 requires a re-proposal. Reviewer marked this a QUESTION, since it
  may be unreachable in the intended orchestrator.
- **Nothing checks the validator set can support the protocol.** `FastVoteKeeper::new`
  accepts a set where one validator holds 50% of the power, for which `f < n/5` is
  impossible.

### Confirmed correct by the same review
The threshold arithmetic. `is_met` is strict (`weight * denom > total * num`), so equality
is not met; `> 4n/5` equals `n - f` for every `n` with `f = floor((n-1)/5)`, checked for
n = 5..12, so `decision` is right on non-`5f+1` sets too. One undocumented consequence:
`quorum` at `> 2n/5` is **stricter** than `2f+1` when `n != 5f+1` (n=10, f=1 needs 5, not
3) — conservative and therefore safe, but a liveness cost nobody had written down.

## F-23 — Studio offers test generation on an accepted finding

Recording a `set_finding` verdict of `accepted` makes Studio start generating a regression
test for it. Both verdicts recorded so far returned "decision recorded, but test generation
could not start: another workflow already owns component 'fast-round-state-machine'" —
a re-sync was in flight. Sequence finding decisions and pipeline work so the generated
tests actually land.

## F-24 — A decided value could be overwritten after a round change — AGREEMENT VIOLATION

- **Found against:** `85d486e2` · **Fixed in:** `e600629e` and `99c8468c` · **Source:** Studio
  (property `decision_is_final_and_commit_is_terminal`, with a generated reproducing test)
- **Severity:** the most serious class of bug this protocol can have. Two different values
  decided at one height.
- **Component:** `fast-round-state-machine`
- **Reproduced by:** Studio's generated test
  `a_decision_is_never_replaced_after_a_new_round`, which failed with
  "a second decision must not be accepted" (exit 101):

```
decide value 7 in round 4   -> step = Commit, decision = Some(7)
apply NewRound(5)           -> step = Propose, decision SURVIVES
second decision quorum      -> guard was `step != Commit`, so it PASSED
                            -> the finalized value was overwritten with 5
```

- **Root cause:** the decide arm guarded on the STEP rather than on the decision, and
  `NewRound` resets the step while carrying the decision forward.
- **Fix, two layers:** `e600629e` changed the guard to `state.decision.is_none()` — a
  decision is a latch, not a step, and the paper treats `decision_p` as write-once (L56
  reads it as one). `99c8468c` then made the invariant structural, so a caller cannot
  bypass it either (see F-25).
- **Missed by:** my 22 hand-written tests. `commit_is_terminal` only applied an input while
  the step was already `Commit`; it never tried `NewRound` first.
- **Verdict recorded:** `accepted` via `set_finding`.

## F-25 — `State`'s safety invariants were enforced only by `apply`, not by the type

- **Found against:** `85d486e2` · **Fixed in:** `99c8468c` · **Source:** reading Studio's
  model (`commitMutator` path), after four property violations survived the F-24 fix
- **Component:** `fast-round-state-machine`
- **How it surfaced:** replay of all 21 test traces was clean, yet four properties still
  failed in simulation. The model has two commit paths — `commitResult` for `apply`, and
  `commitMutator` for the raw public mutators, which it includes as actions precisely
  because they are `pub`. The model described `set_decision` as an "unguarded overwrite",
  which was accurate.
- **Behavior:** a caller holding a `State` could overwrite a finalized decision or step
  back out of `Commit` without going through `apply` at all.
- **Fix:** `set_decision` is write-once; `with_step` refuses to leave `Commit`.
- **Same class as:** F-18 (`ValidatorSet::new`'s overflow check bypassable because the
  field is public). A rule enforced only by a constructor or transition function, while the
  public API can bypass it, enforces nothing.
- **Incompletely fixed — see F-22 open items:** every `State` field is still `pub`, so
  these guards remain advisory. Closing that needs a test refactor.

## F-26 — Three of the four "property violations" were MODEL defects, not code defects

- **Found against:** `7dbe76b6` (after all five review fixes) · **Source:** Studio's own
  post-test refinement · **Status:** four spec fixes OFFERED, awaiting the desktop flow
- **This corrects an earlier claim of mine.** I reported four property violations on
  `fast-round-state-machine` as if all four indicted the code. After the re-sync, Studio
  itself judged three of them to be mis-specified properties. The component now reports
  `findingCount: 0`, `productBugs: 0`, 25 tests logged, `specGaps: 0`.

| Property | Studio's verdict | Was the code wrong? |
| --- | --- | --- |
| `decision_is_final_and_commit_is_terminal` | model is **stale** — spec still guards on `step != Commit`, code now guards on `decision.is_none()` | **Yes, originally** — see F-24. Fixed in `e600629e`; the spec has not caught up |
| `round_timeout_armed_at_most_once_per_round` | `staleTimeoutBits` conjunct mis-specified | **Yes, separately** — see F-20/F-22a. The conjunct is *also* wrong |
| `repropose_only_carries_a_value_we_hold` | latch compares against `pre.valid`, not the post-state | **No** |
| `valid_p_never_decreases` | second conjunct unsound under the model's own shape | **No** |

### Why the two non-defects were false alarms

**`repropose_only_carries_a_value_we_hold`.** `reproposeBroken(pre, r)` judges an
`ORepropose` output against the valid pair held *before* the transition. But the
L36-L37 → L15-L16 path raises `valid` and re-proposes the just-raised pair in **one**
step: `VoteQuorumForValue` sets valid, then `propose_now` reads it. The re-proposal does
name a pair the state holds — one raised within the same transition. Already pinned by the
passing test `vote_quorum_while_waiting_makes_the_proposer_repropose`.

**`valid_p_never_decreases`.** The property is
`not(validDecreased) and validRound(state) == maxValidRound`. The first conjunct is the
genuine monotonicity claim and it holds. The second compares against a running maximum over
the **whole run**, but the model's main action takes a nondeterministically chosen `pre` —
`apply` is a pure function and callers hand it states they built themselves, which is why
the instrumentation logs the pre-state whole. So a step can legitimately begin from an
unrelated state whose valid round is below a maximum reached earlier. Already pinned by the
passing test `vote_quorum_never_lowers_valid`.

### What Studio offered

Two concrete fix options per request, each with a cost estimate and what it enables — for
example, judging the re-proposal against `r.st.valid` instead of `pre.valid`, or comparing
`staleTimeoutBits` against `pre.scheduled` so only bits that *survived* a round change are
flagged. Studio also noted for each that **no new test could fail**, because the correct
behaviour is already pinned by a passing test, so generating one would only duplicate it.

### Why this is not applied yet

The operator MCP has no call that accepts a post-test refinement, and the Studio skill is
explicit that model repair after setup is a desktop flow. `advance_component` returns
`ready` and declines it. The four spec fixes are waiting in the Studio desktop.

**Nothing is blocked on this.** These are model repairs; the code is correct in all four
cases and its 27 tests pass. Until they are applied, the component will keep reporting
these four properties as violated, and that report should be read as stale.

### The lesson for the exercise

A property violation is a claim that the model and the code disagree — it does not say
which is wrong. Three of four here indicted the model. That is not a failure of the method:
Studio diagnosed its own specs precisely, cited the exact line and counterexample seed for
each, and said plainly "not a code defect" rather than leaving me to assume the code was at
fault. But it does mean a raw violation count is a bad metric, and I should not have
reported one as though it were a bug count.

## F-27 — Second review round: I introduced a bug fixing the first one

- **Found against:** `51c77153` · **Fixed in:** the commit that follows it · **Source:**
  independent reviewer, second round (resumed with round-one context)
- The reviewer re-read the five fixes from F-22 and cleared three of them explicitly, so
  the confirmations are as informative as the defects.

### F-27a — DEFINITE/High. My own fix over-widened `VoteQuorumForValue`
Fixing F-22d I removed the `this_round` gate entirely, leaving no relation between the
quorum's round and ours. But L36 sets `valid_p` from `round_p`, and L47 runs inside
`WaitForValid` whose loop condition `valid_p.round < round_p - 1` bounds `r` **below**
`round_p`. Neither line lets `valid_p.round` exceed `round_p` — the paper's core
restriction, that the observation rule captures valid values *before* a process moves up.

With the gate gone, `VoteQuorumForValue(round 9, v)` at round 0 sets `valid = (9, v)`. The
node then votes **nil in every round up to 9** (L21 fails, and L28's `valid_round() <= vr`
is impossible), and re-proposes with `vr > round_p`, which every receiver rejects as
malformed. A self-inflicted lock.

**Reachable, not hypothetical:** `FastVoteKeeper::apply_vote` emits its quorum output for
any round, and the keeper's own test `future_round_votes_never_produce_a_skip` asserts a
round-9 quorum is reported to a node at round 0. **The keeper manufactures the input that
breaks the state machine.** **Fixed:** the arm now guards `quorum_round <= state.round`.

### F-27b — DEFINITE/Medium-High. `Commit` was not terminal: a decided node emitted proposals
Two paths, both pre-existing rather than introduced, and neither covered by F-24/F-25 which
concern the decided *value*:
1. The decide arm never cleared `awaiting_valid`, so a proposer that decided mid-wait still
   had it set; a later vote quorum drove `propose_now` and emitted `Repropose` **from a
   committed state**.
2. `(_, Input::NewRound(round)) if state.round < round` matched in `Commit`. `with_step`
   correctly refused to leave Commit, but `update_round` still advanced the round and
   `start_round` ran to completion — scheduling timeouts and emitting proposals after
   deciding. L56 makes `decision_p = nil` the *reason* StartRound is not called.

**Fixed:** the decide arm clears `awaiting_valid`, and both `NewRound` arms require
`state.decision.is_none()`.

### F-27c — Vote keeper hardening (all LIKELY, all fixed)
- **Outputs now carry their round.** After F-27a the round is safety-load-bearing, yet the
  consumer had to re-derive it from the vote it passed in. Making a caller reconstruct
  safety-relevant data is how a check gets skipped.
- **`prune_votes` destroyed the cross-round justification.** `has_vote_quorum` and
  `has_decision_quorum` read the live tally, which pruning deleted — but L27 verifies a
  re-proposal against `2f+1` from an *earlier* round and L42's decision quorum may come
  from a different round than the proposal. In classic Tendermint pruning below the current
  round is safe; here it is not. **Fixed:** a `reached` record, separate from the tallies,
  that pruning does not touch.
- **A pruned round could re-report.** `entry(round).or_default()` recreated empty latches,
  so replayed votes fired the thresholds again. The same `reached` record fixes it.
- **`Round::Nil` was tallied.** Algorithm 1 defines no vote at an undefined round.
- **No ordering check on `FastThresholdParams`.** Swapped params would silently invert L36
  and L42. Now a `debug_assert`.

### Confirmed correct by the same review
- **Fix 2 (the `≤` write) is sound.** The direct write bypassing `set_valid`'s monotonicity
  guard is reached only when `valid_round() <= vr`, and `vr` is already proven
  `is_defined() && vr < state.round`, so the round component stays monotone and only the
  value is replaced — exactly L29-L30.
- **The keeper's two-thresholds-on-one-tally logic is correct.** `&&` short-circuits so
  nothing latches prematurely; `decision` implies `quorum`, so a decision output can never
  precede its vote-quorum output; two disjoint `2f+1` quorums in one round are both
  reported, and the state machine correctly ignores the second because L36 requires
  `round_p > valid_p.round` — the asymmetry with L29-L30's `≤` is deliberate on both sides.
- Fixes 1, 3 and 5 faithful as written.

### Open item 1 escalated
`armed_precommit_rounds` was a new **public mutable** field whose emptiness is an L39
safety latch, and unlike `scheduled_timeouts` it was not excluded from equality — so two
otherwise-identical states compared unequal. **The equality inconsistency is fixed**; the
underlying issue stands: with `step`, `valid` and `decision` private, F-27a and F-27b would
both have been unreachable by construction. That is now the highest-leverage open item.

## F-28 — Pruning blinds equivocation detection for the pruned round

- **Found against:** `b245fa86` · **Source:** Studio's `fast-vote-keeper` design worker,
  which surfaced it as a consequence of modelling `prune_votes` exactly and then judged it
  **a real defect, pre-existing** · **Status:** open, not fixed
- **Component:** `fast-vote-keeper`, and by inspection the classic `vote-keeper` too
- **Behavior:** `prune_votes(min_round)` drops `per_round`, which holds `votes_by_address`
  — the record of the FIRST vote each validator cast in that round. Equivocation is
  detected by comparing a new vote against that first vote. After pruning, a replayed vote
  for a pruned round is re-tallied as a first vote, so the memory it would have conflicted
  with is gone.
- **Consequence:** a validator that voted A in a round can, once that round is pruned, vote
  B for the same round and **not be detected as equivocating**. Votes for old rounds do
  arrive late in practice — through sync, WAL replay, or a catching-up peer.
- **Why it matters beyond this component:** accountability evidence is per-HEIGHT, and
  `EvidenceMap` is deliberately never pruned precisely because evidence must survive the
  round it came from. A round being behind us is not a reason to stop detecting a double
  vote in it.
- **I introduced the occasion, not the defect.** My F-27c fix kept the reached-threshold
  record alive across pruning so L27 and L42 keep their justifications; it did not keep the
  first-vote record, and I did not notice that gap until the model was designed against it.
  The classic keeper prunes the same way, so the defect predates this work.
- **Candidate fix:** retain `votes_by_address` (or a compact digest of it) across pruning,
  the way the `reached` record and the evidence map already are. Cost is one map per height
  rather than per round, bounded by the validator set.
### Fixed, and Studio's own generated test proves it

Studio triaged this as **`data-loss-or-corruption`** with `suggestedAction: fix-first` —
explicitly *"rather than generate-test, because a test written against today's behavior
would pin the defect"* — and generated
`equivocation_across_a_prune_is_still_recorded_as_evidence` against the DESIRED behaviour,
marked `#[ignore]` with "fails on current code".

**Fix:** `first_votes` moved out of `PerRound` into its own map that `prune_votes` does not
touch, the same shape already used for `reached`. Only the weight tallies are pruned now,
which is what actually grows with traffic. The generated test then passed and its
`#[ignore]` was removed: 15 keeper tests pass.

Studio's triage also ruled out the alternatives before concluding, which is why I trusted
it: reachability 638/3000 in simulation (so not an over-constrained predicate),
instrumentation present at the tally site (so not a missing log call), and the wired test
command covering the only target that exercises this keeper (so not a scope gap).

Its severity argument, which I agree with: accountability evidence is per HEIGHT, so a
double vote in round 3 is equally provable whether the node is now in round 3 or round 9;
and it is **remotely triggerable by exactly the adversary it targets** — an equivocator
need only delay its second vote until the victim has moved on, which ordinary gossip and
sync delivery make easy. Blast radius is bounded: `reached` survives pruning so a rebuilt
round cannot re-report a threshold, and the exposure is to accountability rather than
agreement — no double decision follows.

### Still open in the CLASSIC keeper

`code/crates/core-votekeeper/src/keeper.rs` prunes the same way and has the same blindness.
Not fixed here: it changes shipped Malachite behaviour and its component carries confirmed
models, so it is a judgement for the maintainers rather than part of the 5f+1 work. The fix
is the same shape and the evidence above transfers directly.

## F-29 — Third review: my fault-budget check would have broken the classic path

- **Found against:** `26553e1a` · **Fixed in:** the commit after `aa7d2ad3` · **Source:**
  independent reviewer, third round
- The reviewer was asked to check the new `ConsensusProtocol` selection type. It found a
  critical defect, a false claim in my own documentation, and three design problems — and
  verified the parts that were right against the code rather than against my description.

### F-29a — CRITICAL. The check rejected the validator sets Malachite actually runs
`tolerates_at_least_one_fault` (then named `check_validator_set`) accepted a set only when
`largest * d < total`. For classic that rejects any set where one validator holds a third
or more, which is **every set of three or fewer**, and the reviewer counted the usages:

| Set | Uses in this repo | Classic verdict |
| --- | --- | --- |
| `[2, 3, 2]` | **62** | rejected |
| `[1, 1, 1]` | 13 | rejected |
| `[1, 2, 3]` | 9 | rejected |
| `[25, 25, 25, 25]` | 16 | accepted |

`[2, 3, 2]` is the most-used validator set in the repository. Threading this in as the
"hard startup check" the plan calls for would have **broken the classic path**, directly
against the coexistence constraint that nothing is removed from it.

The arithmetic was right; the question was wrong. `largest < total/d` asks *"does this set
tolerate at least one fault?"*, not *"does it satisfy the protocol's assumption?"* —
`[2, 3, 2]` satisfies classic's assumption at `f = 0`, and a three-node network with a 2/3
quorum is safe and shipped. **Fixed:** renamed to `tolerates_at_least_one_fault`, documented
as ADVISORY with an explicit "do not use as a startup gate for Classic", and pinned by a
test asserting those small sets fail the check and are still legitimate.

### F-29b — My doc comment's justifying example was false, and untested
It claimed `[5, 3, 1, 1]` is "fine for classic and hopeless for fast". Total 10, largest 5:
classic gives `5 x 3 = 15 >= 10`, so it is rejected for **both**. The test using that exact
set checked only the Fast arm, so the claim was never executed. **Fixed:** the example is
now `[3, 3, 3, 1]`, which genuinely behaves as described, and a test asserts both arms.

### F-29c — Three copies of the same fractions, none cross-checked
`ThresholdParam::TWO_F_PLUS_ONE`/`F_PLUS_ONE`, `FastThresholdParams::N_MINUS_F`/
`TWO_F_PLUS_ONE`, and now `ConsensusProtocol::{quorum,decision,honest}` — with nothing
keeping them in sync. **Fixed:** both `Default` impls now derive from `ConsensusProtocol`,
and a test fails if the constants and the protocol drift apart.

### F-29d — `saturating_mul` hid a malformed set inside an intolerance verdict
The reviewer confirmed my worry was **unfounded in the safe direction** — saturation clamps
to `u64::MAX`, which is `>=` any total, so an overflowing product always rejects. But it
reported a malformed set as `SingleValidatorExceedsFaultBudget`. **Fixed:** `checked_mul`
with a distinct `PowerOverflow` variant.

### Verified correct against the code, not my claim
`Classic.decision() == Classic.quorum() == 2/3` — confirmed at
`core-votekeeper/src/keeper.rs:687` and `signing/src/ext.rs:757/1137/1207`, which use
`thresholds.quorum` for certificate verification. `Fast.honest() == None` is right, and
`ext.rs:1208` (`RoundCertificateType::Skip => &thresholds.honest`) is the single site that
consumes it — exactly the skip machinery the fast protocol removes. The `>=` boundary is
correct because `f < n/d` is strict.

### Still open, recorded rather than fixed
- **`Option` is the wrong shape for threading.** Adding `protocol` *beside*
  `threshold_params` creates two sources of truth that can disagree —
  `protocol: Fast` with `threshold_params: 2/3` would compile and run a fast node on
  classic quorums. Replacing it forces `.expect()` into `Driver::new`. The reviewer's
  suggestion: make `protocol` the only source and have the classic driver derive its
  params internally. Documented on `classic_threshold_params` for now.
- **Network-wide agreement is still unenforced.** Nothing carries the protocol into
  genesis, the handshake or certificate verification, so a fast node and a classic node on
  one network would disagree silently at the first quorum. The enum is a prerequisite for
  that check, not the check. Now stated in its own doc comment so it cannot be misread as
  closing the item.
- `NoFaultTolerance` has no `Display`/`Error` impl; `ConsensusProtocol` has no
  `Display`/`FromStr`, so config parsing depends on the optional `serde` feature.

## F-30 — Fourth review: the construction-time guarantee was only a convention

- **Found against:** `bf6ac554` · **Fixed in:** the commit that follows · **Source:**
  independent reviewer, fourth round
- I threaded `ConsensusProtocol` into `Params` taking the reviewer's own recommended shape
  — protocol as the single stored source, thresholds derived — and claimed the fast case
  could only fail at startup. It could not.

### F-30a — DEFINITE. The panic escaped construction, into a logging statement
`State.params` is `pub` and `Params.protocol` was `pub`, so
`state.params.protocol = ConsensusProtocol::Fast` after `State::new` is legal safe Rust.
The next `threshold_params()` then aborts **inside a handler** — `decide.rs:51`,
`finalize.rs:37`, `sync.rs:164`, `liveness.rs:64` and `:190` — or, worst, at
`state.rs:348`, which is the `info!` block logging "Voting power required". In the
reviewer's words: *"A consensus node that aborts while logging is the worst version of this
failure."*

**This is the third round running of the same pattern**: a guard living in a method while
the field stays public. F-25 was `State`'s mutators, F-22-open-1 was `State`'s fields, and
this is `Params`. The lesson is now explicit: **a method guard on a public field is a
comment, not an invariant.**

**Fixed** by making the guarantee structural rather than conventional: `protocol` is
private and `Params::classic` is the only constructor, so the classic consensus path cannot
hold a protocol it does not implement — at construction or afterwards. `threshold_params()`
is consequently **total**, with no `expect` at all, rather than fallible-but-unreachable.
A `Params::fast` constructor belongs there when a fast driver exists.

### F-30b — `Default::default()` at construction sites was weaker than I realised
I had worried it would survive a change to `ConsensusProtocol`'s `Default`. The reviewer
pointed out something sharper: `Default::default()` is **type-inferred**, so it survives a
change to the FIELD'S TYPE as well. Moot now — the constructor takes the remaining fields
explicitly and there is no protocol argument to get wrong.

### F-30c — The Driver keeps its own threshold copy
`core-driver/src/driver.rs:38`, set at `:96` and reused in `move_to_height` at `:146`. It is
derived once and correct today, but it is the one place the single-source claim does not
reach. With F-30a fixed it can no longer diverge, since nothing can change the protocol
after construction. Recorded rather than changed.

### F-30d — Nothing operator-facing can select a protocol, and two concrete obstacles
`app/src/spawn.rs` hardcodes classic and never consults `cfg`, though every other field in
that struct is derived from it. Before a TOML field can exist: **`crates/config` has no
`malachitebft-core-types` dependency at all**, and the workspace entry does not enable its
`serde` feature, so `ConsensusProtocol`'s feature-gated `serde` derive is unavailable to
`Config`. Both must be added first. Noted at the call site rather than half-wired.

### Q2 came back clean
The reviewer checked every path rather than repeating my grep: all seven `threshold_params()`
reads go through `Params`, the five `verify_*_certificate` helpers take it as a parameter
from exactly those callers, and no `Deref`, re-export or macro reaches thresholds another
way. No non-test `src` file constructs `ThresholdParams` or uses the raw constants.

## F-31 — The fast driver exists

- **Added in:** the same commit · **Not yet reviewed or modelled**
- `core-driver/src/fast/` — the multiplexing neither the state machine nor the keeper can
  do alone. Three of the paper's rules need something in between:
  - **L27**: a re-proposal is offered only once the keeper confirms `2f+1` votes exist
    *from the round the proposal names*. Without it the state machine would be asked to
    trust a justification nobody verified.
  - **L42**: the decision pairs a fresh proposal from one round with `n - f` votes from
    another, so the driver retains fresh proposals for the whole height and pairs a quorum
    with a proposal it may have seen rounds earlier. A quorum with no retained proposal
    decides nothing rather than inventing a value.
  - **L15-L16**: the state machine re-proposes an identifier; the driver resolves it back
    to the value the original fresh proposal carried.
- `FreshProposals` is keyed by identifier, not round, and is cleared per height rather than
  pruned per round — a proposal from an early round stays relevant all height, because L42
  lets the deciding quorum arrive in any later one.
- 6 tests. **Next: independent review, then Studio**, per the working loop.

## F-32 — Fifth review: the fast driver, including a test that pinned a bug as intended

- **Found against:** `1d51e828` · **Fixed in:** the commit that follows · **Source:**
  independent reviewer, fifth round

### F-32a — DEFINITE/High. A re-proposal is dropped exactly when it matters
`resolve` returned `None` when no fresh proposal was retained for the identifier, which
`apply_round` turned into an empty output. The state machine had **already transitioned** —
`propose_now` cleared `awaiting_valid` — so the node sat in `Propose` as proposer with no
proposal, **no propose timeout** (the proposer path schedules none) and no `WaitForValid`.
It stalled until some other node's `QuorumAny` happened to arm a precommit timeout.

The insight I had missed: this is the **ordinary** case, not an edge case. `state.valid` is
set from `Input::VoteQuorumForValue`, and **votes carry only `id(v)`**; it is also set from
the L27 re-proposal arm, whose proposal `FreshProposals::keep` deliberately ignores. So a
lagging or recovering node routinely holds `valid = (vr, id)` with no value behind it, and
becoming proposer produced nothing at all.

**Root cause is a divergence from the paper.** L15-L16 broadcasts the *identifier*; a
correct proposer never needs the value. This driver reconstructs a full-value proposal,
which both changes the wire format and creates the hole. Closing it properly needs the
value-or-id proposal type the plan already calls for (Stage 0 finding 5). **Interim fix:**
schedule the propose timeout instead of emitting nothing, so the round ends, everyone votes
nil, and the height progresses. Documented at the site as a known divergence.

### F-32b — DEFINITE/High. An unpairable decision quorum was lost forever
I suspected this and asked; the reviewer confirmed it. The `continue` was not a deferral but
a drop: the keeper latches `decision_quorum` per `(round, value)` and **never re-emits**,
and `apply_proposal` never re-checked. L42 is a symmetric `upon` — both conjuncts persist
and whichever arrives second fires it — but the code only evaluated it on the vote edge.
Votes-before-value is the normal ordering for a lagging node, since votes are small and
sync delivers certificates ahead of payloads.

**Fixed:** `apply_proposal` now re-evaluates L42 after retaining. That needed a keeper query
that did not exist — `has_decision_quorum` requires a round, and a caller holding a proposal
has none — so `decision_quorum_round(value_id) -> Option<Round>` was added.

**And my test pinned the bug as intended behaviour.** `a_quorum_without_its_proposal_decides_nothing`
asserted only the first half of the rule. It is now
`a_quorum_that_arrives_before_its_proposal_still_decides`, which asserts both. A test that
enshrines a defect is worse than no test, and this one was written by the same hand that
wrote the defect.

### F-32c — DEFINITE/Medium. Proposals the application rejected were retained
`keep` ran before the validity branch, so an invalid proposal could later supply the value
for a decision. My comment justified it with "even a proposal we vote nil on may supply the
value" — which conflates two different nil votes: nil because L21's binding clause forbids
the value (**keep**), and nil because `validate(v)` failed (**must not keep**). The classic
driver already gates on this. Malachite lets applications define validity and does not
guarantee determinism, so this is the safety-relevant direction. **Fixed.**

### F-32d — LIKELY/Medium. One `proposer` field answers for every input round
`Info` is built with `self.proposer` for all inputs, but that field means "proposer of the
round being entered", and nothing enforces that `set_proposer` is called before each
`NewRound`. Since F-27a, `VoteQuorumForValue` legitimately accepts quorums for rounds
*below* the current one, so a stale proposer makes `Repropose` emittable for a round we do
not propose. The reviewer checked the other half and cleared it: **no path inside the state
machine emits `Repropose` without `is_proposer()`**, so the exposure is entirely the
driver's bookkeeping. **Open** — the fix is to derive the proposer per input round.

### Cleared by the same review
- The round cannot move between the state machine deciding to re-propose and the driver
  resolving it: `resolve` runs immediately after the state is stored, and none of the three
  `Repropose` paths change the round.
- The `mem::replace` dummy state is never observable — `apply` is total, with no panic or
  unwrap on any arm, and nothing between the replace and the restore can return early.
- Batch ordering L36 → L42 → L39 is right, and no earlier output misapplies a later one.
  One cosmetic consequence: after a decision, the batch still emits a precommit
  `ScheduleTimeout`. Harmless, since the timeout arm requires `decision.is_none()`.

### And the pattern did NOT recur
I asked the reviewer to call out loudly any fourth instance of "a method guard on a public
field". There is none here: every `Driver` field and `FreshProposals::by_id` is private, and
the only mutating entry points are `process` and `set_proposer`. **The first of the four
modules where the encapsulation is right by construction rather than by convention.**

### Still open from this round
`FreshProposals` growth is bounded only by distinct values proposed in a height, and `keep`
runs before any proposer check, so any peer reaching the driver can grow it — the same class
as F-01, and it deserves the same verdict.

---

## Open verification gaps (not findings, but worth tracking)

- **The fast round state machine now has an independent model** (`fast-round-state-machine`,
  created 09-11), whose properties are derived from Algorithm 1 rather than from the Rust.
  It has already produced F-20, a defect the 22 hand-written tests missed. The model is not
  yet through its first oracle run.
- **The fast vote keeper is still verified only by its own 10 tests.** Its component
  (`fast-vote-keeper`) exists but has not been set up.
- **The fast module is not under the oracle.** `round-state-machine`'s test command is
  `-p arc-malachitebft-core-driver --test it`, which does not run
  `core-state-machine/tests/fast_round.rs`. Widening it is the concrete step to get the
  fast module measured.
- **Every bridge check in the interaction map is `unchecked`** — the cross-component
  requirements are stated intent, not evidence.
- **`round-state-machine`, `vote-keeper`, `consensus-orchestrator` slipped from `ready`
  back to `oracle`** during the 09-10 session. Cause unknown.

### F-33a — DEFINITE/Low. The oracle's letter mapping can alias two validators

Studio's `fast-driver` instrumentation names validators by letter for the model,
reserving `a` for the node itself. The fallback arm

```rust
(Some(i), None) => LETTERS.get(i).copied().unwrap_or("z"),
```

runs when the node's own address is *not* in the validator set. In that case the
validator at index 0 is also lettered `a`, colliding with the node's own letter
from the early return above it. Two distinct addresses then look like one
validator to the model, which would make a vote from validator 0 indistinguishable
from a self-vote.

Unreachable today: `fast_driver.rs` builds six validators and passes `me =
addrs[0]`, so the node is always in its own set and the `(Some(i), None)` arm is
dead. The correct fix is to letter from `b` in that arm, or to treat a node
outside its own validator set as `z` like any other non-validator.

Instrumentation-only — the whole block sits behind `quint_oracle::enabled()` and
cannot affect production behaviour. Recorded rather than fixed to keep
Studio-managed instrumentation Studio-owned; it belongs in the next `wire`
restart.

### F-33b — Studio's own battery caught five unreachable observations

The `fast-driver` validation battery reported five observations on the decision
path that no sampled run reached: `decision_fired_on_the_proposal_edge`,
`decision_fired_on_the_vote_edge`, `decision_quorum_waited_for_its_proposal`,
`repropose_resolved_to_a_full_proposal`, and `l42_skipped_because_already_decided`.

The worker attributed this to the search failing to assemble a four-fifths quorum
plus a matching proposal by chance, not to the observations being unsatisfiable,
and fixed it by adding two search-guidance arms. Recorded because an unreachable
observation is exactly the shape of a vacuous check — the same anti-vacuity
discipline as [F-26] — and because the fix was Studio's, not mine.

### F-33c — A property was submitted with its falsifiability check outstanding

The instrumentation report states, verbatim: "The promised property
mutation-check could not run before submission — `run_quint_check` is refused at
the modeling stage. I will run it now that the check tools are available and
report the results."

The property at issue is `keeper_outputs_keep_their_reported_round`, which the
worker itself pre-committed to drop: "if the mutation check shows it cannot fail
independently of the L27 property, I will drop it rather than submit a vacuous
invariant and say so."

Approved the `instrumentation_result` gate anyway — the gate reviews the
repository edit, which is additive, builds clean, and leaves the 8 driver tests
passing; property falsifiability is a separate claim that the worker can still
settle. Open until the worker reports the mutation result. If it does not, I run
the check myself before this component is called ready.

### F-32d — analysis refined, and the fix is narrower than the finding assumed

Traced every `is_proposer()` site in the fast state machine before designing a fix,
because "derive the proposer per input round" implied a per-round proposer map and
that turns out to be the wrong shape.

| Site | Guard | Exposed to a stale `proposer`? |
| --- | --- | --- |
| `state_machine.rs:257` (L36 re-propose) | `this_round && is_proposer() && !awaiting_valid` | **No** — `this_round` already pins it |
| `state_machine.rs:386` (L47 re-propose) | `this_round && awaiting_valid && is_proposer()` | **No** — same |
| `state_machine.rs:335` (L36 while waiting) | `awaiting_valid && is_proposer()` | **Indirectly** — see below |
| `state_machine.rs:409` (`start_round`, L6-L18) | `if !is_proposer()` early return | **Yes — this is the whole exposure** |

`awaiting_valid` is only ever set inside `start_round` *after* its `is_proposer()`
early return (`state_machine.rs:422`, `state.rs:210`), so a node holding
`awaiting_valid` was necessarily the proposer of the round it entered. Site 335
therefore inherits its correctness from site 409 rather than needing its own guard,
and the two `this_round` sites were already closed by F-27a.

So the finding reduces to one question: **can a round be entered without naming its
proposer?** Today yes — `set_proposer` and `Input::NewRound(round)` are separate
calls and nothing orders them. A node that proposed round `r-1` and does not propose
`r` takes the proposer path in `r`; the mirror case silently misses its own proposal
slot and the round times out.

**The fix is to delete the ordering requirement, not to tolerate it.** The classic
driver already has the answer — `Input::NewRound(Ctx::Height, Round, Ctx::Address)`
(`core-driver/src/input.rs:15`) carries the proposer *with* the round, so the
question cannot be asked. The fast driver becomes `NewRound(Round, Ctx::Address)`
and `set_proposer` goes away. Cheap: `set_proposer` has **no production caller**,
only 5 sites in `tests/fast_driver.rs`.

**Held, not applied.** Studio's `fast-driver` coverage run is in flight against this
exact file, and its just-approved instrumentation models `Driverset_proposer` as an
independent action. Applying the fix mid-run would drift the component under its own
measurement. The sequence is: let the run finish, apply the fix, re-review, then
`restart_component` (no stage) to re-sync the drift — which keeps the spec and the
approved observations.

Worth noting for the exercise: Studio modelled `set_proposer` as a free-standing
action reachable in any state, which is a faithful model of the API and is exactly
the freedom the defect lives in. The model was right; the API was wrong.

## F-34 — The fast-driver component reached `ready`, and its tests needed a control

- **Found against:** `ac4916df` · **Fixed in:** `c796d359` · **Source:** Studio coverage run
  plus my own mutation check

Studio's `fast-driver` run completed: `ready`, `wired`, 8 logged tests, **0 product bugs**,
3 findings. One (`guard_scenario` on `FreshProposalskeep`) Studio triaged itself as
`out-of-scope`, and its reasoning holds — the guard is reachable only from inside
`Driver::apply_proposal`, so an event for it would nest inside `Driverprocess` where the
model has no place for it, and the same two conditions are already observed on the
instrumented path.

### F-34b, F-34c — two genuine driver-level gaps, and Studio wrote the tests
`equivocating_vote_not_tallied` (182 of 3000 samples) and
`vote_from_a_non_validator_discarded` (123 of 3000). Both were untested because every
other test in the file votes each validator at most once, with addresses drawn only from
the set it built. Studio generated a test for each, marked `#[ignore]`. Both passed, so
both are adopted.

I had independently written the same two tests before noticing Studio's. Mine were
dropped: Studio's carry `reproduces obs:...` traceability back to the observation.

### F-34a — but the generated tests could not fail
Every assertion in both generated tests is negative — "no decision was produced". They
therefore hold on a driver that can **never decide at all**, which is the exact vacuity
shape [F-26] and [F-33b] are about.

**Proved rather than asserted.** Replacing the `RoundOutput::Decision` arm of `resolve`
with a discard:

| Test | On the mutant |
| --- | --- |
| Studio's two, as generated | **pass** — vacuous |
| The same two, with a control added | **fail** — falsifiable |

Each now ends by asserting that a legitimate fifth vote still decides. This is the second
time Studio produced a correct-but-unfalsifiable artifact ([F-33b] was the first, and
Studio caught that one itself). The pattern is worth stating plainly: **Studio is reliable
at finding which sequences are unreached, and less reliable at making the resulting test
able to fail.** Mutation-checking every generated test before adopting it is the cheap
countermeasure.

### F-34d — the coverage insight cannot be read
`get_component_insights` with `sections: ["coverage"]` fails with `invalid report: sampled
family references observation index 1 outside the confirmed contract`. The component
reached `ready` with `observationsConfirmed: false` and `confirmedObservations: []`, yet
its report indexes observations positionally. `evidence` and `status` read fine, so the
findings above were recoverable. Studio-side; recorded, not actionable from here.

## F-32d — fixed

`Input::NewRound(Round)` became `Input::NewRound(Round, Ctx::Address)` and `set_proposer`
is gone. The ordering hazard is not guarded against, it is unrepresentable: there is no
longer a way to enter a round without naming its proposer. `set_proposer` had no production
caller, so the change cost 7 test call sites.

`the_proposer_of_the_previous_round_does_not_answer_for_the_next` pins it: a node that
proposes round 0 and then enters round 1 under a different proposer must take neither
proposer path, and must schedule the L18 propose timeout instead.

**One hazard I introduced and caught while doing it.** My first pass rewrote every bare
`Input::NewRound(Round::new(n))` in the tests to pass `a[0]`. But `driver_with(false)`
builds a driver whose round-0 proposer is `a[1]`, so that silently made *us* the proposer
in every test that had deliberately arranged not to be. It failed to compile for an
unrelated reason, which is the only reason I looked. The redo substitutes per test,
reading each one's `driver_with` argument. A mechanical rewrite across tests is exactly
where a semantic change hides behind a passing suite.

### F-33c — resolved: the property cannot fail, and the reason is worse than suspected

Studio's worker submitted `keeper_outputs_keep_their_reported_round` with its
falsifiability check outstanding, pre-committing to "drop it rather than submit a
vacuous invariant" if the check showed it could not fail independently of the L27
property. The worker never reported back; the component reached `ready` with the
property still in the list. I ran the check.

It is worse than the worker's own hypothesis. The property is not merely entangled
with another — it is a **tautology**, and no mutation of the Rust could ever falsify
it, because it never observes the Rust at all.

`keeper_outputs_keep_their_reported_round` is `not(keeperRoundDrifted)`. That ghost has
exactly one producer, `quint-specs/fast-driver.qnt:622`, fed by one definition at
line 610:

```
val drifted = r.round != roundOfKOut(o)
```

`r` is `routeKOut(acc.d, o)`, and `routeKOut` sets `round` by projecting the same field
of the same `o` that `roundOfKOut` projects:

| Keeper output | `routeKOut(...).round` (line 582-599) | `roundOfKOut(o)` (line 572-577) |
| --- | --- | --- |
| `KVoteQuorum(q)` | `q.round` | `q.round` |
| `KQuorumAny(r)` | `r` | `r` |
| `KDecisionQuorum(q)` | `q.round` (both branches) | `q.round` |

So `drifted` is identically `false` in every reachable state, `"keeper_round_drifted"`
never enters `bad`, the latch is never set, and the invariant holds by construction.
It compares the spec against itself.

**The property must be dropped**, exactly as the worker pre-committed. It is carried
into the re-sync below rather than edited in place, since the spec is Studio-managed.

**The lesson is about where to look.** A mutation check on the *Rust* would have
reported "property never fails" and invited the conclusion that the code is simply
correct. Reading the spec showed the property was structurally incapable of failing.
For a model-level invariant, the falsifiability question has to be asked of the model,
not of the implementation — which is the same lesson as [F-34a], one level up: there
the generated *test* could not fail; here the generated *property* cannot.

## F-35 — Sixth review: the operator-facing protocol selection (F-30d)

- **Found against:** `59038473` · **Fixed in:** the commit that follows · **Source:**
  independent reviewer, sixth round

The reviewer verified by *running* things rather than reading them — workspace check,
config tests, real testnet generation, a live node start with `protocol = "fast"`, and the
classic `n3f0` suite. Four findings, all real, all fixed.

### F-35a — DEFINITE/Medium. No breaking-change entry, and CI would likely have caught it
`BREAKING_CHANGES.md`'s `## Unreleased` section was empty. The 0.8.0 section documents a
structurally identical change (a `#[serde(default)]` field added to `P2pConfig`), so the
project treats this shape as a documented break. `ConsensusConfig` has all-public fields
and no `#[non_exhaustive]`, so any downstream exhaustive struct literal breaks.

The CI half the reviewer flagged as LIKELY: `semver.yml` checks `arc-malachitebft-app`,
and `app/src/config.rs` is `pub use malachitebft_config::*;`. Rustdoc inlines cross-crate
glob re-exports, so `ConsensusConfig` appears in app's rustdoc JSON, which is what
`constructible_struct_adds_field` keys on. **Entries added for both crates.**

### F-35b — DEFINITE/Medium. The option existed but was invisible
`crates/test/app/config.toml` is the reference config — not decorative, it is
`include_str!`'d and parsed by a test. It gained no `protocol` entry, while generated
configs *did* start emitting `protocol = "classic"`. An operator would find a key in their
generated config documented nowhere, with nothing saying that `"fast"` refuses to boot.
Against the coexistence constraint, "which value keeps my existing behaviour" is precisely
what has to be written down. **Documented, with the env override and the not-yet-runnable
warning.**

### F-35c — DEFINITE/Low. The refusal came too late to prevent side effects
With `protocol = "fast"` the node logged `Starting network service`, then `Opened WAL`, and
only then errored: the check sat in `spawn_consensus_actor`, by which point the builder had
already spawned the network, WAL, host and node actors. Harmless for the CLI, an actor leak
plus a stray WAL file for a library embedder.

**Fixed by hoisting the decision into `check_consensus_protocol`,** called at the top of
`Builder::build` before `spawn_node_actor` — and still called inside
`spawn_consensus_actor` for embedders that bypass the builder. A value knowable from the
TOML alone should never open a file descriptor.

### F-35d — DEFINITE/Low. The guarantee rested on an unguarded match arm
The entire "no silent downgrade" argument was one `match` arm with no test. The three tests
I had written covered *parsing* only. Hoisting the check made it testable without an actor
system: `the_fast_protocol_is_refused_rather_than_downgraded` and
`the_default_protocol_is_accepted` now pin both directions.

### The reviewer cleared four areas, and disproved one worry
- **Backward compatibility:** no `deny_unknown_fields` anywhere; both `ConsensusConfig`
  literal sites already use `..Default::default()`; the checked-in reference config still
  parses; `MALACHITE__CONSENSUS__PROTOCOL` works with no plumbing.
- **TOML field order** — the thing I was most worried about, since a bare key after a table
  header belongs to that table. Checked against real generated output, not reasoned about:
  `toml` emits scalars before sub-tables regardless, so first position is the *safe*
  position. Not a problem.
- **Feature unification:** `core-types` is `no_std` but its optional serde is declared
  `default-features = false`, so enabling it cannot drag in std; every `cfg(feature =
  "serde")` site is a bare derive. And `crates/test` already enabled the same feature, so
  unification was happening across most of the workspace already.
- **Test vacuity:** the reviewer actively tried to break my "rejects unknown protocol" test
  and could not — the document shape is held constant and only the enum value varies, so
  `is_err()` can only come from variant rejection. One fair correction, though: the first
  test's docstring claimed it reproduces "the shape of every configuration file written
  before the field existed", which **overstates it** — it round-trips the *current* struct
  minus one line. The real historical-file guard is `parse_default_config_file`.

### And a design note that is not a defect yet
`protocol` is a per-node field for a property that is network-wide and genesis-fixed, with
no cross-validation. Unreachable while `fast` refuses to boot — but the moment the fast
driver is wired into the consensus actor, the refusal disappears and this becomes the live
failure mode. **A TODO now sits on `check_consensus_protocol`**, the function that must be
changed to wire it up, so the two cannot be separated.

## `FreshProposals` growth — resolved: the same class as classic, and the same dependency

Left open since F-32 ("bounded only by distinct values proposed in a height, and `keep`
runs before any proposer check, so any peer reaching the driver can grow it"). Checked it
against the classic path before fixing anything, and the conclusion is that there is
nothing to fix in the driver.

**Proposer validation is not the driver's job in either protocol.** The classic driver's
`apply_proposal` (`core-driver/src/driver.rs:890-908`) checks the *height* and nothing
else; membership is checked upstream, in the consensus actor, at
`core-consensus/src/handle/proposal.rs:191` (`validator_set.get_by_address(...)`). The
fast driver sits at the same layer and inherits the same contract.

**The stores are the same order of growth**, not different ones:

| | Keyed by | Cleared | Bounded by |
| --- | --- | --- | --- |
| classic `ProposalKeeper` | `BTreeMap<Round, PerRound>` | per height | rounds × proposals per round |
| fast `FreshProposals` | identifier | per height | distinct values in the height |

So adding a proposer check inside the fast driver would not close a hole the classic path
leaves open; it would diverge from the architecture for no gain, and after F-32d the fast
driver only knows the *current* round's proposer anyway, so it could not evaluate a
proposal naming an earlier round.

**What this really is: a dependency, not a defect.** Both stores are bounded only because
something upstream rejects non-members first. For classic that something exists. For fast
it does not yet — nothing wires the fast driver into the consensus actor, which is the
same gap that makes `consensus.protocol = "fast"` refuse to boot. **Recorded against the
same TODO on `check_consensus_protocol`**, which is the function that has to change to
wire it up: whatever does that must route fast proposals through the membership check the
classic path already uses, and must not hand the driver raw gossip.

Downgraded from an open finding to a documented precondition. [F-01] stays open on its own
merits — that one is a genuine unbounded *evidence* store on the classic path, with no
upstream gate behind it.

