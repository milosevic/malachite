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

---

## Open verification gaps (not findings, but worth tracking)

- **The fast round state machine is verified by nothing but its own tests.** 22 pass at
  `e237290b`, but they share an author and a reading of Algorithm 1 with the code. They
  guard against regression, not against a shared misreading. No Quint model of the fast
  protocol exists.
- **The fast module is not under the oracle.** `round-state-machine`'s test command is
  `-p arc-malachitebft-core-driver --test it`, which does not run
  `core-state-machine/tests/fast_round.rs`. Widening it is the concrete step to get the
  fast module measured.
- **Every bridge check in the interaction map is `unchecked`** — the cross-component
  requirements are stated intent, not evidence.
- **`round-state-machine`, `vote-keeper`, `consensus-orchestrator` slipped from `ready`
  back to `oracle`** during the 09-10 session. Cause unknown.
