# Fast Tendermint (n > 5f)

Implementation plan for adapting Malachite to the two-step, `n > 5f` variant of Tendermint.

**Reference:** Preston Vander Vos, Daniel Cason, *"Fast Tendermint: Speeding Up a Foundational
Consensus Protocol"*, [arXiv:2608.13434](https://arxiv.org/abs/2608.13434) (13 Aug 2026).
The paper ships a Quint specification, which is directly relevant to us — see
[Stage 0](#stage-0--pin-the-specification) below.

Target branch: `zm_5f+1` (cut from `main` @ `72143f6c`).

> **Status: draft plan, not yet validated.** The protocol summary below was extracted from the
> arXiv HTML rendering, not from a line-by-line read of the PDF. Every pseudocode rule and
> threshold cited here must be re-checked against the paper before code is written. Stage 0
> exists for exactly that.

---

## 1. What the protocol changes

Classic Tendermint: `n > 3f`, three communication steps (propose → prevote → precommit), and two
pieces of carried-over round state, `lockedValue/lockedRound` and `validValue/validRound`.

Fast Tendermint: `n > 5f`, **two** communication steps in the good case, achieved by

1. **collapsing prevote and precommit into a single voting step**, and
2. **merging `locked` and `valid` into one `valid: (round, valueId)` pair**.

The good case is: proposer broadcasts a proposal → everyone votes once → a node decides as soon as
it has seen the proposal plus `n − f` votes for it.

Two thresholds now act on that *single* vote tally, in the *same* round:

| Threshold | Uniform-power form (`n = 5f+1`) | Fraction of total power | Role |
| --- | --- | --- | --- |
| `n − f` | `4f+1` | > 4/5 | **decide**; also advances the round on "any value" (slow path) |
| `2f+1` | `2f+1` | > 2/5 | **set `valid`**; justifies a re-proposal |
| `f+1` | `f+1` | > 1/5 | round skip (unchanged in role) |

Derivation of the fractions, for `n = 5f+1`: `4f+1 > (4/5)(5f+1) = 4f+0.8`; `2f+1 > (2/5)(5f+1) =
2f+0.4`; `f+1 > (1/5)(5f+1) = f+0.2`. All three map cleanly onto Malachite's existing
"strictly greater than numerator/denominator of total voting power" representation.

Sketch of the rules as extracted (to be confirmed in Stage 0):

- **Propose** — proposer sends `⟨PROPOSAL, round, v, validRound⟩`; `validRound = −1` for a fresh
  value, otherwise it re-proposes `valid.value` and carries `valid.round`.
- **Vote on a fresh proposal** — on `⟨PROPOSAL, r, v, −1⟩`, if `validate(v)` and
  (`valid.round = −1` or `valid.value = id(v)`), vote for `id(v)`.
- **Vote on a re-proposal** — accept `⟨PROPOSAL, r, v, vr⟩` when `2f+1` votes for `id(v)` were seen
  in round `vr` and `vr ≥ valid.round`.
- **Observe** — on `2f+1` votes for `id(v)` in the current round, set `valid ← (round, id(v))`.
- **Decide** — on the proposal for `v` plus `n − f` votes for `id(v)` in the same round, decide `v`.
- **Liveness timing** — the paper states `τ_Precommit > 2Δ` and `τ_Propose > 2Δ + τ_Precommit`.

Safety rests on: once `id(v)` has `n − f` votes in round `r`, no other value can reach `2f+1` votes
in any round `r' ≥ r` (the paper's Lemma 2). That is the `n > 5f` quorum-intersection argument, and
it is the single load-bearing claim the whole change depends on.

---

## 2. Compatibility: this is a fork, not a flag

The two protocols are **not** interoperable, at three separate levels:

- **Resilience** — a 3f+1 validator set is unsafe under the fast rules.
- **Wire** — the vote step count and the certificate quorum sizes both differ.
- **Certificates** — a commit certificate carrying `2f+1` power does not prove a fast-path decision,
  and one carrying `n − f` power is not what a classic node expects. Sync between the two is
  therefore unsound in both directions.

**Recommendation:** treat Fast Tendermint as a distinct protocol mode selected at genesis and
resolved at compile time or at node construction — not a runtime-togglable config value, and never
something that can differ between nodes in one validator set. Concretely: keep classic Tendermint
as the default path and gate the fast path behind a Cargo feature plus an explicit
`ConsensusProtocol` field on the params, with a hard startup check that the two agree.

---

## 3. Component-by-component impact

Studio has `round-state-machine`, `vote-keeper`, `consensus-orchestrator`, `wal` and `value-sync`
at `ready`, and `driver` in progress. The confirmed behaviors and properties on those components
are what this change has to renegotiate, so they double as the acceptance checklist.

### 3.1 `core-types` — thresholds and certificates

`code/crates/core-types/src/threshold.rs`

`ThresholdParams` today carries exactly **two** params:

```rust
pub struct ThresholdParams {
    pub quorum: ThresholdParam, // 2f+1, i.e. new(2, 3)
    pub honest: ThresholdParam, // f+1,  i.e. new(1, 3)
}
```

Fast Tendermint needs **three** distinct thresholds simultaneously. Add a third field (working name
`decision` / `n − f`), and provide a `ThresholdParams::fast()` constructor with
`decision = new(4,5)`, `quorum = new(2,5)`, `honest = new(1,5)`.

The good news: `threshold_params` is already plumbed as data — `Params<Ctx>` →
`core-consensus/src/state.rs:75` → `Driver::new` (`core-driver/src/driver.rs:87`) →
`VoteKeeper::new` (`driver.rs:90`, `driver.rs:146`). Nothing hardcodes 2/3 outside `threshold.rs`.
Every current call site passes `ThresholdParams::default()`, so introducing a second constructor is
additive.

Boundary conditions need the same treatment the existing `threshold_params_corner_cases` test gives
2/3: the 4/5 and 2/5 boundaries must be **not met** at exact equality. This is already flagged as an
unchecked bridge check in the interaction map — *"`ThresholdParam::is_met` … treats the exact 2/3
boundary as not met"* — and the fast variant makes it load-bearing twice over.

`code/crates/core-types/src/certificate.rs`

- `CommitCertificate` must be verified at `n − f`, not `quorum`.
- `PolkaCertificate` becomes the *re-proposal justification* certificate at `2f+1`. Its name stops
  matching its meaning; consider renaming to something step-neutral.
- `signing/src/ext.rs` has ~10 verification entry points taking `ThresholdParams`; each needs to say
  *which* threshold it verifies against, rather than defaulting to `quorum`.

`code/crates/core-types/src/vote.rs`

`VoteType` is `{ Prevote, Precommit }`. The cheapest sound option is to **keep the enum and use only
`Precommit`** on the fast path — the single voting step is semantically a precommit, this keeps the
codec and WAL entry shapes untouched, and a fast node that ever receives a `Prevote` can reject it
as malformed. Adding a third variant would ripple through every codec impl (proto, JSON, Borsh) for
no gain.

### 3.2 `core-votekeeper` — the structural change

This is the hardest part of the change, and it is **not** a parameter swap.

Today `threshold_to_output` (`keeper.rs:585-637`) maps one vote type in one round to **at most one**
`Threshold`, and `emit_at_most_once_per_round` guarantees each output fires once. Fast Tendermint
needs **two different thresholds over the same precommit tally in the same round** — a `2f+1`
"set `valid`" event *and* a later `n − f` "decide" event — and the `2f+1` event must not swallow the
`n − f` one.

Required changes:

- Extend `Threshold` (or `Output`) so `2f+1`-for-value and `n−f`-for-value are distinct outputs, e.g.
  `Output::VoteValue(v)` (at `2f+1`) and `Output::DecisionQuorum(v)` (at `n − f`), with `Any` also
  needing an `n − f` flavour for the slow-path round advance.
- Both must be independently latched, so crossing `2f+1` and later `n − f` in the same round yields
  two emissions. The existing per-round emitted-output set generalizes to this, but the
  `emit_at_most_once_per_round` property must be restated per (round, threshold) rather than per
  (round, vote type).
- `PolkaAny`/`PolkaNil`/`PolkaValue` become dead on the fast path.

Studio properties that need re-derivation, not just re-running: `polka_value_needs_quorum`,
`polka_any_reported_on_prevote_quorum`, `precommit_value_reported_on_quorum`,
`precommit_nil_distinguishable_from_split`, `emit_at_most_once_per_round`.

Properties that carry over unchanged: `tally_matches_voters`, `tally_never_overflows`,
`evidence_is_real_equivocation`, `evidence_bounded_per_validator`,
`skip_round_only_from_future_rounds`.

Also confirm the goal *"PrecommitValue outranks SkipRound in a future round"* still holds when there
are two value thresholds competing with `SkipRound`.

### 3.3 `core-state-machine` — collapse the steps

`code/crates/core-state-machine/src/{state,input,output,state_machine}.rs`

- `Step`: `Unstarted → Propose → Prevote → Precommit → Commit` becomes
  `Unstarted → Propose → Vote → Commit`. Everything keyed on `Step::Prevote` goes.
- `State`: replace the `locked` / `valid` pair of `Option<RoundValue<Ctx::Value>>` with a single
  `valid: Option<RoundValue<...>>`. Note the paper's `valid` holds `id(value)`, while Malachite's
  `RoundValue` holds the full `Value` — decide whether to store the id (paper-faithful, smaller) or
  the value (matches the existing proposal-keeper lookup path). Storing the id means re-proposal has
  to fetch the full value from the proposal keeper, which is where it already lives.
- `Input`: drop `PolkaAny`, `PolkaNil`, `ProposalAndPolkaCurrent`, `TimeoutPrevote`. Keep
  `ProposalAndPolkaPrevious` but rename to reflect a `2f+1`-vote justification. Add an input for
  "proposal + `n − f` votes" as the decide trigger (`ProposalAndPrecommitValue` may serve, but it is
  currently fed at `quorum`).
- `ScheduledTimeouts`: the `PREVOTE_BIT` retires; the bitset drops to two tracked kinds.
- `TimeoutKind::Prevote` becomes unused on the fast path — leave the variant in place for the
  classic path.
- The `pol_round` asserts in `prevote()` / `prevote_previous()` move to the merged vote rule. The
  interaction map already carries an unchecked bridge check that these asserts are unreachable given
  how `mux.rs` routes proposals; the merge is a chance to discharge it rather than re-inherit it.

Confirmed behaviors that survive as-is, and should be re-checked rather than rewritten:
*non-proposer never emits a proposal*; *decision output carries the decided proposal's round*;
*round never moves backwards*; *proposal round mismatch never panics*. Properties
`only_proposer_emits_proposal`, `decision_is_never_overwritten`, `commit_step_is_terminal`,
`round_never_moves_backwards`, `decision_output_round_matches_state` all carry over.

`timeout_scheduled_at_most_once_per_round` narrows to two kinds.

The confirmed goal *"locked node unlocks for an older polka"* is the one behavior whose **meaning**
changes: with `locked` and `valid` merged there is no separate unlock, and the intended behavior
becomes the `vr ≥ valid.round` re-proposal acceptance rule. Expect this card to be retracted and
replaced rather than re-confirmed.

### 3.4 `core-driver` — multiplexing

`code/crates/core-driver/src/mux.rs` — the helpers `has_polka_value`, `has_polka_nil`,
`has_polka_any`, `has_precommit_any`, `find_non_value_threshold` all encode the two-vote-type shape.
They collapse to a single-vote-type set with a *threshold* parameter:
`has_votes_for(round, value, threshold)`.

`apply_polka_certificate_votes` / `apply_commit_certificate_votes` must apply their votes against the
right threshold.

Note `driver` is currently at Studio stage `investigate` and not yet `ready` — its model is not
settled, so there is less confirmed contract here to preserve, and correspondingly less safety net.

### 3.5 `core-consensus` — orchestration

Mostly threshold-parameterization rather than restructuring:

- `handle/vote.rs` — one vote type to admit.
- `handle/decide.rs` — the decision quorum becomes `n − f`. The interaction map already flags that
  this path *"skips the local re-verification that the voting path performs"* on the sync branch;
  worth resolving here rather than porting forward.
- `handle/propose.rs` / `proposal.rs` — re-proposal now carries `valid.round`.
- `params.rs` — `HIDDEN_LOCK_ROUND` (the hidden-lock mitigation) is a classic-Tendermint construct.
  Whether the hidden-lock problem even exists under merged `valid` state needs an explicit answer;
  do not port the mitigation on faith.
- `MAX_FUTURE_ROUND_LOOKAHEAD` is unaffected.

### 3.6 Downstream: WAL, sync, codec

- **WAL** (`ready`) — entry format is per-vote; if the fast path only ever writes `Precommit`, replay
  is structurally unchanged. The *no-amnesia* property still requires the vote be durable before
  publication, and with one voting step there is one fewer append per round — a latency win worth
  measuring. Cross-protocol replay must be refused: a WAL written by a classic node must not be
  replayed by a fast node.
- **`value-sync`** (`ready`) — certificate verification threshold changes; the *safe catch-up*
  property is only preserved if the certificate quorum matches the protocol the certificate was
  produced under. Add the protocol identifier to what sync checks.
- **`message-codec`** (in progress, stage `wire`) — if `VoteType` is unchanged, codec changes are
  limited to certificate threshold semantics rather than encodings.

---

## 4. Staged plan

### Stage 0 — pin the specification

Read the paper's PDF properly and, crucially, **obtain the authors' Quint specification**. The paper
states it ships one and that they model-checked the protocol with it. Malachite already has
`quint-specs/round-state-machine.qnt` (786 lines) and `quint-specs/vote-keeper.qnt` (664 lines)
model-checked against this codebase, and the `test/mbt` crate replays Quint ITF traces against the
Rust code. If the paper's spec can be reconciled with ours, the MBT suite becomes the primary
correctness instrument for this whole change — which would be the single highest-leverage thing to
establish before writing any Rust.

Deliverable: a confirmed rule-by-rule transcription of the protocol, and a decision on whether we
adopt, adapt, or independently re-derive the Quint model.

*Contact the authors — Daniel is reachable internally, and the reconciliation question is much
cheaper to ask than to reverse-engineer.*

### Stage 1 — thresholds (no behavior change)

Add the third threshold to `ThresholdParams` and the `fast()` constructor; thread it through
`signing/src/ext.rs` verification entry points so each names its threshold explicitly. Extend the
corner-case tests to the 4/5 and 2/5 boundaries. Classic path behavior must be bit-identical after
this stage — it is a pure refactor and should be reviewable as one.

### Stage 2 — Quint model of the fast protocol

Write (or adapt) `quint-specs/fast-round-state-machine.qnt` and `quint-specs/fast-vote-keeper.qnt`.
Model-check agreement, the Lemma 2 intersection claim, and termination **before** touching Rust.
This ordering is the point of having Studio: a protocol change is where the model earns its cost.

### Stage 3 — vote keeper

The two-thresholds-on-one-tally restructure. Independently testable and the highest-risk unit; do it
before the state machine so the state machine has something correct to consume.

### Stage 4 — round state machine

Step collapse and `locked`/`valid` merge. Largest diff, but mechanical once Stages 2 and 3 are
settled.

### Stage 5 — driver and orchestrator

Multiplexer generalization, decide path at `n − f`, re-proposal carrying `valid.round`, and the
`HIDDEN_LOCK_ROUND` question answered explicitly.

### Stage 6 — end-to-end

Multi-node tests at `n = 6` (`f = 1`) via `test/framework`; byzantine injection via
`engine-byzantine` (equivocation, force-nil, amnesia) against the fast rules; crash/restart tests
for WAL replay. Measure the actual latency win — two steps instead of three is the entire
justification for a 5x-instead-of-3x replica cost, so the number matters.

### Stage 7 — Studio reconciliation

Re-sync the affected components so the models track the new code, and work the behavior deck for the
cards whose meaning changed (notably *"locked node unlocks for an older polka"*).

---

## 5. Open questions

1. **Is the 5x replica cost acceptable for the target deployment?** `n > 5f` means 6 validators to
   tolerate 1, and 11 to tolerate 2. This is a product question that should be answered before
   Stage 1, because it determines whether this is a research branch or a shipping path.
2. **Fallback under `f ≥ n/5`.** If the validator set degrades past the fast bound, does the system
   halt, or fall back to three-step operation? A dynamic fallback is a substantially harder protocol
   than either endpoint and should be explicitly out of scope for v1.
3. **`valid` as id or full value?** Paper-faithful vs. matching the existing proposal-keeper path.
4. **Does the hidden-lock problem survive the `locked`/`valid` merge?** Determines whether
   `HIDDEN_LOCK_ROUND` ports at all.
5. **Vote extensions** — unchanged in principle, but the extension is now attached to the only vote
   in the round rather than to the second of two. Confirm `VoteExtensionPolicy` still makes sense.
6. **Equivocation evidence** — with one vote type, a double-vote is a single shape rather than two.
   The `equivocation-detection` component's *no double count* property should get simpler, not
   harder; confirm that.

---

## 6. What this plan rests on, and what it does not

Grounded in the repository: all file paths, the `ThresholdParams` shape and its plumbing, the `Step`
and `Input` enums, the `mux.rs` helper set, `VoteType`, and the `quint-specs` inventory.

Grounded in Studio (models `ready` for `round-state-machine`, `vote-keeper`,
`consensus-orchestrator`, `wal`, `value-sync`; `driver` still `investigate`): the confirmed behavior
cards and property names cited as the acceptance checklist. Every bridge check in the interaction
map is currently `unchecked`, so none of the cross-component requirements quoted here has been
verified against the code — they are stated intent, not evidence.

**Not** grounded: the protocol rules themselves, which come from a single automated read of the
arXiv HTML. Stage 0 is a prerequisite, not a formality.
