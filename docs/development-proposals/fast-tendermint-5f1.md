# Fast Tendermint (n > 5f)

Implementation plan for adapting Malachite to the two-step, `n > 5f` variant of Tendermint.

**Reference:** Preston Vander Vos, Daniel Cason, *"Fast Tendermint: Speeding Up a Foundational
Consensus Protocol"*, [arXiv:2608.13434](https://arxiv.org/abs/2608.13434) (13 Aug 2026).

**Method decision (Zarko, 2026-09-10).** The authors publish a Quint specification at
`github.com/circlefin/formal-tendermint/tree/master/fast-tendermint`. We do **not** adopt or
reconcile it. It serves as *requirements and specification input only* — a second opinion on what
the protocol must do. The model we build against our code is produced by **Quint Studio**, and
Studio also drives test generation. Malachite's existing `test/mbt` ITF-replay machinery is
**inspiration only**; it is not the instrument for this work.

Target branch: `zm_5f+1` (based on `zm_studio_v0.8.0` + `quint-studio-main`, containing v0.8.0).

---

## Stage 0 — pin the specification — **DONE**

Algorithm 1 transcribed from the paper. State: `round_p`, `step_p ∈ {propose, precommit}`,
`decision_p`, and `valid_p := (round, id(value))` initialised to `(-1, nil)`.

```
 6: function StartRound(round)
 7:   round_p ← round
 8:   step_p ← propose
 9:   if proposer(round_p) = p then
10:      if round_p > 0 then
11:         WaitForValid(timeoutPrecommit(round_p))
12:      if valid_p.value = nil then
13:         proposal ← getValue()          ⊳ Fresh proposals carry a full value v
14:      else
15:         proposal ← valid_p.value       ⊳ Re-proposals carry a value identifier id(v)
16:      broadcast ⟨PROPOSAL, round_p, proposal, valid_p.round⟩
17:   else
18:      schedule OnTimeoutPropose(round_p) after timeoutPropose(round_p)

20: upon ⟨PROPOSAL, round_p, v, -1⟩ from proposer(round_p) while step_p = propose do
21:   if validate(v) ∧ (valid_p.round = -1 ∨ valid_p.value = id(v)) then
22:      broadcast ⟨PRECOMMIT, round_p, id(v)⟩
23:   else
24:      broadcast ⟨PRECOMMIT, round_p, nil⟩
25:   step_p ← precommit

27: upon ⟨PROPOSAL, round_p, id(v), vr⟩ from proposer(round_p) with 0≤vr<round_p
        AND 2f+1 ⟨PRECOMMIT, vr, id(v)⟩ while step_p = propose do
28:   if valid_p.round ≤ vr ∨ valid_p.value = id(v) then
29:      if valid_p.round ≤ vr then
30:         valid_p ← (vr, id(v))
31:      broadcast ⟨PRECOMMIT, round_p, id(v)⟩
32:   else
33:      broadcast ⟨PRECOMMIT, round_p, nil⟩
34:   step_p ← precommit

36: upon 2f+1 ⟨PRECOMMIT, round_p, id(v)⟩ with round_p > valid_p.round do
37:   valid_p ← (round_p, id(v))

39: upon n-f ⟨PRECOMMIT, r, *⟩ for the first time with r ≥ round_p do
40:   schedule OnTimeoutPrecommit(r) after timeoutPrecommit(r)

42: upon ⟨PROPOSAL, r, v, -1⟩ from proposer(r) AND n-f ⟨PRECOMMIT, r', id(v)⟩ do
43:   decision_p ← v

45: function WaitForValid(timeout)   ⊳ Run by the proposer of rounds > 0
46:   while (valid_p.round < round_p-1) ∧ !timeout.elapsed() do
47:      if 2f+1 ⟨PRECOMMIT, r, id(v)⟩ with r > valid_p.round then
48:         valid_p ← (r, id(v))

50: function OnTimeoutPropose(round)
51:   if round = round_p ∧ step_p = propose then
52:      broadcast ⟨PRECOMMIT, round_p, nil⟩
53:      step_p ← precommit

55: function OnTimeoutPrecommit(round)
56:   if round ≥ round_p ∧ decision_p = nil then
57:      StartRound(round+1)
```

### Five findings that change the plan

**1. There are only TWO thresholds, and `f+1` disappears entirely.**

| Threshold | Uniform form (`n=5f+1`) | Fraction of total power | Used at |
| --- | --- | --- | --- |
| `n − f` | `4f+1` | > 4/5 | L39 arm precommit timeout (round advance); L42 decide |
| `2f+1` | `2f+1` | > 2/5 | L27 justify re-proposal; L36 set `valid`; L47 in WaitForValid |

Derivation for `n = 5f+1`: `4f+1 > (4/5)(5f+1) = 4f+0.8`; `2f+1 > (2/5)(5f+1) = 2f+0.4`.

Tendermint's `f+1` "one correct process in a higher round" rule is **removed**, deliberately. The
paper: *"for the sake of safety, the observation rule needs to capture valid values before a process
moves to a higher round. For this reason, the quorum any rule, with an n−f quorum, is the only
allowed path to skip rounds."* A lagging process catches up only via L39.

**2. `SkipRound` is deleted, not reparameterised.** This is a behavioral removal in Malachite, not a
threshold tweak: `VoteKeeper::Output::SkipRound`, the `honest` threshold param, `Input::SkipRound`,
and the `EnterRoundCertificate` / `RoundCertificateType` machinery all lose their fast-path role.
Round advance becomes purely "n−f precommits for any value at `r ≥ round_p` → arm
`OnTimeoutPrecommit(r)`".

**3. `WaitForValid` is a genuinely new mechanism with no Malachite analogue.** The proposer of any
round > 0 waits — bounded by `timeoutPrecommit` — until it has learned a `valid_p` from round
`round_p - 1`, *before* it decides whether to propose fresh or re-propose. Malachite has nothing
like this: today `StartRound` immediately emits `GetValueAndScheduleTimeout` or re-proposes from
`valid`. This reorders the propose path and is new work, not a modification.

**4. The decision rule's two rounds can differ.** L42 wants a *fresh* proposal (`validRound = -1`)
from round `r` **plus** `n−f` precommits from round `r'`, and `r ≠ r'` is allowed. Malachite's
`Input::ProposalAndPrecommitValue` couples proposal and precommits within one round. Two
consequences: the fresh proposal is what establishes `validate(v)` (a re-proposal carries only
`id(v)` and cannot be decided on alone), so the *original* fresh proposal must be retained across
rounds; and the commit certificate is a cross-round object.

**5. Re-proposals carry only `id(v)`, fresh proposals carry the full value.** Explicit in the L13/L15
comments. Malachite's `Proposal` always carries `Ctx::Value`, so the proposal type (and its codec)
gains a value-or-id distinction. This also settles an earlier open question: `valid_p` holds the
**id**, not the value — the full value is recovered from the retained fresh proposal.

Two earlier guesses now confirmed: `step_p ∈ {propose, precommit}` means the surviving vote step is
literally named *precommit*, so reusing `VoteType::Precommit` and never emitting `Prevote` is
faithful rather than merely convenient; and `τ_Precommit > 2Δ`, `τ_Propose > 2Δ + τ_Precommit`.

Not obtained: the paper does not name the invariants it model-checked, nor the configuration
(process count, rounds) it checked at. Since we are deriving our own model in Studio, this does not
block us.

---

## 1. Compatibility: this is a fork, not a flag

Not interoperable with classic Tendermint at three levels — resilience (a 3f+1 set is unsafe under
the fast rules), wire (vote step count and quorum sizes differ), and certificates (a `2f+1` commit
certificate does not prove a fast-path decision; an `n−f` one is not what a classic node expects,
making sync unsound in both directions).

**Recommendation:** genesis-selected mode, resolved at compile time or node construction, with a
hard startup check that all nodes agree. Classic stays the default. Never a runtime toggle.

---

## 2. Component-by-component impact

Studio has `round-state-machine`, `vote-keeper`, `consensus-orchestrator`, `wal` and `value-sync` at
`ready`; `driver` at `investigate`; `message-codec` at `wire`. Their confirmed behavior cards and
property names are the acceptance checklist below.

### 2.1 `core-types` — thresholds, certificates, proposals

`core-types/src/threshold.rs`. `ThresholdParams` today is `{quorum: 2/3, honest: 1/3}`. The fast
variant needs `{decision: 4/5, quorum: 2/5}` and **no honest param**. So: add a `decision` field,
repurpose `quorum`, and make the absence of `honest` explicit rather than leaving a dead 1/5 value
that invites a resurrected `SkipRound`. `threshold_params` is already plumbed as data
(`Params<Ctx>` → `core-consensus/src/state.rs:75` → `Driver::new` at `core-driver/src/driver.rs:87`
→ `VoteKeeper::new` at `:90` and `:146`), and nothing hardcodes 2/3 outside `threshold.rs`.

Extend the `threshold_params_corner_cases` test to the 4/5 and 2/5 boundaries: both must be **not
met** at exact equality. The interaction map already flags this as an unchecked bridge check for
2/3; the fast variant makes it load-bearing twice.

`certificate.rs`: `CommitCertificate` verifies at `n−f` and becomes **cross-round** (finding 4).
`PolkaCertificate` becomes the `2f+1` re-proposal justification — rename to something step-neutral.
`signing/src/ext.rs` has ~10 verification entry points taking `ThresholdParams`; each must name
which threshold it checks instead of defaulting to `quorum`.

`vote.rs`: keep `VoteType` and use only `Precommit` (per Stage 0). A fast node receiving a `Prevote`
rejects it as malformed. `proposal.rs`: needs the full-value vs. `id(v)` distinction from finding 5.

### 2.2 `core-votekeeper` — the structural change

Still the hardest part, and confirmed structural. `threshold_to_output` (`keeper.rs:585-637`) maps
one vote type in one round to **at most one** `Threshold`, latched by `emit_at_most_once_per_round`.
The fast protocol needs **two thresholds over the same precommit tally in the same round** — `2f+1`
(L36, set `valid`) and `n−f` (L39/L42) — independently latched, the first not swallowing the second.

Changes: distinct outputs for `2f+1`-for-value vs `n−f`-for-value, plus an `n−f`-for-any (L39);
independent latching, so `emit_at_most_once_per_round` is restated per (round, threshold) rather
than per (round, vote type); `PolkaAny`/`PolkaNil`/`PolkaValue` and **`SkipRound`** all die.

Properties needing re-derivation: `polka_value_needs_quorum`,
`polka_any_reported_on_prevote_quorum`, `precommit_value_reported_on_quorum`,
`precommit_nil_distinguishable_from_split`, `emit_at_most_once_per_round`,
`skip_round_only_from_future_rounds` (retires). Carrying over: `tally_matches_voters`,
`tally_never_overflows`, `evidence_is_real_equivocation`, `evidence_bounded_per_validator`.

The confirmed goal *"PrecommitValue outranks SkipRound in a future round"* retires with `SkipRound`.

### 2.3 `core-state-machine` — collapse the steps

`Step` becomes `Unstarted → Propose → Precommit → Commit`. `State` replaces the `locked`/`valid`
pair with a single `valid: Option<RoundValue<ValueId>>` holding the **id**.

`Input`: drop `PolkaAny`, `PolkaNil`, `ProposalAndPolkaCurrent`, `TimeoutPrevote`, `SkipRound`.
`ProposalAndPolkaPrevious` becomes the L27 re-proposal-with-`2f+1`-justification input. Add the L39
"n−f for any" input and the L42 cross-round decide input.

`ScheduledTimeouts` loses `PREVOTE_BIT`. `TimeoutKind::Prevote` stays for the classic path but is
unused on the fast one. The `pol_round` asserts in `prevote()`/`prevote_previous()` fold into the
merged rule — a chance to discharge the standing bridge check that they are unreachable rather than
re-inherit it.

**`WaitForValid` needs a home.** It is a bounded wait inside `StartRound`, which a pure transition
function cannot express. Options: a new `Output::WaitForValid(Timeout)` with the orchestrator
holding the propose decision until it fires or `valid` advances; or model it as entering `Propose`
with a pending flag and re-evaluating on each `2f+1` observation. This is the main **design question
Studio's model should settle before Rust is written.**

Surviving confirmed behaviors, to re-check rather than rewrite: *non-proposer never emits a
proposal*; *decision output carries the decided proposal's round*; *round never moves backwards*;
*proposal round mismatch never panics*. Properties `only_proposer_emits_proposal`,
`decision_is_never_overwritten`, `commit_step_is_terminal`, `round_never_moves_backwards`,
`decision_output_round_matches_state` carry over; `timeout_scheduled_at_most_once_per_round` narrows
to two kinds. The goal *"locked node unlocks for an older polka"* changes meaning — with the merge
there is no unlock, and the intent becomes L28's `valid_p.round ≤ vr ∨ valid_p.value = id(v)`.
Expect that card retracted and replaced.

### 2.4 `core-driver` — multiplexing

`mux.rs`: `has_polka_value`, `has_polka_nil`, `has_polka_any`, `has_precommit_any`,
`find_non_value_threshold` collapse to one single-vote-type helper parameterised by threshold.
`apply_polka_certificate_votes` / `apply_commit_certificate_votes` must apply against the right one.
The driver must also **retain fresh proposals across rounds** for finding 4. `driver` is only at
`investigate`, so there is less confirmed contract to preserve — and correspondingly less safety net.

### 2.5 `core-consensus`

`handle/vote.rs`: one vote type. `handle/decide.rs`: `n−f`, cross-round; the interaction map already
flags that the sync branch skips the voting path's local re-verification — resolve rather than port.
`handle/propose.rs`: `WaitForValid` plus the fresh/`id` distinction. `params.rs`: `HIDDEN_LOCK_ROUND`
is a classic construct — decide explicitly whether hidden locks even exist under merged `valid`
before porting the mitigation. `MAX_FUTURE_ROUND_LOOKAHEAD` is unaffected, but note that with
`SkipRound` gone its interaction with catch-up changes: the comment justifying it cites the `f+1`
mechanism that no longer exists.

### 2.6 Downstream

**WAL**: one fewer append per round — a latency win worth measuring; no-amnesia still requires
durable-before-publish. Refuse cross-protocol replay. **`value-sync`**: certificate threshold
changes and certificates become cross-round; add a protocol identifier to what sync verifies.
**`message-codec`**: with `VoteType` unchanged, the codec work is the proposal value-or-id
distinction plus certificate semantics.

---

## 3. Staged plan

**Stage 1 — thresholds, no behavior change.** Add `decision`, repurpose `quorum`, remove `honest`
from the fast params; make every `signing/src/ext.rs` entry point name its threshold; extend the
corner-case tests. Classic behavior bit-identical — reviewable as a pure refactor.

**Stage 2 — Studio derives the model.** Set up the components Studio does not yet have
(`core-types-domain` first — the threshold arithmetic is the load-bearing change — then `driver` to
`ready`, then `signing`, `equivocation-detection`), and have Studio produce the fast-protocol model
against the code. Model-check agreement, the L42/L36 intersection argument, termination, and settle
the `WaitForValid` design question **before Rust**. Use the authors' spec as a cross-check on
requirements, never as a source to merge.

**Stage 3 — vote keeper.** Two-thresholds-on-one-tally, `SkipRound` removal. Highest-risk unit;
do it before the state machine.

**Stage 4 — round state machine.** Step collapse, `locked`/`valid` merge, `WaitForValid`.

**Stage 5 — driver and orchestrator.** Mux generalization, cross-round decide, fresh-proposal
retention, `HIDDEN_LOCK_ROUND` answered.

**Stage 6 — tests, via Studio.** Studio's test generation from the model's uncovered behavior
families is the primary instrument. Multi-node runs at `n = 6` (`f = 1`) through `test/framework`;
byzantine injection via `engine-byzantine`; crash/restart for WAL replay. Measure the latency win —
two steps instead of three is the whole justification for a 5x replica cost.

**Stage 7 — Studio reconciliation.** Re-sync affected components and work the behavior deck for the
cards whose meaning changed.

---

## 4. Open questions

1. **Is the 5x replica cost acceptable for the target deployment?** 6 validators to tolerate 1, 11
   to tolerate 2. Answer before Stage 1 — it decides research branch vs. shipping path.
2. **How is `WaitForValid` expressed** in a pure transition function? See 2.3. Studio's model should
   settle this.
3. **Fallback when `f ≥ n/5`.** Halt, or fall back to three-step? A dynamic fallback is a harder
   protocol than either endpoint; recommend explicitly out of scope for v1.
4. **Cross-round commit certificates** (finding 4) — how long must a fresh proposal be retained, and
   what bounds that memory?
5. **Does the hidden-lock problem survive** the `locked`/`valid` merge?
6. **Vote extensions** — now attached to the only vote in the round. Confirm `VoteExtensionPolicy`
   still makes sense.
7. **Equivocation evidence** — one vote type should *simplify* the no-double-count property.

---

## 5. What this rests on

**Paper:** Algorithm 1 transcribed verbatim (Stage 0). The five findings above follow directly from
those lines. Not obtained: the model-checked invariant names and configuration.

**Repository:** all file paths, `ThresholdParams` and its plumbing, the `Step`/`Input` enums, the
`mux.rs` helper set, `VoteType`, `quint-specs` inventory — all verified against the branch.

**Studio:** confirmed behavior cards and property names, from models `ready` on
`round-state-machine`, `vote-keeper`, `consensus-orchestrator`, `wal`, `value-sync`. Every bridge
check in the interaction map is currently `unchecked`, so the cross-component requirements quoted
here are stated intent, not evidence.

**Deliberately not used:** the authors' Quint specification and Malachite's `test/mbt` ITF-replay
suite. Requirements input and inspiration respectively, per the method decision at the top.
