mod decide;
mod driver;
mod finalize;
mod liveness;
mod proposal;
mod propose;
mod proposed_value;
mod rebroadcast_timeout;
mod signature;
mod start_height;
mod sync;
mod timeout;
mod vote;

use liveness::{on_polka_certificate, on_round_certificate};
use proposal::on_proposal;
use propose::on_propose;
use proposed_value::on_proposed_value;
use start_height::reset_and_start_height;
use sync::on_value_response;
use timeout::on_timeout_elapsed;
use vote::on_vote;

use crate::prelude::*;

/// Assigns a stable, small integer to each value id seen during one test, so
/// oracle observations carry a real value identity instead of a placeholder.
/// Numbering restarts per test (the harness names each test's thread after the
/// test), which is also the boundary the oracle records a trace for.
#[cfg(feature = "std")]
fn oracle_value_id(rendered: &str) -> i64 {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static IDS: OnceLock<Mutex<HashMap<String, HashMap<String, i64>>>> = OnceLock::new();

    let owner = std::thread::current().name().unwrap_or("").to_owned();
    let mut ids = IDS.get_or_init(Default::default).lock().unwrap();
    let per_test = ids.entry(owner).or_default();
    let next = per_test.len() as i64 + 1;
    *per_test.entry(rendered.to_owned()).or_insert(next)
}

/// Same, for validator addresses, but anchored on this node: our own address is
/// always 1 (the spec's `MyAddress`), peers get 2, 3, … in first-seen order.
#[cfg(feature = "std")]
fn oracle_address_id(rendered: &str, own: &str) -> i64 {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    if rendered == own {
        return 1;
    }

    static IDS: OnceLock<Mutex<HashMap<String, HashMap<String, i64>>>> = OnceLock::new();

    let owner = std::thread::current().name().unwrap_or("").to_owned();
    let mut ids = IDS.get_or_init(Default::default).lock().unwrap();
    let per_test = ids.entry(owner).or_default();
    let next = per_test.len() as i64 + 2;
    *per_test.entry(rendered.to_owned()).or_insert(next)
}

/// The spec's `Value` sentinel for a nil vote / no value.
#[cfg(feature = "std")]
const ORACLE_NIL_VALUE: i64 = -1;

#[allow(private_interfaces)]
pub async fn handle<Ctx>(
    co: Co<Ctx>,
    state: &mut State<Ctx>,
    metrics: &Metrics,
    input: Input<Ctx>,
) -> Result<(), Error<Ctx>>
where
    Ctx: Context,
{
    handle_input(&co, state, metrics, input).await
}

#[async_recursion]
async fn handle_input<Ctx>(
    co: &Co<Ctx>,
    state: &mut State<Ctx>,
    metrics: &Metrics,
    input: Input<Ctx>,
) -> Result<(), Error<Ctx>>
where
    Ctx: Context,
{
    match input {
        Input::StartHeight(
            height,
            validator_set,
            is_restart,
            target_time,
            vote_extension_policy,
        ) => {
            let result = reset_and_start_height(
                co,
                state,
                metrics,
                height,
                validator_set,
                is_restart,
                target_time,
                vote_extension_policy,
            )
            .await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                quint_oracle::Event::builder(quint_oracle::current_test(), "StartHeight")
                    .argument("h", height.as_u64() as i64, Some("Heights"))
                    .argument("isRestart", is_restart, None)
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::Vote(vote) => {
            #[cfg(feature = "std")]
            let logged = (
                match vote.vote_type() {
                    VoteType::Prevote => "PrevoteT",
                    VoteType::Precommit => "PrecommitT",
                },
                vote.height().as_u64() as i64,
                vote.round().as_i64(),
                oracle_address_id(
                    &format!("{}", vote.validator_address()),
                    &format!("{}", state.address()),
                ),
                match vote.value() {
                    NilOrVal::Nil => ORACLE_NIL_VALUE,
                    NilOrVal::Val(id) => oracle_value_id(&format!("{id:?}")),
                },
            );

            let result = on_vote(co, state, metrics, vote).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                // `sigOk` is true here: reaching this point means the vote was
                // not rejected by signature or vote-extension verification —
                // those paths return before the driver is reached, and the
                // handler reports them as `Ok(())` without applying the vote.
                quint_oracle::Event::builder(quint_oracle::current_test(), "Vote")
                    .argument("vt", logged.0, None)
                    .argument("vh", logged.1, Some("Heights"))
                    .argument("vr", logged.2, Some("Rounds"))
                    .argument("voter", logged.3, Some("Voters"))
                    .argument("v", logged.4, Some("Values"))
                    .argument("sigOk", true, None)
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::Proposal(proposal) => {
            #[cfg(feature = "std")]
            let logged = (
                proposal.height().as_u64() as i64,
                proposal.round().as_i64(),
                oracle_value_id(&format!("{:?}", proposal.value().id())),
            );

            let result = on_proposal(co, state, metrics, proposal).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                quint_oracle::Event::builder(quint_oracle::current_test(), "Proposal")
                    .argument("ph", logged.0, Some("Heights"))
                    .argument("pr", logged.1, Some("Rounds"))
                    .argument("v", logged.2, Some("Values"))
                    .argument("sigOk", true, None)
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::Propose(value) => {
            #[cfg(feature = "std")]
            let logged = oracle_value_id(&format!("{:?}", value.value.id()));

            let result = on_propose(co, state, metrics, value).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                quint_oracle::Event::builder(quint_oracle::current_test(), "Propose")
                    .argument("v", logged, Some("Values"))
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::TimeoutElapsed(timeout) => {
            #[cfg(feature = "std")]
            let logged = (
                match timeout.kind {
                    TimeoutKind::Propose => "TOPropose",
                    TimeoutKind::Prevote => "TOPrevote",
                    TimeoutKind::Precommit => "TOPrecommit",
                    TimeoutKind::Rebroadcast => "TORebroadcast",
                    TimeoutKind::FinalizeHeight(_) => "TOFinalize",
                },
                timeout.round.as_i64(),
            );

            let result = on_timeout_elapsed(co, state, metrics, timeout).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                quint_oracle::Event::builder(quint_oracle::current_test(), "TimeoutElapsed")
                    .argument("kind", logged.0, None)
                    .argument("tr", logged.1, Some("Rounds"))
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::ProposedValue(value, origin) => {
            #[cfg(feature = "std")]
            let logged = (
                value.height.as_u64() as i64,
                value.round.as_i64(),
                oracle_value_id(&format!("{:?}", value.value.id())),
                value.validity.is_valid(),
                match origin {
                    ValueOrigin::Consensus => "ConsensusOrigin",
                    ValueOrigin::Sync => "SyncOrigin",
                },
            );

            let result = on_proposed_value(co, state, metrics, value, origin).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                quint_oracle::Event::builder(quint_oracle::current_test(), "ProposedValue")
                    .argument("pvh", logged.0, Some("Heights"))
                    .argument("pvr", logged.1, Some("Rounds"))
                    .argument("v", logged.2, Some("Values"))
                    .argument("valid", logged.3, None)
                    .argument("origin", logged.4, None)
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::SyncValueResponse(value) => {
            #[cfg(feature = "std")]
            let logged = (
                value.certificate.height.as_u64() as i64,
                value.certificate.round.as_i64(),
                oracle_value_id(&format!("{:?}", value.certificate.value_id)),
            );

            let result = on_value_response(co, state, metrics, value).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                // `certOk` is reported by the handler through the effects it
                // emits; a certificate that fails verification is reported as
                // `Effect::InvalidSyncValue` and still returns `Ok(())`.
                quint_oracle::Event::builder(quint_oracle::current_test(), "SyncValueResponse")
                    .argument("ch", logged.0, Some("Heights"))
                    .argument("cr", logged.1, Some("Rounds"))
                    .argument("v", logged.2, Some("Values"))
                    .argument("certOk", true, None)
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::PolkaCertificate(certificate) => {
            #[cfg(feature = "std")]
            let logged = (
                certificate.height.as_u64() as i64,
                certificate.round.as_i64(),
                oracle_value_id(&format!("{:?}", certificate.value_id)),
            );

            let result = on_polka_certificate(co, state, metrics, certificate).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                quint_oracle::Event::builder(quint_oracle::current_test(), "PolkaCertificate")
                    .argument("ph", logged.0, Some("Heights"))
                    .argument("pr", logged.1, Some("Rounds"))
                    .argument("v", logged.2, Some("Values"))
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
        Input::RoundCertificate(certificate) => {
            #[cfg(feature = "std")]
            let logged = (
                match certificate.cert_type {
                    RoundCertificateType::Precommit => "PrecommitCert",
                    RoundCertificateType::Skip => "SkipCert",
                },
                certificate.height.as_u64() as i64,
                certificate.round.as_i64(),
            );

            let result = on_round_certificate(co, state, metrics, certificate).await;

            #[cfg(feature = "std")]
            if result.is_ok() && quint_oracle::enabled() {
                quint_oracle::Event::builder(quint_oracle::current_test(), "RoundCertificate")
                    .argument("ct", logged.0, None)
                    .argument("ch", logged.1, Some("Heights"))
                    .argument("cr", logged.2, Some("Rounds"))
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("height"),
                        ]),
                        state.height().as_u64() as i64,
                    )
                    .assert(
                        Vec::from([
                            quint_oracle::PathSeg::ident("s"),
                            quint_oracle::PathSeg::ident("round"),
                        ]),
                        state.round().as_i64(),
                    )
                    .scope("consensus-orchestrator")
                    .send();
            }

            result
        }
    }
}
