use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use async_trait::async_trait;
use malachitebft_core_types::{
    CertificateError, CommitCertificate, CommitSignature, Context, ExtendedCommitCertificate,
    ExtendedCommitSignature, NilOrVal, PolkaCertificate, PolkaSignature, Round, RoundCertificate,
    RoundCertificateType, RoundSignature, Signature, SignedExtension, ThresholdParams, Validator,
    ValidatorSet, ValueId, VoteExtensionPolicy, VoteExtensionScope, VoteType, VotingPower,
};

use crate::Verifier;

/// Quint oracle: report a certificate's signer list, one event per signature. A list
/// cannot travel as a single logged argument — replay only accepts a value the spec's
/// own nondet set contains — so each signer arrives as its own event, as its RANK in
/// the validator set (-1 when the set does not contain it, which is the
/// UnknownValidator case). Order and repeats are preserved, because the dedupe check
/// keys on them.
fn oracle_log_signers<Ctx: Context>(addresses: &[Ctx::Address], validator_set: &Ctx::ValidatorSet) {
    quint_oracle::Event::builder(quint_oracle::current_test(), "certificate_signers_begin")
        .scope("core-types-domain")
        .send();

    let mut sorted: Vec<alloc::string::String> = (0..validator_set.count())
        .filter_map(|i| validator_set.get_by_index(i))
        .map(|v| alloc::format!("{}", v.address()))
        .collect();
    sorted.sort();
    sorted.dedup();

    for address in addresses {
        let rendered = alloc::format!("{address}");
        let rank = sorted
            .iter()
            .position(|a| a == &rendered)
            .map_or(-1i64, |i| i as i64);

        quint_oracle::Event::builder(quint_oracle::current_test(), "add_signer")
            .argument("signer", rank, Some("SIGNER_RANKS"))
            .scope("core-types-domain")
            .send();
    }
}

/// Quint oracle: the verifier's power-accumulation loop aborts on the first problem
/// rather than summing through it, so each exit is its own spec action. This reports
/// whichever arm the loop took.
fn log_verify_arm(action: &'static str, latch: &'static str) {
    quint_oracle::Event::builder(quint_oracle::current_test(), action)
        .assert(
            Vec::from([
                quint_oracle::PathSeg::ident("state"),
                quint_oracle::PathSeg::ident(latch),
            ]),
            true,
        )
        .scope("core-types-domain")
        .send();
}

/// Extension trait providing additional certificate verification functionality.
///
/// This trait extends the base [`Verifier`] functionality with methods for verifying
/// certificates against validator sets. It is automatically implemented for any type
/// that implements [`Verifier`].
#[async_trait]
pub trait VerifierExt<Ctx>
where
    Ctx: Context,
{
    /// Verify a commit signature in a commit certificate against the public key of its validator.
    ///
    /// ## Return
    /// Return the voting power of that validator if the signature is valid.
    async fn verify_commit_signature(
        &self,
        ctx: &Ctx,
        certificate: &CommitCertificate<Ctx>,
        commit_sig: &CommitSignature<Ctx>,
        validator: &Ctx::Validator,
    ) -> Result<VotingPower, CertificateError<Ctx>>;

    /// Verify a polka signature in a polka certificate against the public key of its validator.
    ///
    /// ## Return
    /// Return the voting power of that validator if the signature is valid.
    async fn verify_polka_signature(
        &self,
        ctx: &Ctx,
        certificate: &PolkaCertificate<Ctx>,
        signature: &PolkaSignature<Ctx>,
        validator: &Ctx::Validator,
    ) -> Result<VotingPower, CertificateError<Ctx>>;

    /// Verify a round signature in a round certificate against the public key of its validator.
    ///
    /// ## Return
    /// Return the voting power of that validator if the signature is valid.
    async fn verify_round_signature(
        &self,
        ctx: &Ctx,
        certificate: &RoundCertificate<Ctx>,
        signature: &RoundSignature<Ctx>,
        validator: &Ctx::Validator,
    ) -> Result<VotingPower, CertificateError<Ctx>>;

    /// Verify the given certificate against the given validator set.
    ///
    /// - For each commit signature in the certificate:
    ///   - Reconstruct the signed precommit and verify its signature.
    ///   - If the signature is invalid, the entire certificate is rejected and
    ///     nothing is stored.
    /// - Check that we have 2/3+ of voting power has signed the certificate.
    ///
    /// If any of those steps fail, return a [`CertificateError`].
    async fn verify_commit_certificate(
        &self,
        ctx: &Ctx,
        certificate: &CommitCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
    ) -> Result<(), CertificateError<Ctx>>;

    /// Verify the given extended commit certificate against the given validator set.
    ///
    /// In addition to the checks performed by [`Self::verify_commit_certificate`]
    /// — reconstructing each precommit, verifying its signature, and enforcing
    /// the 2/3+ voting-power quorum — this method enforces the supplied
    /// [`VoteExtensionPolicy`]. [`VoteExtensionPolicy::Disabled`] rejects any
    /// present extension; [`VoteExtensionPolicy::Required`] rejects missing
    /// extensions and verifies every present extension against the
    /// [`VoteExtensionScope`] formed by `(height, round, value_id,
    /// validator_address)`. A single unexpected, missing, or invalid extension
    /// causes the entire certificate to be rejected.
    async fn verify_extended_commit_certificate(
        &self,
        ctx: &Ctx,
        certificate: &ExtendedCommitCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
        vote_extension_policy: VoteExtensionPolicy,
    ) -> Result<(), CertificateError<Ctx>>;

    /// Verify the polka certificate against the given validator set.
    ///
    /// - For each signature in the certificate:
    ///   - Reconstruct the signed prevote and verify its signature.
    ///   - If the signature is invalid, the entire certificate is rejected and
    ///     known-bad signatures must never be stored or re-broadcast.
    /// - Check that we have 2/3+ of voting power has signed the certificate.
    ///
    /// If any of those steps fail, return a [`CertificateError`].
    async fn verify_polka_certificate(
        &self,
        ctx: &Ctx,
        certificate: &PolkaCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
    ) -> Result<(), CertificateError<Ctx>>;

    /// Verify the round certificate against the given validator set.
    ///
    /// - For each signature in the certificate:
    ///   - Reconstruct the signed vote and verify its signature.
    ///   - If the signature is invalid, the entire certificate is rejected and
    ///     known-bad signatures must never be replayed into the vote keeper
    ///     or re-broadcast in a locally-built certificate.
    /// - Check that the required voting power has signed the certificate:
    ///   - If `Precommit`, ensure that 2/3+ of the voting power is represented.
    ///   - If `Skip`, ensure that 1/3+ of the voting power is represented.
    ///
    /// Returns a [`CertificateError`] if any verification step fails.
    async fn verify_round_certificate(
        &self,
        ctx: &Ctx,
        certificate: &RoundCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
    ) -> Result<(), CertificateError<Ctx>>;
}

/// Quint oracle: project a certificate onto the model's `Cert` payload and log the
/// `verify_certificate` transition. The whole certificate travels as one argument, so
/// replay pins every pick from the logged value and consumes no unguided budget.
///
/// `entries` carries, per signature, the projected address, vote type, value and the
/// signature's `Sig` record — the signer being whichever key was seen producing those
/// Quint oracle: open a certificate and then verify it.
///
/// `begin_certificate` carries the certificate-level scalars, each entry arrives via its
/// own `add_certificate_entry`, and `verify_certificate` takes no payload at all — so
/// every part of the certificate reaches the model through a pinnable logged argument.
#[cfg(feature = "quint-oracle")]
fn log_begin_certificate<Ctx>(
    kind: i64,
    height: &Ctx::Height,
    round: Round,
    value: i64,
    policy: i64,
) where
    Ctx: Context,
{
    if !quint_oracle::enabled() {
        return;
    }

    use crate::quint_ids as qids;

    quint_oracle::Event::builder(quint_oracle::current_test(), "begin_certificate")
        .argument("kind", kind, Some("CERT_KINDS"))
        .argument("height", qids::height(height), Some("HEIGHTS"))
        .argument("round", i64::from(round.as_i64().max(0)), Some("ROUNDS"))
        .argument("value", value, Some("VOTE_VALUES"))
        .argument("policy", policy, Some("EXT_POLICIES"))
        .scope("signing")
        .send();
}

/// Quint oracle: the verification itself. No payload — the certificate is `w.pending`.
#[cfg(feature = "quint-oracle")]
fn log_verify_certificate() {
    if !quint_oracle::enabled() {
        return;
    }

    use crate::quint_ids as qids;

    quint_oracle::Event::builder(quint_oracle::current_test(), "verify_certificate")
        .assert(
            Vec::from([
                quint_oracle::PathSeg::ident("w"),
                quint_oracle::PathSeg::ident("calls"),
            ]),
            qids::next_call(),
        )
        .scope("signing")
        .send();
}

/// Quint oracle: emit one `add_certificate_entry` for a single certificate signature.
///
/// One event per signature rather than one payload for the whole certificate: a
/// variable-length entry list cannot be a nondet domain, so a `Cert` argument pinned
/// nothing and replay silently used the empty initial certificate instead.
///
/// `sig_covers` says whether the entry's signature is over exactly the vote the verifier
/// reconstructs — false for one replayed from another height, round or value.
#[cfg(feature = "quint-oracle")]
#[allow(clippy::too_many_arguments)]
fn log_certificate_entry<Ctx>(
    address: &Ctx::Address,
    is_prevote: bool,
    value: i64,
    signature: &Signature<Ctx>,
    extension: Option<&SignedExtension<Ctx>>,
    height: &Ctx::Height,
    round: Round,
    value_of_scope: i64,
) where
    Ctx: Context,
{
    use crate::quint_ids as qids;
    use malachitebft_core_types::SigningScheme;

    let typ = qids::vote_type_token(is_prevote);
    let addr = qids::addr(address);
    let h = qids::height(height);
    let r = i64::from(round.as_i64().max(0));

    let sig_bytes = Ctx::SigningScheme::encode_signature(signature);
    let preimage = qids::vote_preimage_tokens(typ, h, r, value, addr);

    // The attached extension is flattened, matching the model's `Entry`: `ext_value ==
    // NO_EXT` means none is attached, and the ext signature fields are then unused.
    let (ext_value, ext_sig_signer, ext_sig_covers) = match extension {
        None => (qids::NO_EXT, qids::FORGED_SIGNER, false),
        Some(signed) => {
            let blob = qids::extension(&signed.message);
            let bytes = Ctx::SigningScheme::encode_signature(&signed.signature);
            let expected = qids::extension_preimage_tokens(h, r, value_of_scope, addr, blob);
            (
                blob,
                qids::signature_signer(&bytes),
                qids::signature_covers(&bytes, &expected),
            )
        }
    };

    quint_oracle::Event::builder(quint_oracle::current_test(), "add_certificate_entry")
        .argument("addr", addr, Some("ADDRS"))
        .argument("typ", typ, Some("VOTE_TYPES"))
        .argument("value", value, Some("VOTE_VALUES"))
        .argument(
            "sig_signer",
            qids::signature_signer(&sig_bytes),
            Some("KEYS"),
        )
        .argument(
            "sig_covers",
            qids::signature_covers(&sig_bytes, &preimage),
            None,
        )
        .argument("ext_value", ext_value, Some("EXTS"))
        .argument("ext_sig_signer", ext_sig_signer, Some("KEYS"))
        .argument("ext_sig_covers", ext_sig_covers, None)
        .scope("signing")
        .send();
}

/// Quint oracle: emit one entry event per signature of a commit or extended-commit
/// certificate. Both reconstruct a PRECOMMIT over the certificate's own value, and only
/// the extended form carries vote extensions (ext.rs:146-152).
#[cfg(feature = "quint-oracle")]
fn log_commit_entries<Ctx, S>(
    height: &Ctx::Height,
    round: Round,
    value_id: &ValueId<Ctx>,
    signatures: &[S],
) where
    Ctx: Context,
    S: CommitSignatureEntry<Ctx>,
{
    use crate::quint_ids as qids;

    let value = qids::value_id(value_id);

    for entry in signatures {
        log_certificate_entry::<Ctx>(
            entry.address(),
            false,
            value,
            entry.signature(),
            entry.extension(),
            height,
            round,
            value,
        );
    }
}

/// Quint oracle: one entry event per polka signature. Every signature reconstructs a
/// PREVOTE over the certificate's own value, and never carries an extension.
#[cfg(feature = "quint-oracle")]
fn log_polka_entries<Ctx>(
    height: &Ctx::Height,
    round: Round,
    value_id: &ValueId<Ctx>,
    signatures: &[PolkaSignature<Ctx>],
) where
    Ctx: Context,
{
    use crate::quint_ids as qids;

    let value = qids::value_id(value_id);

    for signature in signatures {
        log_certificate_entry::<Ctx>(
            &signature.address,
            true,
            value,
            &signature.signature,
            None,
            height,
            round,
            value,
        );
    }
}

/// Quint oracle: one entry event per round signature. Each names its OWN vote type and
/// value (`RoundSignature`), which is why the model's `Entry` carries a value of its own.
#[cfg(feature = "quint-oracle")]
fn log_round_entries<Ctx>(height: &Ctx::Height, round: Round, signatures: &[RoundSignature<Ctx>])
where
    Ctx: Context,
{
    use crate::quint_ids as qids;

    for signature in signatures {
        let value = qids::nil_or_value(&signature.value_id);
        log_certificate_entry::<Ctx>(
            &signature.address,
            signature.vote_type == VoteType::Prevote,
            value,
            &signature.signature,
            None,
            height,
            round,
            value,
        );
    }
}

/// Quint oracle: a round certificate carries no `value_id` of its own, so the
/// certificate-level value is taken from the first signature; each entry still reports
/// the value it actually named.
#[cfg(feature = "quint-oracle")]
fn log_round_certificate<Ctx>(certificate: &RoundCertificate<Ctx>)
where
    Ctx: Context,
{
    if !quint_oracle::enabled() {
        return;
    }

    use crate::quint_ids as qids;

    let kind = match certificate.cert_type {
        RoundCertificateType::Precommit => qids::KIND_ROUND_PRECOMMIT,
        RoundCertificateType::Skip => qids::KIND_ROUND_SKIP,
    };

    let value = certificate
        .round_signatures
        .first()
        .map(|signature| qids::nil_or_value(&signature.value_id))
        .unwrap_or(qids::NIL_VALUE);

    log_begin_certificate::<Ctx>(
        kind,
        &certificate.height,
        certificate.round,
        value,
        qids::POLICY_DISABLED,
    );
    log_round_entries::<Ctx>(
        &certificate.height,
        certificate.round,
        &certificate.round_signatures,
    );
    log_verify_certificate();
}

/// Quint oracle: install the validator set the verifier was handed.
///
/// The model's certificate outcome reads `w.validators` — the quorum, unknown-validator
/// and voting-power arms all depend on it — so the set has to reach the model before any
/// `verify_certificate`. Every certificate entry point receives it as an argument, so
/// this fires immediately before the certificate's own event.
///
/// One validator per event, not the whole map as a single payload: the suite builds 21
/// different power arrays over up to seven validators, and no enumerable set of maps
/// could hold them all — whereas each `add_validator` pick is a small scalar the log
/// pins exactly.
#[cfg(feature = "quint-oracle")]
fn log_set_validator_set<Ctx>(validator_set: &Ctx::ValidatorSet)
where
    Ctx: Context,
{
    if !quint_oracle::enabled() {
        return;
    }

    use crate::quint_ids as qids;
    use malachitebft_core_types::{SigningScheme, Validator, ValidatorSet};

    quint_oracle::Event::builder(quint_oracle::current_test(), "begin_validator_set")
        .scope("signing")
        .send();

    for validator in validator_set.iter() {
        let key_bytes = Ctx::SigningScheme::encode_public_key(validator.public_key());

        quint_oracle::Event::builder(quint_oracle::current_test(), "add_validator")
            .argument("addr", qids::addr(validator.address()), Some("ADDRS"))
            .argument("key", qids::key_bytes_id(&key_bytes), Some("KEYS"))
            // `VotingPower` is a u64 and the overflow test uses `u64::MAX`, which an
            // `as i64` cast would silently wrap to -1 and which the evaluator cannot hold
            // either. `power_token` saturates at the model's accumulator bound instead.
            .argument(
                "power",
                qids::power_token(validator.voting_power()),
                Some("POWERS"),
            )
            .scope("signing")
            .send();
    }
}

/// Quint oracle: log one of the single-signature entry points
/// (`verify_commit_signature` / `verify_polka_signature` / `verify_round_signature`).
/// These are public and separately callable, and perform no quorum check — so the
/// outcome turns only on the signer's address and whether its signature covers the vote
/// the verifier reconstructs. Those are the arguments, as scalars: a whole certificate
/// payload here pinned no replay choice at all.
#[cfg(feature = "quint-oracle")]
fn log_verify_single_signature<Ctx>(
    address: &Ctx::Address,
    signature: &Signature<Ctx>,
    expected_preimage: &[i64],
) where
    Ctx: Context,
{
    if !quint_oracle::enabled() {
        return;
    }

    use crate::quint_ids as qids;
    use malachitebft_core_types::SigningScheme;

    let sig_bytes = Ctx::SigningScheme::encode_signature(signature);

    quint_oracle::Event::builder(quint_oracle::current_test(), "verify_single_signature")
        .argument("addr", qids::addr(address), Some("ADDRS"))
        .argument(
            "sig_signer",
            qids::signature_signer(&sig_bytes),
            Some("KEYS"),
        )
        .argument(
            "sig_covers",
            qids::signature_covers(&sig_bytes, expected_preimage),
            None,
        )
        .assert(
            Vec::from([
                quint_oracle::PathSeg::ident("w"),
                quint_oracle::PathSeg::ident("calls"),
            ]),
            qids::next_call(),
        )
        .scope("signing")
        .send();
}

trait CommitSignatureEntry<Ctx>
where
    Ctx: Context,
{
    fn address(&self) -> &Ctx::Address;

    fn signature(&self) -> &Signature<Ctx>;

    fn extension(&self) -> Option<&SignedExtension<Ctx>>;
}

impl<Ctx> CommitSignatureEntry<Ctx> for CommitSignature<Ctx>
where
    Ctx: Context,
{
    fn address(&self) -> &Ctx::Address {
        &self.address
    }

    fn signature(&self) -> &Signature<Ctx> {
        &self.signature
    }

    fn extension(&self) -> Option<&SignedExtension<Ctx>> {
        None
    }
}

impl<Ctx> CommitSignatureEntry<Ctx> for ExtendedCommitSignature<Ctx>
where
    Ctx: Context,
{
    fn address(&self) -> &Ctx::Address {
        &self.address
    }

    fn signature(&self) -> &Signature<Ctx> {
        &self.signature
    }

    fn extension(&self) -> Option<&SignedExtension<Ctx>> {
        self.extension.as_ref()
    }
}

struct CommitSignatureVerification<'a, Ctx>
where
    Ctx: Context,
{
    ctx: &'a Ctx,
    height: Ctx::Height,
    round: Round,
    value_id: &'a ValueId<Ctx>,
    vote_extension_policy: VoteExtensionPolicy,
}

struct CommitVerification<'a, Ctx>
where
    Ctx: Context,
{
    signature: CommitSignatureVerification<'a, Ctx>,
    validator_set: &'a Ctx::ValidatorSet,
    thresholds: ThresholdParams,
}

async fn verify_commit_signature_entry<Ctx, P, S>(
    verifier: &P,
    verification: &CommitSignatureVerification<'_, Ctx>,
    signature: &S,
    validator: &Ctx::Validator,
) -> Result<VotingPower, CertificateError<Ctx>>
where
    Ctx: Context,
    P: Verifier<Ctx>,
    S: CommitSignatureEntry<Ctx> + Sync,
{
    let vote = verification.ctx.new_precommit(
        verification.height,
        verification.round,
        NilOrVal::Val(verification.value_id.clone()),
        validator.address().clone(),
    );

    if verifier
        .verify_signed_vote(&vote, signature.signature(), validator.public_key())
        .await
        .map_err(|e| CertificateError::VerificationError(e.into_source()))?
        .is_invalid()
    {
        return Err(CertificateError::InvalidCommitSignature(
            CommitSignature::new(signature.address().clone(), signature.signature().clone()),
        ));
    }

    let Some(signed_ext) = signature.extension() else {
        if verification.vote_extension_policy.is_required() {
            return Err(CertificateError::MissingVoteExtension(
                signature.address().clone(),
            ));
        }

        return Ok(validator.voting_power());
    };

    if verification.vote_extension_policy.is_disabled() {
        return Err(CertificateError::UnexpectedVoteExtension(
            signature.address().clone(),
        ));
    }

    let scope = VoteExtensionScope::new(
        verification.height,
        verification.round,
        verification.value_id.clone(),
        validator.address().clone(),
    );

    if verifier
        .verify_signed_vote_extension(
            &scope,
            &signed_ext.message,
            &signed_ext.signature,
            validator.public_key(),
        )
        .await
        .map_err(|e| CertificateError::VerificationError(e.into_source()))?
        .is_invalid()
    {
        return Err(CertificateError::InvalidVoteExtensionSignature(
            validator.address().clone(),
        ));
    }

    Ok(validator.voting_power())
}

async fn verify_commit_signature_entries<Ctx, P, S>(
    verifier: &P,
    verification: CommitVerification<'_, Ctx>,
    signatures: &[S],
) -> Result<(), CertificateError<Ctx>>
where
    Ctx: Context,
    P: Verifier<Ctx>,
    S: CommitSignatureEntry<Ctx> + Sync,
{
    let mut signed_voting_power: VotingPower = 0;
    let mut seen_validators = BTreeSet::new();

    if quint_oracle::enabled() {
        oracle_log_signers::<Ctx>(
            &signatures
                .iter()
                .map(|s| s.address().clone())
                .collect::<Vec<_>>(),
            verification.validator_set,
        );
    }

    for signature in signatures {
        let validator_address = signature.address();

        if !seen_validators.insert(validator_address) {
            if quint_oracle::enabled() {
                log_verify_arm(
                    "verify_certificate_power_duplicate_vote",
                    "duplicate_vote_rejected",
                );
            }

            return Err(CertificateError::DuplicateVote(validator_address.clone()));
        }

        let Some(validator) = verification.validator_set.get_by_address(validator_address) else {
            if quint_oracle::enabled() {
                log_verify_arm(
                    "verify_certificate_power_unknown_validator",
                    "signer_unknown_to_set",
                );
            }

            return Err(CertificateError::UnknownValidator(
                validator_address.clone(),
            ));
        };

        let voting_power =
            verify_commit_signature_entry(verifier, &verification.signature, signature, validator)
                .await?;
        let Some(accumulated) = signed_voting_power.checked_add(voting_power) else {
            if quint_oracle::enabled() {
                log_verify_arm(
                    "verify_certificate_power_overflow",
                    "signed_power_overflowed",
                );
            }

            return Err(CertificateError::VotingPowerOverflow {
                signed: signed_voting_power,
                added: voting_power,
            });
        };
        signed_voting_power = accumulated;
    }

    let total_voting_power = verification.validator_set.total_voting_power();

    if quint_oracle::enabled() {
        quint_oracle::Event::builder(quint_oracle::current_test(), "verify_certificate_power")
            .assert(
                Vec::from([
                    quint_oracle::PathSeg::ident("state"),
                    quint_oracle::PathSeg::ident("last_signed_power_value"),
                ]),
                signed_voting_power,
            )
            .assert(
                Vec::from([
                    quint_oracle::PathSeg::ident("state"),
                    quint_oracle::PathSeg::ident("last_signed_power_total"),
                ]),
                total_voting_power,
            )
            .scope("core-types-domain")
            .send();
    }

    if verification
        .thresholds
        .quorum
        .is_met(signed_voting_power, total_voting_power)
    {
        Ok(())
    } else {
        Err(CertificateError::NotEnoughVotingPower {
            signed: signed_voting_power,
            total: total_voting_power,
            expected: verification
                .thresholds
                .quorum
                .min_expected(total_voting_power),
        })
    }
}

#[async_trait]
impl<Ctx, P> VerifierExt<Ctx> for P
where
    Ctx: Context,
    P: Verifier<Ctx>,
{
    async fn verify_commit_signature(
        &self,
        ctx: &Ctx,
        certificate: &CommitCertificate<Ctx>,
        commit_sig: &CommitSignature<Ctx>,
        validator: &Ctx::Validator,
    ) -> Result<VotingPower, CertificateError<Ctx>> {
        #[cfg(feature = "quint-oracle")]
        {
            let value = crate::quint_ids::value_id(&certificate.value_id);
            let expected = crate::quint_ids::vote_preimage_tokens(
                crate::quint_ids::vote_type_token(false),
                crate::quint_ids::height(&certificate.height),
                i64::from(certificate.round.as_i64().max(0)),
                value,
                crate::quint_ids::addr(validator.address()),
            );
            log_verify_single_signature::<Ctx>(
                validator.address(),
                &commit_sig.signature,
                &expected,
            );
        }

        verify_commit_signature_entry(
            self,
            &CommitSignatureVerification {
                ctx,
                height: certificate.height,
                round: certificate.round,
                value_id: &certificate.value_id,
                vote_extension_policy: VoteExtensionPolicy::Disabled,
            },
            commit_sig,
            validator,
        )
        .await
    }

    async fn verify_polka_signature(
        &self,
        ctx: &Ctx,
        certificate: &PolkaCertificate<Ctx>,
        signature: &PolkaSignature<Ctx>,
        validator: &Ctx::Validator,
    ) -> Result<VotingPower, CertificateError<Ctx>> {
        #[cfg(feature = "quint-oracle")]
        {
            let value = crate::quint_ids::value_id(&certificate.value_id);
            let expected = crate::quint_ids::vote_preimage_tokens(
                crate::quint_ids::vote_type_token(true),
                crate::quint_ids::height(&certificate.height),
                i64::from(certificate.round.as_i64().max(0)),
                value,
                crate::quint_ids::addr(validator.address()),
            );
            log_verify_single_signature::<Ctx>(
                validator.address(),
                &signature.signature,
                &expected,
            );
        }

        // Reconstruct the vote that was signed
        let vote = ctx.new_prevote(
            certificate.height,
            certificate.round,
            NilOrVal::Val(certificate.value_id.clone()),
            validator.address().clone(),
        );

        // Verify signature
        if self
            .verify_signed_vote(&vote, &signature.signature, validator.public_key())
            .await
            .map_err(|e| CertificateError::VerificationError(e.into_source()))?
            .is_invalid()
        {
            return Err(CertificateError::InvalidPolkaSignature(signature.clone()));
        }

        Ok(validator.voting_power())
    }

    async fn verify_round_signature(
        &self,
        ctx: &Ctx,
        certificate: &RoundCertificate<Ctx>,
        signature: &RoundSignature<Ctx>,
        validator: &Ctx::Validator,
    ) -> Result<VotingPower, CertificateError<Ctx>> {
        #[cfg(feature = "quint-oracle")]
        {
            let value = crate::quint_ids::nil_or_value(&signature.value_id);
            let expected = crate::quint_ids::vote_preimage_tokens(
                crate::quint_ids::vote_type_token(signature.vote_type == VoteType::Prevote),
                crate::quint_ids::height(&certificate.height),
                i64::from(certificate.round.as_i64().max(0)),
                value,
                crate::quint_ids::addr(validator.address()),
            );
            log_verify_single_signature::<Ctx>(
                validator.address(),
                &signature.signature,
                &expected,
            );
        }

        let vote_type = signature.vote_type;
        let vote = match vote_type {
            VoteType::Prevote => ctx.new_prevote(
                certificate.height,
                certificate.round,
                signature.value_id.clone(),
                validator.address().clone(),
            ),
            VoteType::Precommit => ctx.new_precommit(
                certificate.height,
                certificate.round,
                signature.value_id.clone(),
                validator.address().clone(),
            ),
        };

        // Verify signature
        if self
            .verify_signed_vote(&vote, &signature.signature, validator.public_key())
            .await
            .map_err(|e| CertificateError::VerificationError(e.into_source()))?
            .is_invalid()
        {
            return Err(CertificateError::InvalidRoundSignature(signature.clone()));
        }

        Ok(validator.voting_power())
    }

    async fn verify_commit_certificate(
        &self,
        ctx: &Ctx,
        certificate: &CommitCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
    ) -> Result<(), CertificateError<Ctx>> {
        // Quint oracle: logged on ENTRY, because the verification loops below return
        // early on the first bad entry and logging at the end would drop every rejection
        // class. The certificate arrives as begin + one event per entry + verify, so
        // every part of it is a pinnable logged argument.
        #[cfg(feature = "quint-oracle")]
        if quint_oracle::enabled() {
            use crate::quint_ids as qids;
            log_set_validator_set::<Ctx>(validator_set);
            log_begin_certificate::<Ctx>(
                qids::KIND_COMMIT,
                &certificate.height,
                certificate.round,
                qids::value_id(&certificate.value_id),
                qids::POLICY_DISABLED,
            );
            log_commit_entries::<Ctx, _>(
                &certificate.height,
                certificate.round,
                &certificate.value_id,
                &certificate.commit_signatures,
            );
            log_verify_certificate();
        }

        verify_commit_signature_entries(
            self,
            CommitVerification {
                signature: CommitSignatureVerification {
                    ctx,
                    height: certificate.height,
                    round: certificate.round,
                    value_id: &certificate.value_id,
                    vote_extension_policy: VoteExtensionPolicy::Disabled,
                },
                validator_set,
                thresholds,
            },
            &certificate.commit_signatures,
        )
        .await
    }

    async fn verify_extended_commit_certificate(
        &self,
        ctx: &Ctx,
        certificate: &ExtendedCommitCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
        vote_extension_policy: VoteExtensionPolicy,
    ) -> Result<(), CertificateError<Ctx>> {
        // Quint oracle: logged on ENTRY, because the verification loops below return
        // early on the first bad entry and logging at the end would drop every rejection
        // class. The certificate arrives as begin + one event per entry + verify, so
        // every part of it is a pinnable logged argument.
        #[cfg(feature = "quint-oracle")]
        if quint_oracle::enabled() {
            use crate::quint_ids as qids;
            log_set_validator_set::<Ctx>(validator_set);
            log_begin_certificate::<Ctx>(
                qids::KIND_EXTENDED_COMMIT,
                &certificate.height,
                certificate.round,
                qids::value_id(&certificate.value_id),
                qids::policy_token(vote_extension_policy.is_disabled()),
            );
            log_commit_entries::<Ctx, _>(
                &certificate.height,
                certificate.round,
                &certificate.value_id,
                &certificate.commit_signatures,
            );
            log_verify_certificate();
        }

        verify_commit_signature_entries(
            self,
            CommitVerification {
                signature: CommitSignatureVerification {
                    ctx,
                    height: certificate.height,
                    round: certificate.round,
                    value_id: &certificate.value_id,
                    vote_extension_policy,
                },
                validator_set,
                thresholds,
            },
            &certificate.commit_signatures,
        )
        .await
    }

    async fn verify_polka_certificate(
        &self,
        ctx: &Ctx,
        certificate: &PolkaCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
    ) -> Result<(), CertificateError<Ctx>> {
        // Quint oracle: logged on ENTRY, because the verification loops below return
        // early on the first bad entry and logging at the end would drop every rejection
        // class. The certificate arrives as begin + one event per entry + verify, so
        // every part of it is a pinnable logged argument.
        #[cfg(feature = "quint-oracle")]
        if quint_oracle::enabled() {
            use crate::quint_ids as qids;
            log_set_validator_set::<Ctx>(validator_set);
            log_begin_certificate::<Ctx>(
                qids::KIND_POLKA,
                &certificate.height,
                certificate.round,
                qids::value_id(&certificate.value_id),
                qids::POLICY_DISABLED,
            );
            log_polka_entries::<Ctx>(
                &certificate.height,
                certificate.round,
                &certificate.value_id,
                &certificate.polka_signatures,
            );
            log_verify_certificate();
        }

        let mut signed_voting_power: VotingPower = 0;
        let mut seen_validators = Vec::new();

        if quint_oracle::enabled() {
            oracle_log_signers::<Ctx>(
                &certificate
                    .polka_signatures
                    .iter()
                    .map(|s| s.address.clone())
                    .collect::<Vec<_>>(),
                validator_set,
            );
        }

        for signature in &certificate.polka_signatures {
            let validator_address = &signature.address;

            // Abort if validator already voted
            if seen_validators.contains(&validator_address) {
                if quint_oracle::enabled() {
                    log_verify_arm(
                        "verify_certificate_power_duplicate_vote",
                        "duplicate_vote_rejected",
                    );
                }

                return Err(CertificateError::DuplicateVote(validator_address.clone()));
            }

            // Add the validator to the list of seen validators
            seen_validators.push(validator_address);

            // Abort if validator not in validator set
            let Some(validator) = validator_set.get_by_address(validator_address) else {
                if quint_oracle::enabled() {
                    log_verify_arm(
                        "verify_certificate_power_unknown_validator",
                        "signer_unknown_to_set",
                    );
                }

                return Err(CertificateError::UnknownValidator(
                    validator_address.clone(),
                ));
            };

            // Verify the signature and propagate the verification error.
            let voting_power = self
                .verify_polka_signature(ctx, certificate, signature, validator)
                .await?;

            let Some(accumulated) = signed_voting_power.checked_add(voting_power) else {
                if quint_oracle::enabled() {
                    log_verify_arm(
                        "verify_certificate_power_overflow",
                        "signed_power_overflowed",
                    );
                }

                return Err(CertificateError::VotingPowerOverflow {
                    signed: signed_voting_power,
                    added: voting_power,
                });
            };
            signed_voting_power = accumulated;
        }

        let total_voting_power = validator_set.total_voting_power();

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "verify_certificate_power")
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("last_signed_power_value"),
                    ]),
                    signed_voting_power,
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("state"),
                        quint_oracle::PathSeg::ident("last_signed_power_total"),
                    ]),
                    total_voting_power,
                )
                .scope("core-types-domain")
                .send();
        }

        // Check if we have 2/3+ voting power
        if thresholds
            .quorum
            .is_met(signed_voting_power, total_voting_power)
        {
            Ok(())
        } else {
            Err(CertificateError::NotEnoughVotingPower {
                signed: signed_voting_power,
                total: total_voting_power,
                expected: thresholds.quorum.min_expected(total_voting_power),
            })
        }
    }

    async fn verify_round_certificate(
        &self,
        ctx: &Ctx,
        certificate: &RoundCertificate<Ctx>,
        validator_set: &Ctx::ValidatorSet,
        thresholds: ThresholdParams,
    ) -> Result<(), CertificateError<Ctx>> {
        // Quint oracle: logged on ENTRY — the loop below returns early on the first bad
        // entry, so logging at the end would drop every rejection class from the trace.
        #[cfg(feature = "quint-oracle")]
        log_set_validator_set::<Ctx>(validator_set);

        #[cfg(feature = "quint-oracle")]
        log_round_certificate::<Ctx>(certificate);

        let mut signed_voting_power: VotingPower = 0;
        let mut seen_validators = Vec::new();

        for signature in &certificate.round_signatures {
            let validator_address = &signature.address;

            // Abort if validator already voted
            if seen_validators.contains(&validator_address) {
                return Err(CertificateError::DuplicateVote(validator_address.clone()));
            }

            // Add the validator to the list of seen validators
            seen_validators.push(validator_address);

            // Abort if validator not in validator set
            let validator = validator_set
                .get_by_address(validator_address)
                .ok_or_else(|| CertificateError::UnknownValidator(validator_address.clone()))?;

            // Precommit certificates must not contain votes of type Prevote.
            if certificate.cert_type == RoundCertificateType::Precommit
                && signature.vote_type == VoteType::Prevote
            {
                return Err(CertificateError::InvalidVoteType(validator_address.clone()));
            }

            // Verify the signature and propagate the verification error.
            let voting_power = self
                .verify_round_signature(ctx, certificate, signature, validator)
                .await?;

            signed_voting_power = signed_voting_power.checked_add(voting_power).ok_or(
                CertificateError::VotingPowerOverflow {
                    signed: signed_voting_power,
                    added: voting_power,
                },
            )?;
        }

        let total_voting_power = validator_set.total_voting_power();

        let threshold = match certificate.cert_type {
            RoundCertificateType::Precommit => &thresholds.quorum,
            RoundCertificateType::Skip => &thresholds.honest,
        };

        if threshold.is_met(signed_voting_power, total_voting_power) {
            Ok(())
        } else {
            Err(CertificateError::NotEnoughVotingPower {
                signed: signed_voting_power,
                total: total_voting_power,
                expected: threshold.min_expected(total_voting_power),
            })
        }
    }
}
