//! `TestContext`-typed wrappers over the Quint Studio `signing` identity projection.
//!
//! Every registry lives in [`malachitebft_signing::quint_ids`] — the component's SINGLE
//! first-seen index space. This module only adapts the concrete `TestContext` types onto
//! it and assembles the record and token-list shapes the spec declares. It keeps no
//! registry of its own: a second one would drift from the certificate layer's, and the
//! replayed trace would name different validators than the test did.

use bytes::Bytes;
use malachitebft_core_types::{NilOrVal, Round, VoteExtensionScope, VoteType};
use malachitebft_signing::quint_ids as shared;
use quint_oracle::{record, ToLogged, Value};

use crate::signing::{PublicKey, Signature};
use crate::{Address, Height, Proposal, TestContext, ValueId, Vote};

/// Field tags of the proposal signing encoding, as `signingCore` declares them. The
/// vote tags live in the shared module, since the certificate layer rebuilds votes too.
const TAG_P_HEIGHT: i64 = 201;
const TAG_P_ROUND: i64 = 202;
const TAG_P_VALUE: i64 = 203;
const TAG_P_POLROUND: i64 = 204;
const TAG_P_ADDR: i64 = 205;

/// No extension attached to a vote.
pub const NO_EXT: i64 = shared::NO_EXT;

/// The model's `KeyId` for a public key.
pub fn key(public_key: &PublicKey) -> i64 {
    // Keyed on the 32 encoding bytes, which is exactly what the certificate layer
    // derives from `SigningScheme::encode_public_key`, so both agree on the index.
    shared::key_bytes_id(public_key.as_bytes())
}

/// The model's `KeyId` for raw public-key bytes. Bytes that are not 32 long cannot
/// name a key at all.
pub fn key_from_bytes(bytes: &[u8]) -> i64 {
    if bytes.len() == 32 {
        shared::key_bytes_id(bytes)
    } else {
        shared::FORGED_SIGNER
    }
}

/// The model's `Addr` for a validator address.
pub fn addr(address: &Address) -> i64 {
    shared::addr(address)
}

/// The model's height.
pub fn height(h: Height) -> i64 {
    shared::height(&h)
}

/// The model's round. `Round::Nil` and any negative round project to `0`.
pub fn round(r: Round) -> i64 {
    r.as_i64().max(0)
}

/// The model's value id for a concrete value.
pub fn value_id(id: &ValueId) -> i64 {
    shared::value_id(id)
}

/// The model's value field of a vote. Nil takes its own reserved token, so a nil vote's
/// preimage is never equal to the preimage of a vote for a real value.
pub fn nil_or_value(v: &NilOrVal<ValueId>) -> i64 {
    shared::nil_or_value(v)
}

/// The model's peer id.
pub fn peer(peer_id: &[u8]) -> i64 {
    shared::peer(peer_id)
}

/// The model's extension blob id.
pub fn extension(ext: &Bytes) -> i64 {
    shared::extension(ext)
}

/// Remember which key produced a signature and what it covers.
pub fn remember_signature(signature: &Signature, signer: i64, preimage: Vec<i64>) {
    shared::remember_signature(&signature.to_bytes(), signer, preimage);
}

/// The model's `sig_signer`. A signature this test never saw being produced is bytes no
/// key made.
pub fn signature_signer(signature: &Signature) -> i64 {
    shared::signature_signer(&signature.to_bytes())
}

/// The model's `sig_covers`: whether the signature is over exactly the bytes the
/// verifier is checking it against.
pub fn signature_covers(signature: &Signature, expected: &[i64]) -> bool {
    shared::signature_covers(&signature.to_bytes(), expected)
}

/// The next signing count, for the `w.signings` conformance assert.
pub fn next_signing() -> i64 {
    shared::next_signing()
}

/// The next verification count, for the `w.calls` conformance assert.
pub fn next_call() -> i64 {
    shared::next_call()
}

fn is_prevote(typ: VoteType) -> bool {
    matches!(typ, VoteType::Prevote)
}

/// The model's `VoteFields` record for a vote.
pub fn vote_fields(vote: &Vote) -> Value {
    let ext = match &vote.extension {
        None => NO_EXT,
        Some(signed) => extension(&signed.message),
    };

    shared::vote_fields_value(
        shared::vote_type_token(is_prevote(vote.typ)),
        height(vote.height),
        round(vote.round),
        nil_or_value(&vote.value),
        addr(&vote.validator_address),
        ext,
    )
}

/// The token list `vote_preimage` builds for a vote — the attached extension is
/// deliberately absent, exactly as `Vote::to_sign_bytes` drops it.
pub fn vote_preimage(vote: &Vote) -> Vec<i64> {
    shared::vote_preimage_tokens(
        shared::vote_type_token(is_prevote(vote.typ)),
        height(vote.height),
        round(vote.round),
        nil_or_value(&vote.value),
        addr(&vote.validator_address),
    )
}

/// The model's `ProposalFields` record for a proposal.
pub fn proposal_fields(proposal: &Proposal) -> Value {
    record([
        ("height", height(proposal.height).to_logged()),
        ("round", round(proposal.round).to_logged()),
        ("value", value_id(&proposal.value.id()).to_logged()),
        ("pol_round", round(proposal.pol_round).to_logged()),
        ("addr", addr(&proposal.validator_address).to_logged()),
    ])
}

/// The token list `proposal_preimage` builds for a proposal.
pub fn proposal_preimage(proposal: &Proposal) -> Vec<i64> {
    Vec::from([
        TAG_P_HEIGHT,
        height(proposal.height),
        TAG_P_ROUND,
        round(proposal.round),
        TAG_P_VALUE,
        value_id(&proposal.value.id()),
        TAG_P_POLROUND,
        round(proposal.pol_round),
        TAG_P_ADDR,
        addr(&proposal.validator_address),
    ])
}

/// The model's `Scope` record for a vote-extension scope.
pub fn scope_fields(scope: &VoteExtensionScope<TestContext>) -> Value {
    record([
        ("height", height(scope.height).to_logged()),
        ("round", round(scope.round).to_logged()),
        ("value", value_id(&scope.value_id).to_logged()),
        ("addr", addr(&scope.validator_address).to_logged()),
    ])
}

/// The token list `extension_preimage` builds: the domain tag, the length-prefixed
/// precommit preimage the scope reconstructs, then the length-prefixed extension.
pub fn extension_preimage(scope: &VoteExtensionScope<TestContext>, ext: &Bytes) -> Vec<i64> {
    shared::extension_preimage_tokens(
        height(scope.height),
        round(scope.round),
        value_id(&scope.value_id),
        addr(&scope.validator_address),
        extension(ext),
    )
}

/// Whether raw bytes are a real Ed25519 curve point of the right length.
fn on_curve(bytes: &[u8]) -> bool {
    <[u8; 32]>::try_from(bytes)
        .ok()
        .map(|arr| PublicKey::from_bytes(arr).is_ok())
        .unwrap_or(false)
}

/// The model's `Bytes` record for a raw public-key encoding, carrying exactly what
/// `decode_public_key` inspects.
pub fn key_bytes(bytes: &[u8]) -> Value {
    shared::bytes_value(
        bytes.len() as i64,
        key_from_bytes(bytes),
        shared::LOCAL_CURVE,
        on_curve(bytes),
    )
}

/// The token list `pov_preimage` builds for a validator proof.
pub fn pov_preimage(public_key: &[u8], peer_id: &[u8]) -> Vec<i64> {
    shared::pov_preimage_tokens(
        public_key.len() as i64,
        key_from_bytes(public_key),
        on_curve(public_key),
        peer(peer_id),
    )
}
