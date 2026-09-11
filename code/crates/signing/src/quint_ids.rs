//! Per-test identity projection for the Quint Studio `signing` oracle.
//!
//! The `signing` model works over small integer identities while the code deals in
//! 20-byte addresses, `u64` heights, value-id hashes and arbitrary peer-id bytes. Every
//! logged identity is projected onto an index assigned in first-seen order.
//!
//! This module is the SINGLE index space for the component. Both log sites — the
//! certificate layer in [`crate::ext`] and the concrete `Signer`/`Verifier`
//! implementation in the test-support crate — project through here, so an address seen
//! first by one side keeps the same index on the other. Two separate registries would
//! drift and the replayed trace would name different validators than the test did.
//!
//! Identities are keyed by their `Display` rendering, which every `Context` associated
//! type this component touches already provides. The registries are thread-local, which
//! is also the per-test scope: the Rust test harness gives each test its own thread.
//!
//! Compiled only under the `quint-oracle` feature, so `no_std` and production builds
//! carry none of this — including the `std` this module itself uses.

extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::{Debug, Display};

use malachitebft_core_types::NilOrVal;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

/// Bytes no private key produced.
pub const FORGED_SIGNER: i64 = -1;

/// No extension attached to a vote.
pub const NO_EXT: i64 = -1;

/// The value field of a vote for nil. A token no concrete value id takes, so a nil
/// vote's preimage is never equal to the preimage of a vote for a real value.
pub const NIL_VALUE: i64 = -2;

/// Field tags of the vote signing encoding, as `signingCore` declares them.
pub const TAG_V_TYP: i64 = 101;
pub const TAG_V_HEIGHT: i64 = 102;
pub const TAG_V_ROUND: i64 = 103;
pub const TAG_V_VALUE: i64 = 104;
pub const TAG_V_ADDR: i64 = 105;

std::thread_local! {
    /// Public keys and the addresses derived from them share one index space, so a
    /// validator is named by a single number: address `2` always pairs with key `2`.
    static KEY_IX: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    static ADDR_IX: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    static HEIGHT_IX: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    static VALUE_IX: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    static PEER_IX: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    static EXT_IX: RefCell<HashMap<String, usize>> = RefCell::new(HashMap::new());
    /// Which key produced each signature this test has seen being made, so a
    /// verification can name the signer; anything else is bytes no key made.
    /// For each signature this test saw being produced: which key made it, and the
    /// exact preimage tokens it covers. A verifier cannot invert a signature, but the
    /// instrumentation watched the signing, so it legitimately knows both.
    static SIG_IX: RefCell<HashMap<String, (i64, Vec<i64>)>> = RefCell::new(HashMap::new());
    /// Signings and verification calls performed, counted independently of the model
    /// so a missed or double-fired log site shows up as a conformance mismatch.
    static SIGNINGS: Cell<i64> = const { Cell::new(0) };
    static CALLS: Cell<i64> = const { Cell::new(0) };
}

fn ix(
    registry: &'static std::thread::LocalKey<RefCell<HashMap<String, usize>>>,
    key: String,
) -> usize {
    registry.with(|m| {
        let mut m = m.borrow_mut();
        let next = m.len();
        *m.entry(key).or_insert(next)
    })
}

/// The model's `KeyId` for a public key, named by its encoding bytes: `0`, `1`, ….
///
/// Bytes rather than `Display`, because neither `SigningScheme::PublicKey` nor the
/// concrete ed25519 key is `Display` — and `encode_public_key` is in the trait, so
/// every caller can reach the same key material.
pub fn key_bytes_id(bytes: &[u8]) -> i64 {
    ix(&KEY_IX, hex_key(bytes)) as i64
}

/// The model's `Addr` for a validator address: `0`, `1`, ….
pub fn addr<A: Display>(address: &A) -> i64 {
    ix(&ADDR_IX, address.to_string()) as i64
}

/// The model's height. The first height a test touches is `1`, matching `HEIGHTS`.
pub fn height<H: Display>(h: &H) -> i64 {
    ix(&HEIGHT_IX, h.to_string()) as i64 + 1
}

/// The model's value id for a concrete value: `0`, `1`, ….
pub fn value_id<V: Display>(id: &V) -> i64 {
    ix(&VALUE_IX, id.to_string()) as i64
}

/// The model's peer id: `0`, `1`, ….
pub fn peer(peer_id: &[u8]) -> i64 {
    ix(&PEER_IX, hex_key(peer_id)) as i64
}

/// The model's extension blob id: `0`, `1`, ….
///
/// `Context::Extension` exposes only `size_bytes()`, so the blob is keyed on its
/// `Debug` rendering — the one bound the trait does carry. Both log surfaces call
/// THIS function, so they agree on the index whatever the rendering looks like.
pub fn extension<E: Debug>(ext: &E) -> i64 {
    ix(&EXT_IX, format!("{ext:?}")) as i64
}

/// Remember which key produced a signature and what it covers, so a later verification
/// can report both without inverting the signature.
pub fn remember_signature(signature_bytes: &[u8], signer: i64, preimage: Vec<i64>) {
    SIG_IX.with(|m| {
        m.borrow_mut()
            .insert(hex_key(signature_bytes), (signer, preimage));
    });
}

/// The model's `sig_covers`: whether these bytes are a signature over exactly
/// `expected` — the message the verifier is checking them against. False for bytes no
/// key produced, and false for a real signature presented against a different message
/// (a replay across heights, rounds or values).
pub fn signature_covers(signature_bytes: &[u8], expected: &[i64]) -> bool {
    SIG_IX.with(|m| {
        m.borrow()
            .get(&hex_key(signature_bytes))
            .map(|(_, preimage)| preimage.as_slice() == expected)
            .unwrap_or(false)
    })
}

/// The model's `signer` field of a signature. A signature this test never saw being
/// produced is bytes no key made, i.e. [`FORGED_SIGNER`].
pub fn signature_signer(signature_bytes: &[u8]) -> i64 {
    SIG_IX
        .with(|m| m.borrow().get(&hex_key(signature_bytes)).map(|(s, _)| *s))
        .unwrap_or(FORGED_SIGNER)
}

/// The next signing count, for the `w.signings` conformance assert.
pub fn next_signing() -> i64 {
    SIGNINGS.with(|c| {
        c.set(c.get() + 1);
        c.get()
    })
}

/// The next verification/decode count, for the `w.calls` conformance assert.
pub fn next_call() -> i64 {
    CALLS.with(|c| {
        c.set(c.get() + 1);
        c.get()
    })
}

/// A stable registry key for opaque bytes.
fn hex_key(bytes: &[u8]) -> String {
    use core::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The `VoteTyp` token inside a preimage, where the model carries an int.
pub fn vote_type_token(is_prevote: bool) -> i64 {
    if is_prevote {
        1
    } else {
        2
    }
}

/// Certificate-kind tokens, one per public verification entry point.
pub const KIND_COMMIT: i64 = 1;
pub const KIND_EXTENDED_COMMIT: i64 = 2;
pub const KIND_POLKA: i64 = 3;
pub const KIND_ROUND_PRECOMMIT: i64 = 4;
pub const KIND_ROUND_SKIP: i64 = 5;

/// Vote-extension policy tokens.
pub const POLICY_DISABLED: i64 = 0;
pub const POLICY_REQUIRED: i64 = 1;

/// The accumulator bound the model uses for `checked_add`. A `u64` maximum is outside
/// the evaluator's integer range, so a power at or above this saturates to it — which
/// preserves the overflow class: such a validator alone sits at the bound, and adding
/// any other power overflows, exactly as `checked_add` does.
pub const POWER_MAX: i64 = 1_000_000;

/// The model's `power` value for a validator.
pub fn power_token(voting_power: u64) -> i64 {
    match i64::try_from(voting_power) {
        Ok(p) if p < POWER_MAX => p,
        _ => POWER_MAX,
    }
}

/// The model's `policy` token.
pub fn policy_token(disabled: bool) -> i64 {
    if disabled {
        POLICY_DISABLED
    } else {
        POLICY_REQUIRED
    }
}

/// The model's `Entry` record for one certificate signature. Every field is a plain
/// scalar: a payload-free variant nested inside a logged record has no bare-name
/// encoding, so nothing here may be a Quint variant.
#[allow(clippy::too_many_arguments)]
pub fn entry_value(
    addr: i64,
    typ: i64,
    value: i64,
    sig_signer: i64,
    sig_covers: bool,
    ext_value: i64,
    ext_sig_signer: i64,
    ext_sig_covers: bool,
) -> quint_oracle::Value {
    use quint_oracle::ToLogged;

    quint_oracle::record([
        ("addr", addr.to_logged()),
        ("typ", typ.to_logged()),
        ("value", value.to_logged()),
        ("sig_signer", sig_signer.to_logged()),
        ("sig_covers", sig_covers.to_logged()),
        ("ext_value", ext_value.to_logged()),
        ("ext_sig_signer", ext_sig_signer.to_logged()),
        ("ext_sig_covers", ext_sig_covers.to_logged()),
    ])
}

/// The token list `vote_preimage` builds: the bare protobuf field pairs, with no domain
/// tag, no network material, and no attached extension.
pub fn vote_preimage_tokens(typ: i64, height: i64, round: i64, value: i64, addr: i64) -> Vec<i64> {
    Vec::from([
        TAG_V_TYP,
        typ,
        TAG_V_HEIGHT,
        height,
        TAG_V_ROUND,
        round,
        TAG_V_VALUE,
        value,
        TAG_V_ADDR,
        addr,
    ])
}

/// The model's `VoteFields` record.
pub fn vote_fields_value(
    typ: i64,
    height: i64,
    round: i64,
    value: i64,
    addr: i64,
    ext: i64,
) -> quint_oracle::Value {
    use quint_oracle::ToLogged;

    quint_oracle::record([
        ("typ", typ.to_logged()),
        ("height", height.to_logged()),
        ("round", round.to_logged()),
        ("value", value.to_logged()),
        ("addr", addr.to_logged()),
        ("ext", ext.to_logged()),
    ])
}

/// Domain tag of the vote-extension preimage.
pub const DOMAIN_VOTE_EXT: i64 = 301;

/// Domain tag of the validator-proof preimage.
pub const DOMAIN_POV: i64 = 302;

/// The curve id the local signing scheme claims.
pub const LOCAL_CURVE: i64 = 1;

/// The model's value field of a vote, or of a round certificate's signature. A nil
/// value takes the reserved [`NIL_VALUE`] token, which `value_id` — which only ever
/// returns a non-negative first-seen index — can never produce. Two genuinely
/// different preimages therefore never compare equal in the log.
pub fn nil_or_value<V: Display>(v: &NilOrVal<V>) -> i64 {
    match v {
        NilOrVal::Nil => NIL_VALUE,
        NilOrVal::Val(id) => value_id(id),
    }
}

/// The token list `pov_preimage` builds: the domain tag, the public-key length, the
/// key bytes' tokens, then the length-prefixed peer id.
pub fn pov_preimage_tokens(pk_len: i64, pk_key: i64, pk_on_curve: bool, peer: i64) -> Vec<i64> {
    Vec::from([
        DOMAIN_POV,
        pk_len,
        pk_len,
        pk_key,
        LOCAL_CURVE,
        if pk_on_curve { 1 } else { 0 },
        1,
        peer,
    ])
}

/// The model's `Bytes` record: exactly what a `SigningScheme` decoder inspects.
pub fn bytes_value(len: i64, key: i64, curve: i64, on_curve: bool) -> quint_oracle::Value {
    use quint_oracle::ToLogged;

    quint_oracle::record([
        ("len", len.to_logged()),
        ("key", key.to_logged()),
        ("curve", curve.to_logged()),
        ("on_curve", on_curve.to_logged()),
    ])
}

/// The token list `extension_preimage` builds: the domain tag, the length-prefixed
/// precommit preimage the scope reconstructs, then the length-prefixed extension.
pub fn extension_preimage_tokens(
    height: i64,
    round: i64,
    value: i64,
    addr: i64,
    ext: i64,
) -> Vec<i64> {
    let inner = vote_preimage_tokens(vote_type_token(false), height, round, value, addr);

    let mut tokens = Vec::from([DOMAIN_VOTE_EXT, inner.len() as i64]);
    tokens.extend_from_slice(&inner);
    tokens.push(1);
    tokens.push(ext);
    tokens
}
