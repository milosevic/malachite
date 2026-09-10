// Signing & Verification — Malachite BFT
//
// Grounds `code/crates/signing` (the `Signer` / `Verifier` / `VerifierExt` traits),
// `code/crates/signing-ed25519` and `code/crates/signing-ecdsa` (the `SigningScheme`
// key/signature codecs), and the reference implementation in `code/crates/test/src/signing.rs`.
//
// WHAT IS MODELLED
//   * The canonical PREIMAGE built for each of the four signing purposes, token for token,
//     including what each layout OMITS. This is the component's real attack surface.
//   * sign / verify for all four purposes, over an unforgeable signature primitive.
//   * The `SigningScheme` public-key and signature decoders, with each distinct failure cause.
//   * The whole `VerifierExt` certificate-verification decision tree, in code order.
//   * Totality: every verification and every decode is total over arbitrary, adversary-supplied
//     input; none of them is a partial function or carries a caller-established precondition.
//
// WHAT IS NOT MODELLED
//   * Cryptographic forgery or malleability of Ed25519 / ECDSA itself. This component does not
//     implement curve arithmetic; it delegates to `ed25519-consensus` and `k256`/`p256`/`p384`,
//     and the primitive is assumed EUF-CMA secure. KEY COMPROMISE IS modelled.
//   * The base64/JSON `serializers/` subtrees — a second encoding layer over the same bytes,
//     which round-trips through the `encode`/`decode` pair modelled here.
//   * Per-curve dispatch differences between k256/p256/p384 — one parameterised curve id
//     rather than three copies of mechanical delegation.
//
// THRESHOLDS are classic Tendermint, exactly as `core-types/src/threshold.rs:54-57` defines
// them: n > 3f, quorum = `TWO_F_PLUS_ONE` = 2/3 of total voting power, honest = `F_PLUS_ONE`
// = 1/3, and `is_met` is STRICTLY greater (`weight * den > total * num`).

module signingCore {
  import basicSpells.* from "./spells/basicSpells"

  // ---------------------------------------------------------------------------
  // Types
  // ---------------------------------------------------------------------------

  /// A private key's identity. Its public key carries the same id.
  type KeyId = int

  /// One abstract byte-field of a signed preimage.
  type Token = int

  /// The exact byte sequence that gets signed.
  type Preimage = List[Token]

  /// A wire encoding of a key or a signature, valid or malformed. `len` is the byte
  /// length the decoder checks, `key` the key it encodes, `curve` the curve it claims,
  /// `on_curve` whether the point is a real curve point.
  type Bytes = { len: int, key: int, curve: int, on_curve: bool }

  /// A signature. The underlying scheme is assumed unforgeable, so a signature value is
  /// exactly "who signed" plus "what they signed", and verification is structural equality.
  /// `signer == FORGED_SIGNER` stands for bytes that no private key produced.
  type Sig = { signer: int, preimage: Preimage }

  type Addr = int

  type Purpose = PVote | PProposal | PExtension | PProof

  /// The fields of a vote. `ext` is the extension attached to it (-1 for none); the
  /// signing encoding deliberately drops it (test/src/vote.rs:55-62).
  /// `typ` is an int TOKEN, not a variant: this record travels in a logged payload, and
  /// a payload-free variant nested inside a record has no bare-name encoding there — so
  /// no logged record could ever match a variant-typed field.
  type VoteFields =
    { typ: int, height: int, round: int, value: int, addr: Addr, ext: int }

  /// The fields of a proposal, as `Proposal::to_sign_bytes` encodes them.
  type ProposalFields =
    { height: int, round: int, value: int, pol_round: int, addr: Addr }

  /// A `VoteExtensionScope`: height, round, value id, validator address.
  type Scope = { height: int, round: int, value: int, addr: Addr }

  /// One certificate entry — an address, the vote type and value it signed, its vote
  /// signature, and optionally an attached vote extension. A round certificate's
  /// signatures each name their own value (`RoundSignature::value_id`), so the value
  /// lives on the entry; every other kind reconstructs the certificate's own value.
  /// The attached vote extension is FLATTENED rather than an `Option`: `ext_value ==
  /// NO_EXT` means no extension is attached, and `ext_sig` is then unused. A
  /// payload-carrying variant has no logged encoding, so an `Option` here would make
  /// the certificate payload unreplayable.
  type Entry =
    { addr: Addr, typ: int, value: int,
      sig_signer: int, sig_covers: bool,
      ext_value: int, ext_sig_signer: int, ext_sig_covers: bool }

  /// A certificate as it arrives off the wire.
  /// `kind` and `policy` are int tokens, for the same reason as `VoteFields.typ`.
  type Cert = { kind: int, height: int, round: int, value: int,
                entries: List[Entry], policy: int }

  type Validator = { key: KeyId, power: int }

  type Threshold = { num: int, den: int }

  /// Every `CertificateError` variant the verification tree can produce.
  type CertError =
    | DuplicateVote
    | UnknownValidator
    | InvalidCommitSignature
    | MissingVoteExtension
    | UnexpectedVoteExtension
    | InvalidVoteExtensionSignature
    | InvalidVoteType
    | VotingPowerOverflow
    | NotEnoughVotingPower

  /// The result of any verification entry point. Total: every input lands on one arm.
  type Outcome = Valid | Invalid | VerifyErr | CertErr(CertError)

  type DecodeCause = WrongLength | NotOnCurve | WrongCurve

  /// The result of a `SigningScheme` decode. Total over arbitrary bytes.
  type DecodeResult = Decoded(int) | DecodeFailed(DecodeCause)

  /// What a signer signed, recorded at signing time: the purpose, the exact bytes, the
  /// key, the network the node was on, and the logical subject (the peer id, for a
  /// validator proof) so cross-network claims can be stated over the same subject.
  type SignRecord =
    { purpose: Purpose, preimage: Preimage, key: KeyId, net: int, subject: int }

  /// What a verifier accepted: the exact bytes, the key, and the network it was on.
  type AcceptRecord = { preimage: Preimage, key: KeyId, net: int }

  /// Every distinct outcome class the code can reach, latched as a ghost so that
  /// silent paths (a decode cause, a rejection reason) become observable.
  type Event =
    | VoteSigned | ProposalSigned | ExtensionSigned | ProofSigned
    | VoteValid | VoteInvalidWrongKey | VoteInvalidWrongMessage
    | ProposalValid | ProposalInvalid
    | ExtensionValid | ExtensionInvalidWrongScope
    | ProofValid | ProofInvalidTampered | ProofDecodeError
    | KeyDecoded | KeyDecodeWrongLength | KeyDecodeNotOnCurve | KeyDecodeWrongCurve
    | SigDecoded | SigDecodeWrongLength
    | CommitAccepted | ExtendedAcceptedWithExts | ExtendedAcceptedWithoutExts
    | PolkaAccepted | RoundPrecommitAccepted | SkipAccepted | SkipAcceptedBelowQuorum
    | CertRejDuplicate | CertRejUnknownValidator | CertRejInvalidSignature
    | CertRejInsufficientPower | CertRejMissingExtension | CertRejUnexpectedExtension
    | CertRejInvalidExtensionSignature | CertRejInvalidVoteType | CertRejOverflow
    | EmptySignatureSetRejected
    | SingleSignatureEntryPointUsed | KeyCompromised

  /// The whole signing world: keys, the values an adversary can present, the configured
  /// validator set, the certificate under construction, and the verification ghosts.
  type World = {
    issued: Set[Sig],
    compromised: Set[KeyId],
    wild: Set[Sig],
    byte_pool: Set[Bytes],
    validators: Addr -> Validator,
    network: int,
    pending: Cert,
    accepted: Set[Cert],
    signed_log: Set[SignRecord],
    signed_votes: Set[{ key: KeyId, vote: VoteFields }],
    signed_proposals: Set[{ key: KeyId, proposal: ProposalFields }],
    signed_exts: Set[{ key: KeyId, scope: Scope, ext: int }],
    signed_proofs: Set[{ key: KeyId, pk: Bytes, peer: int }],
    outcomes: List[Outcome],
    calls: int,
    signings: int,
    events: Set[Event],
    accepted_sigs: Set[AcceptRecord],
  }

  // ---------------------------------------------------------------------------
  // Constants and domains
  // ---------------------------------------------------------------------------

  /// Protobuf field tags of a vote. Distinct from every proposal tag.
  pure val TAG_V_TYP: Token = 101
  pure val TAG_V_HEIGHT: Token = 102
  pure val TAG_V_ROUND: Token = 103
  pure val TAG_V_VALUE: Token = 104
  pure val TAG_V_ADDR: Token = 105

  /// Protobuf field tags of a proposal.
  pure val TAG_P_HEIGHT: Token = 201
  pure val TAG_P_ROUND: Token = 202
  pure val TAG_P_VALUE: Token = 203
  pure val TAG_P_POLROUND: Token = 204
  pure val TAG_P_ADDR: Token = 205

  /// `b"malachitebft/vote-extension/v1\0"` (test/src/signing.rs:19).
  pure val DOMAIN_VOTE_EXT: Token = 301
  /// `b"PoV"` (core-types/src/validator_proof.rs:10).
  pure val DOMAIN_POV: Token = 302

  /// Bytes no private key ever produced: a fabricated or tampered signature.
  pure val FORGED_SIGNER: int = -1

  /// No extension attached to a vote.
  pure val NO_EXT: int = -1

  /// The value field of a vote for nil. A token no concrete value id takes, so a nil
  /// vote's preimage is never equal to the preimage of a vote for a real value.
  pure val NIL_VALUE: int = -2

  pure val KEY_LEN: int = 32
  pure val SIG_LEN: int = 64
  pure val LOCAL_CURVE: int = 1
  pure val OTHER_CURVE: int = 2

  /// The accumulator bound `checked_add` guards (ext.rs:295-300). `VotingPower` is a
  /// `u64`, whose maximum the evaluator cannot hold, so the bound is modelled at this
  /// value and the instrumentation SATURATES any real power at it. That preserves the
  /// behaviour class exactly: `invalid_commit_certificate_signed_voting_power_overflow`
  /// builds `[u64::MAX, 1]`, which arrives as `[POWER_MAX, 1]` and overflows on the
  /// SECOND add — the same step the real `checked_add` fails on.
  pure val POWER_MAX: int = 1000000

  /// Identities are projected onto these domains in first-seen order per test, so the
  /// sets are sized for the real suite's fan-out, not for one scenario.
  /// `commit_certificate_validator_set_mismatch` builds TWO sets of four validators, so
  /// a single test can name eight distinct keys and addresses; the widest single set is
  /// seven (`with_validators([20; 7])`). Ten leaves headroom and keeps a spare address
  /// that is in no set, so `UnknownValidator` stays reachable.
  pure val KEYS: Set[KeyId] = Set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
  pure val ADDRS: Set[Addr] = Set(0, 1, 2, 3, 4, 5, 6, 7, 8, 9)

  /// Every voting power the certificate suite's `with_validators([...])` calls produce,
  /// plus `POWER_MAX` so the `checked_add` overflow arm stays reachable in simulation.
  /// Every voting power the certificate suite's `with_validators([...])` calls produce,
  /// including the `u64::MAX` the overflow test uses.
  pure val POWERS: Set[int] =
    Set(0, 1, 5, 10, 12, 15, 16, 19, 20, 21, 22, 23, 24, 25, 29, 30, 31, 32,
        33, 34, 35, 36, 40, 50, 75, 90, POWER_MAX)
  pure val HEIGHTS: Set[int] = Set(1, 2, 3)
  pure val ROUNDS: Set[int] = Set(0, 1, 2)
  /// Concrete value ids. A proposal and a `VoteExtensionScope` always name one.
  pure val VALUES: Set[int] = Set(0, 1, 2)
  /// A vote's value field, and a round certificate's: either a concrete id or nil.
  pure val VOTE_VALUES: Set[int] = VALUES.union(Set(NIL_VALUE))
  pure val EXTS: Set[int] = Set(0, 1, 2, 3)
  pure val PEERS: Set[int] = Set(0, 1, 2)
  pure val NETWORKS: Set[int] = Set(1, 2)
  pure val VOTE_TYPES: Set[int] = Set(TYP_PREVOTE, TYP_PRECOMMIT)
  pure val CERT_KINDS: Set[int] =
    Set(KIND_COMMIT, KIND_EXTENDED_COMMIT, KIND_POLKA, KIND_ROUND_PRECOMMIT, KIND_ROUND_SKIP)
  pure val EXT_POLICIES: Set[int] = Set(POLICY_DISABLED, POLICY_REQUIRED)

  /// Vote-type tokens, as they appear both in a preimage and in a logged payload.
  pure val TYP_PREVOTE: int = 1
  pure val TYP_PRECOMMIT: int = 2

  /// Certificate-kind tokens, one per public verification entry point.
  pure val KIND_COMMIT: int = 1
  pure val KIND_EXTENDED_COMMIT: int = 2
  pure val KIND_POLKA: int = 3
  pure val KIND_ROUND_PRECOMMIT: int = 4
  pure val KIND_ROUND_SKIP: int = 5

  /// Vote-extension policy tokens.
  pure val POLICY_DISABLED: int = 0
  pure val POLICY_REQUIRED: int = 1

  pure val QUORUM: Threshold = { num: 2, den: 3 }
  pure val HONEST: Threshold = { num: 1, den: 3 }

  /// Field combinations for votes, offered as ONE pick. `ext` covers both an attached
  /// extension and none, so the "the encoding drops it" claim is falsifiable.
  pure val VOTE_FIELDS: Set[VoteFields] =
    VOTE_TYPES.map(t => HEIGHTS.map(h => ROUNDS.map(r => VOTE_VALUES.map(v =>
      ADDRS.map(a => Set(NO_EXT, 0).map(e =>
        { typ: t, height: h, round: r, value: v, addr: a, ext: e }))))))
      .flatten().flatten().flatten().flatten().flatten()

  /// Field combinations for proposals, offered as ONE pick.
  pure val PROPOSAL_FIELDS: Set[ProposalFields] =
    HEIGHTS.map(h => ROUNDS.map(r => VALUES.map(v => ROUNDS.map(pr =>
      ADDRS.map(a =>
        { height: h, round: r, value: v, pol_round: pr, addr: a })))))
      .flatten().flatten().flatten().flatten()

  /// Vote-extension scopes, offered as ONE pick.
  pure val SCOPES: Set[Scope] =
    HEIGHTS.map(h => ROUNDS.map(r => VALUES.map(v => ADDRS.map(a =>
      { height: h, round: r, value: v, addr: a }))))
      .flatten().flatten().flatten()

  /// A well-formed public-key encoding.
  pure def encode_public_key(k: KeyId): Bytes =
    { len: KEY_LEN, key: k, curve: LOCAL_CURVE, on_curve: true }

  /// A well-formed signature encoding.
  pure def encode_signature(s: Sig): Bytes =
    { len: SIG_LEN, key: s.signer, curve: LOCAL_CURVE, on_curve: true }

  /// Byte lengths that are not a public key at all.
  pure val WRONG_KEY_LENS: Set[int] = Set(0, 16, 31, 33, 64)

  /// The encodings offered to the decoders: the well-formed ones plus every malformed
  /// shape the network can present — empty, truncated, over-long, a valid-length
  /// non-curve point (the `INVALID_ED25519_POINT` unit test), and a wrong-curve SEC1
  /// encoding.
  ///
  /// Each shape carries exactly what the projection produces for it: bytes that are not
  /// `KEY_LEN` long cannot name a key, so they take `FORGED_SIGNER` and are not on the
  /// curve. Describing them any other way makes a real logged value unrepresentable.
  pure val CANDIDATE_KEY_BYTES: Set[Bytes] =
    KEYS.map(k => encode_public_key(k))
      .union(WRONG_KEY_LENS.map(l =>
        { len: l, key: FORGED_SIGNER, curve: LOCAL_CURVE, on_curve: false }))
      .union(KEYS.map(k =>
        { len: KEY_LEN, key: k, curve: LOCAL_CURVE, on_curve: false }))
      .union(KEYS.map(k =>
        { len: KEY_LEN, key: k, curve: OTHER_CURVE, on_curve: true }))

  /// Signature encodings. A signature is never `KEY_LEN` long, so it never names a key.
  pure val CANDIDATE_SIG_BYTES: Set[Bytes] =
    Set({ len: SIG_LEN, key: FORGED_SIGNER, curve: LOCAL_CURVE, on_curve: true },
        { len: 0, key: FORGED_SIGNER, curve: LOCAL_CURVE, on_curve: false },
        { len: 63, key: FORGED_SIGNER, curve: LOCAL_CURVE, on_curve: false },
        { len: 65, key: FORGED_SIGNER, curve: LOCAL_CURVE, on_curve: false })

  /// The validator set a node starts with: the one
  /// `valid_commit_certificate_with_exact_threshold_voting_power` pins, zero-power
  /// validator included.
  pure val VS_EXACT: Addr -> Validator =
    Map(0 -> { key: 0, power: 21 }, 1 -> { key: 1, power: 22 },
        2 -> { key: 2, power: 24 }, 3 -> { key: 3, power: 0 })

  // ---------------------------------------------------------------------------
  // Preimage construction — the heart of the component
  // ---------------------------------------------------------------------------

  pure def bytes_tokens(b: Bytes): Preimage =
    List(b.len, b.key, b.curve, if (b.on_curve) 1 else 0)

  /// Vote preimage: the bare protobuf field pairs of `Vote::to_sign_bytes`
  /// (test/src/vote.rs:55-62). NO domain tag, NO network material, and the attached
  /// extension is deliberately excluded from the encoding.
  pure def vote_preimage(v: VoteFields): Preimage =
    List(TAG_V_TYP, v.typ, TAG_V_HEIGHT, v.height, TAG_V_ROUND, v.round,
         TAG_V_VALUE, v.value, TAG_V_ADDR, v.addr)

  /// Proposal preimage: the bare protobuf field pairs of `Proposal::to_sign_bytes`
  /// (test/src/proposal.rs:34). Distinct field tags, no domain tag, no network material.
  pure def proposal_preimage(p: ProposalFields): Preimage =
    List(TAG_P_HEIGHT, p.height, TAG_P_ROUND, p.round, TAG_P_VALUE, p.value,
         TAG_P_POLROUND, p.pol_round, TAG_P_ADDR, p.addr)

  /// Vote-extension preimage: `DOMAIN || len(precommit) || precommit || len(ext) || ext`
  /// (test/src/signing.rs:19-53). The scope is bound through the reconstructed precommit,
  /// so all four scope fields are covered.
  pure def extension_preimage(s: Scope, ext: int): Preimage =
    val precommit =
      vote_preimage({ typ: TYP_PRECOMMIT, height: s.height, round: s.round,
                      value: s.value, addr: s.addr, ext: NO_EXT })
    List(DOMAIN_VOTE_EXT, precommit.length()).concat(precommit).concat(List(1, ext))

  /// Validator-proof preimage: `"PoV" || len(pk) || pk || len(peer) || peer`
  /// (core-types/src/validator_proof.rs:48-57). Deliberately network-agnostic.
  pure def pov_preimage(pk: Bytes, peer: int): Preimage =
    List(DOMAIN_POV, pk.len).concat(bytes_tokens(pk)).concat(List(1, peer))

  /// A validator proof's logical subject: the exact public-key bytes it binds together
  /// with the peer id. Injective over the modelled domains.
  pure def pov_subject(pk: Bytes, peer: int): int =
    pk.len * 10000 + pk.key * 1000 + pk.curve * 100 + (if (pk.on_curve) 10 else 0) + peer

  /// Structural verification. The scheme is assumed unforgeable, so a signature
  /// verifies exactly when it was produced by this key over these bytes.
  pure def verifies(sig: Sig, preimage: Preimage, key: KeyId): bool =
    sig.signer == key and sig.preimage == preimage

  // ---------------------------------------------------------------------------
  // SigningScheme codecs — total over arbitrary bytes
  // ---------------------------------------------------------------------------

  /// `SigningScheme::decode_public_key`. Ed25519 checks the slice length first
  /// (`InvalidSliceLength`, signing-ed25519/src/lib.rs:52-56) and then the curve point;
  /// the ECDSA SEC1 path additionally rejects a key from the wrong curve.
  pure def decode_public_key(b: Bytes): DecodeResult =
    if (b.len != KEY_LEN) DecodeFailed(WrongLength)
    else if (not(b.on_curve)) DecodeFailed(NotOnCurve)
    else if (b.curve != LOCAL_CURVE) DecodeFailed(WrongCurve)
    else Decoded(b.key)

  /// `SigningScheme::decode_signature`.
  pure def decode_signature(b: Bytes): DecodeResult =
    if (b.len != SIG_LEN) DecodeFailed(WrongLength) else Decoded(b.key)

  pure def decode_ok(r: DecodeResult): bool =
    match r { | Decoded(_) => true | DecodeFailed(_) => false }

  pure def decoded_key(r: DecodeResult): int =
    match r { | Decoded(k) => k | DecodeFailed(_) => FORGED_SIGNER }

  pure def key_decode_event(r: DecodeResult): Event =
    match r {
      | Decoded(_) => KeyDecoded
      | DecodeFailed(cause) =>
        match cause {
          | WrongLength => KeyDecodeWrongLength
          | NotOnCurve => KeyDecodeNotOnCurve
          | WrongCurve => KeyDecodeWrongCurve
        }
    }

  // ---------------------------------------------------------------------------
  // Certificate verification — ext.rs, in code order
  // ---------------------------------------------------------------------------

  pure def threshold_of(kind: int): Threshold =
    if (kind == KIND_ROUND_SKIP) HONEST else QUORUM

  /// `Threshold::is_met` — strictly greater (core-types/src/threshold.rs:68-78).
  pure def is_met(weight: int, total: int, t: Threshold): bool =
    weight * t.den > total * t.num

  pure def total_power(vals: Addr -> Validator): int =
    vals.keys().fold(0, (acc, a) => acc + vals.get(a).power)

  /// Only `ExtendedCommitSignature` carries an extension; `CommitSignature::extension()`
  /// returns None for every other certificate kind (ext.rs:146-152).
  /// Whether this entry carries a vote extension the verifier will look at.
  pure def has_effective_ext(c: Cert, e: Entry): bool =
    c.kind == KIND_EXTENDED_COMMIT and e.ext_value != NO_EXT

  /// `VoteExtensionPolicy` only applies on the extended-commit path; the plain commit
  /// path hardcodes `Disabled` (ext.rs:341).
  pure def effective_policy(c: Cert): int =
    if (c.kind == KIND_EXTENDED_COMMIT) c.policy else POLICY_DISABLED

  /// The vote the verifier reconstructs for an entry: a prevote for a polka certificate,
  /// the entry's own vote type for a round certificate, a precommit otherwise.
  pure def expected_vote_typ(c: Cert, typ: int): int =
    if (c.kind == KIND_POLKA) TYP_PREVOTE
    else if (c.kind == KIND_ROUND_PRECOMMIT or c.kind == KIND_ROUND_SKIP) typ
    else TYP_PRECOMMIT

  pure def expected_vote_for(c: Cert, typ: int, value: int, addr: Addr): VoteFields =
    val v = if (c.kind == KIND_ROUND_PRECOMMIT or c.kind == KIND_ROUND_SKIP) value else c.value
    { typ: expected_vote_typ(c, typ), height: c.height, round: c.round,
      value: v, addr: addr, ext: NO_EXT }

  pure def expected_vote(c: Cert, e: Entry, addr: Addr): VoteFields =
    expected_vote_for(c, e.typ, e.value, addr)

  /// The `VoteExtensionScope` the verifier forms for an entry.
  pure def entry_scope(c: Cert, addr: Addr): Scope =
    { height: c.height, round: c.round, value: c.value, addr: addr }

  type CertAcc = { err: Option[CertError], seen: Set[Addr], power: int, exts: int }

  pure val EMPTY_ACC: CertAcc = { err: None, seen: Set(), power: 0, exts: 0 }

  /// One iteration of the verification loop, in the code's order: duplicate address,
  /// unknown validator, vote type, vote signature, extension policy, extension
  /// signature, overflow-checked power accumulation. Once an error is set the loop has
  /// returned, so later entries leave the accumulator untouched.
  pure def step_entry(acc: CertAcc, e: Entry, c: Cert, vals: Addr -> Validator): CertAcc =
    if (acc.err != None) acc
    else if (acc.seen.contains(e.addr)) { ...acc, err: Some(DuplicateVote) }
    else if (not(vals.keys().contains(e.addr))) { ...acc, err: Some(UnknownValidator) }
    else if (c.kind == KIND_ROUND_PRECOMMIT and e.typ == TYP_PREVOTE)
      { ...acc, err: Some(InvalidVoteType) }
    else
      val v = vals.get(e.addr)
      val seen2 = acc.seen.union(Set(e.addr))
      val overflows = acc.power + v.power > POWER_MAX
      if (not(e.sig_covers and e.sig_signer == v.key))
        { ...acc, err: Some(InvalidCommitSignature), seen: seen2 }
      else
        val scope = entry_scope(c, e.addr)
        if (not(has_effective_ext(c, e)))
          if (effective_policy(c) == POLICY_REQUIRED)
            { ...acc, err: Some(MissingVoteExtension), seen: seen2 }
          else if (overflows) { ...acc, err: Some(VotingPowerOverflow), seen: seen2 }
          else { ...acc, seen: seen2, power: acc.power + v.power }
        else if (effective_policy(c) == POLICY_DISABLED)
          { ...acc, err: Some(UnexpectedVoteExtension), seen: seen2 }
        else if (not(e.ext_sig_covers and e.ext_sig_signer == v.key))
          { ...acc, err: Some(InvalidVoteExtensionSignature), seen: seen2 }
        else if (overflows) { ...acc, err: Some(VotingPowerOverflow), seen: seen2 }
        else { ...acc, seen: seen2, power: acc.power + v.power, exts: acc.exts + 1 }

  pure def cert_acc(c: Cert, vals: Addr -> Validator): CertAcc =
    c.entries.foldl(EMPTY_ACC, (acc, e) => step_entry(acc, e, c, vals))

  /// `verify_*_certificate`. TOTAL: every certificate value, however malformed, lands
  /// on exactly one arm — `Valid` or a typed `CertificateError`.
  pure def cert_outcome(c: Cert, vals: Addr -> Validator): Outcome =
    val acc = cert_acc(c, vals)
    match acc.err {
      | Some(err) => CertErr(err)
      | None =>
        if (is_met(acc.power, total_power(vals), threshold_of(c.kind))) Valid
        else CertErr(NotEnoughVotingPower)
    }

  /// The single-signature entry points (`verify_commit_signature`, `verify_polka_signature`,
  /// `verify_round_signature`) — one entry, no quorum check.
  pure def single_signature_outcome(addr: Addr, sig_signer: int, sig_covers: bool,
                                    vals: Addr -> Validator): Outcome =
    if (not(vals.keys().contains(addr))) CertErr(UnknownValidator)
    else if (not(sig_covers and sig_signer == vals.get(addr).key))
      CertErr(InvalidCommitSignature)
    else Valid

  pure def accept_events(c: Cert, acc: CertAcc, vals: Addr -> Validator): Set[Event] =
    if (c.kind == KIND_COMMIT) Set(CommitAccepted)
    else if (c.kind == KIND_EXTENDED_COMMIT)
      if (acc.exts > 0) Set(ExtendedAcceptedWithExts) else Set(ExtendedAcceptedWithoutExts)
    else if (c.kind == KIND_POLKA) Set(PolkaAccepted)
    else if (c.kind == KIND_ROUND_PRECOMMIT) Set(RoundPrecommitAccepted)
    else if (is_met(acc.power, total_power(vals), QUORUM)) Set(SkipAccepted)
    else Set(SkipAccepted, SkipAcceptedBelowQuorum)

  pure def reject_event(err: CertError): Event =
    match err {
      | DuplicateVote => CertRejDuplicate
      | UnknownValidator => CertRejUnknownValidator
      | InvalidCommitSignature => CertRejInvalidSignature
      | MissingVoteExtension => CertRejMissingExtension
      | UnexpectedVoteExtension => CertRejUnexpectedExtension
      | InvalidVoteExtensionSignature => CertRejInvalidExtensionSignature
      | InvalidVoteType => CertRejInvalidVoteType
      | VotingPowerOverflow => CertRejOverflow
      | NotEnoughVotingPower => CertRejInsufficientPower
    }

  /// The events a certificate verification latches.
  pure def cert_events(c: Cert, vals: Addr -> Validator): Set[Event] =
    val acc = cert_acc(c, vals)
    val empty_ev = if (c.entries.length() == 0) Set(EmptySignatureSetRejected) else Set()
    match acc.err {
      | Some(err) => Set(reject_event(err)).union(empty_ev)
      | None =>
        if (is_met(acc.power, total_power(vals), threshold_of(c.kind)))
          accept_events(c, acc, vals)
        else Set(CertRejInsufficientPower).union(empty_ev)
    }

  /// One entry signed by the validator the verifier will look up: the vote it
  /// reconstructs, plus optionally a vote extension over the entry's own scope.
  pure def signed_entry(c: Cert, vals: Addr -> Validator, addr: Addr, typ: int,
                        with_ext: bool, ev: int, valid_ext: bool): Entry =
    val key = vals.get(addr).key
    { addr: addr, typ: expected_vote_typ(c, typ), value: c.value,
      sig_signer: key, sig_covers: true,
      ext_value: if (with_ext) ev else NO_EXT,
      ext_sig_signer: if (valid_ext) key else FORGED_SIGNER,
      ext_sig_covers: valid_ext }

  /// `CertificateBuilder::with_votes(0..n)` — the bulk form the certificate unit tests
  /// use: one signed entry for EVERY validator in the set.
  pure def all_signed_entries(c: Cert, vals: Addr -> Validator, typ: int,
                              with_ext: bool, ev: int, valid_ext: bool): List[Entry] =
    vals.keys().fold(List(), (l, a) =>
      l.append(signed_entry(c, vals, a, typ, with_ext, ev, valid_ext)))

  /// Every signature carried by a list of entries.
  pure def empty_cert(kind: int, height: int, round: int, value: int,
                      policy: int): Cert =
    { kind: kind, height: height, round: round, value: value,
      entries: List(), policy: policy }

  /// The signatures an adversary can present: everything it saw plus everything it made.
  pure def presented(w: World): Set[Sig] = w.wild.union(w.issued)

  pure val initial_world: World = {
    issued: Set(),
    compromised: Set(),
    wild: Set(),
    byte_pool: CANDIDATE_KEY_BYTES.union(CANDIDATE_SIG_BYTES),
    validators: VS_EXACT,
    network: 1,
    pending: empty_cert(KIND_COMMIT, 1, 0, 0, POLICY_DISABLED),
    accepted: Set(),
    signed_log: Set(),
    signed_votes: Set(),
    signed_proposals: Set(),
    signed_exts: Set(),
    signed_proofs: Set(),
    outcomes: List(),
    calls: 0,
    signings: 0,
    events: Set(),
    accepted_sigs: Set(),
  }
}

module signing {
  import basicSpells.* from "./spells/basicSpells"
  import signingCore.*

  /// The whole signing world.
  var w: World

  action init: bool = w' = initial_world

  // ---------------------------------------------------------------------------
  // Signing
  // ---------------------------------------------------------------------------

  pure def record_signature(world: World, sig: Sig, purpose: Purpose, subject: int,
                            ev: Event): World =
    { ...world,
      issued: world.issued.union(Set(sig)),
      signed_log: world.signed_log.union(
        Set({ purpose: purpose, preimage: sig.preimage, key: sig.signer,
              net: world.network, subject: subject })),
      signings: world.signings + 1,
      events: world.events.union(Set(ev)) }

  /// `Signer::sign_vote` (test/src/signing.rs:208-211).
  action sign_vote(key: KeyId, vote: VoteFields): bool = all {
    val world = record_signature(w, { signer: key, preimage: vote_preimage(vote) },
                                 PVote, vote.value, VoteSigned)
    w' = { ...world, signed_votes: world.signed_votes.union(Set({ key: key, vote: vote })) },
  }

  /// `Signer::sign_proposal` (test/src/signing.rs:213-219).
  action sign_proposal(key: KeyId, proposal: ProposalFields): bool = all {
    val world = record_signature(w, { signer: key, preimage: proposal_preimage(proposal) },
                                 PProposal, proposal.value, ProposalSigned)
    w' = { ...world,
           signed_proposals:
             world.signed_proposals.union(Set({ key: key, proposal: proposal })) },
  }

  /// `Signer::sign_vote_extension` (test/src/signing.rs:221-230).
  action sign_vote_extension(key: KeyId, scope: Scope, ext: int): bool = all {
    val world = record_signature(w, { signer: key, preimage: extension_preimage(scope, ext) },
                                 PExtension, ext, ExtensionSigned)
    w' = { ...world,
           signed_exts:
             world.signed_exts.union(Set({ key: key, scope: scope, ext: ext })) },
  }

  /// `Signer::sign_validator_proof` (test/src/signing.rs:232-241). The public key bytes
  /// it binds are whatever the caller passed, valid or not, so they also enter the
  /// decoder's input pool.
  action sign_validator_proof(key: KeyId, pk_bytes: Bytes, peer_id: int): bool = all {
    val world = record_signature(w, { signer: key, preimage: pov_preimage(pk_bytes, peer_id) },
                                 PProof, pov_subject(pk_bytes, peer_id), ProofSigned)
    w' = { ...world,
           byte_pool: world.byte_pool.union(Set(pk_bytes)),
           signed_proofs:
             world.signed_proofs.union(Set({ key: key, pk: pk_bytes, peer: peer_id })) },
  }

  /// `Ed25519::generate_keypair` / `Ecdsa::generate_keypair`.
  action generate_keypair(key: KeyId): bool = all {
    w' = { ...w, byte_pool: w.byte_pool.union(Set(encode_public_key(key))) },
  }

  // ---------------------------------------------------------------------------
  // Verification — total over every presented value
  // ---------------------------------------------------------------------------

  pure def record_verification(world: World, ok: bool, outcome: Outcome, ev: Event,
                               preimage: Preimage, key: KeyId): World =
    { ...world,
      outcomes: world.outcomes.append(outcome),
      calls: world.calls + 1,
      events: world.events.union(Set(ev)),
      accepted_sigs:
        if (ok) world.accepted_sigs.union(
                  Set({ preimage: preimage, key: key, net: world.network }))
        else world.accepted_sigs }

  /// `Verifier::verify_signed_vote` (test/src/signing.rs:85-94). A guarded READ: the
  /// only guard is that the signature is a value someone actually presented; the
  /// verification itself is total over that value.
  /// `sig_signer` is the key that produced the bytes, or `FORGED_SIGNER` for bytes no
  /// key made; `sig_covers` is whether they cover the message being checked. A signature
  /// cannot be inverted, so those two are everything a verifier — or the instrumentation
  /// watching one — can know, and together they separate all three outcomes. TOTAL: no
  /// guard at all, because the real verifier has no precondition on the bytes.
  action verify_signed_vote(vote: VoteFields, sig_signer: int, sig_covers: bool,
                            key: KeyId): bool = {
    val pre = vote_preimage(vote)
    val ok = sig_covers and sig_signer == key
    val ev =
      if (ok) VoteValid
      else if (sig_covers) VoteInvalidWrongKey
      else VoteInvalidWrongMessage
    w' = record_verification(w, ok, if (ok) Valid else Invalid, ev, pre, key)
  }

  /// `Verifier::verify_signed_proposal` (test/src/signing.rs:96-107).
  action verify_signed_proposal(proposal: ProposalFields, sig_signer: int,
                                sig_covers: bool, key: KeyId): bool = {
    val pre = proposal_preimage(proposal)
    val ok = sig_covers and sig_signer == key
    w' = record_verification(w, ok, if (ok) Valid else Invalid,
                             if (ok) ProposalValid else ProposalInvalid, pre, key)
  }

  /// `Verifier::verify_signed_vote_extension` (test/src/signing.rs:109-121).
  action verify_signed_vote_extension(scope: Scope, ext: int, sig_signer: int,
                                      sig_covers: bool, key: KeyId): bool = {
    val pre = extension_preimage(scope, ext)
    val ok = sig_covers and sig_signer == key
    w' = record_verification(w, ok, if (ok) Valid else Invalid,
                             if (ok) ExtensionValid else ExtensionInvalidWrongScope,
                             pre, key)
  }

  /// `Verifier::verify_validator_proof` (test/src/signing.rs:123-136). Three arms: the
  /// embedded public key is decoded FIRST, and a decode failure is an `Err`, not `Invalid`.
  action verify_validator_proof(pk_bytes: Bytes, peer_id: int, sig_signer: int,
                                sig_covers: bool): bool = {
    val dec = decode_public_key(pk_bytes)
    val pre = pov_preimage(pk_bytes, peer_id)
    val ok = decode_ok(dec) and sig_covers and sig_signer == decoded_key(dec)
    val outcome = if (not(decode_ok(dec))) VerifyErr else if (ok) Valid else Invalid
    val ev =
      if (not(decode_ok(dec))) ProofDecodeError
      else if (ok) ProofValid
      else ProofInvalidTampered
    w' = record_verification(w, ok, outcome, ev, pre, decoded_key(dec))
  }

  /// `SigningScheme::decode_public_key` — total over arbitrary bytes.
  action decode_public_key_op(b: Bytes): bool = all {
    w.byte_pool.contains(b),
    val dec = decode_public_key(b)
    w' = { ...w,
           outcomes: w.outcomes.append(if (decode_ok(dec)) Valid else VerifyErr),
           calls: w.calls + 1,
           events: w.events.union(Set(key_decode_event(dec))) },
  }

  /// `SigningScheme::decode_signature` — total over arbitrary bytes.
  action decode_signature_op(b: Bytes): bool = all {
    w.byte_pool.contains(b),
    val dec = decode_signature(b)
    w' = { ...w,
           outcomes: w.outcomes.append(if (decode_ok(dec)) Valid else VerifyErr),
           calls: w.calls + 1,
           events: w.events.union(
             Set(if (decode_ok(dec)) SigDecoded else SigDecodeWrongLength)) },
  }

  // ---------------------------------------------------------------------------
  // Certificate assembly and verification
  // ---------------------------------------------------------------------------

  /// Begin installing a validator set: drop whatever was configured before.
  ///
  /// The set arrives one validator at a time rather than as a single payload, because
  /// the real suite builds 21 different power arrays over up to seven validators and no
  /// enumerable set of maps could hold them all. Every pick here is a small scalar the
  /// log pins exactly.
  action begin_validator_set: bool =
    w' = { ...w, validators: Map() }

  /// Install one validator into the set being built.
  action add_validator(addr: Addr, key: KeyId, power: int): bool = all {
    not(w.validators.keys().contains(addr)),
    w' = { ...w,
           validators: w.validators.put(addr, { key: key, power: power }),
           byte_pool: w.byte_pool.union(Set(encode_public_key(key))) },
  }

  /// Test-side certificate assembly (`CertificateBuilder`). Sim machinery: it has no
  /// oracle log site — the certificate reaches `verify_certificate` as one payload.
  action begin_certificate(kind: int, height: int, round: int, value: int,
                           policy: int): bool =
    w' = { ...w, pending: empty_cert(kind, height, round, value, policy) }

  /// Append an entry to the certificate under construction. This is also the
  /// malformed-certificate adversary action: the address may be a duplicate or unknown,
  /// the vote type wrong for the kind, the signature any presented value, and the
  /// extension present or absent regardless of policy.
  action add_certificate_entry(addr: Addr, typ: int, value: int, sig_signer: int,
                               sig_covers: bool, ext_value: int, ext_sig_signer: int,
                               ext_sig_covers: bool): bool =
    w' = { ...w,
           pending: { ...w.pending,
                      entries: w.pending.entries.append(
                        { addr: addr, typ: typ, value: value,
                          sig_signer: sig_signer, sig_covers: sig_covers,
                          ext_value: ext_value, ext_sig_signer: ext_sig_signer,
                          ext_sig_covers: ext_sig_covers }) } }

  /// Sign the vote the verifier will reconstruct for this validator and append the entry
  /// — exactly what `CertificateBuilder::with_votes` does in the certificate unit tests.
  /// Sim machinery: the certificate reaches `verify_certificate` as one payload.
  action add_signed_entry(addr: Addr, typ: int): bool = all {
    w.validators.keys().contains(addr),
    val v = w.validators.get(addr)
    val vote = expected_vote_for(w.pending, typ, w.pending.value, addr)
    val sig = { signer: v.key, preimage: vote_preimage(vote) }
    w' = { ...w,
           issued: w.issued.union(Set(sig)),
           signed_votes: w.signed_votes.union(Set({ key: v.key, vote: vote })),
           signed_log: w.signed_log.union(
             Set({ purpose: PVote, preimage: sig.preimage, key: v.key,
                   net: w.network, subject: vote.value })),
           events: w.events.union(Set(VoteSigned)),
           pending: { ...w.pending,
                      entries: w.pending.entries.append(
                        { addr: addr, typ: expected_vote_typ(w.pending, typ),
                          value: w.pending.value,
                          sig_signer: v.key, sig_covers: true,
                          ext_value: NO_EXT, ext_sig_signer: FORGED_SIGNER,
                          ext_sig_covers: false }) } },
  }

  /// The same, with a vote extension attached. `valid_ext` false attaches an extension
  /// signature no key produced, reaching `InvalidVoteExtensionSignature`.
  action add_signed_entry_with_extension(addr: Addr, ev: int, valid_ext: bool): bool = all {
    w.validators.keys().contains(addr),
    val v = w.validators.get(addr)
    val vote = expected_vote_for(w.pending, TYP_PRECOMMIT, w.pending.value, addr)
    val sig = { signer: v.key, preimage: vote_preimage(vote) }
    val scope = entry_scope(w.pending, addr)
    val epre = extension_preimage(scope, ev)
    val esig = { signer: if (valid_ext) v.key else FORGED_SIGNER, preimage: epre }
    w' = { ...w,
           issued: if (valid_ext) w.issued.union(Set(sig, esig)) else w.issued.union(Set(sig)),
           signed_votes: w.signed_votes.union(Set({ key: v.key, vote: vote })),
           signed_exts:
             if (valid_ext) w.signed_exts.union(Set({ key: v.key, scope: scope, ext: ev }))
             else w.signed_exts,
           signed_log: w.signed_log.union(
             Set({ purpose: PVote, preimage: sig.preimage, key: v.key,
                   net: w.network, subject: vote.value })),
           events: w.events.union(Set(VoteSigned)),
           pending: { ...w.pending,
                      entries: w.pending.entries.append(
                        { addr: addr, typ: expected_vote_typ(w.pending, TYP_PRECOMMIT),
                          value: w.pending.value,
                          sig_signer: v.key, sig_covers: true,
                          ext_value: ev, ext_sig_signer: esig.signer,
                          ext_sig_covers: valid_ext }) } },
  }

  /// `CertificateBuilder::with_votes(0..n)`: sign the reconstructed vote for every
  /// validator in the set and install the whole entry list at once. Sim machinery.
  action add_signed_entries_for_all(typ: int, with_ext: bool, ev: int,
                                    valid_ext: bool): bool = all {
    w.validators.keys().size() > 0,
    val entries = all_signed_entries(w.pending, w.validators, typ, with_ext, ev, valid_ext)
    val votes = entries.foldl(Set(), (acc, e) =>
      acc.union(Set({ key: w.validators.get(e.addr).key,
                      vote: expected_vote_for(w.pending, e.typ, e.value, e.addr) })))
    w' = { ...w,
           issued: w.issued.union(
             votes.map(r => { signer: r.key, preimage: vote_preimage(r.vote) })),
           signed_votes: w.signed_votes.union(votes),
           signed_log: w.signed_log.union(
             votes.map(r => { purpose: PVote, preimage: vote_preimage(r.vote),
                              key: r.key, net: w.network, subject: r.vote.value })),
           events: w.events.union(Set(VoteSigned)),
           pending: { ...w.pending, entries: entries } },
  }

  /// `verify_commit_certificate`, `verify_extended_commit_certificate`,
  /// `verify_polka_certificate`, `verify_round_certificate` (ext.rs:420-588). TOTAL: the
  /// whole certificate arrives as one typed payload and every value, however malformed,
  /// lands on exactly one arm.
  /// Takes NO payload: the certificate was assembled entry by entry into `w.pending`,
  /// so every part of it arrived through a pinnable logged argument. A whole-`Cert`
  /// parameter had no nondet to pin against and replay fell back to the empty initial
  /// certificate, which made every certificate observation vacuous.
  action verify_certificate: bool = {
    val cert = w.pending
    val outcome = cert_outcome(cert, w.validators)
    w' = { ...w,
           outcomes: w.outcomes.append(outcome),
           calls: w.calls + 1,
           events: w.events.union(cert_events(cert, w.validators)),
           accepted:
             if (outcome == Valid) w.accepted.union(Set(cert)) else w.accepted }
  }

  /// `verify_commit_signature` / `verify_polka_signature` / `verify_round_signature`
  /// (ext.rs:318-418) — public and separately callable, no quorum check.
  action verify_single_signature(addr: Addr, sig_signer: int, sig_covers: bool): bool =
    w' = { ...w,
           outcomes: w.outcomes.append(
             single_signature_outcome(addr, sig_signer, sig_covers, w.validators)),
           calls: w.calls + 1,
           events: w.events.union(Set(SingleSignatureEntryPointUsed)) }

  // ---------------------------------------------------------------------------
  // Adversary surface — sim-side machinery, no oracle log site
  // ---------------------------------------------------------------------------

  /// A private key leaks. From here the adversary can produce signatures under it.
  action compromise_key(key: KeyId): bool = all {
    not(w.compromised.contains(key)),
    w' = { ...w,
           compromised: w.compromised.union(Set(key)),
           events: w.events.union(Set(KeyCompromised)) },
  }

  /// A signature seen on the wire becomes an adversary-presentable value.
  action observe_signature(sig: Sig): bool = all {
    w.issued.contains(sig),
    w' = { ...w, wild: w.wild.union(Set(sig)) },
  }

  /// The adversary signs arbitrary bytes with a key it controls. It can do this only for
  /// a compromised key: for any other key the scheme is assumed unforgeable.
  action sign_with_compromised_key(key: KeyId, pre: Preimage): bool = all {
    w.compromised.contains(key),
    w' = { ...w, wild: w.wild.union(Set({ signer: key, preimage: pre })) },
  }

  /// Arbitrary signature bytes, or a real signature with a flipped byte — the
  /// `verify_rejects_tampered_signature` case. No private key produced them, so they
  /// must never verify.
  action forge_signature(pre: Preimage): bool =
    w' = { ...w, wild: w.wild.union(Set({ signer: FORGED_SIGNER, preimage: pre })) }

  /// Arbitrary and malformed key and signature encodings arrive off the network: empty,
  /// truncated, over-long, a valid-length non-curve point, the all-zero key, and a
  /// wrong-curve SEC1 encoding.
  action submit_encoded_bytes(b: Bytes): bool =
    w' = { ...w, byte_pool: w.byte_pool.union(Set(b)) }

  /// The node moves to a different network; the same signatures are presented there.
  action switch_network(n: int): bool = all {
    NETWORKS.contains(n),
    n != w.network,
    w' = { ...w, network: n },
  }

  // ---------------------------------------------------------------------------
  // step
  // ---------------------------------------------------------------------------

  action step: bool = any {
    nondet key = KEYS.oneOf()
    nondet vote = VOTE_FIELDS.oneOf()
    sign_vote(key, vote),

    nondet key = KEYS.oneOf()
    nondet proposal = PROPOSAL_FIELDS.oneOf()
    sign_proposal(key, proposal),

    nondet key = KEYS.oneOf()
    nondet scope = SCOPES.oneOf()
    nondet ext = EXTS.oneOf()
    sign_vote_extension(key, scope, ext),

    nondet key = KEYS.oneOf()
    nondet peer_id = PEERS.oneOf()
    sign_validator_proof(key, encode_public_key(key), peer_id),

    // A proof whose embedded public key is malformed — reaches the `Err` arm.
    nondet key = KEYS.oneOf()
    nondet peer_id = PEERS.oneOf()
    nondet pk = CANDIDATE_KEY_BYTES.oneOf()
    sign_validator_proof(key, pk, peer_id),

    nondet key = KEYS.oneOf()
    generate_keypair(key),

    all {
      nondet vote = VOTE_FIELDS.oneOf()
      nondet sig_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet sig_covers = Set(true, false).oneOf()
      nondet key = KEYS.oneOf()
      verify_signed_vote(vote, sig_signer, sig_covers, key),
    },

    all {
      nondet proposal = PROPOSAL_FIELDS.oneOf()
      nondet sig_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet sig_covers = Set(true, false).oneOf()
      nondet key = KEYS.oneOf()
      verify_signed_proposal(proposal, sig_signer, sig_covers, key),
    },

    all {
      nondet scope = SCOPES.oneOf()
      nondet ext = EXTS.oneOf()
      nondet sig_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet sig_covers = Set(true, false).oneOf()
      nondet key = KEYS.oneOf()
      verify_signed_vote_extension(scope, ext, sig_signer, sig_covers, key),
    },

    all {
      w.byte_pool.size() > 0,
      nondet pk_bytes = w.byte_pool.oneOf()
      nondet peer_id = PEERS.oneOf()
      nondet sig_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet sig_covers = Set(true, false).oneOf()
      verify_validator_proof(pk_bytes, peer_id, sig_signer, sig_covers),
    },

    all {
      w.byte_pool.size() > 0,
      nondet b = w.byte_pool.oneOf()
      decode_public_key_op(b),
    },

    all {
      w.byte_pool.size() > 0,
      nondet b = w.byte_pool.oneOf()
      decode_signature_op(b),
    },

    begin_validator_set,

    all {
      w.validators.keys().size() < ADDRS.size(),
      nondet addr = ADDRS.oneOf()
      nondet key = KEYS.oneOf()
      nondet power = POWERS.oneOf()
      add_validator(addr, key, power),
    },

    nondet kind = CERT_KINDS.oneOf()
    nondet height = HEIGHTS.oneOf()
    nondet round = ROUNDS.oneOf()
    nondet value = VOTE_VALUES.oneOf()
    nondet policy = EXT_POLICIES.oneOf()
    begin_certificate(kind, height, round, value, policy),

    all {
      presented(w).size() > 0,
      nondet addr = ADDRS.oneOf()
      nondet typ = VOTE_TYPES.oneOf()
      nondet value = VOTE_VALUES.oneOf()
      nondet sig_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet sig_covers = Set(true, false).oneOf()
      add_certificate_entry(addr, typ, value, sig_signer, sig_covers,
                            NO_EXT, FORGED_SIGNER, false),
    },

    all {
      presented(w).size() > 0,
      nondet addr = ADDRS.oneOf()
      nondet value = VOTE_VALUES.oneOf()
      nondet sig_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet ev = EXTS.oneOf()
      nondet ext_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet ext_covers = Set(true, false).oneOf()
      add_certificate_entry(addr, TYP_PRECOMMIT, value, sig_signer, true,
                            ev, ext_signer, ext_covers),
    },

    // Hand the verifier the exact message that was signed — the happy path.
    all {
      w.signed_votes.size() > 0,
      nondet r = w.signed_votes.oneOf()
      verify_signed_vote(r.vote, r.key, true, r.key),
    },

    all {
      w.signed_votes.size() > 0,
      nondet r = w.signed_votes.oneOf()
      nondet key = KEYS.oneOf()
      verify_signed_vote(r.vote, r.key, true, key),
    },

    all {
      w.signed_proposals.size() > 0,
      nondet r = w.signed_proposals.oneOf()
      verify_signed_proposal(r.proposal, r.key, true, r.key),
    },

    all {
      w.signed_exts.size() > 0,
      nondet r = w.signed_exts.oneOf()
      verify_signed_vote_extension(r.scope, r.ext, r.key, true, r.key),
    },

    all {
      w.signed_proofs.size() > 0,
      nondet r = w.signed_proofs.oneOf()
      verify_validator_proof(r.pk, r.peer, r.key, true),
    },

    all {
      w.validators.keys().size() > 0,
      nondet addr = w.validators.keys().oneOf()
      nondet typ = VOTE_TYPES.oneOf()
      add_signed_entry(addr, typ),
    },

    all {
      w.validators.keys().size() > 0,
      nondet addr = w.validators.keys().oneOf()
      nondet ev = EXTS.oneOf()
      nondet valid_ext = Set(true, false).oneOf()
      add_signed_entry_with_extension(addr, ev, valid_ext),
    },

    all {
      w.validators.keys().size() > 0,
      nondet typ = VOTE_TYPES.oneOf()
      nondet with_ext = Set(true, false).oneOf()
      nondet ev = EXTS.oneOf()
      nondet valid_ext = Set(true, false).oneOf()
      add_signed_entries_for_all(typ, with_ext, ev, valid_ext),
    },

    verify_certificate,

    all {
      nondet addr = ADDRS.oneOf()
      nondet sig_signer = KEYS.union(Set(FORGED_SIGNER)).oneOf()
      nondet sig_covers = Set(true, false).oneOf()
      verify_single_signature(addr, sig_signer, sig_covers),
    },

    nondet key = KEYS.oneOf()
    compromise_key(key),

    all {
      w.issued.size() > 0,
      nondet sig = w.issued.oneOf()
      observe_signature(sig),
    },

    all {
      w.compromised.size() > 0,
      nondet key = w.compromised.oneOf()
      nondet vote = VOTE_FIELDS.oneOf()
      sign_with_compromised_key(key, vote_preimage(vote)),
    },

    nondet vote = VOTE_FIELDS.oneOf()
    forge_signature(vote_preimage(vote)),

    nondet b = CANDIDATE_KEY_BYTES.union(CANDIDATE_SIG_BYTES).oneOf()
    submit_encoded_bytes(b),

    nondet n = NETWORKS.oneOf()
    switch_network(n),
  }

  // ---------------------------------------------------------------------------
  // Correctness properties
  // ---------------------------------------------------------------------------

  /// A signature only verifies against the exact bytes its own key signed.
  val verification_accepts_only_signed_preimages: bool =
    w.accepted_sigs.forall(a =>
      w.compromised.contains(a.key)
        or w.signed_log.exists(s => s.key == a.key and s.preimage == a.preimage))

  /// A signature over one message purpose never verifies as another purpose.
  ///
  /// Proved through the leading token of each preimage: the four builders must produce
  /// disjoint leading tokens, which is what a domain tag is for. The model represents
  /// distinct protobuf field tags as distinct tokens, so this states the layout-level
  /// obligation the trait docs place on implementations, not the wire-level encoding.
  val purposes_are_domain_separated: bool =
    val vote_tags = VOTE_FIELDS.map(v => vote_preimage(v).head())
    val proposal_tags = PROPOSAL_FIELDS.map(p => proposal_preimage(p).head())
    val ext_tags = SCOPES.map(s => EXTS.map(e => extension_preimage(s, e).head())).flatten()
    val pov_tags =
      KEYS.map(k => PEERS.map(p => pov_preimage(encode_public_key(k), p).head())).flatten()
    and {
      vote_tags.intersect(proposal_tags).size() == 0,
      vote_tags.intersect(ext_tags).size() == 0,
      vote_tags.intersect(pov_tags).size() == 0,
      proposal_tags.intersect(ext_tags).size() == 0,
      proposal_tags.intersect(pov_tags).size() == 0,
      ext_tags.intersect(pov_tags).size() == 0,
    }

  /// A vote-extension signature never verifies against a different scope.
  val extension_signature_binds_every_scope_field: bool =
    EXTS.forall(e => SCOPES.map(s => extension_preimage(s, e)).size() == SCOPES.size())

  /// A vote or proposal signature is bound to the network it was cast on.
  ///
  /// The `Verifier`/`Signer` trait docs state network-scoped domain separation as an
  /// obligation on implementations. The modelled implementation — the test signing
  /// provider in `code/crates/test/src/signing.rs` — puts no network material in vote or
  /// proposal preimages, so the same vote signed on two networks yields identical bytes
  /// and this property is expected to be violated. That is a gap between the documented
  /// contract and that provider, not a safety bug in the consensus protocol: a production
  /// provider is expected to add network scoping, and this property catches its absence.
  val consensus_preimages_are_network_scoped: bool =
    w.signed_log.forall(a => w.signed_log.forall(b =>
      a.net == b.net
        or a.purpose != b.purpose
        or (a.purpose != PVote and a.purpose != PProposal)
        or a.preimage != b.preimage))

  /// A validator proof signed on one network is the same proof on every other network.
  val pov_preimage_is_network_agnostic: bool =
    w.signed_log.forall(a => w.signed_log.forall(b =>
      a.purpose != PProof
        or b.purpose != PProof
        or a.key != b.key
        or a.subject != b.subject
        or a.preimage == b.preimage))

  /// Every verification and every decode call produces exactly one recorded result.
  val verification_is_total_over_all_inputs: bool =
    w.outcomes.length() == w.calls

  /// Accumulated voting power never wraps past the accumulator bound.
  val accumulated_power_never_wraps: bool =
    w.accepted.forall(c => cert_acc(c, w.validators).power <= POWER_MAX)

  /// An accepted certificate's signed voting power exceeds the threshold its kind requires.
  val accepted_certificate_meets_its_threshold: bool =
    w.accepted.forall(c =>
      val signed =
        c.entries.foldl(Set(), (s, e) => s.union(Set(e.addr)))
          .fold(0, (acc, a) =>
            if (w.validators.keys().contains(a)) acc + w.validators.get(a).power else acc)
      is_met(signed, total_power(w.validators), threshold_of(c.kind)))

  /// An accepted certificate names each signer once, and every signer is a known validator.
  val accepted_certificate_has_distinct_known_signers: bool =
    w.accepted.forall(c =>
      val addrs = c.entries.foldl(List(), (l, e) => l.append(e.addr))
      and {
        addrs.foldl(Set(), (s, a) => s.union(Set(a))).size() == addrs.length(),
        addrs.foldl(true, (ok, a) => ok and w.validators.keys().contains(a)),
      })

  /// An accepted precommit round certificate contains no prevotes.
  val precommit_round_certificate_has_no_prevotes: bool =
    w.accepted.forall(c =>
      c.kind != KIND_ROUND_PRECOMMIT
        or c.entries.foldl(true, (ok, e) => ok and e.typ != TYP_PREVOTE))

  /// An accepted extended commit certificate matches its vote-extension policy.
  val accepted_extended_certificate_honors_extension_policy: bool =
    w.accepted.forall(c =>
      c.kind != KIND_EXTENDED_COMMIT
        or c.entries.foldl(true, (ok, e) =>
             ok and (if (c.policy == POLICY_DISABLED) e.ext_value == NO_EXT
                     else e.ext_value != NO_EXT)))

  /// Encoding a key or a signature and decoding it back yields the original.
  val key_and_signature_encoding_round_trip: bool =
    KEYS.forall(k => decode_public_key(encode_public_key(k)) == Decoded(k))
      and w.issued.forall(s => decode_signature(encode_signature(s)) == Decoded(s.signer))

  /// A vote signature covers the same bytes whatever extension is attached to the vote.
  val vote_signature_is_independent_of_attached_extension: bool =
    VOTE_FIELDS.forall(v => vote_preimage(v) == vote_preimage({ ...v, ext: NO_EXT }))

  // ---------------------------------------------------------------------------
  // Observations
  // ---------------------------------------------------------------------------

  /// A vote was signed.
  val vote_signed: bool = w.events.contains(VoteSigned)
  /// A proposal was signed.
  val proposal_signed: bool = w.events.contains(ProposalSigned)
  /// A vote extension was signed.
  val extension_signed: bool = w.events.contains(ExtensionSigned)
  /// A validator proof was signed.
  val validator_proof_signed: bool = w.events.contains(ProofSigned)
  /// A vote signature verified.
  val vote_verify_valid: bool = w.events.contains(VoteValid)
  /// A vote signature was rejected because it was checked against the wrong public key.
  val vote_verify_invalid_wrong_key: bool = w.events.contains(VoteInvalidWrongKey)
  /// A vote signature was rejected because it covers different bytes.
  val vote_verify_invalid_wrong_message: bool = w.events.contains(VoteInvalidWrongMessage)
  /// A proposal signature verified.
  val proposal_verify_valid: bool = w.events.contains(ProposalValid)
  /// A proposal signature was rejected.
  val proposal_verify_invalid: bool = w.events.contains(ProposalInvalid)
  /// A vote-extension signature verified against its own scope.
  val extension_verify_valid: bool = w.events.contains(ExtensionValid)
  /// A vote-extension signature was rejected against a different scope.
  val extension_verify_invalid_wrong_scope: bool = w.events.contains(ExtensionInvalidWrongScope)
  /// A validator proof verified.
  val proof_verify_valid: bool = w.events.contains(ProofValid)
  /// A validator proof with an altered signature, public key or peer id was rejected.
  val proof_verify_invalid_tampered: bool = w.events.contains(ProofInvalidTampered)
  /// A validator proof carrying an undecodable public key produced an error, not Invalid.
  val proof_verify_errors_on_malformed_key: bool = w.events.contains(ProofDecodeError)
  /// A public key decoded.
  val public_key_decoded: bool = w.events.contains(KeyDecoded)
  /// A public key was rejected for having the wrong byte length.
  val public_key_decode_rejects_wrong_length: bool = w.events.contains(KeyDecodeWrongLength)
  /// A correctly sized public key was rejected for not being a curve point.
  val public_key_decode_rejects_non_curve_point: bool = w.events.contains(KeyDecodeNotOnCurve)
  /// A public key from a different curve was rejected.
  val public_key_decode_rejects_wrong_curve: bool = w.events.contains(KeyDecodeWrongCurve)
  /// A signature decoded.
  val signature_decoded: bool = w.events.contains(SigDecoded)
  /// A signature was rejected for having the wrong byte length.
  val signature_decode_rejects_wrong_length: bool = w.events.contains(SigDecodeWrongLength)
  /// A commit certificate was accepted.
  val commit_certificate_accepted: bool = w.events.contains(CommitAccepted)
  /// An extended commit certificate carrying vote extensions was accepted.
  val extended_commit_certificate_accepted_with_extensions: bool =
    w.events.contains(ExtendedAcceptedWithExts)
  /// An extended commit certificate with no vote extensions was accepted.
  val extended_commit_certificate_accepted_without_extensions: bool =
    w.events.contains(ExtendedAcceptedWithoutExts)
  /// A polka certificate was accepted.
  val polka_certificate_accepted: bool = w.events.contains(PolkaAccepted)
  /// A precommit round certificate was accepted.
  val round_precommit_certificate_accepted: bool = w.events.contains(RoundPrecommitAccepted)
  /// A skip round certificate was accepted.
  val skip_certificate_accepted: bool = w.events.contains(SkipAccepted)
  /// A skip round certificate was accepted on voting power short of a quorum.
  val skip_certificate_accepted_below_quorum: bool = w.events.contains(SkipAcceptedBelowQuorum)
  /// A certificate was rejected for naming the same validator twice.
  val certificate_rejected_duplicate_vote: bool = w.events.contains(CertRejDuplicate)
  /// A certificate was rejected for naming a validator outside the set.
  val certificate_rejected_unknown_validator: bool = w.events.contains(CertRejUnknownValidator)
  /// A certificate was rejected for carrying an invalid vote signature.
  val certificate_rejected_invalid_signature: bool = w.events.contains(CertRejInvalidSignature)
  /// A certificate was rejected for not reaching its voting-power threshold.
  val certificate_rejected_insufficient_power: bool = w.events.contains(CertRejInsufficientPower)
  /// A certificate was rejected for a missing vote extension under a required policy.
  val certificate_rejected_missing_extension: bool = w.events.contains(CertRejMissingExtension)
  /// A certificate was rejected for carrying a vote extension under a disabled policy.
  val certificate_rejected_unexpected_extension: bool =
    w.events.contains(CertRejUnexpectedExtension)
  /// A certificate was rejected for an invalid vote-extension signature.
  val certificate_rejected_invalid_extension_signature: bool =
    w.events.contains(CertRejInvalidExtensionSignature)
  /// A precommit round certificate was rejected for containing a prevote.
  val certificate_rejected_invalid_vote_type: bool = w.events.contains(CertRejInvalidVoteType)
  /// A certificate was rejected because accumulating its voting power would overflow.
  val certificate_rejected_voting_power_overflow: bool = w.events.contains(CertRejOverflow)
  /// A certificate with no signatures at all was rejected.
  val empty_signature_set_rejected: bool = w.events.contains(EmptySignatureSetRejected)
  /// A single certificate signature was verified through its own public entry point.
  val single_signature_entry_point_used: bool = w.events.contains(SingleSignatureEntryPointUsed)
  /// A private key was compromised.
  val key_compromised: bool = w.events.contains(KeyCompromised)
  /// A signature accepted on one network was accepted again on a different one.
  val cross_network_signature_accepted: bool =
    w.accepted_sigs.exists(a => w.accepted_sigs.exists(b =>
      a.net != b.net and a.preimage == b.preimage and a.key == b.key))
}
