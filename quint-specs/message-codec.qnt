// Message Codec — the `Codec` trait (code/crates/codec/src/lib.rs) and the
// Protobuf / Borsh / JSON encode-decode machinery that puts consensus, sync,
// engine and peer messages on the wire and takes them off again:
//
//   code/crates/proto/src/lib.rs                  Protobuf trait + error taxonomy
//   code/crates/test/src/codec/proto/mod.rs       the Protobuf codec impls
//   code/crates/test/src/codec/json/{mod,raw}.rs  the JSON codec impls
//   code/crates/core-consensus/src/ser/borsh.rs   SignedConsensusMsg / LivenessMsg tags
//   code/crates/sync/src/ser/borsh.rs             Status / Request / Response
//   code/crates/peer/src/ser/borsh.rs             PeerId (validates)
//   code/crates/engine/src/ser/borsh.rs           StreamId (does not validate)
//
// The model MIRRORS the code, bugs included: where a decoder silently defaults,
// drops or re-interprets, the model does the same and the correctness properties
// below are what the simulator can violate.

module messageCodecCore {
  import basicSpells.* from "./spells/basicSpells"

  /// The three wire formats this component implements.
  type Transport = Proto | Json | Borsh

  type VoteType = Prevote | Precommit

  /// The message families the codecs are instantiated for.
  type MsgKind =
    | KVote
    | KProposal
    | KPolkaCert
    | KRoundCert
    | KStatus
    | KValueRequest
    | KExtraRequest
    | KStreamMessage

  /// One `Codec<T>` / `BorshDeserialize` implementation, i.e. the decoder the
  /// caller picked. Which decoder runs is not derivable from the bytes.
  type Decoder =
    | DSignedConsensus
    | DLiveness
    | DStatus
    | DRequest
    | DStreamMsg
    | DPolkaCert

  /// `malachitebft_proto::Error`.
  type ErrKind = EDecode | EMissingField | EInvalidData | EUnknownMessageType | EOther

  type NodeStatus = Running | Panicked

  /// An abstract domain message. Only the fields the codecs actually branch on
  /// are represented.
  type MsgValue = {
    kind: MsgKind,
    // certificate signatures, as the set of signer ids
    signatures: Set[int],
    // `RoundSignature::vote_type` as the protobuf enum NUMBER on the wire
    voteTypeWire: int,
    // `RoundCertificate::cert_type` as the protobuf enum number
    certTypeWire: int,
    // a round certificate whose `round` is Nil — `expect("round should not be nil")`
    roundNil: bool,
    // `Status::peer_id.id` parses as a multihash
    peerIdWellFormed: bool,
    height: int,
    // `ValueRequest::end_height`, an optional protobuf field
    endHeight: Option[int],
    // declared byte length of a borsh-encoded StreamId
    streamIdLen: int,
    // the inner `from_sign_bytes` payload of a JSON RawSignedConsensusMsg parses
    innerParsable: bool,
    // the bytes carry a field tag this build does not know
    hasUnknownField: bool,
  }

  /// The encoded bytes in flight.
  type Wire = {
    transport: Transport,
    // the borsh leading discriminant; -1 when the encoder writes none
    tag: int,
    // the `Any` envelope's type_url
    typeUrl: str,
    // what was written, abstractly
    payload: MsgValue,
  }

  type Outcome = Pending | Ok(MsgValue) | Err(ErrKind) | Crashed

  type CodecState = {
    // the domain value handed to an encoder; None for attacker-supplied bytes
    source: Option[MsgValue],
    wire: Option[Wire],
    outcome: Outcome,
    // the vote type a decoded round signature ended up carrying
    decodedVoteType: Option[VoteType],
    // `to_bytes` re-applied to the decoded value
    reencoded: Option[Wire],
    // the decode went through `Protobuf::from_any`
    fromAnyUsed: bool,
    node: NodeStatus,
    // a consumer accepted the decoded certificate
    certAccepted: bool,
    // ghost latches for silent behaviors
    voteTypeDefaulted: bool,
    endHeightDefaulted: bool,
    polkaSignaturesDropped: bool,
    tagCrossDecoded: bool,
    streamIdUnvalidated: bool,
    requestVariantAssumed: bool,
    unknownFieldDropped: bool,
    encodePanicked: bool,
  }

  pure val STREAM_ID_LEN: int = 8
  pure val PROTO_TYPE_URL: str = "malachite.Message"
  pure val FOREIGN_TYPE_URL: str = "foreign.Other"

  pure val TRANSPORTS: Set[Transport] = Set(Proto, Json, Borsh)
  pure val DECODERS: Set[Decoder] =
    Set(DSignedConsensus, DLiveness, DStatus, DRequest, DStreamMsg, DPolkaCert)

  pure def isKnownVoteTypeWire(w: int): bool = w == 0 or w == 1
  pure def isKnownCertTypeWire(w: int): bool = w == 0 or w == 1

  /// `sig.vote_type()` — the prost accessor maps every unrecognized enum number
  /// onto the zero variant (test/src/codec/proto/mod.rs:164, test/src/vote.rs:157).
  pure def decodeVoteTypeWire(w: int): VoteType = if (w == 1) Precommit else Prevote
  pure def encodeVoteType(vt: VoteType): int = if (vt == Precommit) 1 else 0

  pure def isRequestKind(k: MsgKind): bool = k == KValueRequest or k == KExtraRequest

  pure def baseValue(k: MsgKind): MsgValue = {
    kind: k,
    signatures: Set(),
    voteTypeWire: 0,
    certTypeWire: 0,
    roundNil: false,
    peerIdWellFormed: true,
    height: 10,
    endHeight: Some(10),
    streamIdLen: STREAM_ID_LEN,
    innerParsable: true,
    hasUnknownField: false,
  }

  /// Which message kinds a given `Codec<T>` implementation can produce.
  pure def decoderAccepts(d: Decoder, k: MsgKind): bool =
    match d {
      | DSignedConsensus => k == KVote or k == KProposal
      | DLiveness        => k == KVote or k == KPolkaCert or k == KRoundCert
      | DStatus          => k == KStatus
      | DRequest         => isRequestKind(k)
      | DStreamMsg       => k == KStreamMessage
      | DPolkaCert       => k == KPolkaCert
    }

  /// The borsh discriminant the encoder writes. `SignedConsensusMsg` uses 0/1 and
  /// `LivenessMsg` reuses 0/1/2; `Request` writes none at all.
  pure def borshTag(k: MsgKind): int =
    match k {
      | KVote      => 0
      | KProposal  => 1
      | KPolkaCert => 1
      | KRoundCert => 2
      | _          => -1
    }

  /// The JSON `RawLivenessMsg` encoder hard-codes `polka_signatures: vec![]`
  /// (test/src/codec/json/raw.rs:359).
  pure def encodedPayload(t: Transport, v: MsgValue): MsgValue =
    if (t == Json and v.kind == KPolkaCert) { ...v, signatures: Set() } else v

  pure def encodeWire(t: Transport, v: MsgValue): Wire = {
    transport: t,
    tag: if (t == Borsh) borshTag(v.kind) else -1,
    typeUrl: PROTO_TYPE_URL,
    payload: encodedPayload(t, v),
  }

  /// `encode_round_certificate` calls `expect("round should not be nil")`.
  pure def encodePanics(t: Transport, v: MsgValue): bool =
    t == Proto and v.kind == KRoundCert and v.roundNil

  /// What a protobuf decode of `w` under decoder `d` produces.
  pure def protoOutcome(w: Wire, d: Decoder): Outcome =
    if (not(decoderAccepts(d, w.payload.kind))) Err(EMissingField)
    else if (w.payload.kind == KStatus and not(w.payload.peerIdWellFormed))
      // `PeerId::from_bytes(..).unwrap()` (test/src/codec/proto/mod.rs:343)
      Crashed
    else if (w.payload.kind == KRoundCert and not(isKnownCertTypeWire(w.payload.certTypeWire)))
      Err(EOther)
    else if (w.payload.kind == KRoundCert)
      // the unknown vote_type number is silently folded onto Prevote
      Ok({ ...w.payload,
           voteTypeWire: encodeVoteType(decodeVoteTypeWire(w.payload.voteTypeWire)),
           hasUnknownField: false })
    else if (isRequestKind(w.payload.kind))
      match w.payload.endHeight {
        | Some(e) =>
          if (e < w.payload.height) Err(EInvalidData)
          else Ok({ ...w.payload, kind: KValueRequest, hasUnknownField: false })
        // `end_height.unwrap_or(req.height)` (test/src/codec/proto/mod.rs:377)
        | None => Ok({ ...w.payload, kind: KValueRequest,
                       endHeight: Some(w.payload.height), hasUnknownField: false })
      }
    // `Self::Proto::decode` drops field tags this build does not know
    else Ok({ ...w.payload, hasUnknownField: false })

  /// What a JSON decode of `w` under decoder `d` produces.
  pure def jsonOutcome(w: Wire, d: Decoder): Outcome =
    if (not(decoderAccepts(d, w.payload.kind))) Err(EDecode)
    else if (d == DSignedConsensus and not(w.payload.innerParsable))
      // `Vote::from_bytes(..).unwrap()` / `Proposal::from_sign_bytes(..).unwrap()`
      // inside `From<RawSignedConsensusMsg>` (test/src/codec/json/raw.rs:47-62)
      Crashed
    else Ok(w.payload)

  /// What a borsh decode of `w` under decoder `d` produces. The decoder, not the
  /// bytes, decides which tag space the leading byte is read in.
  pure def borshOutcome(w: Wire, d: Decoder): Outcome =
    match d {
      // no discriminant is written or read: every payload becomes a ValueRequest
      | DRequest => Ok({ ...w.payload, kind: KValueRequest })
      // `PeerId::from_bytes` is checked here (peer/src/ser/borsh.rs)
      | DStatus =>
        if (not(w.payload.peerIdWellFormed)) Err(EInvalidData) else Ok(w.payload)
      // `StreamId::deserialize_reader` wraps any Vec<u8> unchecked (engine/src/ser/borsh.rs)
      | DStreamMsg => Ok(w.payload)
      | DPolkaCert => Ok(w.payload)
      | DSignedConsensus =>
        if (w.tag == 0) Ok({ ...w.payload, kind: KVote })
        else if (w.tag == 1) Ok({ ...w.payload, kind: KProposal })
        else Err(EInvalidData)
      | DLiveness =>
        if (w.tag == 0) Ok({ ...w.payload, kind: KVote })
        else if (w.tag == 1) Ok({ ...w.payload, kind: KPolkaCert })
        else if (w.tag == 2) Ok({ ...w.payload, kind: KRoundCert })
        else Err(EInvalidData)
    }

  pure def decodeOutcome(w: Wire, d: Decoder): Outcome =
    match w.transport {
      | Proto => protoOutcome(w, d)
      | Json  => jsonOutcome(w, d)
      | Borsh => borshOutcome(w, d)
    }

  pure def isOk(o: Outcome): bool = match o { | Ok(_) => true | _ => false }
  pure def isPending(o: Outcome): bool = match o { | Pending => true | _ => false }
  pure def isErrOutcome(o: Outcome): bool = match o { | Err(_) => true | _ => false }
  pure def isErrOf(o: Outcome, e: ErrKind): bool =
    match o { | Err(k) => k == e | _ => false }
  pure def okKindIs(o: Outcome, k: MsgKind): bool =
    match o { | Ok(v) => v.kind == k | _ => false }

  pure val initial_state: CodecState = {
    source: None,
    wire: None,
    outcome: Pending,
    decodedVoteType: None,
    reencoded: None,
    fromAnyUsed: false,
    node: Running,
    certAccepted: false,
    voteTypeDefaulted: false,
    endHeightDefaulted: false,
    polkaSignaturesDropped: false,
    tagCrossDecoded: false,
    streamIdUnvalidated: false,
    requestVariantAssumed: false,
    unknownFieldDropped: false,
    encodePanicked: false,
  }

  pure def applyEncode(s: CodecState, t: Transport, v: MsgValue): CodecState =
    if (encodePanics(t, v))
      { ...s, source: Some(v), node: Panicked, encodePanicked: true }
    else
      { ...s,
        source: Some(v),
        wire: Some(encodeWire(t, v)),
        outcome: Pending,
        polkaSignaturesDropped:
          s.polkaSignaturesDropped or
          (t == Json and v.kind == KPolkaCert and v.signatures != Set()) }

  pure def applyDecodeResult(s: CodecState, w: Wire, d: Decoder, o: Outcome): CodecState =
    { ...s,
      outcome: o,
      node: if (o == Crashed) Panicked else s.node,
      decodedVoteType:
        if (okKindIs(o, KRoundCert)) Some(decodeVoteTypeWire(w.payload.voteTypeWire))
        else s.decodedVoteType,
      voteTypeDefaulted:
        s.voteTypeDefaulted or
        (okKindIs(o, KRoundCert) and not(isKnownVoteTypeWire(w.payload.voteTypeWire))),
      endHeightDefaulted:
        s.endHeightDefaulted or
        (okKindIs(o, KValueRequest) and w.transport == Proto and w.payload.endHeight == None),
      tagCrossDecoded:
        s.tagCrossDecoded or
        (isOk(o) and not(okKindIs(o, w.payload.kind))),
      streamIdUnvalidated:
        s.streamIdUnvalidated or
        (okKindIs(o, KStreamMessage) and w.payload.streamIdLen != STREAM_ID_LEN),
      requestVariantAssumed:
        s.requestVariantAssumed or
        (d == DRequest and w.transport == Borsh and w.payload.kind != KValueRequest),
      unknownFieldDropped:
        s.unknownFieldDropped or (isOk(o) and w.payload.hasUnknownField) }

  pure def applyReset(s: CodecState): CodecState =
    { ...s,
      source: None,
      wire: None,
      outcome: Pending,
      decodedVoteType: None,
      reencoded: None,
      fromAnyUsed: false,
      certAccepted: false }

  /// The attacker-supplied and version-skewed wires a peer can put on the network
  /// or a migrated WAL can hold.
  pure val UNTRUSTED_WIRES: Set[Wire] = Set(
    // a proto Status whose peer_id bytes are not a valid multihash
    { transport: Proto, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KStatus), peerIdWellFormed: false } },
    // the same over borsh, where PeerId::from_bytes IS checked
    { transport: Borsh, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KStatus), peerIdWellFormed: false } },
    // a round certificate signature with an unrecognized vote_type number
    { transport: Proto, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KRoundCert), signatures: Set(1), voteTypeWire: 99 } },
    // an unrecognized cert_type number
    { transport: Proto, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KRoundCert), signatures: Set(1), certTypeWire: 7 } },
    // a sync value request that omits end_height
    { transport: Proto, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KValueRequest), endHeight: None } },
    // an end_height below height
    { transport: Proto, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KValueRequest), endHeight: Some(9) } },
    // bytes carrying a field tag this build does not know
    { transport: Proto, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KVote), hasUnknownField: true } },
    // an Any envelope with a foreign type_url
    { transport: Proto, tag: -1, typeUrl: FOREIGN_TYPE_URL, payload: baseValue(KVote) },
    // a JSON SignedConsensusMsg whose inner sign-bytes do not parse
    { transport: Json, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KProposal), innerParsable: false } },
    // borsh LivenessMsg PolkaCertificate bytes (tag 1) replayed as a SignedConsensusMsg
    { transport: Borsh, tag: 1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KPolkaCert), signatures: Set(1, 2, 3) } },
    // a corrupted StreamId length prefix
    { transport: Borsh, tag: -1, typeUrl: PROTO_TYPE_URL,
      payload: { ...baseValue(KStreamMessage), streamIdLen: 4096 } },
    // a borsh Request wire carrying a variant this build does not have
    { transport: Borsh, tag: -1, typeUrl: PROTO_TYPE_URL, payload: baseValue(KExtraRequest) },
    // an out-of-range borsh discriminant
    { transport: Borsh, tag: 7, typeUrl: PROTO_TYPE_URL, payload: baseValue(KVote) },
  )

  /// The well-formed domain values a local caller hands to an encoder.
  pure val DOMAIN_VALUES: Set[MsgValue] = Set(
    baseValue(KVote),
    baseValue(KProposal),
    { ...baseValue(KPolkaCert), signatures: Set(1, 2, 3) },
    { ...baseValue(KRoundCert), signatures: Set(1, 2), voteTypeWire: 1 },
    { ...baseValue(KRoundCert), roundNil: true },
    baseValue(KStatus),
    baseValue(KValueRequest),
    baseValue(KExtraRequest),
    baseValue(KStreamMessage),
  )
}

module messageCodec {
  import messageCodecCore.*
  import basicSpells.* from "./spells/basicSpells"

  var codec: CodecState

  action init: bool = codec' = initial_state

  /// `Codec::encode` / `Protobuf::to_bytes` — encode a domain value onto the wire.
  action encode(transport: Transport, value: MsgValue): bool = all {
    codec.node == Running,
    codec.wire == None,
    codec' = applyEncode(codec, transport, value),
  }

  /// `Protobuf::to_any` — wrap the encoded message in an `Any` envelope.
  action to_any(value: MsgValue): bool = all {
    codec.node == Running,
    codec.wire == None,
    not(encodePanics(Proto, value)),
    codec' = { ...applyEncode(codec, Proto, value), fromAnyUsed: false },
  }

  /// A peer or a migrated WAL hands the node bytes it did not produce itself.
  action deliver_untrusted_wire(wire: Wire): bool = all {
    codec.node == Running,
    codec.wire == None,
    codec' = { ...codec, source: None, wire: Some(wire), outcome: Pending },
  }

  /// `Codec::decode` / `Protobuf::from_bytes` — decode the wire in flight with
  /// the `Codec<T>` implementation the caller picked.
  action decode(decoder: Decoder): bool = all {
    codec.node == Running,
    codec.wire != None,
    isPending(codec.outcome),
    codec' =
      match codec.wire {
        | Some(w) => applyDecodeResult(codec, w, decoder, decodeOutcome(w, decoder))
        | None => codec
      },
  }

  /// `Protobuf::from_any` — decode out of an `Any` envelope. The type_url check is
  /// delegated to `Any::to_msg`, whose mismatch surfaces as `Error::Decode`.
  action from_any(decoder: Decoder): bool = all {
    codec.node == Running,
    isPending(codec.outcome),
    match codec.wire {
      | Some(w) => w.transport == Proto
      | None => false
    },
    codec' =
      match codec.wire {
        | Some(w) =>
          if (w.typeUrl != PROTO_TYPE_URL)
            { ...codec, outcome: Err(EDecode), fromAnyUsed: true }
          else
            { ...applyDecodeResult(codec, w, decoder, decodeOutcome(w, decoder)),
              fromAnyUsed: true }
        | None => codec
      },
  }

  /// `Protobuf::to_bytes` applied again to the value just decoded — what a relay
  /// puts back on the wire, and what a signature gets re-checked against.
  action reencode: bool = all {
    codec.node == Running,
    codec.reencoded == None,
    isOk(codec.outcome),
    codec' =
      match codec.outcome {
        | Ok(v) =>
          match codec.wire {
            | Some(w) => { ...codec, reencoded: Some(encodeWire(w.transport, v)) }
            | None => codec
          }
        | _ => codec
      },
  }

  /// A consumer takes the decoded certificate as evidence.
  action accept_certificate: bool = all {
    codec.node == Running,
    not(codec.certAccepted),
    okKindIs(codec.outcome, KPolkaCert) or okKindIs(codec.outcome, KRoundCert),
    codec' = { ...codec, certAccepted: true },
  }

  /// Move on to the next message; the latched history of what the codecs did stays.
  action reset: bool = all {
    codec.node == Running,
    codec.wire != None,
    codec' = applyReset(codec),
  }

  action step: bool = any {
    {
      nondet transport = TRANSPORTS.oneOf()
      nondet value = DOMAIN_VALUES.oneOf()
      encode(transport, value)
    },
    {
      nondet value = DOMAIN_VALUES.oneOf()
      to_any(value)
    },
    {
      nondet wire = UNTRUSTED_WIRES.oneOf()
      deliver_untrusted_wire(wire)
    },
    {
      nondet decoder = DECODERS.oneOf()
      decode(decoder)
    },
    {
      nondet decoder = DECODERS.oneOf()
      from_any(decoder)
    },
    reencode,
    accept_certificate,
    reset,
  }

  // ───────────────────────── observations ─────────────────────────

  /// A decode succeeded and produced a domain value.
  val decoded_ok: bool = isOk(codec.outcome)

  /// A decode failed because a required field was absent.
  val decode_missing_field: bool = isErrOf(codec.outcome, EMissingField)

  /// A decode failed because a field's data was out of range.
  val decode_invalid_data: bool = isErrOf(codec.outcome, EInvalidData)

  /// A decode failed as a generic protobuf decode error.
  val decode_generic_error: bool = isErrOf(codec.outcome, EDecode)

  /// A decode failed as an untyped `Other` error.
  val decode_other_error: bool = isErrOf(codec.outcome, EOther)

  /// Decoding aborted the process instead of returning an error.
  val decode_aborted_process: bool = codec.outcome == Crashed

  /// A round signature carrying an unrecognized `vote_type` number decoded as a
  /// known vote type.
  val unknown_vote_type_defaulted: bool = codec.voteTypeDefaulted

  /// A value request that omitted `end_height` was served as a single-height range.
  val end_height_defaulted: bool = codec.endHeightDefaulted

  /// The JSON encoder wrote a polka certificate with its signatures stripped.
  val polka_signatures_dropped_by_encoder: bool = codec.polkaSignaturesDropped

  /// Bytes written as one borsh message decoded as a different message type.
  val borsh_tag_cross_decoded: bool = codec.tagCrossDecoded

  /// A StreamId of unexpected length was accepted without validation.
  val stream_id_accepted_unvalidated: bool = codec.streamIdUnvalidated

  /// A sync Request payload of a foreign variant was decoded as a ValueRequest.
  val request_variant_assumed: bool = codec.requestVariantAssumed

  /// A decode succeeded over bytes carrying a field tag this build cannot re-emit.
  val unknown_field_dropped_on_decode: bool = codec.unknownFieldDropped

  /// Re-encoding the decoded value produced different bytes than arrived.
  val reencode_differs_from_wire: bool =
    match codec.reencoded {
      | Some(r) => match codec.wire { | Some(w) => r != w | None => false }
      | None => false
    }

  /// Encoding a round certificate whose round is Nil aborted the process.
  val encode_aborted_on_nil_round: bool = codec.encodePanicked

  /// A certificate with no signatures at all was accepted as evidence.
  val certificate_accepted_without_signatures: bool =
    codec.certAccepted and
    (match codec.outcome { | Ok(v) => v.signatures == Set() | _ => false })

  // ───────────────────── correctness properties ─────────────────────

  /// A decoded round signature carries the vote type the sender encoded.
  val round_signature_keeps_sender_vote_type: bool =
    match codec.decodedVoteType {
      | None => true
      | Some(vt) =>
        match codec.wire {
          | None => true
          | Some(w) => encodeVoteType(vt) == w.payload.voteTypeWire
        }
    }

  /// A sync request decodes as the variant it was encoded as.
  val sync_request_variant_is_self_describing: bool =
    match codec.outcome {
      | Ok(v) =>
        match codec.wire {
          | None => true
          | Some(w) =>
            (isRequestKind(v.kind) or isRequestKind(w.payload.kind))
              implies v.kind == w.payload.kind
        }
      | _ => true
    }

  /// A polka certificate that survives a round trip carries the signatures it was
  /// encoded with.
  val polka_certificate_signatures_survive_round_trip: bool =
    match codec.outcome {
      | Ok(v) =>
        match codec.source {
          | None => true
          | Some(s) =>
            (s.kind == KPolkaCert and v.kind == KPolkaCert)
              implies v.signatures == s.signatures
        }
      | _ => true
    }

  /// A status message whose peer id cannot be parsed decodes to an error.
  val malformed_peer_id_decodes_to_an_error: bool =
    match codec.wire {
      | None => true
      | Some(w) =>
        (w.payload.kind == KStatus and not(w.payload.peerIdWellFormed))
          implies codec.outcome != Crashed
    }

  /// Decoding bytes the node did not produce itself never aborts the process.
  val untrusted_decode_never_aborts: bool =
    (codec.source == None) implies codec.node == Running

  /// An accepted StreamId has the length a StreamId is defined to have.
  val decoded_stream_id_has_valid_length: bool =
    match codec.outcome {
      | Ok(v) => v.kind == KStreamMessage implies v.streamIdLen == STREAM_ID_LEN
      | _ => true
    }

  /// An `Any` envelope with a foreign type_url fails as UnknownMessageType.
  val type_url_mismatch_reports_unknown_message_type: bool =
    match codec.wire {
      | None => true
      | Some(w) =>
        (codec.fromAnyUsed and w.typeUrl != PROTO_TYPE_URL)
          implies codec.outcome == Err(EUnknownMessageType)
    }

  /// A value request is only accepted when the wire carried an explicit end height.
  val value_request_requires_explicit_end_height: bool =
    match codec.outcome {
      | Ok(v) =>
        v.kind == KValueRequest implies
          (match codec.wire {
            | None => true
            | Some(w) => w.payload.endHeight != None
          })
      | _ => true
    }

  /// A borsh message decodes as the message type its bytes were written as.
  val borsh_tags_identify_one_message_type: bool =
    match codec.outcome {
      | Ok(v) =>
        match codec.wire {
          | None => true
          | Some(w) => (w.transport == Borsh) implies v.kind == w.payload.kind
        }
      | _ => true
    }

  /// Re-encoding an accepted payload reproduces the bytes that arrived.
  val decode_is_canonical: bool =
    match codec.reencoded {
      | None => true
      | Some(r) =>
        match codec.wire {
          | None => true
          | Some(w) => r == w
        }
    }
}
