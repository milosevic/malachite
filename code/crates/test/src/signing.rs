use async_trait::async_trait;
use bytes::Bytes;
use core::mem::size_of;

use malachitebft_core_types::{
    NilOrVal, SignedExtension, SignedMessage, SignedProposal, SignedVote, ValidatorProof,
    VoteExtensionScope,
};
use malachitebft_signing::{Error, Signer, VerificationResult, Verifier};

use crate::{Proposal, TestContext, Vote};

/// Domain-separation tag for vote-extension signatures.
///
/// Differentiates the vote-extension preimage from other signed messages in
/// the system (votes, proposals, validator proofs). The version suffix lets
/// us bump the canonical envelope without ambiguity.
const VOTE_EXTENSION_DOMAIN: &[u8] = b"malachitebft/vote-extension/v1\0";

/// Build the canonical preimage that binds a vote extension to its precommit scope.
///
/// The preimage is
/// `DOMAIN || precommit_len || precommit_sign_bytes || extension_len || extension_bytes`,
/// where `precommit_sign_bytes` is the same canonical form already used to sign
/// the underlying precommit vote (so the binding is over height, round,
/// value_id, vote_type=Precommit, and validator_address).
fn vote_extension_sign_bytes(
    scope: &VoteExtensionScope<TestContext>,
    extension: &Bytes,
) -> Vec<u8> {
    let precommit = Vote::new_precommit(
        scope.height,
        scope.round,
        NilOrVal::Val(scope.value_id),
        scope.validator_address,
    );
    let precommit_bytes = precommit.to_sign_bytes();

    let mut buf = Vec::with_capacity(
        VOTE_EXTENSION_DOMAIN.len()
            + size_of::<u64>()
            + precommit_bytes.len()
            + size_of::<u64>()
            + extension.len(),
    );
    buf.extend_from_slice(VOTE_EXTENSION_DOMAIN);
    buf.extend_from_slice(&(precommit_bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(&precommit_bytes);
    buf.extend_from_slice(&(extension.len() as u64).to_be_bytes());
    buf.extend_from_slice(extension);
    buf
}

pub use malachitebft_signing_ed25519::*;

use crate::quint_signing_ids as qids;

pub trait Hashable {
    type Output;
    fn hash(&self) -> Self::Output;
}

impl Hashable for PublicKey {
    type Output = [u8; 32];

    fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(self.as_bytes());
        hasher.finalize().into()
    }
}

/// Stateless signature verifier. Does not hold any key material —
/// all verification uses the public key passed as a parameter.
#[derive(Debug)]
pub struct Ed25519Verifier;

impl Ed25519Verifier {
    pub fn verify(data: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        public_key.verify(data, signature).is_ok()
    }
}

#[async_trait]
impl Verifier<TestContext> for Ed25519Verifier {
    async fn verify_signed_vote(
        &self,
        vote: &Vote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        let valid = public_key.verify(&vote.to_sign_bytes(), signature).is_ok();

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "verify_signed_vote")
                .argument("vote", qids::vote_fields(vote), Some("VOTE_FIELDS"))
                .argument(
                    "sig_signer",
                    qids::signature_signer(signature),
                    Some("KEYS"),
                )
                .argument(
                    "sig_covers",
                    qids::signature_covers(signature, &qids::vote_preimage(vote)),
                    None,
                )
                .argument("key", qids::key(public_key), Some("KEYS"))
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

        Ok(VerificationResult::from_bool(valid))
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &Proposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        let valid = public_key
            .verify(&proposal.to_sign_bytes(), signature)
            .is_ok();

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "verify_signed_proposal")
                .argument(
                    "proposal",
                    qids::proposal_fields(proposal),
                    Some("PROPOSAL_FIELDS"),
                )
                .argument(
                    "sig_signer",
                    qids::signature_signer(signature),
                    Some("KEYS"),
                )
                .argument(
                    "sig_covers",
                    qids::signature_covers(signature, &qids::proposal_preimage(proposal)),
                    None,
                )
                .argument("key", qids::key(public_key), Some("KEYS"))
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

        Ok(VerificationResult::from_bool(valid))
    }

    async fn verify_signed_vote_extension(
        &self,
        scope: &VoteExtensionScope<TestContext>,
        extension: &Bytes,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        let preimage = vote_extension_sign_bytes(scope, extension);
        let valid = public_key.verify(&preimage, signature).is_ok();

        if quint_oracle::enabled() {
            quint_oracle::Event::builder(
                quint_oracle::current_test(),
                "verify_signed_vote_extension",
            )
            .argument("scope", qids::scope_fields(scope), Some("SCOPES"))
            .argument("ext", qids::extension(extension), Some("EXTS"))
            .argument(
                "sig_signer",
                qids::signature_signer(signature),
                Some("KEYS"),
            )
            .argument(
                "sig_covers",
                qids::signature_covers(signature, &qids::extension_preimage(scope, extension)),
                None,
            )
            .argument("key", qids::key(public_key), Some("KEYS"))
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

        Ok(VerificationResult::from_bool(valid))
    }

    async fn verify_validator_proof(
        &self,
        proof: &ValidatorProof<TestContext>,
    ) -> Result<VerificationResult, Error> {
        if quint_oracle::enabled() {
            quint_oracle::Event::builder(quint_oracle::current_test(), "verify_validator_proof")
                .argument("pk_bytes", qids::key_bytes(&proof.public_key), None)
                .argument("peer_id", qids::peer(&proof.peer_id), Some("PEERS"))
                .argument(
                    "sig_signer",
                    qids::signature_signer(&proof.signature),
                    Some("KEYS"),
                )
                .argument(
                    "sig_covers",
                    qids::signature_covers(
                        &proof.signature,
                        &qids::pov_preimage(&proof.public_key, &proof.peer_id),
                    ),
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

        let public_key = proof.decoded_public_key().map_err(|e| {
            Error::from_source(format!("Invalid public key in validator proof: {e}"))
        })?;
        Ok(VerificationResult::from_bool(Self::verify(
            &proof.preimage(),
            &proof.signature,
            &public_key,
        )))
    }
}

/// Message signer backed by an Ed25519 private key.
/// Also implements `Verifier` so it can be used where both traits are needed.
#[derive(Debug)]
pub struct Ed25519Signer {
    private_key: PrivateKey,
}

impl Ed25519Signer {
    pub fn new(private_key: PrivateKey) -> Self {
        Self { private_key }
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn sign(&self, data: &[u8]) -> Signature {
        self.private_key.sign(data)
    }

    pub fn verify(data: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
        Ed25519Verifier::verify(data, signature, public_key)
    }
}

#[async_trait]
impl Verifier<TestContext> for Ed25519Signer {
    async fn verify_signed_vote(
        &self,
        vote: &Vote,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ed25519Verifier
            .verify_signed_vote(vote, signature, public_key)
            .await
    }

    async fn verify_signed_proposal(
        &self,
        proposal: &Proposal,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ed25519Verifier
            .verify_signed_proposal(proposal, signature, public_key)
            .await
    }

    async fn verify_signed_vote_extension(
        &self,
        scope: &VoteExtensionScope<TestContext>,
        extension: &Bytes,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<VerificationResult, Error> {
        Ed25519Verifier
            .verify_signed_vote_extension(scope, extension, signature, public_key)
            .await
    }

    async fn verify_validator_proof(
        &self,
        proof: &ValidatorProof<TestContext>,
    ) -> Result<VerificationResult, Error> {
        Ed25519Verifier.verify_validator_proof(proof).await
    }
}

#[async_trait]
impl Signer<TestContext> for Ed25519Signer {
    async fn sign_vote(&self, vote: Vote) -> Result<SignedVote<TestContext>, Error> {
        let signature = self.sign(&vote.to_sign_bytes());

        if quint_oracle::enabled() {
            let key = qids::key(&self.private_key.public_key());
            qids::remember_signature(&signature, key, qids::vote_preimage(&vote));

            quint_oracle::Event::builder(quint_oracle::current_test(), "sign_vote")
                .argument("key", key, Some("KEYS"))
                .argument("vote", qids::vote_fields(&vote), Some("VOTE_FIELDS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("w"),
                        quint_oracle::PathSeg::ident("signings"),
                    ]),
                    qids::next_signing(),
                )
                .scope("signing")
                .send();
        }

        Ok(SignedVote::new(vote, signature))
    }

    async fn sign_proposal(
        &self,
        proposal: Proposal,
    ) -> Result<SignedProposal<TestContext>, Error> {
        let signature = self.private_key.sign(&proposal.to_sign_bytes());

        if quint_oracle::enabled() {
            let key = qids::key(&self.private_key.public_key());
            qids::remember_signature(&signature, key, qids::proposal_preimage(&proposal));

            quint_oracle::Event::builder(quint_oracle::current_test(), "sign_proposal")
                .argument("key", key, Some("KEYS"))
                .argument(
                    "proposal",
                    qids::proposal_fields(&proposal),
                    Some("PROPOSAL_FIELDS"),
                )
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("w"),
                        quint_oracle::PathSeg::ident("signings"),
                    ]),
                    qids::next_signing(),
                )
                .scope("signing")
                .send();
        }

        Ok(SignedProposal::new(proposal, signature))
    }

    async fn sign_vote_extension(
        &self,
        scope: VoteExtensionScope<TestContext>,
        extension: Bytes,
    ) -> Result<SignedExtension<TestContext>, Error> {
        let preimage = vote_extension_sign_bytes(&scope, &extension);
        let signature = self.private_key.sign(&preimage);

        if quint_oracle::enabled() {
            let key = qids::key(&self.private_key.public_key());
            qids::remember_signature(
                &signature,
                key,
                qids::extension_preimage(&scope, &extension),
            );

            quint_oracle::Event::builder(quint_oracle::current_test(), "sign_vote_extension")
                .argument("key", key, Some("KEYS"))
                .argument("scope", qids::scope_fields(&scope), Some("SCOPES"))
                .argument("ext", qids::extension(&extension), Some("EXTS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("w"),
                        quint_oracle::PathSeg::ident("signings"),
                    ]),
                    qids::next_signing(),
                )
                .scope("signing")
                .send();
        }

        Ok(SignedMessage::new(extension, signature))
    }

    async fn sign_validator_proof(
        &self,
        public_key: Vec<u8>,
        peer_id: Vec<u8>,
    ) -> Result<ValidatorProof<TestContext>, Error> {
        let preimage = ValidatorProof::<TestContext>::signing_bytes(&public_key, &peer_id);
        let signature = self.private_key.sign(&preimage);

        if quint_oracle::enabled() {
            let key = qids::key(&self.private_key.public_key());
            qids::remember_signature(&signature, key, qids::pov_preimage(&public_key, &peer_id));

            quint_oracle::Event::builder(quint_oracle::current_test(), "sign_validator_proof")
                .argument("key", key, Some("KEYS"))
                .argument("pk_bytes", qids::key_bytes(&public_key), None)
                .argument("peer_id", qids::peer(&peer_id), Some("PEERS"))
                .assert(
                    Vec::from([
                        quint_oracle::PathSeg::ident("w"),
                        quint_oracle::PathSeg::ident("signings"),
                    ]),
                    qids::next_signing(),
                )
                .scope("signing")
                .send();
        }

        Ok(ValidatorProof::new(public_key, peer_id, signature))
    }
}
