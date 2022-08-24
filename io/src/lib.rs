#![no_std]

use codec::{Decode, Encode};
use gstd::{prelude::*, ActorId};
use scale_info::TypeInfo;

/// Typings for u8 arrays.
pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];
pub type PieceId = u128;

/// ClaimData represents an internal data stored inside a claim.
#[derive(Decode, Encode, TypeInfo, Debug, Clone, PartialEq)]
pub struct ClaimData {
    /// Set of hashed data (e.g. BTreeSet::from([city], [street])).
    pub hashed_info: BTreeSet<[u8; 32]>,
    /// Date of issuance of this claim.
    pub issuance_date: u128,
    /// Validation status of the claim.
    pub valid: bool,
}

/// Claim is a main object stored inside the identity storage.
/// Consists of the claim data and all the public keys and signatures.
///
/// # Requirements:
/// * all public keys and signatures MUST be non-zero arrays
#[derive(Decode, Encode, TypeInfo, Debug, Clone, PartialEq)]
pub struct Claim {
    /// Issuer's  public key (e.g. who issued the claim). Can be equal to subject keys
    /// if the subject issues any claim about himself.
    pub issuer: PublicKey,
    /// Issuer's signature with the issuer keypair.
    pub issuer_signature: Signature,
    /// Subject's public key.
    pub subject: PublicKey,
    /// Map of verifiers PublicKey -> Signature
    pub verifiers: BTreeMap<PublicKey, Signature>,
    /// Internal data of the claim
    pub data: ClaimData,
}

#[derive(Debug, Decode, Encode, TypeInfo)]
pub enum IdentityAction {
    /// Issues a new claim either by a subject himself
    /// or by an issuer on behalf of the subject
    ///
    /// # Requirements:
    /// * all public keys and signatures MUST be non-zero arrays
    IssueClaim {
        /// Issuer's public key.
        issuer: PublicKey,
        /// Issuer's signature with his keypair.
        issuer_signature: Signature,
        /// Subject's public key.
        subject: PublicKey,
        /// Claim's data.
        data: ClaimData,
    },
    /// Changes a validation status of the claim.
    /// Can only be performed by a subject or an issuer of the claim.
    ///
    /// # Requirements:
    /// * all public keys and signatures MUST be non-zero arrays
    ClaimValidationStatus {
        /// Validator's public key. Can be either a subject's or an issuer's one.
        validator: PublicKey,
        /// Subject's public key.
        subject: PublicKey,
        /// Claim's id.
        piece_id: PieceId,
        /// New status of the claim.
        status: bool,
    },
    /// Verify a specific claim with a public key and a signature.
    /// Can not be performed by an issuer or a subject.
    ///
    /// # Requirements:
    /// * all public keys and signatures MUST be non-zero arrays
    VerifyClaim {
        /// Verifier's public key.
        verifier: PublicKey,
        /// Verifier's signature.
        verifier_signature: Signature,
        /// Subject's public key.
        subject: PublicKey,
        /// Claim's id.
        piece_id: PieceId,
    },
    /// Check the claim with a hash from it's data set.
    ///
    /// # Requirements:
    /// * all public keys and signatures MUST be non-zero arrays
    CheckClaim {
        /// Subject's public key.
        subject: PublicKey,
        /// Claim's id.
        piece_id: PieceId,
        /// Hash to check against.
        hash: [u8; 32],
    },
}

#[derive(Debug, Decode, Encode, TypeInfo)]
pub enum IdentityEvent {
    ClaimIssued {
        /// Issuer's public key.
        issuer: PublicKey,
        /// Subject's public key.
        subject: PublicKey,
        /// Claim's id generated automatically.
        piece_id: PieceId,
    },
    ClaimValidationChanged {
        /// Validator's public key.
        validator: PublicKey,
        /// Subjects's public key.
        subject: PublicKey,
        /// Claims' id.
        piece_id: PieceId,
        /// Claim's new validation status.
        status: bool,
    },
    VerifiedClaim {
        /// Verifier's public key.
        verifier: PublicKey,
        /// Subject's public key.
        subject: PublicKey,
        /// Claim's id.
        piece_id: PieceId,
    },
    CheckedClaim {
        /// Subject's public key.
        subject: PublicKey,
        /// Claim's id.
        piece_id: PieceId,
        /// The result of the check (e.g. true is it was found in BTreeSet).
        status: bool,
    },
}

#[derive(Debug, Decode, Encode, TypeInfo)]
pub enum IdentityStateQuery {
    /// Get all the claims for a specified public key.
    UserClaims(PublicKey),
    /// Get a specific claim with the provided public key and a claim id.
    Claim(PublicKey, PieceId),
    /// Get all the verifiers' public keys for a corresponding claim.
    Verifiers(PublicKey, PieceId),
    /// Get claim's validation status.
    ValidationStatus(PublicKey, PieceId),
    /// Get claim's issuance date.
    Date(PublicKey, PieceId),
}

#[derive(Debug, Decode, Encode, TypeInfo)]
pub enum IdentityStateReply {
    UserClaims(BTreeMap<PieceId, Claim>),
    Claim(Option<Claim>),
    Verifiers(Vec<PublicKey>),
    ValidationStatus(bool),
    Date(u128),
}

/// Initializes an identity storage.
///
/// # Requirements:
/// * `owner_id` MUST be non-zero address
///
/// `owner_id` - is the owner of the contract.
#[derive(Decode, Encode, TypeInfo)]
pub struct InitIdentity {
    pub owner_id: ActorId,
}
