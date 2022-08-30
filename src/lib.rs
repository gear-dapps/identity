#![no_std]

use gstd::{msg, prelude::*, ActorId};
use identity_io::*;

const ZERO_KEY: [u8; 32] = [0; 32];
const ZERO_SIGNATURE: [u8; 64] = [0; 64];

#[derive(Debug, Default)]
pub struct IdentityStorage {
    pub owner_id: ActorId,
    pub user_claims: BTreeMap<PublicKey, BTreeMap<PieceId, Claim>>,
    pub piece_counter: u128,
}

static mut IDENTITY: Option<IdentityStorage> = None;

impl IdentityStorage {
    /// Creates a new claim.
    ///
    /// # Requirements:
    /// * all the public keys and signatures MUST be non-zero.
    ///
    /// # Arguments:
    /// * `issuer` - the claim issuer's public key.
    /// * `issuer_signature` - the corresponding signature with the `issuer` public key.
    /// * `subject`- the subject's public key.
    /// * `data` - claim's data.
    fn issue_claim(
        &mut self,
        issuer: PublicKey,
        issuer_signature: Signature,
        subject: PublicKey,
        data: ClaimData,
    ) {
        if subject == ZERO_KEY || issuer_signature == ZERO_SIGNATURE || issuer == ZERO_KEY {
            panic!("IDENTITY: Can not use a zero public key");
        }
        self.user_claims.entry(subject).or_default().insert(
            self.piece_counter,
            Claim {
                issuer,
                issuer_signature,
                subject,
                verifiers: BTreeMap::new(),
                data,
            },
        );

        self.piece_counter += 1;
        msg::reply(
            IdentityEvent::ClaimIssued {
                issuer,
                subject,
                piece_id: self.piece_counter - 1,
            },
            0,
        )
        .expect("IDENTITY: Error during replying with IdentityEvent::ClaimIssued");
    }

    /// Changes claim's validation status.
    ///
    /// # Requirements:
    /// * all the public keys and signatures MUST be non-zero.
    ///
    /// # Arguments:
    /// * `validator` - the claim issuer's or subject's public key.
    /// * `subject`- the subject's public key.
    /// * `piece_id` - claim's id.
    /// * `status` - new claim's status.
    fn validation_status(
        &mut self,
        validator: PublicKey,
        subject: PublicKey,
        piece_id: PieceId,
        status: bool,
    ) {
        // TODO!: Unnecessary check
        // TODO!: Check validator (message source)
        if validator == ZERO_KEY || subject == ZERO_KEY {
            panic!("IDENTITY: Can not use a zero public key");
        }
        let data_piece = self
            .user_claims
            .get(&subject)
            .expect("The user has no claims")
            .get(&piece_id)
            .expect("The user has not such claim with the provided piece_id");
        if data_piece.subject != validator && data_piece.issuer != validator {
            panic!("IDENTITY: You can not change this claim");
        }
        self.user_claims
            .entry(subject)
            .or_default()
            .entry(piece_id)
            .and_modify(|claim| claim.data.valid = status);

        msg::reply(
            IdentityEvent::ClaimValidationChanged {
                validator,
                subject,
                piece_id,
                status,
            },
            0,
        )
        .expect("IDENTITY: Error during replying with IdentityEvent::ClaimValidationChanged");
    }

    /// Verifies the claim.
    ///
    /// # Requirements:
    /// * all the public keys and signatures MUST be non-zero.
    /// * `verifier` - MUST differ from the claim's subject or issuer.
    ///
    /// # Arguments:
    /// * `verifier` - the claim verifier's public key.
    /// * `verifier_signature` - the corresponding signature with the `verifier` public key.
    /// * `piece_id` - claim's id.
    /// * `subject` - subject's public key.
    fn verify_claim(
        &mut self,
        verifier: PublicKey,
        verifier_signature: Signature,
        subject: PublicKey,
        piece_id: PieceId,
    ) {
        if verifier == ZERO_KEY || subject == ZERO_KEY || verifier_signature == ZERO_SIGNATURE {
            panic!("IDENTITY: Can not use a zero public key");
        }
        let piece = self
            .user_claims
            .get(&subject)
            .expect("The user has no claims")
            .get(&piece_id)
            .expect("The user has not such claim with the provided piece_id");
        if piece.issuer == verifier || piece.subject == verifier {
            panic!("IDENTITY: You can not verify this claim");
        }
        self.user_claims
            .entry(subject)
            .or_default()
            .entry(piece_id)
            .and_modify(|claim| {
                claim.verifiers.insert(verifier, verifier_signature);
            });
        msg::reply(
            IdentityEvent::VerifiedClaim {
                verifier,
                subject,
                piece_id,
            },
            0,
        )
        .expect("IDENTITY: Error during replying with IdentityEvent::VerifiedClaim");
    }

    /// Check the claim's internal data.
    ///
    /// # Requirements:
    /// * all the public keys and signatures MUST be non-zero.
    /// * `verifier` - MUST differ from the claim's subject or issuer.
    ///
    /// # Arguments:
    /// * `piece_id` - claim's id.
    /// * `subject` - subject's public key.
    /// * `hash` - the hash to check against.
    fn check_claim(&mut self, subject: PublicKey, piece_id: PieceId, hash: [u8; 32]) {
        // TODO!: Rewrite in rust
        let mut status = false;
        if self
            .user_claims
            .get(&subject)
            .expect("The user has no claims")
            .get(&piece_id)
            .expect("The user has not such claim with the provided piece_id")
            .data
            .hashed_info
            .contains(&hash)
        {
            status = true;
        }
        msg::reply(
            IdentityEvent::CheckedClaim {
                subject,
                piece_id,
                status,
            },
            0,
        )
        .expect("IDENTITY: Error during replying with IdentityEvent::CheckedClaim");
    }
}

#[no_mangle]
pub unsafe extern "C" fn init() {
    let config: InitIdentity = msg::load().expect("Unable to decode InitIdentity");
    if config.owner_id == ActorId::zero() {
        panic!("IDENTITY: Owner MUST be non-zero address");
    }
    let id_storage = IdentityStorage {
        owner_id: config.owner_id,
        piece_counter: 1,
        ..Default::default()
    };
    IDENTITY = Some(id_storage);
}

#[gstd::async_main]
async fn main() {
    let action: IdentityAction = msg::load().expect("Unable to decode IdentityAction");
    let identity = unsafe { IDENTITY.get_or_insert(Default::default()) };
    match action {
        IdentityAction::IssueClaim {
            issuer,
            issuer_signature,
            subject,
            data,
        } => identity.issue_claim(issuer, issuer_signature, subject, data),
        IdentityAction::ClaimValidationStatus {
            validator,
            subject,
            piece_id,
            status,
        } => identity.validation_status(validator, subject, piece_id, status),
        IdentityAction::VerifyClaim {
            verifier,
            verifier_signature,
            subject,
            piece_id,
        } => identity.verify_claim(verifier, verifier_signature, subject, piece_id),
        IdentityAction::CheckClaim {
            subject,
            piece_id,
            hash,
        } => identity.check_claim(subject, piece_id, hash),
    }
}

#[no_mangle]
extern "C" fn meta_state() -> *mut [i32; 2] {
    let state: IdentityStateQuery = msg::load().expect("Unable to decode IdentityStateQuery");
    let identity = unsafe { IDENTITY.get_or_insert(Default::default()) };
    let reply = match state {
        IdentityStateQuery::UserClaims(pkey) => {
            IdentityStateReply::UserClaims(match identity.user_claims.get(&pkey) {
                None => BTreeMap::new(),
                Some(claims) => claims.clone(),
            })
        }
        IdentityStateQuery::Claim(pkey, piece_id) => IdentityStateReply::Claim(
            identity
                .user_claims
                .entry(pkey)
                .or_default()
                .get(&piece_id)
                .cloned(),
        ),
        IdentityStateQuery::ValidationStatus(pkey, piece_id) => {
            IdentityStateReply::ValidationStatus(
                identity
                    .user_claims
                    .get(&pkey)
                    .expect("No such public key")
                    .get(&piece_id)
                    .expect("No such piece_id")
                    .data
                    .valid,
            )
        }
        IdentityStateQuery::Date(pkey, piece_id) => IdentityStateReply::Date(
            identity
                .user_claims
                .get(&pkey)
                .expect("No such public key")
                .get(&piece_id)
                .expect("No such piece_id")
                .data
                .issuance_date,
        ),
        IdentityStateQuery::Verifiers(pkey, piece_id) => IdentityStateReply::Verifiers(
            identity
                .user_claims
                .get(&pkey)
                .expect("No such public key")
                .get(&piece_id)
                .expect("No such piece_id")
                .verifiers
                .keys()
                .cloned()
                .collect(),
        ),
    };
    gstd::util::to_leak_ptr(reply.encode())
}

gstd::metadata! {
    title: "Identity",
    init:
        input: InitIdentity,
    handle:
        input: IdentityAction,
        output: IdentityEvent,
    state:
        input: IdentityStateQuery,
        output: IdentityStateReply,
}
