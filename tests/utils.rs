use gstd::{prelude::*, ActorId};
use gtest::{Program, System};
use identity_io::*;

// MESSAGES
pub fn init_identity(sys: &System, user: u64) -> Program {
    sys.init_logger();
    let id_program = Program::current(sys);
    assert!(id_program
        .send(
            user,
            InitIdentity {
                owner_id: ActorId::from(user),
            },
        )
        .log()
        .is_empty());

    id_program
}

pub fn issue_claim_utils(
    id_program: &Program,
    user: u64,
    claim: Claim,
    piece_id: PieceId,
    should_fail: bool,
) {
    let res = id_program.send(
        user,
        IdentityAction::IssueClaim {
            issuer: claim.issuer,
            issuer_signature: claim.issuer_signature,
            subject: claim.subject,
            data: claim.data,
        },
    );

    if should_fail {
        assert!(res.main_failed());
    } else {
        assert!(res.contains(&(
            user,
            IdentityEvent::ClaimIssued {
                issuer: claim.issuer,
                subject: claim.subject,
                piece_id,
            }
            .encode()
        )));
    }
}

pub fn validation_claim_utils(
    id_program: &Program,
    user: u64,
    validator: PublicKey,
    subject: PublicKey,
    piece_id: PieceId,
    status: bool,
    should_fail: bool,
) {
    let res = id_program.send(
        user,
        IdentityAction::ClaimValidationStatus {
            validator,
            subject,
            piece_id,
            status,
        },
    );

    if should_fail {
        assert!(res.main_failed());
    } else {
        assert!(res.contains(&(
            user,
            IdentityEvent::ClaimValidationChanged {
                validator,
                subject,
                piece_id,
                status,
            }
            .encode()
        )));
    }
}

pub fn verify_claim_utils(
    id_program: &Program,
    user: u64,
    verifier: PublicKey,
    verifier_signature: Signature,
    subject: PublicKey,
    piece_id: PieceId,
    should_fail: bool,
) {
    let res = id_program.send(
        user,
        IdentityAction::VerifyClaim {
            verifier,
            verifier_signature,
            subject,
            piece_id,
        },
    );

    if should_fail {
        assert!(res.main_failed());
    } else {
        assert!(res.contains(&(
            user,
            IdentityEvent::VerifiedClaim {
                verifier,
                subject,
                piece_id,
            }
            .encode()
        )));
    }
}

pub fn check_claim_utils(
    id_program: &Program,
    user: u64,
    subject: PublicKey,
    piece_id: PieceId,
    hash: [u8; 32],
    status: bool,
    should_fail: bool,
) {
    let res = id_program.send(
        user,
        IdentityAction::CheckClaim {
            subject,
            piece_id,
            hash,
        },
    );

    if should_fail {
        assert!(res.main_failed());
    } else {
        assert!(res.contains(&(
            user,
            IdentityEvent::CheckedClaim {
                subject,
                piece_id,
                status,
            }
            .encode()
        )));
    }
}

// META-STATE
pub fn check_user_claims_state_utils(
    id_program: &Program,
    subject: PublicKey,
    claims: BTreeMap<PieceId, Claim>,
) {
    match id_program.meta_state(IdentityStateQuery::UserClaims(subject)) {
        gstd::Ok(IdentityStateReply::UserClaims(real_claims)) => {
            if !maps_match(&real_claims, &claims) {
                panic!("IDENTITY: User claims differ")
            }
        }
        _ => {
            unreachable!(
                "Unreachable metastate reply for the IdentityStateQuery::UserClaims payload has occured"
            )
        }
    }
}

pub fn check_claim_state_utils(
    id_program: &Program,
    subject: PublicKey,
    piece_id: PieceId,
    claim: Claim,
) {
    match id_program.meta_state(IdentityStateQuery::Claim(subject, piece_id)) {
        gstd::Ok(IdentityStateReply::Claim(real_claim)) => {
            if let Some(cl) = real_claim {
                if claim != cl {
                    panic!("IDENTITY: Claims differ");
                }
            } else {
                panic!("IDENTITY: No such claim");
            }
        }
        _ => {
            unreachable!(
                "Unreachable metastate reply for the IdentityStateQuery::Claim payload has occured"
            )
        }
    }
}

pub fn check_verifiers_state_utils(
    id_program: &Program,
    subject: PublicKey,
    piece_id: PieceId,
    verifiers: Vec<PublicKey>,
) {
    match id_program.meta_state(IdentityStateQuery::Verifiers(subject, piece_id)) {
        gstd::Ok(IdentityStateReply::Verifiers(real_verifiers)) => {
            if real_verifiers != verifiers {
                panic!("IDENTITY: Verifiers differ");
            }
        }
        _ => {
            unreachable!(
                "Unreachable metastate reply for the IdentityStateQuery::Verifiers payload has occured"
            )
        }
    }
}

pub fn check_date_state_utils(
    id_program: &Program,
    subject: PublicKey,
    piece_id: PieceId,
    date: u128,
) {
    match id_program.meta_state(IdentityStateQuery::Date(subject, piece_id)) {
        gstd::Ok(IdentityStateReply::Date(real_date)) => {
            if real_date != date {
                panic!("IDENTITY: Dates differ");
            }
        }
        _ => {
            unreachable!(
                "Unreachable metastate reply for the IdentityStateQuery::Date payload has occured"
            )
        }
    }
}

pub fn check_valid_state_utils(
    id_program: &Program,
    subject: PublicKey,
    piece_id: PieceId,
    valid: bool,
) {
    match id_program.meta_state(IdentityStateQuery::ValidationStatus(subject, piece_id)) {
        gstd::Ok(IdentityStateReply::ValidationStatus(real_valid)) => {
            if real_valid != valid {
                panic!("IDENTITY: Validation status differ");
            }
        }
        _ => {
            unreachable!(
                "Unreachable metastate reply for the IdentityStateQuery::ValidationStatus payload has occured"
            )
        }
    }
}

fn maps_match<
    T: Eq + gstd::Ord + gstd::Clone,
    U: gstd::Clone + gstd::PartialEq<V>,
    V: gstd::Clone,
>(
    map1: &BTreeMap<T, U>,
    map2: &BTreeMap<T, V>,
) -> bool {
    map1.len() == map2.len()
        && map1.keys().cloned().collect::<Vec<_>>() == map2.keys().cloned().collect::<Vec<_>>()
        && map1.values().cloned().collect::<Vec<_>>() == map2.values().cloned().collect::<Vec<_>>()
}
