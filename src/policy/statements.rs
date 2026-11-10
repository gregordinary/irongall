//! A certificate's statements: the signatures its primary key made over
//! itself, its user IDs, and its subkeys, each attributed to the part it is
//! over by verifying it there, wherever assembly placed it.
//!
//! The order of a certificate's packets is covered by no signature, so where
//! a signature is placed is a guess at what it is over, and anyone who
//! handles the certificate can change it: a User ID or Subkey packet
//! inserted before a statement places it with the inserted part, where it
//! does not verify, and a User Attribute packet inserted before it passes
//! it over. A statement found nowhere restricts nothing, so each one that
//! does not verify where it is placed is tried over every other part it may
//! be over. See [`Statements::of`] for what that search may cost.

use alloc::vec;
use alloc::vec::Vec;

use super::Policy;
use crate::cert::Certificate;
use crate::signature::{Over, PrimaryChecks, Signature, SignatureType, VerifyError};

/// How many octets judging a certificate may hash searching for the parts
/// its signatures are over, for each octet of its signatures.
const SEARCH_OCTETS: usize = 128;

/// What each try of a signature over a part is charged beyond the octets it
/// hashes: finishing a hash, and copying a hash's state, which every try
/// costs however little it hashes.
const TRY_OVERHEAD: usize = 128;

/// A signature and whether irongall honors it.
pub(super) type Statement<'a> = (&'a Signature, bool);

/// A part of a certificate a statement may be over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// The primary key alone.
    Key,
    /// The user ID at this index.
    UserId(usize),
    /// The subkey at this index.
    Subkey(usize),
}

/// The statements a certificate's primary key made, each with the part it is
/// over.
#[derive(Debug)]
pub(super) struct Statements<'a> {
    /// Over the primary key alone: direct-key signatures, key revocations,
    /// and certification revocations that withdraw a direct-key signature.
    pub(super) key: Vec<Statement<'a>>,
    /// Over each user ID, in the certificate's order: certifications, and
    /// certification revocations that withdraw one.
    pub(super) user_ids: Vec<Vec<Statement<'a>>>,
    /// Over each subkey, in the certificate's order: bindings and
    /// revocations. `None` for a subkey the policy refuses, over which no
    /// signature is verified.
    pub(super) subkeys: Vec<Option<Vec<Statement<'a>>>>,
    /// Whether searching for the parts the certificate's signatures are over
    /// would take more than [`Statements::of`] allows, so that statements
    /// may have been missed.
    pub(super) unbounded: bool,
}

/// A signature that does not verify as the primary key's over the part it
/// is placed with, and the part it was tried over there, if any.
type Displaced<'a> = (Statement<'a>, Option<Part>);

impl<'a> Statements<'a> {
    /// Attributes `certificate`'s statements, judging its subkeys under
    /// `policy`.
    ///
    /// Each signature is verified first over the part it is placed with: a
    /// certification revocation that follows a user ID over the user ID and
    /// over the primary key alone, since it may withdraw either's
    /// self-signature. Those that do not verify there, and the
    /// certifications, bindings, and subkey revocations placed with no part,
    /// are then tried over every other part of the kind their type is over,
    /// until one verifies: a certification or a certification revocation
    /// over each user ID, and a subkey binding or revocation over each
    /// subkey the policy accepts. A statement over a subkey the policy
    /// refuses restricts nothing, since the subkey grants nothing, and each
    /// signature over a subkey is hashed over the whole of it, which for a
    /// key irongall does not read may be as long as its packet.
    ///
    /// Which key made a statement is its equation's to say, without the
    /// floor RFC 9580 sets on an Ed25519 signature's hash, so a statement
    /// over a hash too short for its algorithm is attributed, and restricts
    /// (see [`PrimaryChecks::made_by`]).
    ///
    /// A certificate as its maker wrote it places every statement where it
    /// verifies, so what the search tries are the signatures other keys made,
    /// over its user IDs and over parts passed over, and whatever has been
    /// inserted or moved. The search is bounded by the certificate's own
    /// size: it hashes at most [`SEARCH_OCTETS`] octets for each octet of the
    /// certificate's signatures, each try charged [`TRY_OVERHEAD`] octets
    /// beyond what it hashes, and checks no more signatures by their
    /// equation than the certificate holds. Past either bound it stops, and
    /// the certificate is [`unbounded`](Self::unbounded). Both bounds and
    /// what the search costs grow alike with the certificate, so a keyring
    /// that holds a certificate twice judges it as one that holds it once.
    pub(super) fn of(certificate: &'a Certificate, policy: &Policy) -> Statements<'a> {
        let primary = certificate.primary();
        let mut checks = PrimaryChecks::new(primary);
        let mut statements = Statements {
            key: Vec::new(),
            user_ids: vec![Vec::new(); certificate.user_ids().len()],
            subkeys: certificate
                .subkeys()
                .iter()
                .map(|subkey| policy.accepts_key(subkey.key()).then(Vec::new))
                .collect(),
            unbounded: false,
        };
        let mut displaced: Vec<Displaced<'a>> = Vec::new();
        let mut length: usize = 0;
        let mut count: usize = 0;
        let mut held = |honored: &'a [Signature], unhonored: &'a [Signature]| {
            for signature in honored.iter().chain(unhonored) {
                length = length.saturating_add(signature.length());
                count = count.saturating_add(1);
            }
            both(honored, unhonored)
        };

        let (honored, unhonored) = (
            certificate.primary_signatures(),
            certificate.unhonored_primary_signatures(),
        );
        for statement in held(honored, unhonored) {
            if checks.made_by(statement.0, Over::Key).is_ok() {
                statements.key.push(statement);
            } else if statement.0.signature_type() == SignatureType::CERTIFICATION_REVOCATION {
                displaced.push((statement, Some(Part::Key)));
            }
        }
        for (index, user_id) in certificate.user_ids().iter().enumerate() {
            let over = Over::UserId(user_id.value());
            for statement in held(user_id.signatures(), user_id.unhonored_signatures()) {
                let signature = statement.0;
                if checks.made_by(signature, over).is_ok() {
                    statements.push(Part::UserId(index), statement);
                } else if signature.signature_type() == SignatureType::CERTIFICATION_REVOCATION
                    && checks.made_by(signature, Over::Key).is_ok()
                {
                    statements.key.push(statement);
                } else {
                    displaced.push((statement, Some(Part::UserId(index))));
                }
            }
        }
        for (index, subkey) in certificate.subkeys().iter().enumerate() {
            let accepted = statements.subkeys.get(index).is_some_and(Option::is_some);
            for statement in held(subkey.signatures(), subkey.unhonored_signatures()) {
                if accepted
                    && checks
                        .made_by(statement.0, Over::Subkey(subkey.key()))
                        .is_ok()
                {
                    statements.push(Part::Subkey(index), statement);
                } else {
                    displaced.push((statement, accepted.then_some(Part::Subkey(index))));
                }
            }
        }
        let (honored, unhonored) = certificate.unplaced_signatures();
        displaced.extend(held(honored, unhonored).map(|statement| (statement, None)));

        let mut search = Search {
            octets: length.saturating_mul(SEARCH_OCTETS),
            operations: count,
            user_ids: certificate
                .user_ids()
                .iter()
                .enumerate()
                .map(|(index, user_id)| (Part::UserId(index), Over::UserId(user_id.value())))
                .collect(),
            subkeys: certificate
                .subkeys()
                .iter()
                .zip(&statements.subkeys)
                .enumerate()
                .filter(|(_, (_, accepted))| accepted.is_some())
                .map(|(index, (subkey, _))| (Part::Subkey(index), Over::Subkey(subkey.key())))
                .collect(),
        };
        statements.unbounded = search
            .attribute(&mut checks, &mut statements, displaced)
            .is_none();
        statements
    }

    /// Records `statement` as over `part`.
    fn push(&mut self, part: Part, statement: Statement<'a>) {
        let statements = match part {
            Part::Key => Some(&mut self.key),
            Part::UserId(index) => self.user_ids.get_mut(index),
            Part::Subkey(index) => self.subkeys.get_mut(index).and_then(Option::as_mut),
        };
        if let Some(statements) = statements {
            statements.push(statement);
        }
    }
}

/// What is left of the bound on searching for the parts a certificate's
/// signatures are over, and the parts each kind of statement may be over.
struct Search<'a> {
    /// The octets the search may still hash.
    octets: usize,
    /// The signatures it may still check by their equation.
    operations: usize,
    /// Every user ID.
    user_ids: Vec<(Part, Over<'a>)>,
    /// Every subkey the policy accepts.
    subkeys: Vec<(Part, Over<'a>)>,
}

impl<'a> Search<'a> {
    /// Tries each of the `displaced` signatures over the other parts it may
    /// be over, and records it with the one it verifies over. `None` once
    /// the bound is spent.
    ///
    /// Every part a signature is tried over is charged, and the only part
    /// passed over without a try is the one it was tried over where it was
    /// placed, so the search does no work the bound does not count beyond a
    /// step for each signature, however many signatures and parts there
    /// are.
    fn attribute(
        &mut self,
        checks: &mut PrimaryChecks<'_>,
        statements: &mut Statements<'a>,
        displaced: Vec<Displaced<'a>>,
    ) -> Option<()> {
        for (statement, tried) in displaced {
            let signature = statement.0;
            if !checks.may_have_made(signature) {
                continue;
            }
            let signature_type = signature.signature_type();
            let parts: &[(Part, Over<'a>)] = match signature_type {
                SignatureType::GENERIC_CERTIFICATION
                | SignatureType::PERSONA_CERTIFICATION
                | SignatureType::CASUAL_CERTIFICATION
                | SignatureType::POSITIVE_CERTIFICATION
                | SignatureType::CERTIFICATION_REVOCATION => &self.user_ids,
                SignatureType::SUBKEY_BINDING | SignatureType::SUBKEY_REVOCATION => &self.subkeys,
                _ => &[],
            };
            // A certification revocation is placed with a user ID or with
            // the primary key, and was tried over the primary key alone
            // either way, so the user IDs are what is left.
            let candidates = parts.iter().filter(|&&(part, _)| Some(part) != tried);
            for &(part, over) in candidates {
                let cost = checks.cost(signature, over).saturating_add(TRY_OVERHEAD);
                self.octets = self.octets.checked_sub(cost)?;
                let made = checks.made_by(signature, over);
                if made != Err(VerifyError::HashPrefixMismatch) {
                    self.operations = self.operations.checked_sub(1)?;
                }
                if made.is_ok() {
                    statements.push(part, statement);
                    break;
                }
            }
        }
        Some(())
    }
}

/// Each of `honored` paired with `true`, then each of `unhonored` with
/// `false`.
fn both<'a>(
    honored: &'a [Signature],
    unhonored: &'a [Signature],
) -> impl Iterator<Item = Statement<'a>> {
    let honored = honored.iter().map(|signature| (signature, true));
    honored.chain(unhonored.iter().map(|signature| (signature, false)))
}
