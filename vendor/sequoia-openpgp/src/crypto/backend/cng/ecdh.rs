//! Elliptic Curve Diffie-Hellman.

use crate::crypto::mem::Protected;
use crate::crypto::mpi::{self, Ciphertext, SecretKeyMaterial, MPI};
use crate::crypto::SessionKey;
use crate::packet::{key, Key};
use crate::types::Curve;
use crate::{Error, Result};

use crate::crypto::ecdh::{encrypt_wrap, decrypt_unwrap};

use win_crypto_ng as cng;
use cng::asymmetric::{Ecdh, AsymmetricKey, Export};
use cng::asymmetric::{Public, Private, AsymmetricAlgorithm, AsymmetricAlgorithmId};
use cng::asymmetric::ecc::{NamedCurve, NistP256, NistP384, NistP521};
use cng::key_blob::{EccKeyPublicPayload, EccKeyPrivatePayload};

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn encrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    session_key: &SessionKey,
) -> Result<mpi::Ciphertext>
where
    R: key::KeyRole,
{
    let (curve, q) = match recipient.mpis() {
        mpi::PublicKey::ECDH { curve, q, .. } => (curve, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };

    match curve {
        Curve::Cv25519 => return
            Err(Error::InvalidArgument("implemented elsewhere".into()).into()),

        Curve::NistP256 | Curve::NistP384 | Curve::NistP521 => {
            let (Rx, Ry) = q.decode_point(curve)?;

            let (VB, S) = match curve {
                Curve::NistP256 => {
                    // Obtain the authenticated recipient public key R and
                    // generate an ephemeral private key v.
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP256))?;
                    let R = AsymmetricKey::<Ecdh<NistP256>, Public>::import_from_parts(
                        &provider,
                        &EccKeyPublicPayload { x: Rx, y: Ry },
                    )?;
                    let v = AsymmetricKey::builder(Ecdh(NistP256)).build().unwrap();
                    let VB = v.export()?;
                    let VB = MPI::new_point(&VB.x(), &VB.y(), 256);
                    // Compute the shared point S = vR
                    let secret = cng::asymmetric::agreement::secret_agreement(&v, &R)?;
                    // Get the X coordinate
                    let mut S = Protected::from(secret.derive_raw()?);
                    // Returned secret is little-endian, flip it to big-endian
                    S.reverse();

                    assert_eq!(S.len(), 32);

                    (VB, S)
                }
                Curve::NistP384 => {
                    // Obtain the authenticated recipient public key R and
                    // generate an ephemeral private key v.
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP384))?;
                    let R = AsymmetricKey::<Ecdh<NistP384>, Public>::import_from_parts(
                        &provider,
                        &EccKeyPublicPayload { x: Rx, y: Ry },
                    )?;
                    let v = AsymmetricKey::builder(Ecdh(NistP384)).build().unwrap();
                    let VB = v.export()?;
                    let VB = MPI::new_point(&VB.x(), &VB.y(), 384);
                    // Compute the shared point S = vR
                    let secret = cng::asymmetric::agreement::secret_agreement(&v, &R)?;
                    // Get the X coordinate
                    let mut S = Protected::from(secret.derive_raw()?);
                    // Returned secret is little-endian, flip it to big-endian
                    S.reverse();

                    assert_eq!(S.len(), 48);

                    (VB, S)
                }
                Curve::NistP521 => {
                    // Obtain the authenticated recipient public key R and
                    // generate an ephemeral private key v.
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP521))?;
                    let R = AsymmetricKey::<Ecdh<NistP521>, Public>::import_from_parts(
                        &provider,
                        &EccKeyPublicPayload { x: Rx, y: Ry },
                    )?;
                    let v = AsymmetricKey::builder(Ecdh(NistP521)).build().unwrap();
                    let VB = v.export()?;
                    let VB = MPI::new_point(&VB.x(), &VB.y(), 521);
                    // Compute the shared point S = vR
                    let secret = cng::asymmetric::agreement::secret_agreement(&v, &R)?;

                    // Get the X coordinate
                    let mut S = Protected::from(secret.derive_raw()?);
                    // Returned secret is little-endian, flip it to big-endian
                    S.reverse();

                    assert_eq!(S.len(), 66);

                    (VB, S)
                }
                _ => unreachable!(),
            };

            encrypt_wrap(recipient, session_key, VB, &S)
        }

        // Not implemented in CNG.
        Curve::BrainpoolP256 | Curve::BrainpoolP384 | Curve::BrainpoolP512 =>
            Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),

        // N/A
        Curve::Unknown(_) | Curve::Ed25519 =>
            Err(Error::UnsupportedEllipticCurve(curve.clone()).into()),
    }
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
#[allow(non_snake_case)]
pub fn decrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    recipient_sec: &SecretKeyMaterial,
    ciphertext: &Ciphertext,
    plaintext_len: Option<usize>,
) -> Result<SessionKey>
where
    R: key::KeyRole,
{
    let (curve, scalar, e) = match (recipient.mpis(), recipient_sec, ciphertext) {
        (mpi::PublicKey::ECDH { ref curve, ..},
        SecretKeyMaterial::ECDH { ref scalar, },
        Ciphertext::ECDH { ref e, .. }) => (curve, scalar, e),
         _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };

    let S: Protected = match curve {
        Curve::Cv25519 => return
            Err(Error::InvalidArgument("implemented elsewhere".into()).into()),

        Curve::NistP256 | Curve::NistP384 | Curve::NistP521 => {
            // Get the public part V of the ephemeral key and
            // compute the shared point S = rV = rvG, where (r, R)
            // is the recipient's key pair.
            let (Vx, Vy) = e.decode_point(curve)?;
            match curve {
                Curve::NistP256 => {
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP256))?;
                    let V = AsymmetricKey::<Ecdh<NistP256>, Public>::import_from_parts(
                        &provider,
                        &EccKeyPublicPayload { x: Vx, y: Vy },
                    )?;
                    let d = scalar.value_padded(32);
                    let r = AsymmetricKey::<Ecdh<NistP256>, Private>::import_from_parts(
                        &provider,
                        &EccKeyPrivatePayload {
                            x: &[0; 32],
                            y: &[0; 32],
                            d: &d,
                        }
                    )?;

                    let secret = cng::asymmetric::agreement::secret_agreement(&r, &V)?;
                    // Returned secret is little-endian, flip it to big-endian
                    let mut secret = secret.derive_raw()?;
                    secret.reverse();
                    secret.into()
                }
                Curve::NistP384 => {
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP384))?;
                    let V = AsymmetricKey::<Ecdh<NistP384>, Public>::import_from_parts(
                        &provider,
                        &EccKeyPublicPayload { x: Vx, y: Vy },
                    )?;
                    let d = scalar.value_padded(48);
                    let r = AsymmetricKey::<Ecdh<NistP384>, Private>::import_from_parts(
                        &provider,
                        &EccKeyPrivatePayload {
                            x: &[0; 48],
                            y: &[0; 48],
                            d: &d,
                        }
                    )?;

                    let secret = cng::asymmetric::agreement::secret_agreement(&r, &V)?;
                    // Returned secret is little-endian, flip it to big-endian
                    let mut secret = secret.derive_raw()?;
                    secret.reverse();
                    secret.into()
                }
                Curve::NistP521 => {
                    let provider = AsymmetricAlgorithm::open(AsymmetricAlgorithmId::Ecdh(NamedCurve::NistP521))?;
                    let V = AsymmetricKey::<Ecdh<NistP521>, Public>::import_from_parts(
                        &provider,
                        &EccKeyPublicPayload { x: Vx, y: Vy },
                    )?;
                    let d = scalar.value_padded(66);
                    let r = AsymmetricKey::<Ecdh<NistP521>, Private>::import_from_parts(
                        &provider,
                        &EccKeyPrivatePayload {
                            x: &[0; 66],
                            y: &[0; 66],
                            d: &d,
                        }
                    )?;

                    let secret = cng::asymmetric::agreement::secret_agreement(&r, &V)?;
                    // Returned secret is little-endian, flip it to big-endian
                    let mut secret = secret.derive_raw()?;
                    secret.reverse();
                    secret.into()
                }
                _ => unreachable!(),
            }
        },
        _ => {
            return Err(Error::UnsupportedEllipticCurve(curve.clone()).into());
        }
    };

    decrypt_unwrap(recipient.role_as_unspecified(), &S, ciphertext,
                   plaintext_len)
}
