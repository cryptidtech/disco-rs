use cde::TagBuilder;
use crate::tagged::TaggedSlice;
use disco_rs::key::TaggedData;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256;

// We normalize the public and secret key types for ECDH and signing so that
// the rest of the code is easy to read and we don't constantly have to go
// check the documentation of the specific curve library to see what they
// call the object types.

/// NIST P256 public key
pub type PublicKey = p256::PublicKey;
/// NIST P256 public key slice
pub type PublicKeySlice = TaggedSlice<33>;
/// NIST P256 secret key
pub type SecretKey = p256::SecretKey;
/// NIST P256 secret key slice
pub type SecretKeySlice = TaggedSlice<32>;
/// NIST P256 verifying key
pub type VerifyingKey = p256::ecdsa::VerifyingKey;
/// NIST P256 public key slice
pub type VerifyingKeySlice = TaggedSlice<33>;
/// NIST P256 signing key
pub type SigningKey = p256::ecdsa::SigningKey;
/// NIST P256 public key slice
pub type SigningKeySlice = TaggedSlice<32>;

/// Conversion to slice type from lib type
impl From<PublicKey> for PublicKeySlice {
    fn from(pk: PublicKey) -> Self {
        let mut pks = PublicKeySlice::from(pk.to_encoded_point(true).as_ref());
        pks.set_tag(&TagBuilder::from_tag("key.p256.public").build().unwrap());
        pks.set_length(33).unwrap();
        pks
    }
}

/// Conversion to lib type from slice type
impl From<PublicKeySlice> for PublicKey {
    fn from(pk: PublicKeySlice) -> Self {
        PublicKey::from_encoded_point(&p256::EncodedPoint::from_bytes(pk).unwrap()).unwrap()
    }
}

/// Conversion to slice type from lib type
impl From<SecretKey> for SecretKeySlice {
    fn from(sk: SecretKey) -> Self {
        let mut sks = SecretKeySlice::from(sk.to_bytes().as_slice());
        sks.set_tag(&TagBuilder::from_tag("key.p256.secret").build().unwrap());
        sks.set_length(32).unwrap();
        sks
    }
}

/// Conversion to lib type from slice type
impl From<SecretKeySlice> for SecretKey {
    fn from(sk: SecretKeySlice) -> Self {
        SecretKey::from_bytes(sk.as_ref()).unwrap()
    }
}

/// Conversion to slice type from lib type
impl From<VerifyingKey> for VerifyingKeySlice {
    fn from(pk: VerifyingKey) -> Self {
        let mut vks = VerifyingKeySlice::from(pk.to_encoded_point(true).as_ref());
        vks.set_tag(&TagBuilder::from_tag("key.p256.verifying").build().unwrap());
        vks.set_length(33).unwrap();
        vks
    }
}

/// Conversion to lib type from slice type
impl From<VerifyingKeySlice> for VerifyingKey {
    fn from(pk: VerifyingKeySlice) -> Self {
        VerifyingKey::from_encoded_point(&p256::EncodedPoint::from_bytes(pk).unwrap()).unwrap()
    }
}

/// Conversion to slice type from lib type
impl From<SigningKey> for SigningKeySlice {
    fn from(sk: SigningKey) -> Self {
        let mut sks = SigningKeySlice::from(sk.to_bytes().as_slice());
        sks.set_tag(&TagBuilder::from_tag("key.p256.signing").build().unwrap());
        sks.set_length(32).unwrap();
        sks
    }
}

/// Conversion to lib type from slice type
impl From<SigningKeySlice> for SigningKey {
    fn from(sk: SigningKeySlice) -> Self {
        SigningKey::from_bytes(sk.as_ref()).unwrap()
    }
}
