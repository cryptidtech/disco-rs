use cde::TagBuilder;
use crate::tagged::TaggedSlice;
use disco_rs::key::TaggedData;
use elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256;

// We normalize the public and secret key types for ECDH and signing so that
// the rest of the code is easy to read and we don't constantly have to go
// check the documentation of the specific curve library to see what they
// call the object types.

/// NIST K256 public key
pub type PublicKey = k256::PublicKey;
/// NIST K256 public key slice
pub type PublicKeySlice = TaggedSlice<33>;
/// NIST K256 secret key
pub type SecretKey = k256::SecretKey;
/// NIST K256 secret key slice
pub type SecretKeySlice = TaggedSlice<32>;
/// NIST K256 verifying key
pub type VerifyingKey = k256::ecdsa::VerifyingKey;
/// NIST K256 public key slice
pub type VerifyingKeySlice = TaggedSlice<33>;
/// NIST K256 signing key
pub type SigningKey = k256::ecdsa::SigningKey;
/// NIST K256 public key slice
pub type SigningKeySlice = TaggedSlice<32>;

/// Conversion to slice type from lib type
impl From<PublicKey> for PublicKeySlice {
    fn from(pk: PublicKey) -> Self {
        let mut pks = PublicKeySlice::from(pk.to_encoded_point(true).as_ref());
        pks.set_tag(&TagBuilder::from_tag("key.k256.public").build().unwrap());
        pks.set_length(33).unwrap();
        pks
    }
}

/// Conversion to lib type from slice type
impl From<PublicKeySlice> for PublicKey {
    fn from(pk: PublicKeySlice) -> Self {
        PublicKey::from_encoded_point(&k256::EncodedPoint::from_bytes(pk).unwrap()).unwrap()
    }
}

/// Conversion to slice type from lib type
impl From<SecretKey> for SecretKeySlice {
    fn from(sk: SecretKey) -> Self {
        let mut sks = SecretKeySlice::from(sk.to_bytes().as_slice());
        sks.set_tag(&TagBuilder::from_tag("key.k256.secret").build().unwrap());
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
        vks.set_tag(&TagBuilder::from_tag("key.k256.verifying").build().unwrap());
        vks.set_length(33).unwrap();
        vks
    }
}

/// Conversion to lib type from slice type
impl From<VerifyingKeySlice> for VerifyingKey {
    fn from(pk: VerifyingKeySlice) -> Self {
        VerifyingKey::from_encoded_point(&k256::EncodedPoint::from_bytes(pk).unwrap()).unwrap()
    }
}

/// Conversion to slice type from lib type
impl From<SigningKey> for SigningKeySlice {
    fn from(sk: SigningKey) -> Self {
        let mut sks = SigningKeySlice::from(sk.to_bytes().as_slice());
        sks.set_tag(&TagBuilder::from_tag("key.k256.signing").build().unwrap());
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
