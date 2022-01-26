use cde::TagBuilder;
use crate::tagged::TaggedSlice;
use disco_rs::key::TaggedData;
use x25519_dalek;

// We normalize the public and secret key types for ECDH and signing so that
// the rest of the code is easy to read and we don't constantly have to go
// check the documentation of the specific curve library to see what they
// call the object types.

/// Curve25519 public key
pub type PublicKey = x25519_dalek::PublicKey;
/// Curve25519 public key slice
pub type PublicKeySlice = TaggedSlice<33>;
/// Curve25519 secret key
pub type SecretKey = x25519_dalek::StaticSecret;
/// Curve25519 secret key slice
pub type SecretKeySlice = TaggedSlice<32>;

/// Conversion to slice type from lib type
impl From<PublicKey> for PublicKeySlice {
    fn from(pk: PublicKey) -> Self {
        let mut pks = PublicKeySlice::from(&pk.to_bytes()[0..]);
        pks.set_tag(&TagBuilder::from_tag("key.x25519.public").build().unwrap());
        pks.set_length(32).unwrap();
        pks
    }
}

/// Conversion to lib type from slice type
impl From<PublicKeySlice> for PublicKey {
    fn from(pk: PublicKeySlice) -> Self {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&pk.as_ref()[0..32]);
        PublicKey::from(buf)
    }
}

/// Conversion to slice type from lib type
impl From<SecretKey> for SecretKeySlice {
    fn from(sk: SecretKey) -> Self {
        let mut sks = SecretKeySlice::from(&sk.to_bytes());
        sks.set_tag(&TagBuilder::from_tag("key.x25519.secret").build().unwrap());
        sks.set_length(32).unwrap();
        sks
    }
}

/// Conversion to lib type from slice type
impl From<SecretKeySlice> for SecretKey {
    fn from(sk: SecretKeySlice) -> Self {
        SecretKey::from(sk.to_bytes())
    }
}
