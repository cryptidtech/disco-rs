/// Software-only NIST K256
pub mod k256;
/// Software-only NIST P256
pub mod p256;
/// Software-only Curve25519
pub mod x25519;

use core::{
    fmt::{Display, Error as FmtError, Formatter},
    str::FromStr,
};
use disco_rs::{
    error::{Error, ParamError},
    key::{TaggedData, KeyType, KeyGenerator, KeyAgreement},
};
use elliptic_curve::ecdh::diffie_hellman;
use rand_core::{CryptoRng, RngCore};
use crate::tagged::{TaggedSlice, TaggedSliceBuilder};

/// A handy enumeration for all of the different key types we support in
/// software-only mode. This enumeration is a nice abstraction for run-time
/// selection of keys in an abstract way.
#[allow(non_camel_case_types)]
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum AsymKeyType {
    /// NIST K256 key type for ECDH
    K256,
    /// NIST P256 key type for ECDH
    P256,
    /// Curve25519 key type
    X25519,
}

/// This key type does impl FromStr and Display
impl KeyType for AsymKeyType {}

/// Implement a way to generate key pairs from AsymKeyType
impl<'a> KeyGenerator<'a> for AsymKeyType {
    /// The type of key returned from generating keys
    type PublicKey = TaggedSlice<33>;
    type SecretKey = TaggedSlice<32>;

    /// Generate a new key from a random data source
    fn generate(&self, rng: impl RngCore + CryptoRng) -> (Self::PublicKey, Self::SecretKey) {
        match self {
            AsymKeyType::K256 => {
                let s = k256::SecretKey::random(rng);
                (k256::PublicKeySlice::from(s.public_key()), k256::SecretKeySlice::from(s))
            },
            AsymKeyType::P256 => {
                let s = p256::SecretKey::random(rng);
                (p256::PublicKeySlice::from(s.public_key()), p256::SecretKeySlice::from(s))
            },
            AsymKeyType::X25519 => {
                let mut r = RngWrapper(rng);
                let s = x25519_dalek::StaticSecret::new(&mut r);
                let p = x25519_dalek::PublicKey::from(&s);

                (x25519::PublicKeySlice::from(p), x25519::SecretKeySlice::from(s))
            },
        }
    }
}

/// Implement doing ecdh for AsymKeyType
impl<'a> KeyAgreement<'a> for AsymKeyType {
    /// The type of key returned from generating keys
    type SharedSecret = TaggedSlice<32>;
    /// The error type
    type Error = Error;

    /// Do the ECDH operation
    fn ecdh(&self, local: &(impl TaggedData<'a> + ?Sized),
            remote: &(impl TaggedData<'a> + ?Sized)) -> Result<Self::SharedSecret, Self::Error> {
        match self {
            AsymKeyType::K256 => {
                let sslice = k256::SecretKeySlice::from(local.as_ref());
                let pslice = k256::PublicKeySlice::from(remote.as_ref());
                let sk = k256::SecretKey::from(sslice);
                let pk = k256::PublicKey::from(pslice);
                
                let ks = TaggedSliceBuilder::<32>::new("key.shared-secret.ecdh", 32)
                    .from_bytes(diffie_hellman(sk.to_secret_scalar(), pk.as_affine()).as_bytes().as_slice())
                    .build()?;
                Ok(ks)
            },
            AsymKeyType::P256 => {
                let sslice = p256::SecretKeySlice::from(local.as_ref());
                let pslice = p256::PublicKeySlice::from(remote.as_ref());
                let sk = p256::SecretKey::from(sslice);
                let pk = p256::PublicKey::from(pslice);

                let ks = TaggedSliceBuilder::<32>::new("key.shared-secret.ecdh", 32)
                    .from_bytes(diffie_hellman(sk.to_secret_scalar(), pk.as_affine()).as_bytes().as_slice())
                    .build()?;
                Ok(ks)
            },
            AsymKeyType::X25519  => {
                let sslice = x25519::SecretKeySlice::from(local.as_ref());
                let pslice = x25519::PublicKeySlice::from(remote.as_ref());
                let sk = x25519::SecretKey::from(sslice);
                let pk = x25519::PublicKey::from(pslice);

                let ks = TaggedSliceBuilder::<32>::new("key.shared-secret.ecdh", 32)
                    .from_bytes(&sk.diffie_hellman(&pk).to_bytes())
                    .build()?;
                Ok(ks)
            },
        }
    }
}
 

/// Enable creating AsymKeyType from str using parse()
impl FromStr for AsymKeyType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "25519"     => Ok(AsymKeyType::X25519),
            "K256"      => Ok(AsymKeyType::K256),
            "P256"      => Ok(AsymKeyType::P256),
            _ => Err(Error::Param(ParamError::InvalidKeyType))
        }
    }
}

/// Convert AsymKeyType back to a str
impl Display for AsymKeyType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        match self {
            AsymKeyType::X25519 => write!(f, "25519"),
            AsymKeyType::K256 => write!(f, "K256"),
            AsymKeyType::P256 => write!(f, "P256"),
        }
    }
}

struct RngWrapper<R: RngCore + CryptoRng>(R);

impl<R: RngCore + CryptoRng> rand_core5::RngCore for RngWrapper<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core5::Error> {
        self.0
            .try_fill_bytes(dest)
            .map_err(|e| rand_core5::Error::from(e.code().unwrap()))
    }
}

impl<R: RngCore + CryptoRng> rand_core5::CryptoRng for RngWrapper<R> {}
