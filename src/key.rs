use crate::tag::{Tag, TaggedData};
use core::{fmt::Display, str::FromStr};
use rand_core::{CryptoRng, RngCore};

/// Because Disco is an extension of the Noise protocol, it relies upon public key cryptography and
/// key agreement, so there are traits for a key generation function and a key agreement function.
/// Under the hood keys are just byte arrays with tags so when Disco needs to generate a new key or
/// do a key agreement it will call the functions provided by the user of this crate. This allows
/// for maximum algorithmic agility and allows the client to choose their own cryptography
/// algorithms and implementations.

/// Trait for any key type identifier
pub trait KeyType: FromStr + Display {}

/// Trait for any key generator
pub trait KeyGenerator<'a, T, P, S>
where
    T: Tag + Default,
    P: TaggedData<'a, T> + Clone + Default,
    S: TaggedData<'a, T> + Clone + Default,
{
    /// Generate a new key pair...the first returned tagged data is the public key, the other is
    /// the secret key
    fn generate(&self, key_type: &impl KeyType, rng: impl RngCore + CryptoRng) -> (P, S);
}

/// Trait for doing a key agreement
pub trait KeyAgreement<'a, T, P, S, SS>
where
    T: Tag + Default,
    P: TaggedData<'a, T> + Clone + Default,
    S: TaggedData<'a, T> + Clone + Default,
    SS: TaggedData<'a, T> + Clone + Default,
{
    /// The error type if something went wrong
    type Error;

    /// Calculate the shared secret from a local key and a remote key
    fn get_shared_secret(&self, local: &S, remote: &P) -> Result<SS, Self::Error>;
}
