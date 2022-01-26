use core::{
    fmt::Display,
    str::FromStr
};
use crate::error::Error;
use rand_core::{CryptoRng, RngCore};

/// Trait that all CDE tagged data must impl, the super traits are for
/// accessing the data bytes in the object.
pub trait TaggedData<'a>: AsRef<[u8]> + AsMut<[u8]> {
    /// Gets the tag
    fn get_tag(&self) -> &cde::Tag;
    /// Sets the tag from bytes
    fn set_tag(&mut self, tag: &cde::Tag);
    /// Tells if the data is all zeroes
    fn is_zero(&self) -> bool;
    /// Zeroes the data
    fn zero(&mut self);
    /// Returns the maximum amount of data it can hold
    fn max_length(&self) -> usize;
    /// Returns the length of the data contained, 0 if is_zero() == true
    fn length(&self) -> usize;
    /// Sets the data from bytes
    fn set_length(&mut self, len: usize) -> Result<usize, Error>;
}

/// Trait for any key type identifier
pub trait KeyType: FromStr + Display {}

/// Trait for any key generator
pub trait KeyGenerator<'a> {
    /// The public portion of the key, may be zero for symmetric keys
    type PublicKey: TaggedData<'a>;
    /// The secret portion of the key
    type SecretKey: TaggedData<'a>;

    /// Generate a new key from a random data source
    fn generate(&self, rng: impl RngCore + CryptoRng) -> (Self::PublicKey, Self::SecretKey);
}

/// Trait for doing ECDH key agreement
pub trait KeyAgreement<'a> {
    /// The type of key returned from the ECDH operation
    type SharedSecret: TaggedData<'a>;
    /// The error type if something went wrong
    type Error;

    /// Do the ECDH operation
    fn ecdh(&self, local: &(impl TaggedData<'a> + ?Sized),
        remote: &(impl TaggedData<'a> + ?Sized)) -> Result<Self::SharedSecret, Self::Error>;
}


