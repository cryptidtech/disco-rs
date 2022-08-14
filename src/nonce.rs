use crate::tag::{Tag, TaggedData};
use rand_core::{CryptoRng, RngCore};

/// This crate supports the out-of-order delivery of Disco messages to better support any and all
/// transport mechanisms that may deliver messages out of order. One key security concern with
/// out-of-order delivery is that the handshake cannot be done out of order. The strobe construct
/// at the heart of Disco makes sure that the session is aborted if the handshake messages are
/// processed out of order. The other key security concern is that the nonces associated with each
/// message must be tracked to prevent a replay attack. Below are traits for implementing a nonce
/// and a mechanism for tracking nonces. All Disco cares about is if its seen a nonce before or
/// not, the actual implementation is left to the user.

/// Trait for generating nonces and checking if we seen a nonce
pub trait NonceGenerator<'a, T, TD>
where
    T: Tag + Default,
    TD: TaggedData<'a, T> + Clone + Default,
{
    /// Generate a new nonce
    fn generate(&mut self, rng: impl RngCore + CryptoRng) -> TD;

    /// Check and add the nonce if unseen
    fn check_add(&mut self, nonce: &TD) -> bool;

    /// Reset the nonce generator
    fn reset(&mut self);
}
