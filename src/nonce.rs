/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::tag::{Tag, TaggedData};

/// Trait for generating nonces and checking if we seen a nonce
pub trait NonceGenerator<T, N>: Clone + Default
where
    T: Tag,
    N: TaggedData<T>,
{
    /// Generate a new nonce
    fn generate(&mut self) -> N;

    /// Empty nonce
    fn default_nonce(&self) -> N;

    /// Checks a nonce to see if it is valid
    fn check(&mut self, nonce: &N) -> bool;

    /// Resets the nonce generator and restarts it's stream from the channel state
    fn reset(&mut self, channel_state: &[u8; 32]);
}
