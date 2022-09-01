/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//!
#![feature(trait_alias)]
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(feature = "alloc", test))]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

/// Disco session builder
pub mod builder;
/// Disco channel
pub mod channel;
/// Disco errors
pub mod error;
/// Disco handshake
pub mod handshake;
/// Disco key traits
pub mod key;
/// Disco nonce traits
pub mod nonce;
/// Disco params
pub mod params;
/// Disco prologue trait
pub mod prologue;
/// Disco session
pub mod session;
/// Disco tag trait
pub mod tag;
/// Disco transport
pub mod transport;

/// the Result type for all operations
pub type Result<T> = anyhow::Result<T, error::Error>;

#[cfg(not(any(feature = "alloc", feature = "std")))]
mod inner {
    use rand_core::{CryptoRng, Error, RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    pub struct HeaplessRng(XorShiftRng);

    impl Default for HeaplessRng {
        fn default() -> Self {
            Self(XorShiftRng::from_entropy())
        }
    }

    impl CryptoRng for HeaplessRng {}

    impl RngCore for HeaplessRng {
        fn next_u32(&mut self) -> u32 {
            self.0.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.0.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.0.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
            self.0.try_fill_bytes(dest)
        }
    }

    pub fn get_rng() -> impl CryptoRng + RngCore {
        HeaplessRng::default()
    }
}

#[cfg(all(not(feature = "std"), feature = "alloc"))]
mod inner {
    use rand_core::{CryptoRng, RngCore};

    pub fn get_rng() -> impl CryptoRng + RngCore {
        rand::thread_rng()
    }
}

#[cfg(feature = "std")]
mod inner {
    use rand_core::{CryptoRng, RngCore};

    pub fn get_rng() -> impl CryptoRng + RngCore {
        rand::thread_rng()
    }
}
