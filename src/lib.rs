//!
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

/// Disco params
//pub mod params;
/// Disco session
//pub mod session;
/// Disco session builder
//pub mod builder;
/// Disco errors
//pub mod error;

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
