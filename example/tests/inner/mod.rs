#[allow(dead_code)]
use disco_ecdh_example::tagged::{TaggedSlice, TaggedSliceBuilder};
use rand_core::{CryptoRng, RngCore};

pub fn get_rng() -> impl CryptoRng + RngCore {
    rand::thread_rng()
}

pub fn psk() -> TaggedSlice<32> {
    TaggedSliceBuilder::new("key.shared-secret.psk", 32)
        .from_bytes(&[
            0x83, 0xcb, 0x11, 0x86, 0xb9, 0xee, 0x49, 0x7e, 0x68, 0xd1, 0xf2, 0xc1, 0x46, 0x03,
            0xac, 0xb6, 0x42, 0x22, 0x51, 0x04, 0x50, 0x22, 0xa6, 0x2f, 0x01, 0x6c, 0x6d, 0xd5,
            0xbe, 0xd1, 0xb2, 0xde,
        ])
        .build()
        .unwrap()
}

pub fn alice_x25519_keys() -> (
    TaggedSlice<33>,
    TaggedSlice<32>,
    TaggedSlice<33>,
    TaggedSlice<32>,
) {
    (
        /* static public */
        TaggedSliceBuilder::new("key.x25519.public", 32)
            .from_bytes(&[
                0x6e, 0xf0, 0x46, 0xc2, 0xdd, 0xdf, 0xf6, 0x9c, 0xc4, 0x4f, 0x49, 0x48, 0x9f, 0x8d,
                0x55, 0xb4, 0xb4, 0xe1, 0xd6, 0x48, 0xf1, 0x70, 0xcd, 0x05, 0x8e, 0x9a, 0x04, 0x50,
                0x22, 0x7a, 0xc3, 0x04,
            ])
            .build()
            .unwrap(),
        /* static secret */
        TaggedSliceBuilder::new("key.x25519.secret", 32)
            .from_bytes(&[
                0x00, 0x84, 0x32, 0xd7, 0x81, 0x0a, 0x33, 0x39, 0x5f, 0x73, 0x7d, 0xbf, 0x60, 0x41,
                0x10, 0x23, 0x6b, 0x9e, 0xf8, 0x9e, 0x09, 0x06, 0x25, 0x3c, 0xaa, 0x9d, 0xa4, 0xd4,
                0x95, 0xc6, 0xda, 0x6c,
            ])
            .build()
            .unwrap(),
        /* ephemeral public */
        TaggedSliceBuilder::new("key.x25519.public", 32)
            .from_bytes(&[
                0x9f, 0x9d, 0x08, 0x9c, 0x34, 0x8b, 0x88, 0x73, 0x74, 0xf1, 0xdd, 0x83, 0xcb, 0x11,
                0x86, 0xb9, 0xee, 0xf4, 0xd7, 0xbd, 0x13, 0x42, 0x4f, 0x32, 0xbc, 0x2b, 0x03, 0x16,
                0xbb, 0xc8, 0x37, 0x08,
            ])
            .build()
            .unwrap(),
        /* ephemeral secret */
        TaggedSliceBuilder::new("key.x25519.secret", 32)
            .from_bytes(&[
                0xc8, 0xc6, 0xc7, 0x31, 0x7e, 0x66, 0x1b, 0x7e, 0x08, 0xcd, 0x41, 0x98, 0x12, 0x4f,
                0x59, 0x69, 0x4c, 0xfd, 0x4c, 0xf4, 0x0a, 0x52, 0x0b, 0x93, 0xce, 0xd2, 0x84, 0x56,
                0x5c, 0x48, 0xe1, 0x5e,
            ])
            .build()
            .unwrap(),
    )
}

pub fn alice_k256_keys() -> (
    TaggedSlice<33>,
    TaggedSlice<32>,
    TaggedSlice<33>,
    TaggedSlice<32>,
) {
    (
        /* static public */
        TaggedSliceBuilder::new("key.k256.public", 33)
            .from_bytes(&[
                0x03, 0xac, 0xb6, 0x42, 0x22, 0x51, 0x49, 0x7e, 0x68, 0xd1, 0xf2, 0x91, 0x93, 0x0c,
                0xc0, 0xa5, 0x6d, 0x11, 0x4b, 0x67, 0xe3, 0xb1, 0x5a, 0xac, 0xb1, 0x1d, 0x59, 0x97,
                0x5c, 0xa2, 0x10, 0x54, 0x7a,
            ])
            .build()
            .unwrap(),
        /* static secret */
        TaggedSliceBuilder::new("key.k256.secret", 32)
            .from_bytes(&[
                0x69, 0x4f, 0x37, 0x10, 0x8c, 0x15, 0x61, 0x5f, 0xb9, 0xc1, 0x46, 0xe0, 0x8d, 0xa9,
                0xfa, 0x9c, 0x83, 0xbe, 0x80, 0xa9, 0xca, 0xd3, 0xf5, 0xd5, 0x18, 0xce, 0x3d, 0xfd,
                0x83, 0x59, 0x40, 0xa1,
            ])
            .build()
            .unwrap(),
        /* ephemeral public */
        TaggedSliceBuilder::new("key.k256.public", 33)
            .from_bytes(&[
                0x02, 0xfe, 0x7f, 0x4d, 0xb5, 0xd1, 0xb5, 0x47, 0x3c, 0x68, 0xd2, 0xa2, 0xd4, 0xe8,
                0xcc, 0x64, 0xe5, 0x93, 0xe9, 0x0e, 0xe5, 0x86, 0xb9, 0x6f, 0x26, 0xaa, 0x28, 0x5a,
                0x5c, 0x70, 0xe5, 0x0b, 0x88,
            ])
            .build()
            .unwrap(),
        /* ephemeral secret */
        TaggedSliceBuilder::new("key.k256.secret", 32)
            .from_bytes(&[
                0xf0, 0xc3, 0xcd, 0x21, 0xe2, 0x3d, 0x6f, 0xdb, 0x1e, 0x5b, 0xdd, 0xf0, 0xff, 0x7f,
                0x8d, 0x1a, 0x9b, 0x2b, 0xb3, 0x23, 0x55, 0x4a, 0x5a, 0xad, 0x84, 0x81, 0x32, 0x45,
                0xe1, 0x94, 0x28, 0x71,
            ])
            .build()
            .unwrap(),
    )
}

pub fn alice_p256_keys() -> (
    TaggedSlice<33>,
    TaggedSlice<32>,
    TaggedSlice<33>,
    TaggedSlice<32>,
) {
    (
        /* static public */
        TaggedSliceBuilder::new("key.p256.public", 33)
            .from_bytes(&[
                0x02, 0x3c, 0x5c, 0x11, 0x1f, 0xeb, 0x14, 0x71, 0x91, 0x82, 0x52, 0xae, 0x45, 0xf6,
                0xca, 0x25, 0x41, 0x00, 0x56, 0x7f, 0xe9, 0x2e, 0x0b, 0x73, 0xab, 0x48, 0x99, 0x24,
                0x86, 0x0e, 0xde, 0xce, 0xc8,
            ])
            .build()
            .unwrap(),
        /* static secret */
        TaggedSliceBuilder::new("key.p256.secret", 32)
            .from_bytes(&[
                0xba, 0xe8, 0xa6, 0xe5, 0x2d, 0x17, 0xf1, 0x2c, 0x13, 0x0a, 0xeb, 0xb0, 0xe4, 0x1d,
                0x05, 0xff, 0x84, 0xe0, 0x3f, 0x5e, 0x57, 0xc8, 0x8c, 0x19, 0x1d, 0x9c, 0xa4, 0xe6,
                0xad, 0xb0, 0xca, 0x9a,
            ])
            .build()
            .unwrap(),
        /* ephemeral public */
        TaggedSliceBuilder::new("key.p256.public", 33)
            .from_bytes(&[
                0x03, 0x41, 0xd1, 0xba, 0x86, 0x76, 0x76, 0xa9, 0x6f, 0x85, 0x4f, 0xd7, 0x0f, 0xfb,
                0x6e, 0x33, 0x9b, 0x31, 0x5e, 0x96, 0xb5, 0x8d, 0xa3, 0xc0, 0xc7, 0x1a, 0xea, 0x17,
                0x54, 0xe6, 0x11, 0xe8, 0xd1,
            ])
            .build()
            .unwrap(),
        /* ephemeral secret */
        TaggedSliceBuilder::new("key.p256.secret", 32)
            .from_bytes(&[
                0x47, 0x9b, 0x0d, 0x2d, 0xbe, 0x37, 0x58, 0x58, 0x61, 0x48, 0xa4, 0x7b, 0x4b, 0xc6,
                0xbe, 0x6d, 0x8e, 0xcc, 0x2c, 0x80, 0x3c, 0x86, 0xa6, 0x2f, 0x01, 0x6c, 0x6d, 0xd5,
                0xbe, 0xd1, 0xb2, 0xde,
            ])
            .build()
            .unwrap(),
    )
}

pub fn bob_x25519_keys() -> (
    TaggedSlice<33>,
    TaggedSlice<32>,
    TaggedSlice<33>,
    TaggedSlice<32>,
) {
    (
        /* static public */
        TaggedSliceBuilder::new("key.x25519.public", 32)
            .from_bytes(&[
                0x46, 0xa9, 0x49, 0x43, 0x79, 0x61, 0x66, 0x58, 0x1a, 0x61, 0x75, 0x40, 0x2e, 0xda,
                0x98, 0x10, 0x42, 0x03, 0xcb, 0xb9, 0x4e, 0x8f, 0x13, 0x34, 0xbe, 0x81, 0xba, 0x74,
                0x75, 0x56, 0xe4, 0x2f,
            ])
            .build()
            .unwrap(),
        /* static secret */
        TaggedSliceBuilder::new("key.x25519.secret", 32)
            .from_bytes(&[
                0x18, 0x30, 0xa5, 0xa3, 0x12, 0x0c, 0x24, 0x1a, 0x0b, 0x95, 0xa0, 0xdf, 0x99, 0x21,
                0x87, 0xad, 0x3d, 0x3d, 0x01, 0x00, 0x92, 0xd3, 0x38, 0x07, 0x26, 0xc0, 0x45, 0xc1,
                0x73, 0x40, 0x27, 0x5c,
            ])
            .build()
            .unwrap(),
        /* ephemeral public */
        TaggedSliceBuilder::new("key.x25519.public", 32)
            .from_bytes(&[
                0x2f, 0x38, 0x0e, 0x59, 0x16, 0xb8, 0x2a, 0xbd, 0xc0, 0x83, 0x73, 0x67, 0x84, 0x45,
                0x9f, 0x5b, 0x11, 0x17, 0xcb, 0x86, 0x7e, 0xfc, 0xce, 0xfe, 0x93, 0xc8, 0x38, 0xe0,
                0x84, 0x78, 0x3d, 0x2e,
            ])
            .build()
            .unwrap(),
        /* ephemeral secret */
        TaggedSliceBuilder::new("key.x25519.secret", 32)
            .from_bytes(&[
                0x40, 0xf2, 0x17, 0x0e, 0xe2, 0xb0, 0xfc, 0xd0, 0xed, 0xa5, 0x60, 0xc5, 0x3d, 0x18,
                0xfc, 0x80, 0x66, 0x7e, 0xc6, 0xce, 0x36, 0x29, 0x30, 0x45, 0xb8, 0x09, 0x36, 0xc8,
                0xaf, 0xc8, 0x24, 0x44,
            ])
            .build()
            .unwrap(),
    )
}

pub fn bob_k256_keys() -> (
    TaggedSlice<33>,
    TaggedSlice<32>,
    TaggedSlice<33>,
    TaggedSlice<32>,
) {
    (
        /* static public */
        TaggedSliceBuilder::new("key.k256.public", 33)
            .from_bytes(&[
                0x03, 0xad, 0x7a, 0x6a, 0x3e, 0xa7, 0x20, 0x58, 0x86, 0x08, 0x2e, 0xbc, 0xfb, 0x0d,
                0x76, 0xb8, 0x69, 0x57, 0x91, 0x59, 0xb5, 0xdf, 0x5a, 0x78, 0x39, 0x45, 0x70, 0xf3,
                0x97, 0x86, 0xd9, 0xec, 0xcf,
            ])
            .build()
            .unwrap(),
        /* static secret */
        TaggedSliceBuilder::new("key.k256.secret", 32)
            .from_bytes(&[
                0x9a, 0x82, 0x6f, 0x60, 0xb6, 0xff, 0xca, 0x1a, 0x04, 0x00, 0xb8, 0x35, 0x9e, 0xe0,
                0xa2, 0x4f, 0xb5, 0xc6, 0x5a, 0x5c, 0xe0, 0x79, 0xe3, 0x9c, 0x92, 0x67, 0x1c, 0x88,
                0x7d, 0x90, 0x48, 0xdf,
            ])
            .build()
            .unwrap(),
        /* ephemeral public */
        TaggedSliceBuilder::new("key.k256.public", 33)
            .from_bytes(&[
                0x02, 0x3a, 0x5c, 0x77, 0xa5, 0x0b, 0xa1, 0xda, 0xb3, 0x30, 0xf6, 0x8a, 0xe2, 0xb2,
                0xaa, 0xed, 0xa2, 0x69, 0xe4, 0x70, 0xc3, 0x1d, 0xbd, 0x5d, 0xd6, 0x65, 0xcd, 0x1b,
                0x2d, 0x46, 0x3c, 0xee, 0x0a,
            ])
            .build()
            .unwrap(),
        /* ephemeral secret */
        TaggedSliceBuilder::new("key.k256.secret", 32)
            .from_bytes(&[
                0x29, 0x11, 0xc0, 0x56, 0x8a, 0x65, 0x0c, 0x6c, 0xb8, 0xa3, 0xb5, 0x6f, 0x5f, 0xdf,
                0xa9, 0xe4, 0xa2, 0xec, 0x4c, 0x2b, 0xed, 0x30, 0x4b, 0x5d, 0x62, 0xfd, 0x4b, 0x4e,
                0x22, 0xc9, 0x89, 0xa1,
            ])
            .build()
            .unwrap(),
    )
}

pub fn bob_p256_keys() -> (
    TaggedSlice<33>,
    TaggedSlice<32>,
    TaggedSlice<33>,
    TaggedSlice<32>,
) {
    (
        /* static public */
        TaggedSliceBuilder::new("key.p256.public", 33)
            .from_bytes(&[
                0x03, 0xe4, 0x75, 0x2d, 0x0e, 0xe0, 0xa5, 0x7a, 0x6c, 0x8e, 0x5c, 0xe2, 0x4c, 0x4f,
                0x50, 0xbe, 0x44, 0x25, 0x72, 0x57, 0x8c, 0x9e, 0x7d, 0x0c, 0x50, 0xb7, 0x33, 0xa8,
                0xf8, 0x5c, 0x10, 0xe3, 0x34,
            ])
            .build()
            .unwrap(),
        /* static secret */
        TaggedSliceBuilder::new("key.p256.secret", 32)
            .from_bytes(&[
                0xa1, 0xd2, 0x09, 0x5f, 0xa4, 0x57, 0xe8, 0x92, 0x8e, 0xf8, 0xd0, 0x82, 0x5c, 0xf6,
                0x68, 0x94, 0x6c, 0x46, 0x95, 0x06, 0x76, 0x05, 0x7d, 0xe0, 0xe3, 0x0c, 0x64, 0xd2,
                0x0a, 0xa0, 0x9c, 0x8e,
            ])
            .build()
            .unwrap(),
        /* ephemeral public */
        TaggedSliceBuilder::new("key.p256.public", 33)
            .from_bytes(&[
                0x03, 0xd5, 0x52, 0x28, 0xc2, 0x08, 0x18, 0x33, 0x91, 0xe5, 0x36, 0xb1, 0xac, 0xa1,
                0xb3, 0x08, 0x09, 0x3a, 0x9b, 0x26, 0x2e, 0x76, 0x85, 0x85, 0xe1, 0x65, 0x37, 0x36,
                0x80, 0xc7, 0x91, 0x6c, 0x2c,
            ])
            .build()
            .unwrap(),
        /* ephemeral secret */
        TaggedSliceBuilder::new("key.p256.secret", 32)
            .from_bytes(&[
                0xf0, 0x7e, 0x10, 0x5d, 0xa0, 0xcd, 0xe8, 0x1d, 0x35, 0x74, 0xf6, 0xe3, 0x1c, 0x4c,
                0x25, 0x0a, 0x9b, 0x78, 0xb5, 0x17, 0x21, 0x19, 0x8b, 0x0e, 0xeb, 0x91, 0x02, 0xca,
                0xa5, 0x1c, 0xd5, 0x6f,
            ])
            .build()
            .unwrap(),
    )
}
