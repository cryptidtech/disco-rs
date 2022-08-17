#![allow(dead_code)]
use cde::{CryptoData, Tag as CdeTag, TagBuilder};
use core::{
    fmt::{self, Display, Error as FmtError, Formatter},
    marker::PhantomData,
    str::FromStr,
};
use disco_rs::{
    builder::Builder,
    error::{Error, ParamError},
    key::{KeyAgreement, KeyGenerator, KeyType},
    nonce::NonceGenerator,
    params::Params,
    prologue::Prologue,
    session::Session,
    tag::{Tag, TaggedData},
};
use rand_core::{CryptoRng, RngCore};
use serde::{
    de::{self, MapAccess, SeqAccess, Unexpected, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_big_array::BigArray;
use zeroize::Zeroize;

pub type DiscoParams =
    Params<DiscoXeddsa, DiscoTag, DiscoNonce, DiscoPublicKey, DiscoSecretKey, DiscoSharedSecret>;
pub type DiscoSession = Session<
    DiscoXeddsa,
    DiscoNonceGenerator,
    DiscoPrologue,
    DiscoTag,
    DiscoNonce,
    DiscoPublicKey,
    DiscoSecretKey,
    DiscoSharedSecret,
>;
pub type DiscoBuilder = Builder<
    DiscoXeddsa,
    DiscoNonceGenerator,
    DiscoPrologue,
    DiscoTag,
    DiscoNonce,
    DiscoPublicKey,
    DiscoSecretKey,
    DiscoSharedSecret,
>;

/// maximum number of bytes a tag can be
const TAG_LEN: usize = 9;

/// Tag impl for Disco
#[derive(Copy, Clone, Debug, PartialEq, Zeroize)]
pub struct DiscoTag {
    #[zeroize(skip)]
    tag: CdeTag,
    len: usize,
    bytes: [u8; TAG_LEN],
}

impl Serialize for DiscoTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut dt = serializer.serialize_struct("DiscoTag", 2)?;
        dt.serialize_field("len", &self.len.to_be_bytes())?;
        dt.serialize_field("bytes", &self.bytes)?;
        dt.end()
    }
}

impl<'de> Deserialize<'de> for DiscoTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Len,
            Bytes,
        }

        struct DiscoTagVisitor;
        impl<'de> Visitor<'de> for DiscoTagVisitor {
            type Value = DiscoTag;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("struct DiscoTag")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<DiscoTag, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let len_bytes = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let bytes: [u8; TAG_LEN] = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let len = usize::from_be_bytes(len_bytes);
                if let Ok(tag) = TagBuilder::from_bytes(&bytes[..len]).build() {
                    Ok(DiscoTag { tag, len, bytes })
                } else {
                    Err(de::Error::invalid_type(Unexpected::Seq, &self))
                }
            }

            fn visit_map<V>(self, mut map: V) -> Result<DiscoTag, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut len_bytes = None;
                let mut bytes: Option<[u8; TAG_LEN]> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Len => {
                            if len_bytes.is_some() {
                                return Err(de::Error::duplicate_field("len"));
                            }
                            len_bytes = Some(map.next_value()?);
                        }
                        Field::Bytes => {
                            if bytes.is_some() {
                                return Err(de::Error::duplicate_field("bytes"));
                            }
                            bytes = Some(map.next_value()?);
                        }
                    }
                }
                let len_bytes = len_bytes.ok_or_else(|| de::Error::missing_field("len"))?;
                let bytes = bytes.ok_or_else(|| de::Error::missing_field("bytes"))?;
                let len = usize::from_be_bytes(len_bytes);
                if let Ok(tag) = TagBuilder::from_bytes(&bytes[..len]).build() {
                    Ok(DiscoTag { tag, len, bytes })
                } else {
                    Err(de::Error::invalid_type(Unexpected::Map, &self))
                }
            }
        }

        const FIELDS: &'static [&'static str] = &["len", "bytes"];
        deserializer.deserialize_struct("DiscoTag", FIELDS, DiscoTagVisitor)
    }
}

impl Tag for DiscoTag {
    /// Sets the length of the associated data
    fn set_data_length(&mut self, size: usize) {
        self.tag.set_data_length(size);
        self.len = self.tag.bytes(&mut self.bytes);
    }

    /// Gets the length of the associated data
    fn get_data_length(&self) -> usize {
        self.tag.get_data_length()
    }

    /// Try to parse the tag from the bytes
    fn try_parse(&mut self, len: usize) -> bool {
        if let Ok(t) = TagBuilder::from_bytes(&self.bytes[..len]).build() {
            self.tag = t;
            self.len = t.len();
            true
        } else {
            false
        }
    }
}

impl Default for DiscoTag {
    fn default() -> Self {
        let tag = TagBuilder::from_tag("undefined.undefined").build().unwrap();
        let mut bytes = [0u8; TAG_LEN];
        let len = tag.bytes(&mut bytes);
        Self { tag, len, bytes }
    }
}

impl From<&'static str> for DiscoTag {
    fn from(s: &'static str) -> Self {
        let t = TagBuilder::from_tag(s).build().unwrap();
        let mut b = [0u8; TAG_LEN];
        let l = t.bytes(&mut b);
        Self {
            tag: t,
            len: l,
            bytes: b,
        }
    }
}

impl AsRef<[u8]> for DiscoTag {
    // get the tag as a byte array
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl AsMut<[u8]> for DiscoTag {
    // get the tag as a byte array
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

/// This is the impl for public, secret and shared xeddsa secrets
#[derive(Clone, Debug, Default, PartialEq, Zeroize, Serialize, Deserialize)]
pub struct DiscoKeyData<T>
where
    T: Clone + Default,
{
    tag: DiscoTag,
    buf: [u8; 32],
    _t: PhantomData<T>,
}

/// impl TaggedData for the public key
impl<T> TaggedData<DiscoTag> for DiscoKeyData<T>
where
    T: Clone + Default,
{
    /// Get the tag
    fn get_tag(&self) -> &DiscoTag {
        &self.tag
    }

    /// Set the tag
    fn set_tag(&mut self, tag: &DiscoTag) {
        self.tag = *tag;
    }
}

impl<T> AsRef<[u8]> for DiscoKeyData<T>
where
    T: Clone + Default,
{
    // get a reference to the byte array
    fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()
    }
}

impl<T> AsMut<[u8]> for DiscoKeyData<T>
where
    T: Clone + Default,
{
    // get a mutable reference to the byte array
    fn as_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }
}

// create type aliases for easier code reading, this also allows us to have specialized versions of
// from_bytes for each of these aliases allowing us to create tags with the correct values
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Public {}
pub type DiscoPublicKey = DiscoKeyData<Public>;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Secret {}
pub type DiscoSecretKey = DiscoKeyData<Secret>;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Shared {}
pub type DiscoSharedSecret = DiscoKeyData<Shared>;

impl From<&[u8; 32]> for DiscoPublicKey {
    fn from(b: &[u8; 32]) -> Self {
        let mut t = DiscoTag::from("key.x25519.public");
        t.set_data_length(32);
        Self {
            tag: t,
            buf: *b,
            _t: PhantomData,
        }
    }
}

impl Into<[u8; 32]> for DiscoPublicKey {
    fn into(self) -> [u8; 32] {
        self.buf
    }
}

impl From<&[u8; 32]> for DiscoSecretKey {
    fn from(b: &[u8; 32]) -> Self {
        let mut t = DiscoTag::from("key.x25519.secret");
        t.set_data_length(32);
        Self {
            tag: t,
            buf: *b,
            _t: PhantomData,
        }
    }
}

impl Into<[u8; 32]> for DiscoSecretKey {
    fn into(self) -> [u8; 32] {
        self.buf
    }
}

impl From<(&[u8; 32], &'static str)> for DiscoSharedSecret {
    fn from(b: (&[u8; 32], &'static str)) -> Self {
        let mut t = DiscoTag::from(b.1);
        t.set_data_length(32);
        Self {
            tag: t,
            buf: *b.0,
            _t: PhantomData,
        }
    }
}

impl Into<[u8; 32]> for DiscoSharedSecret {
    fn into(self) -> [u8; 32] {
        self.buf
    }
}

/// KeyType + KeyGenerator + KeyAgreement for xeddsa (x2519) keys
#[derive(Clone, Debug, Default, PartialEq, Zeroize, Serialize, Deserialize)]
pub struct DiscoXeddsa {}

/// This type does impl Display and FromStr so we just need to say it does
impl KeyType for DiscoXeddsa {}

/// Implement a way to generate key pairs from Xeddsa
impl KeyGenerator<DiscoTag, DiscoPublicKey, DiscoSecretKey> for DiscoXeddsa {
    /// Generate a new key from a random data source
    fn generate(
        &self,
        _key_type: &impl KeyType,
        rng: impl RngCore + CryptoRng,
    ) -> (DiscoPublicKey, DiscoSecretKey) {
        let mut r = RngWrapper(rng);
        let s = x25519_dalek::StaticSecret::new(&mut r);
        let p = x25519_dalek::PublicKey::from(&s);
        (
            DiscoPublicKey::from(p.as_bytes()),
            DiscoSecretKey::from(&s.to_bytes()),
        )
    }
}

/// Implement doing ecdh for AsymKeyType
impl KeyAgreement<DiscoTag, DiscoPublicKey, DiscoSecretKey, DiscoSharedSecret> for DiscoXeddsa {
    type Error = Error;

    /// Do the ECDH operation
    fn get_shared_secret(
        &self,
        local: &DiscoSecretKey,
        remote: &DiscoPublicKey,
    ) -> Result<DiscoSharedSecret, Self::Error> {
        let mut s = [0u8; 32];
        s.copy_from_slice(local.as_ref());
        let mut p = [0u8; 32];
        p.copy_from_slice(remote.as_ref());
        let secret = x25519_dalek::StaticSecret::from(s);
        let public = x25519_dalek::PublicKey::from(p);
        Ok(DiscoSharedSecret::from((
            &secret.diffie_hellman(&public).to_bytes(),
            "key.shared-secret.ecdh",
        )))
    }
}

/// Enable creating DiscoXeddsa from str using parse()
impl FromStr for DiscoXeddsa {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "25519" => Ok(DiscoXeddsa {}),
            _ => Err(ParamError::InvalidKeyType.into()),
        }
    }
}

/// Convert DiscoXeddsa back to a str
impl Display for DiscoXeddsa {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "25519")
    }
}

/// Disco nonce value
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DiscoNonce {
    tag: DiscoTag,
    buf: [u8; 8], // u64 as 8 little-endian bytes
}

impl TaggedData<DiscoTag> for DiscoNonce {
    /// Get the tag
    fn get_tag(&self) -> &DiscoTag {
        &self.tag
    }

    /// Set the tag
    fn set_tag(&mut self, tag: &DiscoTag) {
        self.tag = *tag;
    }
}

impl AsRef<[u8]> for DiscoNonce {
    // get a reference to the byte array
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl AsMut<[u8]> for DiscoNonce {
    // get a mutable reference to the byte array
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl From<&[u8; 8]> for DiscoNonce {
    fn from(b: &[u8; 8]) -> Self {
        let mut t = DiscoTag::from("nonce.u64.le");
        t.set_data_length(8);
        Self { tag: t, buf: *b }
    }
}

/// Our implementation of the Progolue trait
#[derive(Clone, Serialize, Deserialize)]
pub struct DiscoPrologue {
    #[serde(with = "BigArray")]
    data: [u8; 256],
    len: usize,
}

impl Prologue for DiscoPrologue {}

impl Default for DiscoPrologue {
    fn default() -> Self {
        Self {
            data: [0u8; 256],
            len: 0,
        }
    }
}

impl AsRef<[u8]> for DiscoPrologue {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl FromStr for DiscoPrologue {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut data = [0u8; 256];
        let len = if s.len() > 256 { 256 } else { s.len() };
        data[..len].copy_from_slice(&s.as_bytes()[..len]);
        Ok(Self { data, len })
    }
}

/// The nonce generator and checker for DiscoXeddsa. This implements a simple sliding window for
/// checking nonce values we've seen. It also serves as a monotonic counter for generating nonces.
/// Because Disco has two separate channels, one for inbound and one for outbound messages, the
/// inbound nonce generator is used exclusively for tracking nonces seen. The outbound nonce
/// generator is simply a monotonic counter. The rules for tracking inbound nonces are like this:
///
/// 1. All nonces are unsigned  64-bit integers.
/// 2. A valid nonce is within the window of current +/- threshold.
/// 3. If a nonce is valid and greater than the current value, the current value is assigned this
///    new nonce and the window of validity shifts upwards.
///
/// Typically the threshold value shouldn't be very large; 1024 seems reasonable although tuning in
/// your specific application is probably warranted. Handshakes do not use nonces because they have
/// to happen in a specific order to be valid. Once the handshake with a key agreement operation
/// has completed, nonces are part of the encrypted payload of the message so nonce-based denial of
/// service attacks are entirely prevented unless one endpoint is malicious.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct DiscoNonceGenerator {
    current: u64,
    threshold: u64,
}

impl DiscoNonceGenerator {
    pub fn new(threshold: u64) -> Self {
        Self {
            current: 0,
            threshold,
        }
    }
}

impl NonceGenerator<DiscoTag, DiscoNonce> for DiscoNonceGenerator {
    /// generate a new nonce
    fn generate(&mut self, _rng: impl RngCore + CryptoRng) -> DiscoNonce {
        let nonce = self.current;
        self.current += 1;

        DiscoNonce::from(&nonce.to_le_bytes())
    }

    /// check the validity of a nonce and add it to the list of seen nonces
    fn check_add(&mut self, nonce: &DiscoNonce) -> bool {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(nonce.as_ref());
        let nonce = u64::from_le_bytes(buf);

        let valid = if self.current > self.threshold {
            nonce >= (self.current - self.threshold) && nonce <= (self.current + self.threshold)
        } else {
            nonce <= (self.current + self.threshold)
        };

        if valid && nonce > self.current {
            self.current = nonce;
        }

        valid
    }

    /// reset the nonce generator
    fn reset(&mut self) {
        self.current = 0;
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

pub fn get_rng() -> impl CryptoRng + RngCore {
    rand::thread_rng()
}

#[derive(Clone)]
pub struct DiscoKeys {
    pub sp: DiscoPublicKey,
    pub ss: DiscoSecretKey,
    pub ep: DiscoPublicKey,
    pub es: DiscoSecretKey,
}

impl DiscoKeys {
    pub fn psk() -> DiscoSharedSecret {
        DiscoSharedSecret::from((
            &[
                0x83, 0xcb, 0x11, 0x86, 0xb9, 0xee, 0x49, 0x7e, 0x68, 0xd1, 0xf2, 0xc1, 0x46, 0x03,
                0xac, 0xb6, 0x42, 0x22, 0x51, 0x04, 0x50, 0x22, 0xa6, 0x2f, 0x01, 0x6c, 0x6d, 0xd5,
                0xbe, 0xd1, 0xb2, 0xde,
            ],
            "key.shared-secret.psk",
        ))
    }

    pub fn i_keys() -> Self {
        Self {
            /* static public */
            sp: DiscoPublicKey::from(&[
                0x6e, 0xf0, 0x46, 0xc2, 0xdd, 0xdf, 0xf6, 0x9c, 0xc4, 0x4f, 0x49, 0x48, 0x9f, 0x8d,
                0x55, 0xb4, 0xb4, 0xe1, 0xd6, 0x48, 0xf1, 0x70, 0xcd, 0x05, 0x8e, 0x9a, 0x04, 0x50,
                0x22, 0x7a, 0xc3, 0x04,
            ]),
            /* static secret */
            ss: DiscoSecretKey::from(&[
                0x00, 0x84, 0x32, 0xd7, 0x81, 0x0a, 0x33, 0x39, 0x5f, 0x73, 0x7d, 0xbf, 0x60, 0x41,
                0x10, 0x23, 0x6b, 0x9e, 0xf8, 0x9e, 0x09, 0x06, 0x25, 0x3c, 0xaa, 0x9d, 0xa4, 0xd4,
                0x95, 0xc6, 0xda, 0x6c,
            ]),
            /* ephemeral public */
            ep: DiscoPublicKey::from(&[
                0x9f, 0x9d, 0x08, 0x9c, 0x34, 0x8b, 0x88, 0x73, 0x74, 0xf1, 0xdd, 0x83, 0xcb, 0x11,
                0x86, 0xb9, 0xee, 0xf4, 0xd7, 0xbd, 0x13, 0x42, 0x4f, 0x32, 0xbc, 0x2b, 0x03, 0x16,
                0xbb, 0xc8, 0x37, 0x08,
            ]),
            /* ephemeral secret */
            es: DiscoSecretKey::from(&[
                0xc8, 0xc6, 0xc7, 0x31, 0x7e, 0x66, 0x1b, 0x7e, 0x08, 0xcd, 0x41, 0x98, 0x12, 0x4f,
                0x59, 0x69, 0x4c, 0xfd, 0x4c, 0xf4, 0x0a, 0x52, 0x0b, 0x93, 0xce, 0xd2, 0x84, 0x56,
                0x5c, 0x48, 0xe1, 0x5e,
            ]),
        }
    }

    pub fn r_keys() -> Self {
        Self {
            /* static public */
            sp: DiscoPublicKey::from(&[
                0x46, 0xa9, 0x49, 0x43, 0x79, 0x61, 0x66, 0x58, 0x1a, 0x61, 0x75, 0x40, 0x2e, 0xda,
                0x98, 0x10, 0x42, 0x03, 0xcb, 0xb9, 0x4e, 0x8f, 0x13, 0x34, 0xbe, 0x81, 0xba, 0x74,
                0x75, 0x56, 0xe4, 0x2f,
            ]),
            /* static secret */
            ss: DiscoSecretKey::from(&[
                0x18, 0x30, 0xa5, 0xa3, 0x12, 0x0c, 0x24, 0x1a, 0x0b, 0x95, 0xa0, 0xdf, 0x99, 0x21,
                0x87, 0xad, 0x3d, 0x3d, 0x01, 0x00, 0x92, 0xd3, 0x38, 0x07, 0x26, 0xc0, 0x45, 0xc1,
                0x73, 0x40, 0x27, 0x5c,
            ]),
            /* ephemeral public */
            ep: DiscoPublicKey::from(&[
                0x2f, 0x38, 0x0e, 0x59, 0x16, 0xb8, 0x2a, 0xbd, 0xc0, 0x83, 0x73, 0x67, 0x84, 0x45,
                0x9f, 0x5b, 0x11, 0x17, 0xcb, 0x86, 0x7e, 0xfc, 0xce, 0xfe, 0x93, 0xc8, 0x38, 0xe0,
                0x84, 0x78, 0x3d, 0x2e,
            ]),
            /* ephemeral secret */
            es: DiscoSecretKey::from(&[
                0x40, 0xf2, 0x17, 0x0e, 0xe2, 0xb0, 0xfc, 0xd0, 0xed, 0xa5, 0x60, 0xc5, 0x3d, 0x18,
                0xfc, 0x80, 0x66, 0x7e, 0xc6, 0xce, 0x36, 0x29, 0x30, 0x45, 0xb8, 0x09, 0x36, 0xc8,
                0xaf, 0xc8, 0x24, 0x44,
            ]),
        }
    }
}
