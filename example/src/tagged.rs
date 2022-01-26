use cde::{CryptoData, ENCODER, Tag, TagBuilder};
use core::fmt::{Display, Formatter, Result as FmtResult};
use disco_rs::{
    error::{Error, ProtocolError, BuilderError},
    key::TaggedData,
    Result,
};
use zeroize::Zeroize;

/// Utility for constructed TaggedSlices with tags, lengths and data
#[derive(Copy, Clone)]
pub struct TaggedSliceBuilder<'a, const N: usize> {
    tag: &'a str,
    len: usize,
    bytes: Option<&'a [u8]>,
}

impl<'a, const N: usize> TaggedSliceBuilder<'a, N> {

    /// construct a new builder with the tag and data length
    pub fn new(tag: &'a str, len: usize) -> Self {
        TaggedSliceBuilder::<N> {
            tag: tag,
            len: len,
            bytes: None,
        }
    }

    /// add a reference to the bytes to construct the tagged slice with
    pub fn from_bytes(mut self, b: &'a [u8]) -> Self {
        self.bytes = Some(b);
        self
    }

    /// try to construct a tagged slice
    pub fn build(&self) -> Result<TaggedSlice<N>> {
        if let Some(b) = self.bytes {
            let mut ts = TaggedSlice::<N>::from(b);
            ts.set_tag(&TagBuilder::from_tag(self.tag).build().map_err(|_| ProtocolError::InvalidTag)?);
            ts.set_length(self.len)?;
            Ok(ts)
        } else {
            Err(Error::Builder(BuilderError::MissingBytes))
        }
    }
}

/// Holds key data of a fixed length
#[derive(Copy, Clone, Debug, PartialEq, Zeroize)]
pub struct TaggedSlice<const N: usize>
{
    #[zeroize(skip)]
    tag: Tag,
    len: usize,
    bytes: [u8; N]
}

impl<const N: usize> TaggedSlice<N> {
    /// returns the bytes as a fixed sized slice
    pub fn to_bytes(&self) -> [u8; N] {
        self.bytes
    }
}

impl<const N: usize> CryptoData for TaggedSlice<N> {
    fn len(&self) -> usize {
        self.tag.len() + self.tag.get_data_length()
    }

    fn bytes(&self, buf: &mut [u8]) -> usize {
        // copy the tag bytes
        let len = self.tag.bytes(&mut buf[0..self.tag.len()]);
        // copy the data bytes
        buf[len..len+N].copy_from_slice(&self.bytes);
        len + N
    }

    fn encode_len(&self) -> usize {
        self.tag.encode_len() + ENCODER.encode_len(N)
    }

    fn encode(&self, buf: &mut [u8]) -> usize {
        // encode the tag
        let len = self.tag.encode(&mut buf[0..self.tag.encode_len()]);
        // encode the data
        ENCODER.encode_mut(&self.bytes, &mut buf[len..len+ENCODER.encode_len(N)]);
        self.encode_len()
    }
}

impl<const N: usize> TaggedData<'_> for TaggedSlice<N> {
    fn get_tag(&self) -> &Tag {
        &self.tag
    }

    fn set_tag(&mut self, tag: &Tag) {
        self.tag = *tag;
    }

    fn is_zero(&self) -> bool {
        self.len == 0
    }

    fn zero(&mut self) {
        self.zeroize();
    }

    fn length(&self) -> usize {
        self.len
    }

    fn max_length(&self) -> usize {
        N
    }

    fn set_length(&mut self, len: usize) -> Result<usize> {
        if len > N {
            return Err(Error::Protocol(ProtocolError::InvalidBufferLen));
        }
        self.len = len;
        self.tag.set_data_length(len);
        Ok(self.len)
    }
}

impl<const N: usize> Default for TaggedSlice<N> {
    fn default() -> Self {
        TaggedSlice::<N> {
            tag: Tag::default(),
            len: 0,
            bytes: [0u8; N],
        }
    }
}

impl<const N: usize> Display for TaggedSlice<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "[ ")?;
        for b in &self.bytes {
            write!(f, "0x{:02x},", b)?;
        }
        write!(f, " ]")
    }
}

impl<'a, const N: usize> From<&'a [u8]> for TaggedSlice<N> {
    fn from(b: &'a [u8]) -> Self {
        let mut k = TaggedSlice::<N>::default();
        k.bytes[0..b.len()].copy_from_slice(b);
        k.len = N;
        k
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for TaggedSlice<N> {
    fn from(b: &'a [u8; N]) -> Self {
        let mut k = TaggedSlice::<N>::default();
        k.bytes[0..b.len()].copy_from_slice(b);
        k.len = N;
        k
    }
}

impl<const N: usize> AsRef<[u8]> for TaggedSlice<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> AsMut<[u8]> for TaggedSlice<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}


