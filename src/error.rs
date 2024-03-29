/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use thiserror::Error;

/// Disco errors
#[derive(Error, PartialEq, Copy, Clone, Debug)]
pub enum Error {
    /// A handshake pattern error occurred
    #[error("parameter error")]
    Param(#[from] ParamError),
    /// A builder error occurred
    #[error("builder error")]
    Builder(#[from] BuilderError),
    /// A protocol error occurred
    #[error("protocol error")]
    Protocol(#[from] ProtocolError),
    /// A tag related error occurred
    #[error("tag error")]
    Tag(#[from] TagError),
}

/// Errors that can happen from invalid protocol strings
#[derive(Error, PartialEq, Copy, Clone, Debug)]
pub enum ParamError {
    /// Too few parameters in the protocol string
    #[error("not enough parameters given")]
    TooFewParameters,
    /// Invalid protocol name, must be "Noise"
    #[error("invalid protocol identifier")]
    InvalidProtocol,
    /// Invalid, or unsuported, handshake pattern
    #[error("invalid or unsupported handshake pattern")]
    InvalidHandshake,
    /// Invalid, or unsupported, key type
    #[error("invalid key agreement protocol")]
    InvalidKeyType,
    /// Invalid STROBE protocol version
    #[error("invalid strobe protocol version")]
    InvalidStrobeVersion,
    /// Invalid ephemeral key setup
    #[error("invalid ephemeral key setup")]
    InvalidEphemeralKeys,
    /// Invalid duplex mode for this channel
    #[error("invalid channel duplex mode")]
    InvalidChannelDuplex,
    /// Invalid transport order for this channel
    #[error("invalid channel transport order")]
    InvalidTransportOrder,
}

/// Errors that can happen during building
#[derive(Error, PartialEq, Copy, Clone, Debug)]
pub enum BuilderError {
    /// Missing local secret key
    #[error("missing local secret key needed for this handshake pattern")]
    MissingLocalSecretKey,
    /// Missing remote public key
    #[error("missing remote public key needed for this handshake pattern")]
    MissingRemotePublicKey,
    /// Missing pre-shared key
    #[error("missing pre-shared key needed for this handshake pattern")]
    MissingPreSharedKey,
    /// Invalid tag
    #[error("invalid tag")]
    InvalidTag,
    /// Missing buffer
    #[error("missing bytes")]
    MissingBytes,
}

/// Errors that can happen during handshaking and transport
#[derive(Error, PartialEq, Copy, Clone, Debug)]
pub enum ProtocolError {
    /// Incorrect state for this operation
    #[error("incorrect state for this operation")]
    InvalidState,
    /// Invalid or missing key
    #[error("invalid or missing key")]
    InvalidKey,
    /// Invalid tag
    #[error("invalid tag error")]
    InvalidTag,
    /// Failed MAC of incoming message
    #[error("invalid mac error")]
    InvalidMac,
    /// Invalid data
    #[error("invalid data")]
    InvalidData,
    /// Buffer isn't empty
    #[error("out buffer isn't empty")]
    NonEmptyBuffer,
    /// Invalid TaggedData length
    #[error("invalid length for tagged data")]
    InvalidBufferLen,

    /// Sending a pre-shared key is a protocol error
    #[error("sending pre-shared key error")]
    SendingPsk,
    /// Receiving a pre-shared key is a protocol error
    #[error("receiving pre-shared key error")]
    ReceivingPsk,
    /// Sending the prologue is a protocol error
    #[error("sending prologue error")]
    SendingPrologue,
    /// Receiving the prologue is a protocol error
    #[error("receiving prologue error")]
    ReceivingPrologue,
    /// Sending a secret key is a protocol error
    #[error("sending secret key error")]
    SendingSecretKey,
    /// Receiving a secret key is a protocol error
    #[error("receiving secret key error")]
    ReceivingSecretKey,

    /// Invalid handshake operaion
    #[error("invalid handshake operaion")]
    InvalidHandshakeOp,
    /// Invalid transport operation
    #[error("invalid parameter for channel operation")]
    InvalidTransportOp,
    /// Shared secret calculation error
    #[error("error calculating shared secret")]
    SharedSecretCalculationFailed,
    /// Message limit reached
    #[error("message limit reached, repeat handshake")]
    MessageLimitReached,
    /// Invalid nonce encountered
    #[error("invalid nonce")]
    InvalidNonce,
    /// The channel states aren't the same
    #[error("channel state mismatch")]
    ChannelStateMismatch,
    /// Invalid send command
    #[error("invalid send command")]
    InvalidSend,
    /// Invalid recv commmand
    #[error("invalid recv command")]
    InvalidRecv,
}

/// Errors related to tag parsing
#[derive(Error, PartialEq, Copy, Clone, Debug)]
pub enum TagError {
    /// Parse error
    #[error("tag parse error")]
    ParseError,
}
