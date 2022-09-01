/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    channel::{ChannelDuplex, ChannelRole, ChannelState},
    error::{Error, ParamError},
    Result,
};
use core::{
    fmt::{Display, Error as FmtError, Formatter},
    str::FromStr,
};
use serde::{Deserialize, Serialize};

/// Identifiers for the different keys referenced in handshake scripts
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum HandshakeData {
    /// Local ephemeral public key
    Epub,
    /// Local ephemeral secret key
    Esec,
    /// Payload data
    Payload,
    /// Prologue data
    Prologue,
    /// Pre-shared key
    Psk,
    /// Remote ephemeral public key
    Re,
    /// Remote static public key
    Rs,
    /// Local static public key
    Spub,
    /// Local static secret key
    Ssec,
}

/// Different operations to perform in handshake scripts, see §5 of
/// https://www.discocrypto.com/disco.html
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum HandshakeOp {
    /// Start a message
    Start,
    /// Generate a new key pair
    GenKey,
    /// Get the handshake hash
    GetHandshakeHash,
    /// Does an AD(data)
    MixHash(HandshakeData),
    /// Does a KEY(key) and sets is_keyed to true
    MixKey(HandshakeData),
    /// Does an KEY(ECDH(key, key)) and sets is_keyed to true
    MixKeyDh(HandshakeData, HandshakeData),
    /// Does either a send_CLR(data) or send_ENC(data) + send_MAX(16) depending on is_keyed
    EncryptAndHash(HandshakeData),
    /// Does either a recv_CLR(data) or recv_ENC(data) + recv_MAC(16) depending on is_keyed
    DecryptAndHash(HandshakeData),
    /// Stop marks the end of one side's state changes
    Stop,
    /// End the handshake process and split into send/recv states
    Split,
}

/// The state of the handshake so that this is resumable
#[derive(PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct HandshakeState {
    /// The handshake operations
    handshake: Handshake,
    /// The index to the next handshake operation
    index: usize,
    /// The channel role
    role: ChannelRole,
    /// The channel duplex mode
    duplex: ChannelDuplex,
}

/// HandshakeState impl
impl HandshakeState {
    /// construct a new handshake state from a list of operations
    pub fn new(pattern: Handshake, role: &ChannelRole, duplex: &ChannelDuplex) -> Self {
        HandshakeState {
            handshake: pattern,
            index: 0,
            role: role.clone(),
            duplex: duplex.clone(),
        }
    }
}

/// ChannelState trait impl
impl ChannelState for HandshakeState {
    /// get the channel role
    fn role(&self) -> &ChannelRole {
        &self.role
    }
    /// get the channel duplex
    fn duplex(&self) -> &ChannelDuplex {
        &self.duplex
    }
    /// reset the channel state
    fn reset(&mut self) -> Result<()> {
        self.index = 0;
        Ok(())
    }
}

/// Make it easy walk through the steps of the state machine
impl Iterator for HandshakeState {
    type Item = HandshakeOp;

    fn next(&mut self) -> Option<Self::Item> {
        let pattern = self.handshake.get_pattern(&self.role);
        if self.index < pattern.len() {
            let op = pattern[self.index];
            self.index += 1;
            Some(op)
        } else {
            None
        }
    }
}

/// The handshake patterns we support for now
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum Handshake {
    /// One-way, no static key for initiator
    N,
    /// One-way, static key for initiator known to responder
    K,
    /// One-way, static key for initiator is transmitted to responder
    X,
    /// One-way, no static key for initiator, pre-shared key (i.e. passphrase, biometric, etc)
    Npsk0,
    /// One-way, static key for initiator known to responder, pre-shared key (i.e. passphrase, biometric, etc)
    Kpsk0,
    /// One-way, static key for initiator is transmitted to responder, pre-shared key (i.e. passphrase, biometric, etc)
    Xpsk1,
    /// No static keys for either the initiator or responder
    NN,
    /// Both sides know each other's static public keys
    KK,
    /// Both sides transmit their keys
    XX,
    /// Initiator transmits their static public key immediately
    IK,
    /// Initiator transmits their ephemeral and static public key immediately
    IX,
    /// No static key for the initiator, reponder key known
    NK,
    /// No static key for the initiator, responder transmits key
    NX,
    /// Initiator transmits key and knows responders key, deferred
    XK1,
    /// Initiator and responder know each other's keys, deferred
    KK1,
    /// Initiator and responder know a pre-shared key
    NNpsk2,
}

// From the Noise Extension: Disco specification, the meaning of the operations
// in the following handshake patterns are as follows:
//
// InitSymmetric(protocol_name): calls InitializeStrobe(protocol_name) to do
// protocol separation.
//
// MixKey(key_data): calls KEY(key_data), sets is_keyed to true.
//
// MixHashDh(local, remote): calls AD(ECDH(local, remote)), sets is_keyed to true.
//
// MixHash(data): calls AD(data).
//
// GetHandshakeHash(): calls PRF(32) to get the handshake hash used for channel
// binding as per the Noise spec (section 11.2).
//
// EncryptAndHash(data): if isKeyed is true, then calls send_ENC(data) followed by
// send_MAC(16). if isKeyed is false, then calls send_CLR(data).
//
// DecryptAndHash(data): if isKeyed is true, then calls recv_ENC(data) followed by
// recv_MAC(16). if isKeyed is false, then calls recv_CLR(data).
//
// Split(): clones the strobe state into two copies of the state. calls
// meta_AD("initiator") on initiator state and meta_AD("responder") on the
// responder state. The initiator's outbound state is its initiator state and
// their inbound state is its responder state. The responder's outbound state
// is its responder state and their inbound state is its initiator state. calls
// RATCHET(16) on both states. returns both states.
//
impl Handshake {
    /// Return the appropriate HandshakeState
    pub fn get_pattern(&self, role: &ChannelRole) -> &[HandshakeOp] {
        use ChannelRole::*;
        use HandshakeData::*;
        use HandshakeOp::*;

        match self {
            // N_Strobe Session Setup
            // ========================
            // NOTE: This is the equivalent to libsodium's sealed boxes. This session type is
            // designed to anonymously send messages to a recipient given their public key. Only
            // the recipient can decrypt these messages using their private key. While the
            // recipient can verify the integrity of the message, they cannot verify the identity
            // of the sender.
            //
            // Initiator                            Responder
            //
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = NULL                           | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_N...")        | InitSymmetric("Noise_N...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> e, es, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | payload = DecryptAndHash()
            //                                      | Split()
            Handshake::N => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // K_Strobe Session Setup
            // ========================
            // NOTE: This session type is the equivalent to libsodium's authenticated encryption.
            // This variant in particular assumes that the sender and recipient have already
            // executed a key exchange out-of-band prior to this session's creation.
            //
            // Initiator                            Responder
            //
            //                      -> s
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = Initiator's static pub key
            // |                                    |
            // | InitSymmetric("Noise_K...")        | InitSymmetric("Noise_K...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(s.pub)                     | MixHash(rs)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | MixKeyDh(s.sec, rs)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> e, es, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | MixKeyDh(s.sec, rs)
            //                                      | payload = DecryptAndHash()
            //                                      | Split()
            Handshake::K => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        MixKeyDh(Ssec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        MixKeyDh(Ssec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // X_Strobe Session Setup
            // ========================
            // NOTE: This session type is the equivalent to libsodium's authenticated encryption.
            // This particular session does not require the sender and recipient to have exchanged
            // keys prior to the session. Only the sender needs to know the recipient's public key
            // because the sender ends their's in the message, encrypted.
            //
            // Initiator                            Responder
            //
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_X...")        | InitSymmetric("Noise_X...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | EncryptAndHash(s.pub)
            // | MixKeyDh(s.sec, rs)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> e, es, s, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | rs = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, rs)
            //                                      | payload = DecryptAndHash()
            //                                      | split()
            Handshake::X => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Ssec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // Npsk0_Strobe Session Setup
            // ========================
            // NOTE: This is the equivalent to libsodium's sealed boxes. This session type is
            // designed to anonymously send messages to a recipient given their public key. Only
            // the recipient can decrypt these messages using their private key. While the
            // recipient can verify the integrity of the message, they cannot verify the identity
            // of the sender.
            //
            // Initiator                            Responder
            //
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = NULL                           | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = NULL
            // | psk = pre-shared key value         | psk = pre-shared key value
            // |                                    |
            // | InitSymmetric("Noise_Npsk0...")    | InitSymmetric("Noise_Npsk0...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> psk, e, es, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | payload = DecryptAndHash()
            //                                      | Split()
            Handshake::Npsk0 => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        MixKey(Psk),
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        MixKey(Psk),
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // Kpsk0_Strobe Session Setup
            // ========================
            // NOTE: This session type is the equivalent to libsodium's authenticated encryption.
            // This variant in particular assumes that the sender and recipient have already
            // executed a key exchange out-of-band prior to this session's creation.
            //
            // Initiator                            Responder
            //
            //                      -> s
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = Initiator's static pub key
            // | psk = pre-shared key value         | psk = pre-shared key value
            // |                                    |
            // | InitSymmetric("Noise_Kpsk0...")    | InitSymmetric("Noise_Kpsk0...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(s.pub)                     | MixHash(rs)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | MixKeyDh(s.sec, rs)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> psk, e, es, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | MixKeyDh(s.sec, rs)
            //                                      | payload = DecryptAndHash()
            //                                      | Split()
            Handshake::Kpsk0 => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        MixHash(Rs),
                        /* send */
                        MixKey(Psk),
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        MixKeyDh(Ssec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        MixHash(Spub),
                        /* recv */
                        MixKey(Psk),
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        MixKeyDh(Ssec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // Xpsk1_Strobe Session Setup
            // ========================
            // NOTE: This session type is the equivalent to libsodium's authenticated encryption.
            // This particular session does not require the sender and recipient to have exchanged
            // keys prior to the session. Only the sender needs to know the recipient's public key
            // because the sender ends their's in the message, encrypted.
            //
            // Initiator                            Responder
            //
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = NULL
            // | psk = pre-shared key value         | psk = pre-shared key value
            // |                                    |
            // | InitSymmetric("Noise_Xpsk1...")    | InitSymmetric("Noise_Xpsk1...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | EncryptAndHash(s.pub)
            // | MixKeyDh(s.sec, rs)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> e, es, s, ss, psk, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | rs = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, rs)
            //                                      | payload = DecryptAndHash()
            //                                      | split()
            Handshake::Xpsk1 => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Rs),
                        MixKey(Psk),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Ssec, Rs),
                        MixKey(Psk),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // NN_Strobe Session Setup
            // =======================
            //
            // Initiator                            Responder
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = NULL                           | s = NULL
            // | re = NULL                          | re = NULL
            // | rs = NULL                          | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_NN...")       | InitSymmetric("Noise_NN...")
            // | MixHash(prologue)                  | MixHash(prologue)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | EncryptAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re)
            // | payload = DecryptAndHash()
            // | Split()
            //
            Handshake::NN => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // KK_Strobe Session Setup
            // ========================
            //
            // Initiator                            Responder
            //
            //                      -> s
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = Initiator's static pub key
            // |                                    |
            // | InitSymmetric("Noise_KK...")       | InitSymmetric("Noise_KK...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(s.pub)                     | MixHash(rs)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | MixKeyDh(s.sec, rs)
            // | EncryptAndHash(payload)
            //
            //                      -> e, es, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | MixKeyDh(s.sec, rs)
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | MixKeyDh(s.sec, re)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re))
            // | MixKeyDh(e.sec, rs))
            // | payload = DecryptAndHash()
            // | Split()
            Handshake::KK => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        MixKeyDh(Ssec, Rs),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        MixKeyDh(Ssec, Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // XX_Strobe Session Setup
            // =======================
            //
            // Initiator                            Responder
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = NULL                          | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_XX...")       | InitSymmetric("Noise_XX...")
            // | MixHash(prologue)                  | MixHash(prologue)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixHash(e.pub)
            // | EncryptAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixHash(re)
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | EncryptAndHash(s.pub)
            //                                      | MixKeyDh(s.sec, re)
            //                                      | EncryptAndHash(payload)
            //
            //                      <- e, ee, s, es, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixHash(re)
            // | MixKeyDh(e.sec, re)
            // | rs = DecryptAndHash()
            // | MixKeyDh(e.sec, rs)
            // | payload = DecryptAndHash()
            //
            // +-- send_message()
            // | EncryptAndHash(s.pub)
            // | MixKeyDh(s.sec, re)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> s, se, (payload)
            //
            //                                      +-- recv_message()
            //                                      | rs = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, rs)
            //                                      | payload = DecryptAndHash()
            //                                      | Split()
            Handshake::XX => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Rs),
                        MixKeyDh(Ssec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // IK_Strobe Session Setup
            // =======================
            //
            // Initiator                            Responder
            //
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_IK...")       | InitSymmetric("Noise_IK...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | EncryptAndHash(s.pub)
            // | MixKeyDh(s.sec, rs)
            // | EncryptAndHash(payload)
            //
            //                      -> e, es, s, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | rs = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, rs)
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | MixKeyDh(e.sec, rs)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re)
            // | MixKeyDh(s.sec, re)
            // | payload = DecryptAndHash()
            // | Split()
            //
            Handshake::IK => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Rs),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Ssec, Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // IX_Strobe Session Setup
            // =======================
            //
            // Initiator                            Responder
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = NULL                          | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_IX...")       | InitSymmetric("Noise_IX...")
            // | MixHash(prologue)                  | MixHash(prologue)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | EncryptAndHash(s.pub)
            // | EncryptAndHash(payload)
            //
            //                      -> e, s, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | rs = DecryptAndHash()
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | MixKeyDh(e.sec, rs)
            //                                      | EncryptAndHash(s.pub)
            //                                      | MixKeyDh(s.sec, re)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, s, es, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re)
            // | MixKeyDh(s.sec, re)
            // | rs = DecryptAndHash()
            // | MixKeyDh(e.sec, rs)
            // | payload = DecryptAndHash()
            // | Split()
            //
            Handshake::IX => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Spub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // NK_Strobe Session Setup
            // =======================
            //
            // Initiator                            Responder
            //
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = NULL                           | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_NK...")       | InitSymmetric("Noise_NK...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | MixKeyDh(e.sec, rs)
            // | EncryptAndHash(payload)
            //
            //                      -> e, es, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | MixKeyDh(s.sec, re)
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re))
            // | payload = DecryptAndHash()
            // | Split()
            //
            Handshake::NK => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // NX_Strobe Session Setup
            // =======================
            //
            // Initiator                            Responder
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = NULL                           | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = NULL                          | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_NX...")       | InitSymmetric("Noise_NX...")
            // | MixHash(prologue)                  | MixHash(prologue)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | EncryptAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | EncryptAndHash(s.pub)
            //                                      | MixKeyDh(s.sec, re)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, s, es, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re)
            // | rs = DecryptAndHash()
            // | MixKeyDh(e.sec, rs)
            // | payload = DecryptAndHash()
            // | Split()
            //
            Handshake::NX => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // XK1_Strobe Session Setup
            // ========================
            //
            // Initiator                            Responder
            //
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = NULL
            // |                                    |
            // | InitSymmetric("Noise_XK1...")      | InitSymmetric("Noise_XK1...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | EncryptAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | MixKeyDh(s.sec, re)
            //                                      | EncryptAndHash(payload)
            //
            //                      <- e, ee, es, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re)
            // | MixKeyDh(e.sec, rs)
            // | payload = DecryptAndHash()
            //
            // +-- send_message()
            // | EncryptAndHash(s.pub)
            // | MixKeyDh(s.sec, re)
            // | EncryptAndHash(payload)
            // | Split()
            //
            //                      -> s, se, (payload)
            //
            //                                      +-- recv_message()
            //                                      | rs = DecryptAndHash()
            //                                      | MixKeyDh(e.sec, rs)
            //                                      | payload = DecryptAndHash()
            //                                      | Split()
            //
            Handshake::XK1 => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // KK1_Strobe Session Setup
            // ========================
            //
            // Initiator                            Responder
            //
            //                      -> s
            //                      <- s
            //                      ...
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = Initiator's static key pair    | s = Responder's static key pair
            // | re = NULL                          | re = NULL
            // | rs = Responder's static pub key    | rs = Initiator's static pub key
            // |                                    |
            // | InitSymmetric("Noise_KK1...")      | InitSymmetric("Noise_KK1...")
            // | MixHash(prologue)                  | MixHash(prologue)
            // | MixHash(s.pub)                     | MixHash(rs)
            // | MixHash(rs)                        | MixHash(s.pub)
            //
            // +-- send_message()
            // | e = GenKey
            // | EncryptAndHash(e.pub)
            // | EncryptAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | MixKeyDh(s.sec, re)
            //                                      | MixKeyDh(e.sec, rs)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, es, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re)
            // | MixKeyDh(e.sec, rs)
            // | MixKeyDh(s.sec, re)
            // | payload = DecryptAndHash()
            // | Split()
            //
            Handshake::KK1 => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Spub),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        MixHash(Rs),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
            // NNpsk2_Strobe Session Setup
            // =======================
            //
            // Initiator                            Responder
            //
            // +-- init()                           +-- init()
            // | e = NULL                           | e = NULL
            // | s = NULL                           | s = NULL
            // | re = NULL                          | re = NULL
            // | rs = NULL                          | rs = NULL
            // | psk = pre-shared key value         | psk = pre-shared key value
            // |                                    |
            // | InitSymmetric("Noise_NNpsk2...")   | InitSymmetric("Noise_NNpsk2...")
            // | MixHash(prologue)                  | MixHash(prologue)
            //
            // +-- send_message()
            // | e = GenKey()
            // | EncryptAndHash(e.pub)
            // | EncryptAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = DecryptAndHash()
            //                                      | payload = DecryptAndHash()
            //
            //                                      +-- send_message()
            //                                      | e = GenKey()
            //                                      | EncryptAndHash(e.pub)
            //                                      | MixKeyDh(e.sec, re)
            //                                      | MixKey(psk)
            //                                      | EncryptAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, psk, (payload)
            //
            // +-- recv_message()
            // | re = DecryptAndHash()
            // | MixKeyDh(e.sec, re)
            // | MixKey(psk)
            // | payload = DecryptAndHash()
            // | Split()
            //
            Handshake::NNpsk2 => {
                match role {
                    Initiator => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        Start,
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKey(Psk),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                    Responder => &[
                        /* init */
                        Start,
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        Start,
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKey(Psk),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ],
                }
            }
        }
    }

    /// True if handshake pattern requires local static key
    pub fn needs_local_static_key(&self, role: &ChannelRole) -> bool {
        use ChannelRole::*;
        use Handshake::*;
        match role {
            Initiator => match self {
                N | Npsk0 | NN | NK | NX | NNpsk2 => false,
                K | X | Kpsk0 | Xpsk1 | KK | XX | IK | IX | XK1 | KK1 => true,
            },
            Responder => match self {
                N | Npsk0 | NN | NNpsk2 => false,
                K | X | Kpsk0 | Xpsk1 | KK | XX | IK | IX | NK | NX | XK1 | KK1 => true,
            },
        }
    }

    /// True if handshake pattern requires remote static public key before the handshake
    pub fn needs_remote_static_key(&self, role: &ChannelRole) -> bool {
        use ChannelRole::*;
        use Handshake::*;
        match role {
            Initiator => match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | KK | IK | NK | XK1 | KK1 => true,
                IX | NN | XX | NX | NNpsk2 => false,
            },
            Responder => match self {
                K | Kpsk0 | KK | KK1 => true,
                N | X | Npsk0 | Xpsk1 | NN | XX | IK | IX | NK | NX | XK1 | NNpsk2 => false,
            },
        }
    }

    /// True if the handshake pattern and my role requires me to mix my static pub key
    pub fn mix_local_static_key(&self, role: &ChannelRole) -> bool {
        use ChannelRole::*;
        use Handshake::*;
        match role {
            Initiator => match self {
                K | Kpsk0 | KK | KK1 => true,
                N | X | Npsk0 | Xpsk1 | NN | XX | IK | IX | NK | NX | XK1 | NNpsk2 => false,
            },
            Responder => match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | KK | IK | NK | XK1 | KK1 => true,
                NN | XX | IX | NX | NNpsk2 => false,
            },
        }
    }

    /// True if the handshake pattern and my role requires me to mix the remote static pub key
    pub fn mix_remote_static_key(&self, role: &ChannelRole) -> bool {
        use ChannelRole::*;
        use Handshake::*;
        match role {
            Initiator => match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | KK | IK | NK | XK1 | KK1 => true,
                NN | XX | IX | NX | NNpsk2 => false,
            },
            Responder => match self {
                K | Kpsk0 | KK | KK1 => true,
                N | X | Npsk0 | Xpsk1 | NN | XX | IK | IX | NK | NX | XK1 | NNpsk2 => false,
            },
        }
    }

    /// True if the handshake pattern requires a pre-shared key before the handshake
    pub fn needs_pre_shared_key(&self, _role: &ChannelRole) -> bool {
        use Handshake::*;
        match self {
            Npsk0 | Kpsk0 | Xpsk1 | NNpsk2 => true,
            _ => false,
        }
    }

    /// True if handshake pattern defers the local DH operation
    pub fn local_dh_is_deferred(&self, role: &ChannelRole) -> bool {
        use ChannelRole::*;
        use Handshake::*;
        match role {
            Initiator => false,
            Responder => match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | NN | KK | XX | IK | IX | NK | NX | NNpsk2 => {
                    false
                }
                XK1 | KK1 => true,
            },
        }
    }

    /// True if handshake pattern defers the remote DH operation
    pub fn remote_dh_is_deferred(&self, role: &ChannelRole) -> bool {
        use ChannelRole::*;
        use Handshake::*;
        match role {
            Initiator => match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | NN | KK | XX | IK | IX | NK | NX | NNpsk2 => {
                    false
                }
                XK1 | KK1 => true,
            },
            Responder => false,
        }
    }
}

impl FromStr for Handshake {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use self::Handshake::*;
        match s {
            "N" => Ok(N),
            "K" => Ok(K),
            "X" => Ok(X),
            "Npsk0" => Ok(Npsk0),
            "Kpsk0" => Ok(Kpsk0),
            "Xpsk1" => Ok(Xpsk1),
            "NN" => Ok(NN),
            "KK" => Ok(KK),
            "XX" => Ok(XX),
            "IK" => Ok(IK),
            "IX" => Ok(IX),
            "NK" => Ok(NK),
            "NX" => Ok(NX),
            "XK1" => Ok(XK1),
            "KK1" => Ok(KK1),
            "NNpsk2" => Ok(NNpsk2),
            _ => Err(Error::Param(ParamError::InvalidHandshake)),
        }
    }
}

impl Display for Handshake {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), FmtError> {
        use self::Handshake::*;
        match self {
            N => write!(f, "N"),
            K => write!(f, "K"),
            X => write!(f, "X"),
            Npsk0 => write!(f, "Npsk0"),
            Kpsk0 => write!(f, "Kpsk0"),
            Xpsk1 => write!(f, "Xpsk1"),
            NN => write!(f, "NN"),
            KK => write!(f, "KK"),
            XX => write!(f, "XX"),
            IK => write!(f, "IK"),
            IX => write!(f, "IX"),
            NK => write!(f, "NK"),
            NX => write!(f, "NX"),
            XK1 => write!(f, "XK1"),
            KK1 => write!(f, "KK1"),
            NNpsk2 => write!(f, "NNpsk2"),
        }
    }
}
