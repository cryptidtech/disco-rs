use crate::error::{Error, ParamError};
use core::{
    fmt::{Display, Error as FmtError, Formatter},
    str::FromStr,
};

/// Identifiers for the different keys referenced in handshake scripts
#[derive(PartialEq, Copy, Clone, Debug)]
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
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum HandshakeOp {
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
#[derive(PartialEq, Copy, Clone, Debug)]
pub struct HandshakeState {
    handshake: Handshake,
    initiator: bool,
    index: usize,
}

/// HandshakeState impl
impl HandshakeState {
    /// construct a new handshake state from a list of operations
    pub fn new(pattern: Handshake, initiator: bool) -> Self {
        HandshakeState {
            handshake: pattern,
            initiator,
            index: 0,
        }
    }
}

/// Make it easy walk through the steps of the state machine
impl Iterator for HandshakeState {
    type Item = HandshakeOp;

    fn next(&mut self) -> Option<Self::Item> {
        let pattern = self.handshake.get_pattern(self.initiator);
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
#[derive(PartialEq, Copy, Clone, Debug)]
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
// NOTE: every strobe operation is encoded using CDE (https://github.com/cryptidtech/cde)
// and either streamed as text or binary based on the applications requirments.
// each primitive strobe operation has its own tag that can consist of either
// 1, 2, or 3, three-byte "triples". each tag is sent by calling MixHash()
// followed by SendAndHash() for each of the three-byte triples. the result is
// outputing a tag that determins the primitive strobe operation and the length
// of the data to process with the operation. to receive a tag, the receiver
// first calls MixHash() followed by RecvAndHash() for the first three-byte
// triple. If the MSB of the third byte in the triple is set then the length
// of the associated data is greater than 127 bytes in length a second three-
// byte triple must be received. the receiver again calls MixHash() and
// RecvAndHash() to get the second three-byte triple. Again, if the MSB of the
// third by is set, then there is a third three-byte triple and again the
// receiver calls MixHash() and RecvAndHash() to receive the third three-byte
// triple. The strobe operation is encoded in the class and sub-class values
// in the first and second bytes of the first three-byte triple. The length of
// the associated data is encoded as an unsigned varint
// (https://github.com/multiformats/unsigned-varint) of up to seven bytes in
// length giving a maximum payload length of 2^49-1 bytes. once the primitive
// strobe operation is known, it must be performed on the associated data with
// the length given in the tag.
//
//

impl Handshake {
    /// Return the appropriate HandshakeState
    pub fn get_pattern(&self, initiator: bool) -> &[HandshakeOp] {
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
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
                    ]
                } else {
                    &[
                        /* init */
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
                    ]
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
                if initiator {
                    &[
                        /* init */
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
                    ]
                } else {
                    &[
                        /* init */
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
                    ]
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
                if initiator {
                    &[
                        /* init */
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
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        MixKey(Psk),
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
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
                    ]
                } else {
                    &[
                        /* init */
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
                    ]
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
                if initiator {
                    &[
                        /* init */
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
                    ]
                } else {
                    &[
                        /* init */
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
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
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
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
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
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Rs),
                        MixKeyDh(Ssec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
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
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
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
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Spub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        EncryptAndHash(Spub),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Rs),
                        MixKeyDh(Esec, Rs),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Spub),
                        MixHash(Rs),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Esec, Rs),
                        MixKeyDh(Ssec, Re),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        MixHash(Rs),
                        MixHash(Spub),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKeyDh(Ssec, Re),
                        MixKeyDh(Esec, Rs),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
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
                if initiator {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        EncryptAndHash(Payload),
                        Stop,
                        /* recv */
                        DecryptAndHash(Re),
                        MixKeyDh(Esec, Re),
                        MixKey(Psk),
                        DecryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                } else {
                    &[
                        /* init */
                        MixHash(Prologue),
                        /* recv */
                        DecryptAndHash(Re),
                        DecryptAndHash(Payload),
                        Stop,
                        /* send */
                        GenKey,
                        EncryptAndHash(Epub),
                        MixKeyDh(Esec, Re),
                        MixKey(Psk),
                        EncryptAndHash(Payload),
                        GetHandshakeHash,
                        Split,
                    ]
                }
            }
        }
    }

    /// True if handshake pattern requires local static key
    pub fn needs_local_static_key(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                N | Npsk0 | NN | NK | NX | NNpsk2 => false,
                K | X | Kpsk0 | Xpsk1 | KK | XX | IK | IX | XK1 | KK1 => true,
            }
        } else {
            match self {
                N | Npsk0 | NN | NNpsk2 => false,
                K | X | Kpsk0 | Xpsk1 | KK | XX | IK | IX | NK | NX | XK1 | KK1 => true,
            }
        }
    }

    /// True if handshake pattern requires remote static public key before the handshake
    pub fn needs_remote_static_key(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | KK | IK | NK | XK1 | KK1 => true,
                IX | NN | XX | NX | NNpsk2 => false,
            }
        } else {
            match self {
                K | Kpsk0 | KK | KK1 => true,
                N | X | Npsk0 | Xpsk1 | NN | XX | IK | IX | NK | NX | XK1 | NNpsk2 => false,
            }
        }
    }

    /// True if the handshake pattern and my role requires me to mix my static pub key
    pub fn mix_local_static_key(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                K | Kpsk0 | KK | KK1 => true,
                N | X | Npsk0 | Xpsk1 | NN | XX | IK | IX | NK | NX | XK1 | NNpsk2 => false,
            }
        } else {
            match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | KK | IK | NK | XK1 | KK1 => true,
                NN | XX | IX | NX | NNpsk2 => false,
            }
        }
    }

    /// True if the handshake pattern and my role requires me to mix the remote static pub key
    pub fn mix_remote_static_key(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | KK | IK | NK | XK1 | KK1 => true,
                NN | XX | IX | NX | NNpsk2 => false,
            }
        } else {
            match self {
                K | Kpsk0 | KK | KK1 => true,
                N | X | Npsk0 | Xpsk1 | NN | XX | IK | IX | NK | NX | XK1 | NNpsk2 => false,
            }
        }
    }

    /// True if the handshake pattern requires a pre-shared key before the handshake
    pub fn needs_pre_shared_key(&self, _initiator: bool) -> bool {
        use Handshake::*;
        match self {
            Npsk0 | Kpsk0 | Xpsk1 | NNpsk2 => true,
            _ => false,
        }
    }

    /// True if handshake pattern defers the local DH operation
    pub fn local_dh_is_deferred(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            false
        } else {
            match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | NN | KK | XX | IK | IX | NK | NX | NNpsk2 => {
                    false
                }
                XK1 | KK1 => true,
            }
        }
    }

    /// True if handshake pattern defers the remote DH operation
    pub fn remote_dh_is_deferred(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                N | K | X | Npsk0 | Kpsk0 | Xpsk1 | NN | KK | XX | IK | IX | NK | NX | NNpsk2 => {
                    false
                }
                XK1 | KK1 => true,
            }
        } else {
            false
        }
    }
}

impl FromStr for Handshake {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
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
