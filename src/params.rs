use crate::{
    error::{Error, ParamError},
    key::{KeyAgreement, KeyGenerator, KeyType},
};
use core::{
    fmt::{Display, Error as FmtError, Formatter},
    marker::PhantomData,
    str::FromStr,
};
use semver::{Version, VersionReq};
use strobe_rs::STROBE_VERSION;

/// Encapsulates the handshake parameters
#[derive(PartialEq, Clone, Debug)]
pub struct Params<'a, T>
where
    T: KeyType + KeyGenerator<'a> + KeyAgreement<'a> + Clone,
{
    /// The protocol name
    pub protocol: Protocol,
    /// The handshake pattern
    pub handshake: Handshake,
    /// The key type
    pub key_type: T,
    /// The strobe protocol version
    pub version: StrobeVersion,
    /// PhantomData marker for lifetime
    _pd: PhantomData<&'a ()>,
}

impl<'a, T> FromStr for Params<'a, T>
where
    T: KeyType + KeyGenerator<'a> + KeyAgreement<'a> + Clone,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('_');
        Ok(Params {
            protocol: split.next().ok_or(ParamError::TooFewParameters)?.parse()?,
            handshake: split.next().ok_or(ParamError::TooFewParameters)?.parse()?,
            key_type: split
                .next()
                .ok_or(ParamError::TooFewParameters)?
                .parse()
                .map_err(|_| ParamError::InvalidKeyType)?,
            version: split.next().ok_or(ParamError::TooFewParameters)?.parse()?,
            _pd: PhantomData,
        })
    }
}

impl<'a, T> Display for Params<'a, T>
where
    T: KeyType + KeyGenerator<'a> + KeyAgreement<'a> + Clone,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(
            f,
            "{}_{}_{}_{}",
            self.protocol, self.handshake, self.key_type, self.version
        )
    }
}

/// The protocol naming string really should be Disco_XX_25519_STROBEv1.0.2
/// instead of Noise_XX_25519_STROBEv1.0.2 but whatevs
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// Noise protocol
    Noise,
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use self::Protocol::*;
        match s {
            "Noise" => Ok(Noise),
            _ => Err(Error::Param(ParamError::InvalidProtocol)),
        }
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "Noise")
    }
}

/// Identifiers for the different keys referenced in handshake scripts
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum HandshakeData {
    /// Local static public key
    Spub,
    /// Local static secret key
    Ssec,
    /// Local ephemeral public key
    Epub,
    /// Local ephemeral secret key
    Esec,
    /// Remote static public key
    Rs,
    /// Remote ephemeral public key
    Re,
    /// Payload data
    P,
    /// Pre-shared key
    Psk,
}

/// Different operations to perform in handshake scripts
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum HandshakeOp {
    /// Mix in key data, set isKeyed = bool value
    Mix(HandshakeData, bool),
    /// Mix in the result of a DH operation, set isKeyed = bool value
    MixDh(HandshakeData, HandshakeData, bool),
    /// Sends data encrypted if isKeyed is true, plaintext otherwise
    SendData(HandshakeData),
    /// Receives data encrypted if isKeyed is true, plaintext otherwise
    RecvData(HandshakeData),
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
            initiator: initiator,
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
            // | InitSymmetric("Noise_N...")        | InitSymmetric("Noise_N...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re = NULL
            // | rs = Bob's Static Pub Key          | rs = Alice's Static Pub Key
            //
            // +-- send_message()
            // | MixHash(s.pub)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | MixKey(DH(e.sec, rs))
            // | SendAndHash(payload)
            // | MixHash(payload)
            // | Split()
            //
            //                      -> e, es, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(rs)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | MixKey(DH(s.sec, re))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | Split()
            Handshake::N => {
                if initiator {
                    &[
                        /* send */
                        Mix(Rs, false),
                        SendData(Epub),
                        MixDh(Esec, Rs, true),
                        SendData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Spub, false),
                        RecvData(Re),
                        MixDh(Ssec, Re, true),
                        RecvData(P),
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
            // | InitSymmetric("Noise_K...")        | InitSymmetric("Noise_K...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re = NULL
            // | rs = Bob's Static Pub Key          | rs = Alice's Static Pub Key
            //
            // +-- send_message()
            // | MixHash(s.pub)
            // | MixHash(rs)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | MixKey(DH(e.sec, rs))
            // | MixKeyAndHash(DH(s.sec, rs))
            // | SendAndHash(payload)
            // | MixHash(payload)
            // | Split()
            //
            //                      -> e, es, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(rs)
            //                                      | MixHash(s.pub)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | MixKey(DH(s.sec, re))
            //                                      | MixKeyAndHash(DH(s.sec, rs))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | Split()
            Handshake::K => {
                if initiator {
                    &[
                        /* send */
                        Mix(Spub, false),
                        Mix(Rs, false),
                        SendData(Epub),
                        MixDh(Esec, Rs, true),
                        MixDh(Ssec, Rs, true),
                        SendData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Rs, false),
                        Mix(Spub, false),
                        RecvData(Re),
                        MixDh(Ssec, Re, true),
                        MixDh(Ssec, Rs, true),
                        RecvData(P),
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
            // | InitSymmetric("Noise_X...")        | InitSymmetric("Noise_X...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re, rs = NULL
            // | rs = Bob's Static Pub Key          |
            //
            // +-- send_message()
            // | MixHash(rs)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | MixKey(DH(e.sec, rs))
            // | SendAndHash(s.pub)
            // | MixHash(s.pub)
            // | MixKeyAndHash(DH(s.sec, rs))
            // | SendAndHash(payload)
            // | MixHash(payload)
            // | Split()
            //
            //                      -> e, es, s, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(s.pub)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | MixKey(DH(s.sec, re))
            //                                      | rs = RecvAndHash()
            //                                      | MixHash(rs)
            //                                      | MixKeyAndHash(DH(s.sec, rs))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | Split()
            Handshake::X => {
                if initiator {
                    &[
                        /* send */
                        Mix(Rs, false),
                        SendData(Epub),
                        MixDh(Esec, Rs, true),
                        SendData(Spub),
                        MixDh(Ssec, Rs, true),
                        SendData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Spub, false),
                        RecvData(Re),
                        MixDh(Ssec, Re, true),
                        RecvData(Rs),
                        MixDh(Ssec, Rs, true),
                        RecvData(P),
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
            // | InitSymmetric("Noise_NN...")       | InitSymmetric("Noise_NN...")
            // | e = gen_key()                      | e = gen_key()
            // | s, re, res = NULL                  | s, re, rs = NULL
            //
            // +-- send_message()
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKey(DH(e.sec, re))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            //
            Handshake::NN => {
                if initiator {
                    &[
                        /* send */
                        SendData(Epub),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        RecvData(Re),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        SendData(P),
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
            // | InitSymmetric("Noise_KK...")       | InitSymmetric("Noise_KK...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re = NULL
            // | rs = Bob's Static Pub Key          | rs = Alice's Static Pub Key
            //
            // +-- send_message()
            // | MixHash(s.pub)
            // | MixHash(rs)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | MixKey(DH(e.sec, rs))
            // | MixKeyAndHash(DH(s.sec, rs))
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, es, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(rs)
            //                                      | MixHash(s.pub)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | MixKeyAndHash(DH(s.sec, rs))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKeyAndHash(DH(e.sec, re))
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKeyAndHash(DH(e.sec, re))
            // | MixKeyAndHash(DH(e.sec, rs))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            Handshake::KK => {
                if initiator {
                    &[
                        /* send */
                        Mix(Spub, false),
                        Mix(Rs, false),
                        SendData(Epub),
                        MixDh(Esec, Rs, true),
                        MixDh(Ssec, Rs, true),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Rs, false),
                        Mix(Spub, false),
                        RecvData(Re),
                        MixDh(Ssec, Re, true),
                        MixDh(Ssec, Rs, true),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        MixDh(Ssec, Re, true),
                        SendData(P),
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
            // | InitSymmetric("Noise_XX...")       | InitSymmetric("Noise_XX...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re, rs = NULL                      | re, rs = NULL
            //
            // +-- send_message()
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | SendAndHash(s.pub)
            //                                      | MixHash(s.pub)
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //
            //                      <- e, ee, s, es, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKey(DH(e.sec, re))
            // | rs = RecvAndHash()
            // | MixHash(rs)
            // | MixKeyAndHash(DH(e.sec, rs))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            //
            // +-- send_message()
            // | SendAndHash(s.pub)
            // | MixHash(s.pub)
            // | MixKeyAndHash(DH(s.sec, re))
            // | SendAndHash(payload)
            // | MixHash(payload)
            // | Split()
            //
            //                      -> s, se, (payload)
            //
            //                                      +-- recv_message()
            //                                      | rs = RecvAndHash()
            //                                      | MixHash(rs)
            //                                      | MixKeyAndHash(DH(s.sec, rs))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | Split()
            Handshake::XX => {
                if initiator {
                    &[
                        /* send */
                        SendData(Epub),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        RecvData(Rs),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Spub),
                        MixDh(Ssec, Rs, true),
                        SendData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        RecvData(Re),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        SendData(Spub),
                        MixDh(Ssec, Re, true),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Rs),
                        MixDh(Ssec, Rs, true),
                        RecvData(P),
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
            // | InitSymmetric("Noise_IK...")       | InitSymmetric("Noise_IK...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re, rs = NULL
            // | rs = Bob's Static Pub Key
            //
            // +-- send_message()
            // | MixHash(rs)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | MixKey(DH(e.sec, rs))
            // | SendAndHash(s.pub)
            // | MixKeyAndHash(DH(s.sec, rs))
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, es, s, ss, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(s.pub)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | MixKey(DH(s.sec, re))
            //                                      | rs = RecvAndHash()
            //                                      | MixHash(rs)
            //                                      | MixKeyAndHash(DH(s.sec, rs))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKeyAndHash(DH(e.sec, re))
            //                                      | MixKeyAndHash(DH(e.sec, rs))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKeyAndHash(DH(e.sec, re))
            // | MixKeyAndHash(DH(s.sec, re))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            //
            Handshake::IK => {
                if initiator {
                    &[
                        /* send */
                        Mix(Rs, false),
                        SendData(Epub),
                        MixDh(Esec, Rs, true),
                        SendData(Spub),
                        MixDh(Ssec, Rs, true),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Spub, false),
                        RecvData(Re),
                        MixDh(Ssec, Re, true),
                        RecvData(Rs),
                        MixDh(Ssec, Rs, true),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        MixDh(Ssec, Re, true),
                        SendData(P),
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
            // | InitSymmetric("Noise_IX...")       | InitSymmetric("Noise_IX...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re, rs = NULL                      | re, rs = NULL
            //
            // +-- send_message()
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | SendAndHash(s.pub)
            // | MexHash(e.pub)
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, s, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | rs = RecvAndHash()
            //                                      | MixHash(rs)
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKeyAndHash(DH(e.sec, re))
            //                                      | MixKeyAndHash(DH(e.sec, rs))
            //                                      | SendAndHash(s.pub)
            //                                      | MixHash(s.pub)
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, s, es, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKeyAndHash(DH(e.sec, re))
            // | MixKeyAndHash(DH(s.sec, re))
            // | rs = RecvAndHash()
            // | MixHash(rs)
            // | MixKeyAndHash(DH(e.sec, rs))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            //
            Handshake::IX => {
                if initiator {
                    &[
                        /* send */
                        SendData(Epub),
                        SendData(Spub),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        MixDh(Ssec, Re, true),
                        RecvData(Rs),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        RecvData(Re),
                        RecvData(Rs),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        MixDh(Esec, Rs, true),
                        SendData(Spub),
                        MixDh(Ssec, Re, true),
                        SendData(P),
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
            // | InitSymmetric("Noise_NK...")       | InitSymmetric("Noise_NK...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re, rs = NULL
            // | rs = Bob's Static Pub Key
            //
            // +-- send_message()
            // | MixHash(rs)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | MixKey(DH(e.sec, rs))
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, es, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(s.pub)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | MixKey(DH(s.sec, re))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKeyAndHash(DH(e.sec, re))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKeyAndHash(DH(e.sec, re))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            //
            Handshake::NK => {
                if initiator {
                    &[
                        /* send */
                        Mix(Rs, false),
                        SendData(Epub),
                        MixDh(Esec, Rs, true),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Spub, false),
                        RecvData(Re),
                        MixDh(Ssec, Re, true),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        SendData(P),
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
            // | InitSymmetric("Noise_NX...")       | InitSymmetric("Noise_NX...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re, rs = NULL                      | re, rs = NULL
            //
            // +-- send_message()
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKeyAndHash(DH(e.sec, re))
            //                                      | SendAndHash(s.pub)
            //                                      | MixHash(s.pub)
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, s, es, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKeyAndHash(DH(e.sec, re))
            // | rs = RecvAndHash()
            // | MixHash(rs)
            // | MixKeyAndHash(DH(e.sec, rs))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            //
            Handshake::NX => {
                if initiator {
                    &[
                        /* send */
                        SendData(Epub),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        RecvData(Rs),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        RecvData(Re),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        SendData(Spub),
                        MixDh(Ssec, Re, true),
                        SendData(P),
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
            // | InitSymmetric("Noise_XK1...")      | InitSymmetric("Noise_XK1...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re, rs = NULL
            // | rs = Bob's Static Pub Key
            //
            // +-- send_message()
            // | MixHash(rs)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(s.pub)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //
            //                      <- e, ee, es, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKey(AD(e.sec, re))
            // | MixKeyAndHash(AD(e.sec, rs))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            //
            // +-- send_message()
            // | SendAndHash(s.pub)
            // | MixHash(s.pub)
            // | MixKeyAndHash(AD(s.sec, re))
            // | SendAndHash(payload)
            // | MixHash(payload)
            // | Split()
            //
            //                      -> s, se, (payload)
            //
            //                                      +-- recv_message()
            //                                      | rs = RecvAndHash()
            //                                      | MixHash(rs)
            //                                      | MixKeyAndHash(DH(e.sec, rs))
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            Handshake::XK1 => {
                if initiator {
                    &[
                        /* send */
                        Mix(Rs, false),
                        SendData(Epub),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Spub),
                        MixDh(Ssec, Re, true),
                        SendData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Spub, false),
                        RecvData(Re),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        MixDh(Ssec, Re, true),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Rs),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
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
            // | InitSymmetric("Noise_KK1...")      | InitSymmetric("Noise_KK1...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re = NULL                          | re = NULL
            // | rs = Bob's Static Pub Key          | rs = Alice's Static Pub Key
            //
            // +-- send_message()
            // | MixHash(s.pub)
            // | MixHash(rs)
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(rs)
            //                                      | MixHash(s.pub)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | MixKeyAndHash(DH(e.sec, rs))
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, se, es, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKey(DH(e.sec, re))
            // | MixKeyAndHash(DH(e.sec, rs))
            // | MixKeyAndHash(DH(s.sec, re))
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            //
            Handshake::KK1 => {
                if initiator {
                    &[
                        /* send */
                        Mix(Spub, false),
                        Mix(Rs, false),
                        SendData(Epub),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        MixDh(Esec, Rs, true),
                        MixDh(Ssec, Re, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        Mix(Rs, false),
                        Mix(Spub, false),
                        RecvData(Re),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        MixDh(Ssec, Re, true),
                        MixDh(Esec, Rs, true),
                        SendData(P),
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
            // | InitSymmetric("Noise_NNpsk2...")   | InitSymmetric("Noise_NNpsk2...")
            // | e = gen_key()                      | e = gen_key()
            // | s = load_key()                     | s = load_key()
            // | re, rs = NULL                      | re, rs = NULL
            //
            // +-- send_message()
            // | SendAndHash(e.pub)
            // | MixHash(e.pub)
            // | SendAndHash(payload)
            // | MixHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | re = RecvAndHash()
            //                                      | MixHash(re)
            //                                      | payload = RecvAndHash()
            //                                      | MixHash(payload)
            //
            //                                      +-- send_message()
            //                                      | SendAndHash(e.pub)
            //                                      | MixHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | MixHash(psk)
            //                                      | SendAndHash(payload)
            //                                      | MixHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, psk, (payload)
            //
            // +-- recv_message()
            // | re = RecvAndHash()
            // | MixHash(re)
            // | MixKey(DH(e.sec, re))
            // | MixHash(psk)
            // | payload = RecvAndHash()
            // | MixHash(payload)
            // | Split()
            //
            Handshake::NNpsk2 => {
                if initiator {
                    &[
                        /* send */
                        SendData(Epub),
                        SendData(P),
                        Stop,
                        /* recv */
                        RecvData(Re),
                        MixDh(Esec, Re, false),
                        Mix(Psk, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[
                        /* recv */
                        RecvData(Re),
                        RecvData(P),
                        Stop,
                        /* send */
                        SendData(Epub),
                        MixDh(Esec, Re, false),
                        Mix(Psk, true),
                        SendData(P),
                        Split,
                    ]
                }
            }
        }
    }

    /// True if handshake pattern requires local static key
    pub fn needs_local_secret_key(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                N | NN | NK | NX | NNpsk2 => false,
                K | X | KK | XX | IK | IX | XK1 | KK1 => true,
            }
        } else {
            match self {
                N | NN | NNpsk2 => false,
                K | X | KK | XX | IK | IX | NK | NX | XK1 | KK1 => true,
            }
        }
    }

    /// True if handshake pattern requires remote static public key before the handshake
    pub fn needs_remote_public_key(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                N | K | X | KK | IK | NK | XK1 | KK1 => true,
                IX | NN | XX | NX | NNpsk2 => false,
            }
        } else {
            match self {
                K | KK | KK1 => true,
                N | X | NN | XX | IK | IX | NK | NX | XK1 | NNpsk2 => false,
            }
        }
    }

    /// True if the handshake pattern requires a pre-shared key before the handshake
    pub fn needs_pre_shared_key(&self, _initiator: bool) -> bool {
        if *self == Handshake::NNpsk2 {
            true
        } else {
            false
        }
    }

    /// True if handshake pattern defers the local DH operation
    pub fn local_dh_is_deferred(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            false
        } else {
            match self {
                N | K | X | NN | KK | XX | IK | IX | NK | NX | NNpsk2 => false,
                XK1 | KK1 => true,
            }
        }
    }

    /// True if handshake pattern defers the remote DH operation
    pub fn remote_dh_is_deferred(&self, initiator: bool) -> bool {
        use Handshake::*;
        if initiator {
            match self {
                N | K | X | NN | KK | XX | IK | IX | NK | NX | NNpsk2 => false,
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

/// The strobe version we support for now
#[derive(PartialEq, Clone, Debug)]
pub struct StrobeVersion(Version);

impl FromStr for StrobeVersion {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // we get a string like "STROBEv1.0.2" and split it at the 'v'
        let mut split = s.split('v');

        // this should be the string "STROBE"
        let strobe = split.next().ok_or(ParamError::InvalidStrobeVersion)?;
        match strobe {
            "STROBE" => {}
            _ => return Err(Error::Param(ParamError::InvalidStrobeVersion)),
        }

        // this should be a string like "1.0.2"
        let vstr = split.next().ok_or(ParamError::InvalidStrobeVersion)?;

        // we are expecting a version =1.0.2
        let req = VersionReq::parse(format!("={}", STROBE_VERSION).as_str())
            .map_err(|_| ParamError::InvalidStrobeVersion)?;

        // parse the version string
        let ver = Version::parse(vstr).map_err(|_| ParamError::InvalidStrobeVersion)?;

        // check that the version string matches the version requirement
        if req.matches(&ver) {
            Ok(StrobeVersion(ver))
        } else {
            Err(Error::Param(ParamError::InvalidStrobeVersion))
        }
    }
}

impl Display for StrobeVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "STROBEv{}", self.0)
    }
}
