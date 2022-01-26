use core::{
    fmt::{Display, Error as FmtError, Formatter},
    marker::PhantomData,
    str::FromStr,
};
use crate::{
    error::{Error, ParamError},
    key::{KeyAgreement, KeyGenerator, KeyType},
};
use semver::{Version, VersionReq};
use strobe_rs::STROBE_VERSION;

/// Encapsulates the handshake parameters
#[derive(PartialEq, Clone, Debug)]
pub struct Params<'a, T>
where
    T: KeyType + KeyGenerator<'a> + KeyAgreement<'a> + Clone
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
    T: KeyType + KeyGenerator<'a> + KeyAgreement<'a> + Clone
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut split = s.split('_');
        Ok(Params {
            protocol: split.next().ok_or(ParamError::TooFewParameters)?.parse()?,
            handshake: split.next().ok_or(ParamError::TooFewParameters)?.parse()?,
            key_type: split.next().ok_or(ParamError::TooFewParameters)?.parse().map_err(|_| ParamError::InvalidKeyType)?,
            version: split.next().ok_or(ParamError::TooFewParameters)?.parse()?,
            _pd: PhantomData,
        })
    }
}

impl<'a, T> Display for Params<'a, T>
where
    T: KeyType + KeyGenerator<'a> + KeyAgreement<'a> + Clone
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}_{}_{}_{}", self.protocol, self.handshake, self.key_type, self.version)
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
            _ => Err(Error::Param(ParamError::InvalidProtocol))
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
    /// Both sides transmit their keys
    XX,
    /// Initiator transmits key and knows responders key, deferred
    XK1,
    /// Initiator and responder know each other's keys, deferred
    KK1,
}

impl Handshake {

    /// Return the appropriate HandshakeState
    pub fn get_pattern(&self, initiator: bool) -> &[HandshakeOp] {
        use HandshakeOp::*;
        use HandshakeData::*;

        match self {
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
            // | MixHash(e.pub)
            // | SendAndHash(e.pub)
            // | MixHash(payload)
            // | SendAndHash(payload)
            // 
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(re)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | payload = RecvAndHash()
            //
            //                                      +-- send_message()
            //                                      | MixHash(e.pub)
            //                                      | SendAndHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | MixHash(s.pub)
            //                                      | SendAndHash(s.pub)
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | MixHash(payload)
            //                                      | SendAndHash(payload)
            //
            //                      <- e, ee, s, es, (payload)
            //
            // +-- recv_message()
            // | MixHash(re)
            // | re = RecvAndHash()
            // | MixKey(DH(e.sec, re))
            // | MixHash(rs)
            // | rs = RecvAndHash()
            // | MixKeyAndHash(DH(e.sec, rs))
            // | MixHash(payload)
            // | payload = RecvAndHash()
            // 
            // +-- send_message()
            // | MixHash(s.pub)
            // | SendAndHash(s.pub)
            // | MixKeyAndHash(DH(s.sec, re))
            // | SendAndHash(payload)
            // | Split()
            //
            //                      -> s, se, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(rs)
            //                                      | rs = RecvAndHash()
            //                                      | MixKeyAndHash(DH(s.sec, rs))
            //                                      | payload = RecvAndHash()
            //                                      | Split()
            Handshake::XX => {
                if initiator {
                    &[/* send */
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
                    &[/* recv */
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
            },

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
            // | MixHash(e.pub)
            // | SendAndHash(e.pub)
            // | MixHash(payload)
            // | SendAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(s.pub)
            //                                      | MixHash(re)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | payload = RecvAndHash()
            //
            //                                      +-- send_message()
            //                                      | MixHash(e.pub)
            //                                      | SendAndHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | MixHash(payload)
            //                                      | SendAndHash(payload)
            //
            //                      <- e, ee, es, (payload)
            //
            // +-- recv_message()
            // | MixHash(re)
            // | re = RecvAndHash()
            // | MixKey(AD(e.sec, re))
            // | MixKeyAndHash(AD(e.sec, rs))
            // | MixHash(payload)
            // | payload = RecvAndHash()
            //
            // +-- send_message()
            // | MixHash(s.pub)
            // | SendAndHash(s.pub)
            // | MixKeyAndHash(DH(s.sec, re))
            // | SendAndHash(payload)
            // | Split()
            //
            //                      -> s, se, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(rs)
            //                                      | rs = RecvAndHash()
            //                                      | MixKeyAndHash(DH(e.sec, rs))
            //                                      | SendAndHash(payload)
            //                                      | Split()
            Handshake::XK1 => {
                if initiator {
                    &[/* send */
                        Mix(Rs, false),
                        Mix(Epub, false),
                        SendData(Epub),
                        Mix(P, false),
                        SendData(P),
                        Stop,
                      /* recv */
                        Mix(Re, false),
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        MixDh(Esec, Rs, true),
                        Mix(P, true),
                        RecvData(P),
                        Stop,
                      /* send */
                        Mix(Spub, true),
                        SendData(Spub),
                        MixDh(Ssec, Re, true),
                        SendData(P),
                        Split,
                    ]
                } else {
                    &[/* recv */
                        Mix(Spub, false),
                        Mix(Re, false),
                        RecvData(Re),
                        Mix(P, false),
                        RecvData(P),
                        Stop,
                      /* send */
                        Mix(Epub, false),
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        MixDh(Ssec, Re, true),
                        Mix(P, true),
                        SendData(P),
                        Stop,
                      /* recv */
                        Mix(Rs, true),
                        RecvData(Rs),
                        MixDh(Esec, Rs, true),
                        RecvData(P),
                        Split,
                    ]
                }
            },
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
            // | MixHash(e.pub)
            // | SendAndHash(e.pub)
            // | MixHash(payload)
            // | SendAndHash(payload)
            //
            //                      -> e, (payload)
            //
            //                                      +-- recv_message()
            //                                      | MixHash(rs)
            //                                      | MixHash(s.pub)
            //                                      | MixHash(re)
            //                                      | re = RecvAndHash()
            //                                      | MixHash(payload)
            //                                      | payload = RecvAndHash()
            //
            //                                      +-- send_message()
            //                                      | MixHash(e.pub)
            //                                      | SendAndHash(e.pub)
            //                                      | MixKey(DH(e.sec, re))
            //                                      | MixKeyAndHash(DH(s.sec, re))
            //                                      | MixKeyAndHash(DH(e.sec, rs))
            //                                      | MixKeyAndHash(DH(s.sec, rs))
            //                                      | MixHash(payload)
            //                                      | SendAndHash(payload)
            //                                      | Split()
            //
            //                      <- e, ee, es, se, ss, (payload)
            //
            // +-- recv_message()
            // | MixHash(re)
            // | re = RecvAndHash()
            // | MixKey(DH(e.sec, re))
            // | MixKeyAndHash(DH(e.sec, rs))
            // | MixKeyAndHash(DH(s.sec, re))
            // | MixKeyAndHash(DH(s.sec, rs))
            // | MixHash(payload)
            // | payload = RecvAndHash()
            // | SendAndHash(payload)
            // | Split()
            Handshake::KK1 => {
                if initiator {
                    &[/* send */
                        Mix(Spub, false),
                        Mix(Rs, false),
                        Mix(Epub, false),
                        SendData(Epub),
                        Mix(P, false),
                        SendData(P),
                        Stop,
                      /* recv */
                        Mix(Re, false),
                        RecvData(Re),
                        MixDh(Esec, Re, true),
                        MixDh(Esec, Rs, true),
                        MixDh(Ssec, Re, true),
                        MixDh(Ssec, Rs, true),
                        Mix(P, true),
                        RecvData(P),
                        Split,
                    ]
                } else {
                    &[/* recv */
                        Mix(Rs, false),
                        Mix(Spub, false),
                        Mix(Re, false),
                        RecvData(Re),
                        Mix(P, false),
                        RecvData(P),
                        Stop,
                      /* send */
                        Mix(Epub, false),
                        SendData(Epub),
                        MixDh(Esec, Re, true),
                        MixDh(Ssec, Re, true),
                        MixDh(Esec, Rs, true),
                        MixDh(Ssec, Rs, true),
                        Mix(P, true),
                        SendData(P),
                        Split,
                    ]
                }
            }
        }
    }

    /// True if handshake pattern requires local secret key
    pub fn needs_local_secret_key(&self, initiator: bool) -> bool {
        if initiator {
            match self {
                Handshake::XX | Handshake::XK1 => true,
                Handshake::KK1 => false
            }
        } else {
            match self {
                Handshake::XX => true,
                Handshake::XK1 | Handshake::KK1 => false
            }
        }
    }

    /// True if handshake pattern requires remote public key
    pub  fn needs_remote_public_key(&self, initiator: bool) -> bool {
        if initiator {
            match self {
                Handshake::XX => false,
                Handshake::XK1 | Handshake::KK1 => true
            }
        } else {
            match self {
                Handshake::XX | Handshake::XK1 => false,
                Handshake::KK1 => true
            }
        }
    }

    /// True if handshake pattern defers the local DH operation
    pub fn local_dh_is_deferred(&self, initiator: bool) -> bool {
        if initiator {
            false
        } else {
            match self {
                Handshake::XX => false,
                Handshake::XK1 | Handshake::KK1 => true
            }
        }
    }

    /// True if handshake pattern defers the remote DH operation
    pub fn remote_dh_is_deferred(&self, initiator: bool) -> bool {
        if initiator {
            match self {
                Handshake::XX => false,
                Handshake::XK1 | Handshake::KK1 => true
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
            "XX" => Ok(XX),
            "XK1" => Ok(XK1),
            "KK1" => Ok(KK1),
            _ => Err(Error::Param(ParamError::InvalidHandshake))
        }
    }
}

impl Display for Handshake {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        use self::Handshake::*;
        match self {
            XX => write!(f, "XX"),
            XK1 => write!(f, "XK1"),
            KK1 => write!(f, "KK1"),
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
            "STROBE" => {},
            _ => return Err(Error::Param(ParamError::InvalidStrobeVersion))
        }

        // this should be a string like "1.0.2"
        let vstr = split.next().ok_or(ParamError::InvalidStrobeVersion)?;

        // we are expecting a version =1.0.2
        let req = VersionReq::parse(format!("={}", STROBE_VERSION).as_str()).map_err(|_| { ParamError::InvalidStrobeVersion })?;

        // parse the version string
        let ver = Version::parse(vstr).map_err(|_| { ParamError::InvalidStrobeVersion })?;

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
