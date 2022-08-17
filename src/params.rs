/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    error::{Error, ParamError},
    handshake::Handshake,
    key::{KeyAgreement, KeyGenerator, KeyType},
    tag::{Tag, TaggedData},
};
use core::{
    fmt::{Display, Error as FmtError, Formatter},
    marker::PhantomData,
    str::FromStr,
};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use strobe_rs::STROBE_VERSION;

/// Encapsulates the handshake parameters
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct Params<K, T, N, P, S, SS>
where
    K: KeyType + KeyGenerator<T, P, S> + KeyAgreement<T, P, S, SS>,
    T: Tag,
    N: TaggedData<T>,
    P: TaggedData<T>,
    S: TaggedData<T>,
    SS: TaggedData<T>,
{
    /// The protocol name
    pub protocol: Protocol,
    /// The handshake pattern
    pub handshake: Handshake,
    /// The key type
    pub key_type: K,
    /// The strobe protocol version
    pub version: StrobeVersion,
    // phantom markers
    _t: PhantomData<T>,
    _n: PhantomData<N>,
    _p: PhantomData<P>,
    _s: PhantomData<S>,
    _ss: PhantomData<SS>,
}

impl<K, T, N, P, S, SS> FromStr for Params<K, T, N, P, S, SS>
where
    K: KeyType + KeyGenerator<T, P, S> + KeyAgreement<T, P, S, SS>,
    T: Tag,
    N: TaggedData<T>,
    P: TaggedData<T>,
    S: TaggedData<T>,
    SS: TaggedData<T>,
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
            _t: PhantomData,
            _n: PhantomData,
            _p: PhantomData,
            _s: PhantomData,
            _ss: PhantomData,
        })
    }
}

impl<K, T, N, P, S, SS> Display for Params<K, T, N, P, S, SS>
where
    K: KeyType + KeyGenerator<T, P, S> + KeyAgreement<T, P, S, SS>,
    T: Tag,
    N: TaggedData<T>,
    P: TaggedData<T>,
    S: TaggedData<T>,
    SS: TaggedData<T>,
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
#[derive(PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
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

/// The strobe version we support for now
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
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
