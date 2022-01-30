use crate::{
    error::{Error, BuilderError},
    key::{KeyType, KeyGenerator, KeyAgreement, TaggedData},
    params::Params,
    session::Session,
};
use strobe_rs::{Strobe, SecParam};

/// Generates a [`HandshakeState`] and also validates that all of the
/// prerequisites for the given parameters are satisfied.
pub struct Builder<'a, T, P, S>
where
    T: KeyType + KeyGenerator<'a, PublicKey = P, SecretKey = S> + KeyAgreement<'a> + Clone,
    P: TaggedData<'a> + Clone + Default,
    S: TaggedData<'a> + Clone + Default,
{
    /// Disco params
    params: Params<'a, T>,
    /// Local static secret key
    local_static_secret_key: S,
    /// Local static public key
    local_static_public_key: P,
    /// Local ephemeral secret key
    local_ephemeral_secret_key: S,
    /// Local ephemeral public key
    local_ephemeral_public_key: P,
    /// Remote ephemeral public key
    remote_static_public_key: P,
    /// Pre-shared key
    pre_shared_key: S,
    /// Out of order delivery 
    out_of_order: bool,
}

impl<'a, T, P, S> Builder<'a, T, P, S>
where
    T: KeyType + KeyGenerator<'a, PublicKey = P, SecretKey = S> + KeyAgreement<'a> + Clone,
    P: TaggedData<'a> + Clone + Default,
    S: TaggedData<'a> + Clone + Default,
{

    /// Construct a new builder from DiscoParams
    pub fn new(params: &Params<'a, T>) -> Self {
        Builder {
            params: params.clone(),
            local_static_secret_key: S::default(),
            local_static_public_key: P::default(),
            local_ephemeral_secret_key: S::default(),
            local_ephemeral_public_key: P::default(),
            remote_static_public_key: P::default(),
            pre_shared_key: S::default(),
            out_of_order: false,
        }
    }

    /// Add a local static secret key
    pub fn local_static_secret_key(mut self, key: &S) -> Self {
        self.local_static_secret_key = key.clone();
        self
    }

    /// Add a local static public key
    pub fn local_static_public_key(mut self, key: &P) -> Self {
        self.local_static_public_key = key.clone();
        self
    }

    /// Add a local ephemeral secret key
    pub fn local_ephemeral_secret_key(mut self, key: &S) -> Self {
        self.local_ephemeral_secret_key = key.clone();
        self
    }

    /// Add a local ephemeral public key
    pub fn local_ephemeral_public_key(mut self, key: &P) -> Self {
        self.local_ephemeral_public_key = key.clone();
        self
    }

    /// Add a remote static public key
    pub fn remote_static_public_key(mut self, key: &P) -> Self {
        self.remote_static_public_key = key.clone();
        self
    }

    /// Add a pre-shared key
    pub fn pre_shared_key(mut self, key: &S) -> Self {
        self.pre_shared_key = key.clone();
        self
    }

    /// Create strobe states that can handle out-of-order messages
    pub fn out_of_order(mut self, ooo: bool) -> Self {
        self.out_of_order = ooo;
        self
    }

    /// Build an initiator disco session
    pub fn build_initiator(self) -> Result<Session<'a, T, P, S>, Error> {
        self.build(true)
    }

    /// Build a responder disco session
    pub fn build_responder(self) -> Result<Session<'a, T, P, S>, Error> {
        self.build(false)
    }

    /// Construct the disco session
    pub fn build(self, initiator: bool) -> Result<Session<'a, T, P, S>, Error> {
        if self.local_static_secret_key.is_zero() && self.params.handshake.needs_local_secret_key(initiator) {
            return Err(Error::Builder(BuilderError::MissingLocalSecretKey));
        }

        if self.remote_static_public_key.is_zero() && self.params.handshake.needs_remote_public_key(initiator) {
            return Err(Error::Builder(BuilderError::MissingRemotePublicKey));
        }

        if self.pre_shared_key.is_zero() && self.params.handshake.needs_pre_shared_key(initiator) {
            return Err(Error::Builder(BuilderError::MissingPreSharedKey));
        }

        Ok(Session::Initialized {
            strobe: Strobe::new(format!("{}", self.params).as_bytes(), SecParam::B256),
            params: self.params,
            initiator: initiator,
            out_of_order: self.out_of_order,
            sp: self.local_static_public_key,
            ss: self.local_static_secret_key,
            ep: self.local_ephemeral_public_key,
            es: self.local_ephemeral_secret_key,
            rs: self.remote_static_public_key,
            psk: self.pre_shared_key,
        })
    }
}
