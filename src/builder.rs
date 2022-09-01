/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    channel::{Channel, ChannelDuplex, ChannelRole},
    error::{BuilderError, Error},
    handshake::HandshakeState,
    key::{KeyAgreement, KeyGenerator, KeyType},
    nonce::NonceGenerator,
    params::Params,
    prologue::Prologue,
    session::Session,
    tag::{Tag, TaggedData},
    transport::TransportOrder,
};
use core::marker::PhantomData;
use strobe_rs::{SecParam, Strobe};

/// Generates a [`HandshakeState`] and also validates that all of the
/// prerequisites for the given parameters are satisfied.
pub struct Builder<K, PG, NG, T, N, P, S, SS>
where
    K: KeyType + KeyGenerator<T, P, S> + KeyAgreement<T, P, S, SS>,
    PG: Prologue,
    NG: NonceGenerator<T, N>,
    T: Tag,
    N: TaggedData<T>,
    P: TaggedData<T>,
    S: TaggedData<T>,
    SS: TaggedData<T>,
{
    /// Disco params
    params: Params<K, T, P, S, SS>,
    /// Protocol prologue
    prologue: PG,
    /// Nonce generator
    nonce_generator: NG,
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
    pre_shared_key: SS,
    /// Message delivery order
    msg_order: TransportOrder,
    // phantom marker
    _t: PhantomData<T>,
    _n: PhantomData<N>,
}

impl<K, PG, NG, T, N, P, S, SS> Builder<K, PG, NG, T, N, P, S, SS>
where
    K: KeyType + KeyGenerator<T, P, S> + KeyAgreement<T, P, S, SS>,
    PG: Prologue,
    NG: NonceGenerator<T, N>,
    T: Tag,
    N: TaggedData<T>,
    P: TaggedData<T>,
    S: TaggedData<T>,
    SS: TaggedData<T>,
{
    /// Construct a new builder from DiscoParams
    pub fn new(params: &Params<K, T, P, S, SS>, nonce_generator: &NG) -> Self {
        Builder {
            params: params.clone(),
            prologue: PG::default(),
            nonce_generator: nonce_generator.clone(),
            local_static_secret_key: S::default(),
            local_static_public_key: P::default(),
            local_ephemeral_secret_key: S::default(),
            local_ephemeral_public_key: P::default(),
            remote_static_public_key: P::default(),
            pre_shared_key: SS::default(),
            msg_order: TransportOrder::InOrder,
            _t: PhantomData,
            _n: PhantomData,
        }
    }

    /// Add prologue byte sequence that both parties want to confirm is identical
    pub fn with_prologue(mut self, data: &PG) -> Self {
        self.prologue = data.clone();
        self
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
    pub fn pre_shared_key(mut self, key: &SS) -> Self {
        self.pre_shared_key = key.clone();
        self
    }

    /// Create strobe states that can handle out-of-order messages
    pub fn msg_order(mut self, order: &TransportOrder) -> Self {
        self.msg_order = *order;
        self
    }

    /// Build an initiator disco session
    pub fn build_initiator(self) -> Result<Session<K, PG, NG, T, N, P, S, SS>, Error> {
        self.build(&ChannelRole::Initiator)
    }

    /// Build a responder disco session
    pub fn build_responder(self) -> Result<Session<K, PG, NG, T, N, P, S, SS>, Error> {
        self.build(&ChannelRole::Responder)
    }

    /// Construct the disco session
    pub fn build(self, role: &ChannelRole) -> Result<Session<K, PG, NG, T, N, P, S, SS>, Error> {
        if self.local_static_secret_key.get_tag().get_data_length() == 0
            && self.params.handshake.needs_local_static_key(role)
        {
            return Err(Error::Builder(BuilderError::MissingLocalSecretKey));
        }

        if self.remote_static_public_key.get_tag().get_data_length() == 0
            && self.params.handshake.needs_remote_static_key(role)
        {
            return Err(Error::Builder(BuilderError::MissingRemotePublicKey));
        }

        if self.pre_shared_key.get_tag().get_data_length() == 0
            && self.params.handshake.needs_pre_shared_key(role)
        {
            return Err(Error::Builder(BuilderError::MissingPreSharedKey));
        }

        // §5.3.1 InitializeSymmetric(protocol_name)
        let strobe = Strobe::new(format!("{}", self.params).as_bytes(), SecParam::B256);

        // create our handshake state
        let hs = HandshakeState::new(self.params.handshake, role, &ChannelDuplex::Full);

        // create our channel
        let channel = Channel::new(&strobe, &hs, &self.nonce_generator, self.msg_order, false);

        Ok(Session::Handshake {
            params: self.params,
            channel,
            prologue: self.prologue,
            sp: self.local_static_public_key,
            ss: self.local_static_secret_key,
            ep: self.local_ephemeral_public_key,
            es: self.local_ephemeral_secret_key,
            rs: self.remote_static_public_key,
            re: P::default(),
            psk: self.pre_shared_key,
            prf: [0u8; 32],
        })
    }
}
