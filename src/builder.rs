/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    error::{BuilderError, Error},
    handshake::HandshakeState,
    key::{KeyAgreement, KeyGenerator, KeyType},
    nonce::NonceGenerator,
    params::Params,
    prologue::Prologue,
    session::Session,
    tag::{Tag, TaggedData},
};
use core::marker::PhantomData;
use strobe_rs::{SecParam, Strobe};

/// Generates a [`HandshakeState`] and also validates that all of the
/// prerequisites for the given parameters are satisfied.
pub struct Builder<K, NG, PG, T, N, P, S, SS>
where
    K: KeyType + KeyGenerator<T, P, S> + KeyAgreement<T, P, S, SS>,
    NG: NonceGenerator<T, N>,
    PG: Prologue,
    T: Tag,
    N: TaggedData<T>,
    P: TaggedData<T>,
    S: TaggedData<T>,
    SS: TaggedData<T>,
{
    /// Disco params
    params: Params<K, T, N, P, S, SS>,
    /// Nonce generator
    nonces: NG,
    /// Protocol prologue
    prologue: PG,
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
    /// Out of order delivery
    out_of_order: bool,
    /// Re-key threshold
    rekey_in: u64,
    // phantom marker
    _t: PhantomData<T>,
}

impl<K, NG, PG, T, N, P, S, SS> Builder<K, NG, PG, T, N, P, S, SS>
where
    K: KeyType + KeyGenerator<T, P, S> + KeyAgreement<T, P, S, SS>,
    NG: NonceGenerator<T, N>,
    PG: Prologue,
    T: Tag,
    N: TaggedData<T>,
    P: TaggedData<T>,
    S: TaggedData<T>,
    SS: TaggedData<T>,
{
    /// Construct a new builder from DiscoParams
    pub fn new(params: &Params<K, T, N, P, S, SS>, nonces: &NG) -> Self {
        Builder {
            params: params.clone(),
            nonces: nonces.clone(),
            prologue: PG::default(),
            local_static_secret_key: S::default(),
            local_static_public_key: P::default(),
            local_ephemeral_secret_key: S::default(),
            local_ephemeral_public_key: P::default(),
            remote_static_public_key: P::default(),
            pre_shared_key: SS::default(),
            out_of_order: false,
            rekey_in: u64::max_value() - 1,
            _t: PhantomData,
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
    pub fn out_of_order(mut self, ooo: bool) -> Self {
        self.out_of_order = ooo;
        self
    }

    /// Set the number of messages to send before re-key occurs
    pub fn rekey_in(mut self, num: u64) -> Self {
        self.rekey_in = num;
        self
    }

    /// Build an initiator disco session
    pub fn build_initiator(self) -> Result<Session<K, NG, PG, T, N, P, S, SS>, Error> {
        self.build(true)
    }

    /// Build a responder disco session
    pub fn build_responder(self) -> Result<Session<K, NG, PG, T, N, P, S, SS>, Error> {
        self.build(false)
    }

    /// Construct the disco session
    pub fn build(self, initiator: bool) -> Result<Session<K, NG, PG, T, N, P, S, SS>, Error> {
        if self.local_static_secret_key.get_tag().get_data_length() == 0
            && self.params.handshake.needs_local_static_key(initiator)
        {
            return Err(Error::Builder(BuilderError::MissingLocalSecretKey));
        }

        if self.remote_static_public_key.get_tag().get_data_length() == 0
            && self.params.handshake.needs_remote_static_key(initiator)
        {
            return Err(Error::Builder(BuilderError::MissingRemotePublicKey));
        }

        if self.pre_shared_key.get_tag().get_data_length() == 0
            && self.params.handshake.needs_pre_shared_key(initiator)
        {
            return Err(Error::Builder(BuilderError::MissingPreSharedKey));
        }

        // §5.3.1 InitializeSymmetric(protocol_name)
        let strobe = Strobe::new(format!("{}", self.params).as_bytes(), SecParam::B256);

        // create our handshake state
        let hs = HandshakeState::new(self.params.handshake, initiator);

        Ok(Session::Handshake {
            strobe,
            params: self.params,
            nonces: self.nonces,
            handshake_state: hs,
            initiator,
            out_of_order: self.out_of_order,
            rekey_in: self.rekey_in,
            msgs_since_rekey: 0,
            msgs_total: 0,
            is_keyed: false,
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
