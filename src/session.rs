/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    channel::{Channel, ChannelDuplex},
    error::{ParamError, ProtocolError},
    handshake::{HandshakeData, HandshakeOp, HandshakeState},
    inner::get_rng,
    key::{KeyAgreement, KeyGenerator, KeyType},
    nonce::NonceGenerator,
    params::Params,
    prologue::Prologue,
    tag::{Tag, TaggedData},
    transport::{TransportData, TransportOp, TransportState},
    Result,
};
use serde::{Deserialize, Serialize};

use std::println as debug;

/// The maximum size of a single message in bytes (64KB)
pub const MSG_MAX_LEN: usize = u16::max_value() as usize;

/// The fixed size of MAC values in the protocol
pub const MSG_MAC_LEN: usize = 16;

/// The session state for a Disco connection. This ultimately wraps a Strobe
/// state and handles the different Noise protocol messages by updating the
/// Strobe state accordingly. The handshake script is determined by the
/// handshake name (e.g. XX, XK1, KK1) and the elliptic curve protocol is
/// determined by the protocol name (e.g. 25519 for Curve25519, etc).
#[derive(Clone, Serialize, Deserialize)]
pub enum Session<K, PG, NG, T, N, P, S, SS>
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
    /// Sending/receiving the first message transitions to this state and we
    /// stay in this state until the handshake script is complete
    Handshake {
        /// Disco parameters
        params: Params<K, T, P, S, SS>,
        /// Channel state
        channel: Channel<T, HandshakeState, N, NG>,
        /// Optional prologue data
        prologue: PG,
        /// Optional local static public key
        sp: P,
        /// Optional local static secret key
        ss: S,
        /// Local ephemeral public key
        ep: P,
        /// Local ephemeral secret key
        es: S,
        /// Optional remote static public key
        rs: P,
        /// Remote ephemeral public key
        re: P,
        /// Optional pre-shared key
        psk: SS,
        /// The channel state
        prf: [u8; 32],
    },

    /// Completing the handshake script transitions to this state which has
    /// one half-duplex strobe for each direction
    Transport {
        /// Disco parameters
        params: Params<K, T, P, S, SS>,
        /// Outbound channel
        outbound: Channel<T, TransportState, N, NG>,
        /// Inbound channel
        inbound: Channel<T, TransportState, N, NG>,
        /// Optional remote static public key
        rs: P,
        /// Remote ephemeral public key
        re: P,
    },
}

impl<K, PG, NG, T, N, P, S, SS> Session<K, PG, NG, T, N, P, S, SS>
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
    /// Send data, writing the result the msg buffer
    pub fn send(&mut self, data: &[u8], msg: &mut [u8]) -> Result<usize> {
        // the payload for the message is undefined data so we create a tag so that it is properly
        // framed and can be parsed with recv
        let mut tt = T::default();
        tt.set_data_length(data.len());

        // send the tagged data
        self.send_tagged(&tt, data, msg)
    }

    /// Send tagged data, writing the result to the msg buffer
    pub fn send_tagged(&mut self, tag: &T, data: &[u8], msg: &mut [u8]) -> Result<usize> {
        // check some bounds first
        if data.len() > MSG_MAX_LEN || msg.len() < data.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // this index value tracks where the next write should start in the msg so that multiple
        // channel commands can be processed and data written to the message in a single call to
        // this function
        let mut idx = 0;

        match self {
            Session::Handshake {
                ref mut params,
                channel,
                prologue,
                sp,
                ss,
                ref mut ep,
                ref mut es,
                rs,
                re,
                psk,
                ref mut prf,
                ..
            } => {
                use HandshakeData::*;
                use HandshakeOp::*;

                // loop, processing handshake patterns until we hit a Stop or a
                // Split command
                loop {
                    if let Some(op) = channel.next() {
                        match op {
                            // generate a new ephemeral key pair
                            GenKey => {
                                let kt = params.key_type.clone();
                                (*ep, *es) = params.key_type.generate(&kt, get_rng());
                            }

                            // get the channel binding data see §7.1 of the Disco specification
                            GetHandshakeHash => {
                                channel.prf(prf);
                            }

                            // do an AD that mixes the specified data into the strobe state. do not
                            // mix in any data that the other side does not have, does not receive,
                            // or cannot calculate. that will force the strobe states out of sync
                            // and break the session.
                            MixHash(d) => {
                                let mut prologue_tag = T::default();
                                prologue_tag.set_data_length(prologue.as_ref().len());

                                // get the tag reference
                                let tag = match d {
                                    Epub => ep.get_tag(),
                                    Psk => psk.get_tag(),
                                    Prologue => &prologue_tag,
                                    Re => re.get_tag(),
                                    Rs => rs.get_tag(),
                                    Spub => sp.get_tag(),
                                    Esec | Ssec | Payload => {
                                        return Err(ProtocolError::InvalidHandshakeOp.into());
                                    }
                                };

                                // get the buffer reference
                                let data = match d {
                                    Epub => ep.as_ref(),
                                    Psk => psk.as_ref(),
                                    Prologue => prologue.as_ref(),
                                    Re => re.as_ref(),
                                    Rs => rs.as_ref(),
                                    Spub => sp.as_ref(),
                                    Esec | Ssec | Payload => {
                                        return Err(ProtocolError::InvalidHandshakeOp.into());
                                    }
                                };

                                // mix the tag and data into the strobe state
                                channel.send(
                                    false, // don't send the tag, just meta_AD it into the state
                                    false, // don't send the data, just AD it into the state
                                    true,  // irrelevant...
                                    tag, data, msg,
                                )?;
                            }

                            // do a KEY operation and mark the channel as keyed, this op is only
                            // used in psk variants of handshakes
                            MixKey(d) => {
                                channel.key(match d {
                                    Psk => psk.as_ref(),
                                    _ => return Err(ProtocolError::InvalidHandshakeOp.into()),
                                });
                            }

                            // do a key agreement using the specified keys and rekey with it
                            MixKeyDh(l, r) => {
                                // get the local key
                                let local: &S = match l {
                                    Esec => &*es,
                                    Ssec => ss,
                                    _ => return Err(ProtocolError::InvalidKey.into()),
                                };

                                // get the remote key
                                let remote: &P = match r {
                                    Re => &*re,
                                    Rs => rs,
                                    _ => return Err(ProtocolError::InvalidKey.into()),
                                };

                                // calculate the shared secret
                                let kt = params.key_type.clone();
                                let shared_secret = params
                                    .key_type
                                    .get_shared_secret(&kt, local, remote)
                                    .map_err(|_| ProtocolError::SharedSecretCalculationFailed)?;

                                // re-key the session with the result of a shared secret
                                channel.key(shared_secret.as_ref());
                            }

                            // send data either encrypted or in plaintext...
                            EncryptAndHash(d) => {
                                // get the tag reference
                                let tag = match d {
                                    Epub => ep.get_tag(),
                                    Payload => tag,
                                    Prologue => {
                                        return Err(ProtocolError::SendingPrologue.into());
                                    }
                                    Psk => {
                                        return Err(ProtocolError::SendingPsk.into());
                                    }
                                    Re => re.get_tag(),
                                    Rs => rs.get_tag(),
                                    Spub => sp.get_tag(),
                                    Esec | Ssec => {
                                        return Err(ProtocolError::SendingSecretKey.into());
                                    }
                                };

                                // get the buffer reference
                                let data = match d {
                                    Epub => ep.as_ref(),
                                    Payload => data,
                                    Prologue => {
                                        return Err(ProtocolError::SendingPrologue.into());
                                    }
                                    Psk => {
                                        return Err(ProtocolError::SendingPsk.into());
                                    }
                                    Re => re.as_ref(),
                                    Rs => rs.as_ref(),
                                    Spub => sp.as_ref(),
                                    Esec | Ssec => {
                                        return Err(ProtocolError::SendingSecretKey.into());
                                    }
                                };

                                // send the data
                                idx += channel.send(
                                    true,  // send the tag
                                    true,  // send the data
                                    false, // don't force it sent in the clear
                                    tag,
                                    data,
                                    &mut msg[idx..],
                                )?;

                                if d == Payload {
                                    debug!("SENT {} BYTES OF PAYLOAD DATA", data.len());
                                }
                            }

                            // we're sending a message, any DecryptAndHash commands are invalid
                            DecryptAndHash(_) => {
                                return Err(ProtocolError::InvalidHandshakeOp.into());
                            }

                            // start a message by setting up the proper channel states
                            Start => {
                                channel.start();
                            }

                            // our turn is done, so stop here and return how many bytes we wrote to
                            // the output buffer
                            Stop => {
                                channel.stop();
                                return Ok(idx);
                            }

                            // the handshake process has completed and we need to transition to the
                            // transport phase of this link
                            Split => {
                                // split the channel into two half-duplex channels, one for inbound
                                // and the other for outbound
                                let (outbound, inbound) = channel.split(prf);

                                // change to the Transport phase
                                *self = Session::Transport {
                                    params: params.clone(),
                                    outbound,
                                    inbound,
                                    rs: rs.clone(),
                                    re: re.clone(),
                                };

                                debug!("SPLIT AFTER HANDSHAKE");
                                return Ok(idx);
                            }
                        }
                    } else {
                        return Err(ProtocolError::InvalidState.into());
                    }
                }
            }

            Session::Transport { outbound, .. } => {
                use TransportData::*;
                use TransportOp::*;

                // loop, processing transport patterns until we hit a Stop
                loop {
                    if let Some(op) = outbound.next() {
                        match op {
                            // start a new message
                            Start => {
                                outbound.start();
                            }

                            // stop the message
                            Stop => {
                                outbound.stop();
                                return Ok(idx);
                            }

                            // send a nonce
                            SendNonce => {
                                let n = outbound.nonce();
                                let tag = n.get_tag();
                                let data = n.as_ref();
                                idx += outbound.send(
                                    false, // don't send the tag, just mix it in
                                    true,  // do send the data
                                    true,  // force it to be in the clear
                                    tag, data, msg,
                                )?;
                            }

                            // receiving a nonce is an error when sending
                            RecvNonce => {
                                return Err(ProtocolError::InvalidTransportOp.into());
                            }

                            // encrypt and hash the outbound data
                            EncryptAndHash(d) => {
                                // get the tag reference
                                let tag = match d {
                                    Payload => tag,
                                };

                                // get the buffer reference
                                let data = match d {
                                    Payload => data,
                                };

                                // send the data
                                idx += outbound.send(
                                    true,  // send the tag
                                    true,  // send the data
                                    false, // don't force it to be sent in the clear
                                    tag,
                                    data,
                                    &mut msg[idx..],
                                )?;

                                debug!("SENT {} BYTES OF PAYLOAD DATA", tag.get_data_length());
                            }

                            // decrypt and hash the inbound data
                            DecryptAndHash(_) => {
                                return Err(ProtocolError::InvalidTransportOp.into());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Recv a message, disregarding the type tag associated with the payload. The first value in
    /// the return tuple is the number of bytes processed in the msg buffer. The second value in
    /// the return tuple is the number of bytes decrypted and stored in the data buffer.
    pub fn recv(&mut self, msg: &[u8], data: &mut [u8]) -> Result<(usize, usize)> {
        // the caller of this function isn't interested in the type tag so we create a dummy one
        // here to receive the information. we do pass back the data length from the tag as the
        // second value in the tuple.
        let mut tag = T::default();

        // recv the data and get the tag information
        let len = self.recv_tagged(msg, &mut tag, data)?;

        // return the amount of data processed from msg and how much data was received
        Ok((len, tag.get_data_length()))
    }

    /// Recv tagged data from the msg buffer.
    pub fn recv_tagged(&mut self, msg: &[u8], tag: &mut T, data: &mut [u8]) -> Result<usize> {
        // check some limits first
        if msg.len() > MSG_MAX_LEN {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // this index value tracks where the next write should start in the data so that multiple
        // channel commands can be processed and data written to the data buffer in a single call
        // to this function
        let mut idx = 0;

        match self {
            Session::Handshake {
                ref mut params,
                channel,
                ref mut prologue,
                sp,
                ss,
                ref mut ep,
                ref mut es,
                ref mut rs,
                ref mut re,
                psk,
                ref mut prf,
                ..
            } => {
                use HandshakeData::*;
                use HandshakeOp::*;

                // loop, processing handshake patterns until we hit a Stop or a
                // Split command
                loop {
                    if let Some(op) = channel.next() {
                        match op {
                            // generate a new ephemeral key pair
                            GenKey => {
                                let kt = params.key_type.clone();
                                (*ep, *es) = params.key_type.generate(&kt, get_rng());
                            }

                            // get the channel binding data see §7.1 of the Disco specification
                            GetHandshakeHash => {
                                channel.prf(prf);
                            }

                            // do an AD that mixes the specified data into the strobe state. do not
                            // mix in any data that the other side does not have, does not receive,
                            // or cannot calculate. that will force the strobe states out of sync
                            // and break the session.
                            MixHash(d) => {
                                let mut prologue_tag = T::default();
                                prologue_tag.set_data_length(prologue.as_ref().len());

                                // get the tag reference
                                let mut tag = match d {
                                    Epub => ep.get_tag(),
                                    Psk => psk.get_tag(),
                                    Prologue => &mut prologue_tag,
                                    Re => re.get_tag(),
                                    Rs => rs.get_tag(),
                                    Spub => sp.get_tag(),
                                    Esec | Ssec | Payload => {
                                        return Err(ProtocolError::InvalidHandshakeOp.into());
                                    }
                                }
                                .clone();

                                // get the buffer reference
                                let data = match d {
                                    Epub => ep.as_mut(),
                                    Psk => psk.as_mut(),
                                    Prologue => prologue.as_mut(),
                                    Re => re.as_mut(),
                                    Rs => rs.as_mut(),
                                    Spub => sp.as_mut(),
                                    Esec | Ssec | Payload => {
                                        return Err(ProtocolError::InvalidHandshakeOp.into());
                                    }
                                };

                                // mix the tag and data into the strobe state
                                channel.recv(
                                    false, // don't recv the tag, just meta_AD it into the state
                                    false, // don't recv the data, just AD it into the state
                                    true,  // irrelevant...
                                    msg, &mut tag, data,
                                )?;
                            }

                            // do a KEY operation and mark the channel as keyed, this op is only
                            // used in psk variants of handshakes
                            MixKey(d) => {
                                channel.key(match d {
                                    Psk => psk.as_ref(),
                                    _ => return Err(ProtocolError::InvalidHandshakeOp.into()),
                                });
                            }

                            // do a key agreement using the specified keys and rekey with it
                            MixKeyDh(l, r) => {
                                // get the local key
                                let local: &S = match l {
                                    Esec => &*es,
                                    Ssec => ss,
                                    _ => return Err(ProtocolError::InvalidKey.into()),
                                };

                                // get the remote key
                                let remote: &P = match r {
                                    Re => &*re,
                                    Rs => rs,
                                    _ => return Err(ProtocolError::InvalidKey.into()),
                                };

                                // calculate the shared secret
                                let kt = params.key_type.clone();
                                let shared_secret = params
                                    .key_type
                                    .get_shared_secret(&kt, local, remote)
                                    .map_err(|_| ProtocolError::SharedSecretCalculationFailed)?;

                                // re-key the session with the result of a shared secret
                                channel.key(shared_secret.as_ref());
                            }

                            // we're receiving data so any EncryptAndHash commands are invalid
                            EncryptAndHash(_) => {
                                return Err(ProtocolError::InvalidState.into());
                            }

                            // recv data either encrypted or in plaintext...
                            DecryptAndHash(d) => {
                                // get the tag reference
                                let mut tag = match d {
                                    Epub => ep.get_tag(),
                                    Payload => tag,
                                    Prologue => {
                                        return Err(ProtocolError::SendingPrologue.into());
                                    }
                                    Psk => {
                                        return Err(ProtocolError::SendingPsk.into());
                                    }
                                    Re => re.get_tag(),
                                    Rs => rs.get_tag(),
                                    Spub => sp.get_tag(),
                                    Esec | Ssec => {
                                        return Err(ProtocolError::SendingSecretKey.into());
                                    }
                                }
                                .clone();

                                // get the mutable buffer reference
                                let data = match d {
                                    Epub => ep.as_mut(),
                                    Payload => &mut data[idx..],
                                    Prologue => {
                                        return Err(ProtocolError::ReceivingPrologue.into());
                                    }
                                    Psk => {
                                        return Err(ProtocolError::ReceivingPsk.into());
                                    }
                                    Re => re.as_mut(),
                                    Rs => rs.as_mut(),
                                    Spub => sp.as_mut(),
                                    Esec | Ssec => {
                                        return Err(ProtocolError::ReceivingSecretKey.into());
                                    }
                                };

                                // receive the data
                                idx += channel.recv(
                                    true,  // receive the tag
                                    true,  // receive the data
                                    false, // don't force receive it in the clear
                                    &msg[idx..],
                                    &mut tag,
                                    data,
                                )?;

                                if d == Payload {
                                    debug!(
                                        "RECEIVED {} BYTES OF PAYLOAD DATA",
                                        tag.get_data_length()
                                    );
                                }
                            }

                            // start a message receive
                            Start => {
                                channel.start();
                            }

                            // our turn is done so stop and return the number of bytes read
                            Stop => {
                                channel.stop();
                                return Ok(idx);
                            }

                            // the handshake process has completed, switch to transport state
                            Split => {
                                // split the channel into two half-duplex channels, one for inbound
                                // and the other for outbound
                                let (outbound, inbound) = channel.split(prf);

                                // change to the Transport phase
                                *self = Session::Transport {
                                    params: params.clone(),
                                    outbound,
                                    inbound,
                                    rs: rs.clone(),
                                    re: re.clone(),
                                };
                                debug!("SPLIT AFTER HANDSHAKE");
                                return Ok(idx);
                            }
                        }
                    } else {
                        return Err(ProtocolError::InvalidState.into());
                    }
                }
            }

            Session::Transport { inbound, .. } => {
                use TransportOp::*;

                // loop, processing transport patterns until we hit a Stop
                loop {
                    if let Some(op) = inbound.next() {
                        match op {
                            // start a new message
                            Start => {
                                inbound.start();
                            }

                            // stop the message
                            Stop => {
                                inbound.stop();
                                return Ok(idx);
                            }

                            // sending a nonce is an error when receiving
                            SendNonce => {
                                return Err(ProtocolError::InvalidTransportOp.into());
                            }

                            // receive a nonce and check it
                            RecvNonce => {
                                let mut n = inbound.default_nonce();
                                let mut tag = n.get_tag().clone();
                                idx += inbound.recv(
                                    false, // don't recv the tag, just mix it in
                                    true,  // do recv the data
                                    true,  // force it to be in the clear
                                    msg,
                                    &mut tag,
                                    n.as_mut(),
                                )?;

                                // set the tag
                                *n.get_tag_mut() = tag;

                                // check that the nonce is valid
                                if !inbound.check_nonce(&n) {
                                    return Err(ProtocolError::InvalidNonce.into());
                                }
                            }

                            // encrypt and hash the outbound data is an error
                            EncryptAndHash(_) => {
                                return Err(ProtocolError::InvalidState.into());
                            }

                            // decrypt and hash the inbound data
                            DecryptAndHash(_) => {
                                idx += inbound.recv(
                                    true,  // recv the tag
                                    true,  // recv the data
                                    false, // don't force in the clear
                                    &msg[idx..],
                                    tag,
                                    data,
                                )?;

                                debug!("RECEIVED {} BYTES OF PAYLOAD DATA", tag.get_data_length());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get the remote ephemeral public key if there is one
    pub fn get_remote_ephemeral(&self) -> Result<P> {
        Ok(match self {
            Session::Handshake { re, .. } | Session::Transport { re, .. } => re.clone(),
        })
    }

    /// Get the remote static public key if there is one
    pub fn get_remote_static(&self) -> Result<P> {
        Ok(match self {
            Session::Handshake { rs, .. } | Session::Transport { rs, .. } => rs.clone(),
        })
    }

    /// Get the channel state for channel binding. See §11.2 of the Noise Protocol spec
    pub fn get_channel_state(&mut self, channel: ChannelDuplex, data: &mut [u8]) -> Result<()> {
        match channel {
            ChannelDuplex::InboundHalf => {
                if let Session::Transport { inbound, .. } = self {
                    inbound.prf(data);
                    Ok(())
                } else {
                    Err(ParamError::InvalidChannelDuplex.into())
                }
            }
            ChannelDuplex::OutboundHalf => {
                if let Session::Transport { outbound, .. } = self {
                    outbound.prf(data);
                    Ok(())
                } else {
                    Err(ParamError::InvalidChannelDuplex.into())
                }
            }
            ChannelDuplex::Full => {
                if let Session::Handshake { channel, .. } = self {
                    channel.prf(data);
                    Ok(())
                } else {
                    Err(ParamError::InvalidChannelDuplex.into())
                }
            }
        }
    }

    /// True if in the handshake state
    pub fn is_handshaking(&self) -> bool {
        match self {
            Session::Handshake { .. } => true,
            _ => false,
        }
    }

    /// True if in the transport state
    pub fn is_transport(&self) -> bool {
        match self {
            Session::Transport { .. } => true,
            _ => false,
        }
    }

    /// True if data is being sent/received encrypted
    pub fn is_keyed(&self) -> bool {
        match self {
            Session::Transport {
                inbound, outbound, ..
            } => inbound.is_keyed() && outbound.is_keyed(),
            Session::Handshake { channel, .. } => channel.is_keyed(),
        }
    }
}
