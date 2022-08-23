/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    error::ProtocolError,
    handshake::{HandshakeData, HandshakeOp, HandshakeState},
    inner::get_rng,
    key::{KeyAgreement, KeyGenerator, KeyType},
    nonce::NonceGenerator,
    params::Params,
    prologue::Prologue,
    tag::{Tag, TaggedData},
    transport::{Transport, TransportData, TransportOp, TransportState},
    Result,
};
use core::marker::PhantomData;
use log::debug;
use serde::{Deserialize, Serialize};
use strobe_rs::Strobe;

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
pub enum Session<K, NG, PG, T, N, P, S, SS>
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
    /// Sending/receiving the first message transitions to this state and we
    /// stay in this state until the handshake script is complete
    Handshake {
        /// Strobe state
        strobe: Strobe,
        /// Disco parameters
        params: Params<K, T, P, S, SS>,
        /// Nonces generator and tracker
        nonces: NG,
        /// Handshake state
        handshake_state: HandshakeState,
        /// True if initiator, false if responder
        initiator: bool,
        /// True if transport state will handle out-of-order messages
        out_of_order: bool,
        /// Number of messages to send before re-key
        rekey_in: u64,
        /// Messages since a rekey
        msgs_since_rekey: u64,
        /// Total number of messages sent between endpoints
        msgs_total: u64,
        /// True if a keying operation has been completed
        is_keyed: bool,
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
        /// Hash of the handshake state for channel binding
        prf: [u8; 32],
        /// phantom data marker
        _n: PhantomData<N>,
    },

    /// Completing the handshake script transitions to this state which has
    /// one half-duplex strobe for each direction
    Transport {
        /// Disco parameters
        params: Params<K, T, P, S, SS>,
        /// The inbound strobe state
        in_strobe: Strobe,
        /// State for inbound channel
        in_transport_state: TransportState,
        /// The inbound nonce generator and checker
        in_nonces: NG,
        /// The inbound channel state
        in_prf: [u8; 32],
        /// The number of messages received since inbound re-key
        in_msgs_since_rekey: u64,
        /// The outbound strobe state
        out_strobe: Strobe,
        /// State for outbound channel
        out_transport_state: TransportState,
        /// The outbound nonce generator and checker
        out_nonces: NG,
        /// The outbound channel state
        out_prf: [u8; 32],
        /// The number of messages sent since outbound re-key
        out_msgs_since_rekey: u64,
        /// Re-key the session every N messages
        rekey_in: u64,
        /// True if a keying operation was completed during the handshake
        is_keyed: bool,
        /// True if transport state will handle out-of-order messages
        out_of_order: bool,
        /// Total number of messages sent between endpoints
        msgs_total: u64,
        /// Optional remote static public key
        rs: P,
        /// Remote ephemeral public key
        re: P,
    },
}

impl<K, NG, PG, T, N, P, S, SS> Session<K, NG, PG, T, N, P, S, SS>
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
    fn strobe_tag_to_message(
        strobe: &mut Strobe,
        is_keyed: bool,
        tag: &T,
        out_buf: &mut [u8],
        out_offset: usize,
    ) -> Result<usize> {
        // get the length of the tag bytes
        let tag_len = tag.as_ref().len();

        // get our indexes
        let tag_start = out_offset;
        let tag_end = tag_start + tag_len;
        let mac_start = tag_end;
        let mac_end = mac_start + MSG_MAC_LEN;

        // make sure we're not going to write beyond the end of the output buffer
        if mac_end > out_buf.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // copy the tag bytes to the message
        out_buf[tag_start..tag_end].copy_from_slice(tag.as_ref());

        // if keyed then meta_send_enc otherwise meta_send_clr
        if is_keyed {
            // send the three bytes of tag data encrypted
            debug!(
                "SEND_META_ENC:\n\tPT: {:02x?}",
                &out_buf[tag_start..tag_end]
            );
            strobe.meta_send_enc(&mut out_buf[tag_start..tag_end], false);
            debug!("\tCT: {:02x?})", &out_buf[tag_start..tag_end]);
        } else {
            // send the data in the clear
            debug!("SEND_META_CLR({:02x?})", &out_buf[tag_start..tag_end]);
            strobe.meta_send_clr(&out_buf[tag_start..tag_end], false);
        }

        // make this composite
        strobe.meta_ad(&MSG_MAC_LEN.to_ne_bytes(), false);
        debug!("META_AD({:02x?})", &MSG_MAC_LEN.to_ne_bytes());
        // add a mac for the framing data
        strobe.meta_send_mac(&mut out_buf[mac_start..mac_end], false);
        debug!("SEND_META_MAC({:02x?})", &out_buf[mac_start..mac_end]);

        // just return how many bytes we wrote
        Ok(tag_len + MSG_MAC_LEN)
    }

    fn strobe_to_message(
        strobe: &mut Strobe,
        is_keyed: bool,
        in_tag: &T,
        in_buf: &[u8],
        out_buf: &mut [u8],
        out_offset: usize,
    ) -> Result<usize> {
        let mut out_idx = out_offset;
        let tag_len = in_tag.as_ref().len();
        let data_len = in_tag.get_data_length();

        // make sure we're not writing beyond the end of the output buffer
        if out_offset + tag_len + data_len > out_buf.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // output the data tag to bytes
        out_idx += Self::strobe_tag_to_message(strobe, is_keyed, in_tag, out_buf, out_idx)?;

        // copy the data to the message
        out_buf[out_idx..out_idx + data_len].copy_from_slice(&in_buf[..data_len]);

        // if keyed, the send_enc and send_mac, otherwise send_clr
        // make this a composite operation by first meta_AD the data length
        strobe.meta_ad(&data_len.to_ne_bytes(), false);
        debug!("META_AD({:02x?})", &data_len.to_ne_bytes());
        out_idx += if is_keyed {
            // send the data encrypted
            debug!(
                "SEND_ENC:\n\tPT: {:02x?}",
                &out_buf[out_idx..out_idx + data_len]
            );
            strobe.send_enc(&mut out_buf[out_idx..out_idx + data_len], false);
            debug!("\tCT: {:02x?}", &out_buf[out_idx..out_idx + data_len]);
            // make this a composite operation by first meta_AD the mac length
            strobe.meta_ad(&MSG_MAC_LEN.to_ne_bytes(), false);
            debug!("META_AD({:02x?})", &MSG_MAC_LEN.to_ne_bytes());
            // followed by the mac itself
            strobe.send_mac(
                &mut out_buf[out_idx + data_len..out_idx + data_len + 16],
                false,
            );
            debug!(
                "SEND_MAC({:02x?})",
                &out_buf[out_idx + data_len..out_idx + data_len + 16]
            );
            data_len + 16
        } else {
            // send the data in the clear
            debug!("SEND_CLR({:02x?})", &out_buf[out_idx..out_idx + data_len]);
            strobe.send_clr(&out_buf[out_idx..out_idx + data_len], false);
            data_len
        };

        // return the bytes we wrote
        Ok(out_idx - out_offset)
    }

    fn strobe_tag_from_message(
        strobe: &mut Strobe,
        is_keyed: bool,
        in_buf: &[u8],
        in_offset: usize,
        tag: &mut T,
    ) -> Result<usize> {
        let mut in_idx = 0;
        let tag_len = tag.as_mut().len();

        // zero out the tag
        for i in 0..tag_len {
            tag.as_mut()[i] = 0u8;
        }

        loop {
            // the first strobe calls will have more set to false, the remaining calls it will be
            // true for the streaming interface of strobe-rs
            let more = in_idx > 0;

            // make sure we're not going to read beyond the end of the buffer
            if in_offset + in_idx > in_buf.len() {
                return Err(ProtocolError::InvalidBufferLen.into());
            }

            // make sure that we're not going to write beyond the end of the tag buffer
            if in_idx >= tag_len {
                return Err(ProtocolError::InvalidBufferLen.into());
            }

            // copy the next byte over to the tag buffer
            tag.as_mut()[in_idx] = in_buf[in_offset + in_idx];

            // if keyed then meta_recv_enc otherwise meta_recv_clr
            if is_keyed {
                // recv and decrypt the next byte
                debug!(
                    "RECV_META_ENC:\n\tCT: {:02x?}",
                    &tag.as_ref()[in_idx..in_idx + 1]
                );
                strobe.meta_recv_enc(&mut tag.as_mut()[in_idx..in_idx + 1], more);
                debug!("\tPT: {:02x?}", &tag.as_ref()[in_idx..in_idx + 1]);
            } else {
                // recv the next byte
                debug!("RECV_META_CLR({:02x?})", &tag.as_ref()[in_idx..in_idx + 1]);
                strobe.meta_recv_clr(&tag.as_mut()[in_idx..in_idx + 1], more);
            }

            // the index
            in_idx += 1;

            // try to parse the tag from the bytes received so far...
            if tag.try_parse(in_idx) {
                if is_keyed {
                    debug!("RECV_META_ENC:\n\tCT: {:02x?}", &in_buf[in_offset..in_idx]);
                    debug!("\tPT: {:02x?}", &tag.as_mut()[..in_idx]);
                } else {
                    debug!("RECV_META_CLR({:02x?})", &tag.as_ref()[..in_idx]);
                }

                // make sure we're not going to read beyond the end of the buffer
                let mac_start = in_offset + in_idx;
                let mac_end = mac_start + MSG_MAC_LEN;
                if mac_end > in_buf.len() {
                    return Err(ProtocolError::InvalidBufferLen.into());
                }

                // copy the mac
                let mut mac_buf = [0u8; MSG_MAC_LEN];
                mac_buf.copy_from_slice(&in_buf[mac_start..mac_end]);

                // make this composite
                strobe.meta_ad(&MSG_MAC_LEN.to_ne_bytes(), false);
                debug!("META_AD({:02x?})", &MSG_MAC_LEN.to_ne_bytes());

                // read and check the mac
                debug!("RECV_META_MAC({:02x?})", mac_buf);
                strobe
                    .meta_recv_mac(&mut mac_buf)
                    .map_err(|_| ProtocolError::InvalidMac)?;

                return Ok(in_idx + MSG_MAC_LEN);
            }
        }
    }

    fn strobe_from_message(
        strobe: &mut Strobe,
        is_keyed: bool,

        // input
        in_buf: &[u8],    // buffer to read the message from
        in_offset: usize, // offest in the buffer to start reading from

        // output
        out_tag: &mut T,
        out_buf: &mut [u8],
    ) -> Result<(usize, usize)> {
        let mut in_idx = in_offset;

        // recv the data tag
        *out_tag = T::default();
        in_idx += Self::strobe_tag_from_message(strobe, is_keyed, &in_buf, in_idx, out_tag)?;

        // get the data length
        let data_len = out_tag.get_data_length();

        // make sure there's enough room in the TaggedData for the data
        if out_tag.get_data_length() > out_buf.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // copy the message data over
        out_buf[..data_len].copy_from_slice(&in_buf[in_idx..in_idx + data_len]);

        // if keyed then recv_enc and recv_mac otherwize recv_clr
        let mut mac_buf = [0u8; MSG_MAC_LEN];
        // make this a composite operation by meta_AD the expected data length first
        strobe.meta_ad(&data_len.to_ne_bytes(), false);
        debug!("META_AD({:02x?})", &data_len.to_ne_bytes());
        in_idx += if is_keyed {
            // recv and decrypt the data
            debug!("RECV_ENC:\n\tCT: {:02x?}", &out_buf[..data_len]);
            strobe.recv_enc(&mut out_buf[..data_len], false);
            debug!("\tPT: {:02x?}", &out_buf[..data_len]);
            // make this a composite operation
            strobe.meta_ad(&MSG_MAC_LEN.to_ne_bytes(), false);
            debug!("META_AD({:02x?})", &MSG_MAC_LEN.to_ne_bytes());
            // then receive the mac
            mac_buf.copy_from_slice(&in_buf[in_idx + data_len..in_idx + data_len + 16]);
            debug!("RECV_MAC({:02x?})", mac_buf);
            strobe
                .recv_mac(&mut mac_buf)
                .map_err(|_| ProtocolError::InvalidMac)?;
            data_len + 16
        } else {
            // recv the data in the clear
            debug!("RECV_CLR({:02x?})", &out_buf[..data_len]);
            strobe.recv_clr(&out_buf[..data_len], false);
            data_len
        };

        // return just the number of bytes we read
        Ok((in_idx - in_offset, data_len))
    }

    // this uses the AD operation to mix data bytes into the given strobe state
    fn strobe_ad(strobe: &mut Strobe, data: &[u8]) {
        // update the strobe state with the data bytes
        debug!("MIX AD({:02x?})", data);
        if data.len() > 0 {
            strobe.ad(data, false);
        }
    }

    // this uses the KEY operation to rekey with the data bytes
    fn strobe_key(strobe: &mut Strobe, data: &[u8]) {
        // update the strobe state with the data bytes
        debug!("MIX KEY({:02x?})", data);
        if data.len() > 0 {
            strobe.key(data, false);
        }
    }

    // this sends 32 bytes of data in the clear. this is used to send the PRF of the outbound
    // channel so that the recipient knows which session the message is associated with. for
    // out-of-order messaging this value only changes when a rekey happens so rekey often.
    fn strobe_send_clr(
        strobe: &mut Strobe,

        // input
        prf: &[u8; 32],

        // output
        out_buf: &mut [u8],
        out_offset: usize,
    ) -> Result<usize> {
        out_buf[out_offset..out_offset + 32].copy_from_slice(&prf[..32]);
        // composite operation by meta_ad + send_clr
        strobe.meta_ad(&32_usize.to_ne_bytes(), false);
        strobe.send_clr(&out_buf[out_offset..out_offset + 32], false);
        Ok(32)
    }

    // this receives 32 bytes of data in the clear. this is used to receive the PRF of the inbound
    // channel so that we maintain the same state as the sender. typically, a recipient will first
    // read the 32 bytes from the inbount message and use it to know which disco session the
    // message is associated with. once the disco session is restored, we need to receive the 32
    // bytes to that our strobe state stays synchronized with the sender.
    fn strobe_recv_clr(
        strobe: &mut Strobe,

        // input
        in_buf: &[u8],    // buffer to read the message from
        in_offset: usize, // offest in the buffer to start reading from

        // output
        prf: &mut [u8; 32],
    ) -> Result<(usize, usize)> {
        prf[..32].copy_from_slice(&in_buf[in_offset..in_offset + 32]);
        // composite operation by meta_ad + recv_clr
        strobe.meta_ad(&32_usize.to_ne_bytes(), false);
        strobe.recv_clr(&prf[..32], false);
        Ok((32, 32))
    }

    // this updates the messge counts and rekeys if needed or aborts if we're at our message limit
    fn update_message_counts(
        strobe: &mut Strobe,
        since_rekey: &mut u64,
        total: &mut u64,
        rekey_in: u64,
    ) -> Result<()> {
        *since_rekey += 1;
        *total += 1;

        // check if it is time to rekey and rekey the strobe state
        if *since_rekey >= rekey_in {
            debug!("REKEYING NOW!! AFTER {} MSGS", rekey_in);
            strobe.ratchet(16, false);

            // reset the counter
            *since_rekey = 0;
        }

        // check to see if we've reached the message limits
        if *total == u64::max_value() - 1 {
            return Err(ProtocolError::MessageLimitReached.into());
        }

        Ok(())
    }

    // This is the split() operation detailed in the Disco Noise
    // Extension specification (https://discocrypto.com/disco.html)
    fn split(
        strobe: &mut Strobe,
        params: &Params<K, T, P, S, SS>,
        nonces: &NG,
        initiator: bool,
        out_of_order: bool,
        rekey_in: u64,
        msgs_since_rekey: u64,
        msgs_total: u64,
        is_keyed: bool,
        rs: &P,
        re: &P,
        prf: &[u8; 32],
    ) -> Self {
        // This function follows the steps in §5 and §7.3.1 of the Disco extension spec
        // (https://www.discocrypto.com/disco.html) to support both regular and out-of-order
        // message delivery

        // Both message delivery modes follow the steps in §5

        // 1. clone the strobe state into one for inbound and one for outbound
        let mut so = strobe.clone();
        let mut si = so.clone();

        // 2. for the initiator, call meta_AD("initiator") on outbount and meta_AD("responder") on
        //    the inbound. for the responder, call meta_AD("responder") on outbound and
        //    meta_AD("initiator") on inbound.
        if initiator {
            // initiator's outbound state is tagged as "initiator" and
            // inbound state is tagged as "responder"
            so.meta_ad(b"initiator", false);
            si.meta_ad(b"responder", false);
        } else {
            // responder's output state is tagged as "responder" and
            // inbound state is tagged as "initiator"
            so.meta_ad(b"responder", false);
            si.meta_ad(b"initiator", false);
        }

        // 3. call RATCHET(16) on both inbound and outbount for both initiator and responder
        so.ratchet(16, false);
        si.ratchet(16, false);

        // 4. create the correct transport state objects based on the message delivery mode
        let (in_ts, in_n, out_ts, out_n) = if out_of_order {
            // Out-of-order delivery follows the steps in §7.3.1

            // 4.1 call meta_RATCHET(0) on both inbound and outbound
            so.meta_ratchet(0, false);
            si.meta_ratchet(0, false);

            // 4.2 create two transport state objects associated with the strobe states
            let in_ts = TransportState::new(Transport::OutOfOrder, true);
            let out_ts = TransportState::new(Transport::OutOfOrder, false);

            // 4.3 create nonces and reset them
            let mut in_n = nonces.clone();
            in_n.reset();
            let mut out_n = nonces.clone();
            out_n.reset();

            (in_ts, in_n, out_ts, out_n)
        } else {
            // In-order delivery just needs to create new nonces

            // 4.1 create two transport state objects associated with the strobe states
            let in_ts = TransportState::new(Transport::InOrder, true);
            let out_ts = TransportState::new(Transport::InOrder, false);

            // 4.2 create nonces
            let in_n = nonces.clone();
            let out_n = nonces.clone();

            (in_ts, in_n, out_ts, out_n)
        };

        // return valid Transport state
        Session::Transport {
            params: params.clone(),
            in_strobe: si,
            in_transport_state: in_ts,
            in_nonces: in_n,
            in_prf: prf.clone(),
            in_msgs_since_rekey: msgs_since_rekey,
            out_strobe: so,
            out_transport_state: out_ts,
            out_nonces: out_n,
            out_prf: prf.clone(),
            out_msgs_since_rekey: msgs_since_rekey,
            rekey_in,
            is_keyed,
            out_of_order,
            msgs_total,
            rs: rs.clone(),
            re: re.clone(),
        }
    }

    /// Send an outgoing message, returns the number of bytes written to the out_buf
    pub fn send_message(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<usize> {
        // this index value tracks where the next write should start in
        // the out_buf so that multiple handshake commands can be
        // processed in a single call to this function
        let mut out_idx = 0;

        // the payload for the message is undefined data so we create a tag for it here and
        // set the data length properly
        let mut tt = T::default();
        tt.set_data_length(in_buf.len());

        match self {
            Session::Handshake {
                ref mut strobe,
                params,
                ref mut nonces,
                handshake_state,
                initiator,
                out_of_order,
                rekey_in,
                ref mut msgs_since_rekey,
                ref mut msgs_total,
                ref mut is_keyed,
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
                    if let Some(pattern) = handshake_state.next() {
                        match pattern {
                            // generate a new ephemeral key pair
                            GenKey => {
                                let (p, s) = params.key_type.generate(&params.key_type, get_rng());
                                *ep = p;
                                *es = s;
                            }

                            // get the channel binding data see §7.1 of the Disco specification
                            GetHandshakeHash => {
                                strobe.prf(prf, false);
                            }

                            // do an AD that mixes the specified data into the strobe state
                            MixHash(d) => {
                                // mix the data into the strobe state
                                Self::strobe_ad(
                                    strobe,
                                    match d {
                                        Epub => ep.as_ref(),
                                        Esec => es.as_ref(),
                                        Psk => psk.as_ref(),
                                        Payload => in_buf,
                                        Prologue => prologue.as_ref(),
                                        Re => re.as_ref(),
                                        Rs => rs.as_ref(),
                                        Spub => sp.as_ref(),
                                        Ssec => ss.as_ref(),
                                    },
                                );
                            }

                            // do a KEY to rekey using the specified data, which should only be
                            // a pre-shared key (psk)
                            MixKey(d) => {
                                Self::strobe_key(
                                    strobe,
                                    match d {
                                        Psk => psk.as_ref(),
                                        _ => return Err(ProtocolError::InvalidHandshakeOp.into()),
                                    },
                                );

                                // the session is now keyed
                                *is_keyed = true;
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
                                let shared_secret = params
                                    .key_type
                                    .get_shared_secret(local, remote)
                                    .map_err(|_| ProtocolError::SharedSecretCalculationFailed)?;

                                // re-key the session with the result of a shared secret
                                // calculation
                                Self::strobe_key(strobe, shared_secret.as_ref());

                                // the session is now keyed
                                *is_keyed = true;
                            }

                            // depending on the value of is_keyed, this either sends data in the
                            // clear or it sends data encrypted. when sending data in the clear the
                            // sequence of strobe calls is like this:
                            //
                            //     meta_send_clr(data tag)
                            //     send_clr(data)
                            //
                            // when sending data encrypted the sequence of strobe calls is like
                            // this:
                            //
                            //     meta_send_enc(data tag)
                            //     send_enc(data)
                            //     send_mac(16)
                            //
                            EncryptAndHash(d) => {
                                // get the tag reference
                                let tag = match d {
                                    Epub => ep.get_tag(),
                                    Esec => es.get_tag(),
                                    Payload => &tt,
                                    Prologue => {
                                        return Err(ProtocolError::SendingPrologue.into());
                                    }
                                    Psk => {
                                        return Err(ProtocolError::SendingPsk.into());
                                    }
                                    Re => re.get_tag(),
                                    Rs => rs.get_tag(),
                                    Spub => sp.get_tag(),
                                    Ssec => ss.get_tag(),
                                };

                                // get the buffer reference
                                let buf = match d {
                                    Epub => ep.as_ref(),
                                    Esec => es.as_ref(),
                                    Payload => {
                                        debug!("READ {} BYTES FROM IN_BUF", in_buf.len());
                                        in_buf
                                    }
                                    Prologue => {
                                        return Err(ProtocolError::SendingPrologue.into());
                                    }
                                    Psk => {
                                        return Err(ProtocolError::SendingPsk.into());
                                    }
                                    Re => re.as_ref(),
                                    Rs => rs.as_ref(),
                                    Spub => sp.as_ref(),
                                    Ssec => ss.as_ref(),
                                };

                                // strobe the data to the output buffer
                                out_idx += Self::strobe_to_message(
                                    strobe, *is_keyed, &tag, buf, out_buf, out_idx,
                                )?;
                            }

                            // we're sending a message, any RecvData commands are invalid
                            DecryptAndHash(_) => {
                                return Err(ProtocolError::InvalidState.into());
                            }

                            // our turn is done, so stop here and return how many bytes we wrote to
                            // the output buffer
                            Stop => {
                                Self::update_message_counts(
                                    strobe,
                                    msgs_since_rekey,
                                    msgs_total,
                                    *rekey_in,
                                )?;

                                return Ok(out_idx);
                            }

                            // the handshake process has completed and we need to transition to the
                            // transport phase of this link
                            Split => {
                                Self::update_message_counts(
                                    strobe,
                                    msgs_since_rekey,
                                    msgs_total,
                                    *rekey_in,
                                )?;

                                // transition to the Transport phase by splitting
                                *self = Self::split(
                                    strobe,
                                    params,
                                    nonces,
                                    *initiator,
                                    *out_of_order,
                                    *rekey_in,
                                    *msgs_since_rekey,
                                    *msgs_total,
                                    *is_keyed,
                                    rs,
                                    re,
                                    prf,
                                );
                                return Ok(out_idx);
                            }
                        }
                    } else {
                        return Err(ProtocolError::InvalidState.into());
                    }
                }
            }

            Session::Transport {
                ref mut out_strobe,
                ref mut out_transport_state,
                ref mut out_nonces,
                ref mut out_prf,
                ref mut out_msgs_since_rekey,
                rekey_in,
                out_of_order,
                is_keyed,
                ref mut msgs_total,
                ..
            } => {
                use TransportData::*;
                use TransportOp::*;

                // in out-of-order sessions, we clone the strobe state for every message and keep
                // the session strobe the same. in in-order sessions we use the same strobe state
                // every time instead of a clone of an unchanging strobe state
                let mut strobe_copy = out_strobe.clone();
                let msg_strobe = if *out_of_order {
                    &mut strobe_copy
                } else {
                    out_strobe
                };

                // this tracks the nonce for this message
                let mut nonce = N::default();

                // loop, processing transport patterns until we hit a Stop
                loop {
                    if let Some(pattern) = out_transport_state.next() {
                        match pattern {
                            // do an AD that mixes the specified data into the strobe state
                            MixHash(d) => {
                                // mix the data into the strobe state
                                Self::strobe_ad(
                                    msg_strobe,
                                    match d {
                                        Nonce => nonce.as_ref(),
                                        _ => return Err(ProtocolError::InvalidHandshakeOp.into()),
                                    },
                                );
                            }

                            // checking the nonce during a message send doesn't make sense
                            CheckNonce => return Err(ProtocolError::InvalidTransportOp.into()),

                            // send the channel state as a session identifier
                            SendChannelState => {
                                out_idx +=
                                    Self::strobe_send_clr(msg_strobe, &out_prf, out_buf, out_idx)?;
                            }

                            // recv the channel state is an error
                            RecvChannelState => {
                                return Err(ProtocolError::ReceivingPrf.into());
                            }

                            // get a new nonce value
                            GetNonce => {
                                nonce = out_nonces.generate(get_rng());
                            }

                            // encrypt and hash the outbound data
                            EncryptAndHash(d) => {
                                // get the data to mix
                                out_idx += Self::strobe_to_message(
                                    msg_strobe,
                                    *is_keyed,
                                    match d {
                                        Payload => &tt,
                                        Nonce => &nonce.get_tag(),
                                        _ => return Err(ProtocolError::SendingPrf.into()),
                                    },
                                    match d {
                                        Payload => {
                                            debug!("READ {} BYTES FROM IN_BUF", in_buf.len());
                                            in_buf
                                        }
                                        Nonce => {
                                            debug!(
                                                "READ {} BYTES FROM NONCE",
                                                nonce.as_ref().len()
                                            );
                                            nonce.as_ref()
                                        }
                                        _ => return Err(ProtocolError::SendingPrf.into()),
                                    },
                                    out_buf,
                                    out_idx,
                                )?;
                            }

                            // decrypt and hash the inbound data
                            DecryptAndHash(_) => {
                                return Err(ProtocolError::InvalidState.into());
                            }

                            // building the message is done, if we're doing in-order message
                            // delivery we need to make sure the current strobe state becomes the
                            // strobe state we save for the next message
                            Stop => {
                                Self::update_message_counts(
                                    msg_strobe,
                                    out_msgs_since_rekey,
                                    msgs_total,
                                    *rekey_in,
                                )?;

                                // if we're in-order then update the channel state
                                if !*out_of_order {
                                    // do a composite operation by meta_AD the length of the PRF
                                    msg_strobe.meta_ad(&out_prf.len().to_ne_bytes(), false);
                                    // followed by the PRF
                                    msg_strobe.prf(out_prf, false);
                                }
                                return Ok(out_idx);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Read the incoming message, returns the number of bytes processed from the in_buf and the
    /// number of bytes written to the out_buf
    pub fn recv_message(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(usize, usize)> {
        // this index value tracks where the next read should start in the in_buf so that we can
        // process multiple handshake commands in a single call to this function
        let mut in_idx = 0;

        // this index value tracks where the next write should start in the out_buf
        let mut out_idx = 0;

        // the payload coming from the message should be tagged using the default tag value usually
        // representing a byte buffer or undefined type. we create a dummy tag just to received the
        // tag when decrypting the payload but we throw it away since it is really only for
        // internal use only
        let mut tag = T::default();

        match self {
            Session::Handshake {
                ref mut strobe,
                params,
                ref mut nonces,
                handshake_state,
                initiator,
                out_of_order,
                rekey_in,
                ref mut msgs_since_rekey,
                ref mut msgs_total,
                ref mut is_keyed,
                prologue,
                ref mut sp,
                ref mut ss,
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
                    if let Some(pattern) = handshake_state.next() {
                        match pattern {
                            // generate a new ephemeral key pair
                            GenKey => {
                                let (p, s) = params.key_type.generate(&params.key_type, get_rng());
                                *ep = p;
                                *es = s;
                            }

                            // get the channel binding data see §7.1 of the Disco specification
                            GetHandshakeHash => {
                                strobe.prf(prf, false);
                            }

                            // do an AD that mixes the specified data into the strobe state
                            MixHash(d) => {
                                // mix the data into the strobe state
                                Self::strobe_ad(
                                    strobe,
                                    match d {
                                        Epub => ep.as_ref(),
                                        Esec => es.as_ref(),
                                        Psk => psk.as_ref(),
                                        Payload => &out_buf[out_idx..],
                                        Prologue => prologue.as_ref(),
                                        Re => re.as_ref(),
                                        Rs => rs.as_ref(),
                                        Spub => sp.as_ref(),
                                        Ssec => ss.as_ref(),
                                    },
                                );
                            }

                            // do a KEY to rekey using the specified data, which should only be
                            // a pre-shared key (psk)
                            MixKey(d) => {
                                Self::strobe_key(
                                    strobe,
                                    match d {
                                        Psk => psk.as_ref(),
                                        _ => return Err(ProtocolError::InvalidHandshakeOp.into()),
                                    },
                                );

                                // the session is now keyed
                                *is_keyed = true;
                            }

                            // do an ECDH using the specified keys and rekey with it
                            MixKeyDh(l, r) => {
                                let mut tes = es.clone();
                                let mut tre = re.clone();

                                // get the local key
                                let local = match l {
                                    Esec => &mut tes,
                                    Ssec => ss,
                                    _ => return Err(ProtocolError::InvalidKey.into()),
                                };

                                // get the remote key
                                let remote = match r {
                                    Re => &mut tre,
                                    Rs => rs,
                                    _ => return Err(ProtocolError::InvalidKey.into()),
                                };

                                // calculate the shared secret
                                let shared_secret = params
                                    .key_type
                                    .get_shared_secret(local, remote)
                                    .map_err(|_| ProtocolError::SharedSecretCalculationFailed)?;

                                // re-key the session with the result of a shared secret
                                // calculation
                                Self::strobe_key(strobe, shared_secret.as_ref());

                                // the session is now keyed
                                *is_keyed = true;
                            }

                            // we're receiving data so any EncryptAndHash commands are invalid
                            EncryptAndHash(_) => {
                                return Err(ProtocolError::InvalidState.into());
                            }

                            // depending on the value of is_keyed, this either receives data in the
                            // clear or it receives data encrypted. when receiving data in the
                            // clear, the sequence of strobe calls is like this:
                            //
                            //     meta_recv_clr(data tag)
                            //     recv_clr(data)
                            //
                            // when receiving data encrypted, the sequence of strobe calls is like
                            // this:
                            //
                            //     meta_recv_enc(data tag)
                            //     recv_enc(data)
                            //     recv_mac(16)
                            //
                            DecryptAndHash(d) => {
                                // get the mutable buffer reference
                                let buf = match d {
                                    Epub => ep.as_mut(),
                                    Esec => es.as_mut(),
                                    Payload => &mut out_buf[out_idx..],
                                    Prologue => {
                                        return Err(ProtocolError::SendingPrologue.into());
                                    }
                                    Psk => {
                                        return Err(ProtocolError::SendingPsk.into());
                                    }
                                    Re => re.as_mut(),
                                    Rs => rs.as_mut(),
                                    Spub => sp.as_mut(),
                                    Ssec => ss.as_mut(),
                                };

                                // strobe in the incoming data
                                let (i, o) = Self::strobe_from_message(
                                    strobe, *is_keyed, in_buf, in_idx, &mut tag, buf,
                                )?;

                                in_idx += i;

                                // store the decoded tag back in the tagged data
                                match d {
                                    Epub => ep.set_tag(&tag),
                                    Esec => es.set_tag(&tag),
                                    Re => re.set_tag(&tag),
                                    Rs => rs.set_tag(&tag),
                                    Spub => sp.set_tag(&tag),
                                    Ssec => ss.set_tag(&tag),
                                    Payload => {
                                        debug!("WROTE {} BYTES TO OUT_BUF", o);
                                        out_idx += o;
                                    } // update the out_buf index
                                    _ => {}
                                }
                            }

                            // our turn is done so stop and return the number of bytes read
                            Stop => {
                                Self::update_message_counts(
                                    strobe,
                                    msgs_since_rekey,
                                    msgs_total,
                                    *rekey_in,
                                )?;

                                return Ok((in_idx, out_idx));
                            }

                            // the handshake process has completed, switch to transport state
                            Split => {
                                Self::update_message_counts(
                                    strobe,
                                    msgs_since_rekey,
                                    msgs_total,
                                    *rekey_in,
                                )?;

                                *self = Self::split(
                                    strobe,
                                    params,
                                    nonces,
                                    *initiator,
                                    *out_of_order,
                                    *rekey_in,
                                    *msgs_since_rekey,
                                    *msgs_total,
                                    *is_keyed,
                                    rs,
                                    re,
                                    prf,
                                );
                                return Ok((in_idx, out_idx));
                            }
                        }
                    } else {
                        return Err(ProtocolError::InvalidState.into());
                    }
                }
            }

            Session::Transport {
                ref mut in_strobe,
                ref mut in_transport_state,
                ref mut in_nonces,
                ref mut in_prf,
                ref mut in_msgs_since_rekey,
                rekey_in,
                out_of_order,
                is_keyed,
                ref mut msgs_total,
                ..
            } => {
                use TransportData::*;
                use TransportOp::*;

                // in out-of-order sessions, we clone the strobe state for every message and kep
                // the session strobe the same until a rekey happens
                let mut strobe_copy = in_strobe.clone();
                let msg_strobe = if *out_of_order {
                    &mut strobe_copy
                } else {
                    in_strobe
                };

                // this tracks the nonce for this message
                let mut nonce = N::default();

                // loop, processing transport patterns until we hit a Stop
                loop {
                    if let Some(pattern) = in_transport_state.next() {
                        match pattern {
                            // do an AD that mixes the specified data into the strobe state
                            MixHash(d) => {
                                // mix the data into the strobe state
                                Self::strobe_ad(
                                    msg_strobe,
                                    match d {
                                        Nonce => nonce.as_ref(),
                                        _ => return Err(ProtocolError::InvalidHandshakeOp.into()),
                                    },
                                );
                            }

                            // check the nonce value with the nonce generator to ensure it is valid
                            CheckNonce => {
                                debug!("CHECKING NONCE: {:02x?}", nonce.as_ref());
                                if !in_nonces.check_add(&nonce) {
                                    return Err(ProtocolError::InvalidNonce.into());
                                }
                            }

                            // send the channel state is an error
                            SendChannelState => {
                                return Err(ProtocolError::SendingPrf.into());
                            }

                            // recv the channel state and make sure it matches
                            RecvChannelState => {
                                let mut prf = [0u8; 32];
                                let (i, _) =
                                    Self::strobe_recv_clr(msg_strobe, in_buf, in_idx, &mut prf)?;
                                in_idx += i;

                                // make sure that the prf matches the current channel state
                                if prf != *in_prf {
                                    return Err(ProtocolError::ChannelStateMismatch.into());
                                }
                            }

                            // getting the nonce so that we can keep the strobe state synchronized
                            GetNonce => {
                                if !*out_of_order {
                                    // in-order delivery requires getting a nonce and mixing it in
                                    nonce = in_nonces.generate(get_rng());
                                } else {
                                    // this is an error in out-of-order delivery because the nonce
                                    // is transmitted within the encrypted message
                                    return Err(ProtocolError::InvalidTransportOp.into());
                                }
                            }

                            // encrypt and hash the outbound data is an error
                            EncryptAndHash(_) => {
                                return Err(ProtocolError::InvalidState.into());
                            }

                            // decrypt and hash the inbound data
                            DecryptAndHash(d) => {
                                // receive the incoming data
                                let (i, o) = Self::strobe_from_message(
                                    msg_strobe,
                                    *is_keyed,
                                    in_buf,
                                    in_idx,
                                    &mut tag,
                                    match d {
                                        Payload => &mut out_buf[out_idx..],
                                        Nonce => nonce.as_mut(),
                                        _ => return Err(ProtocolError::ReceivingPrf.into()),
                                    },
                                )?;

                                in_idx += i;

                                // set the decoded tag
                                match d {
                                    Nonce => {
                                        debug!("WROTE {} BYTES TO NONCE", o);
                                        nonce.set_tag(&tag)
                                    }
                                    Payload => {
                                        debug!("WROTE {} BYTES TO OUTBUF", o);
                                        out_idx += o;
                                    }
                                    _ => {}
                                };
                            }

                            // building the message is done.
                            Stop => {
                                // this updates message counts and does a rekey if it is time to.
                                // rekey's only affect in-order sessions. out-of-order sessions
                                // must implement their own rekey protocol since messages created
                                // before a rekey but delivered after a rekey cannot be decrypted.
                                Self::update_message_counts(
                                    msg_strobe,
                                    in_msgs_since_rekey,
                                    msgs_total,
                                    *rekey_in,
                                )?;

                                // if we're in-order, update the channel state after every message
                                if !*out_of_order {
                                    // do a composite operation by meta_AD the length of the PRF
                                    msg_strobe.meta_ad(&in_prf.len().to_ne_bytes(), false);
                                    // followed by the PRF
                                    msg_strobe.prf(in_prf, false);
                                }
                                return Ok((in_idx, out_idx));
                            }
                        }
                    }
                }
            }
        }
    }

    /// Manually rekey the specified strobe state. This is really only useful for a higher level
    /// protocol for doing rekeys in out-of-order sessions which requires more coordination than
    /// automatic rekeying does.
    pub fn rekey(&mut self, outbound: bool, out_of_order: bool) {
        match self {
            Session::Handshake { ref mut strobe, .. } => {
                strobe.ratchet(16, false);
                if out_of_order {
                    strobe.meta_ratchet(0, false);
                }
            }
            Session::Transport {
                ref mut in_strobe,
                ref mut out_strobe,
                ..
            } => {
                let strobe = if outbound { out_strobe } else { in_strobe };
                strobe.ratchet(16, false);
                if out_of_order {
                    strobe.meta_ratchet(0, false);
                }
            }
        }
    }

    /// Get the remote ephemeral public key if there is one
    pub fn get_remote_ephemeral(&self) -> Result<P> {
        match self {
            Session::Handshake { re, .. } => Ok(re.clone()),
            Session::Transport { re, .. } => Ok(re.clone()),
        }
    }

    /// Get the remote static public key if there is one
    pub fn get_remote_static(&self) -> Result<P> {
        match self {
            Session::Handshake { rs, .. } => Ok(rs.clone()),
            Session::Transport { rs, .. } => Ok(rs.clone()),
        }
    }

    /// Get the channel state for channel binding. See §11.2 of the Noise Protocol spec
    pub fn get_channel_state(&mut self, inbound: bool, hash: &mut [u8; 32]) -> Result<()> {
        match self {
            Session::Transport {
                in_prf, out_prf, ..
            } => {
                if inbound {
                    hash.copy_from_slice(in_prf);
                } else {
                    hash.copy_from_slice(out_prf);
                }
                Ok(())
            }
            _ => Err(ProtocolError::InvalidState.into()),
        }
    }

    /// Get a specified number of pseudo-random numbers derived from the channel state

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
            Session::Transport { is_keyed, .. } => *is_keyed,
            Session::Handshake { is_keyed, .. } => *is_keyed,
        }
    }
}
