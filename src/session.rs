use crate::{
    error::{Error, ParamError, ProtocolError},
    inner::get_rng,
    key::{KeyType, KeyGenerator, KeyAgreement, TaggedData},
    params::{Params, HandshakeData, HandshakeOp, HandshakeState},
    Result,
};
use cde::{CryptoData, idx, Tag, TagBuilder};
use strobe_rs::Strobe;

// From the Noise Extension: Disco specification, the meaning of the operations
// in the following handshake patterns are as follows:
//
// InitSymmetric(protocol_name): calls InitializeStrobe(protocol_name) to do
// protocol separation.
//
// MixPsk(key_data): this is currently unimplemented because the PSK handshakes
// have special processing rules that we don't support at the moment. plus psk
// handshakes are not required for our first use cases.
//
// MixKey(key_data): calls AD(key_data), sets isKeyed to true.
//
// MixDh(local, remote): calls AD(ECDH(local, remote)), sets isKeyed to true.
//
// MixHash(data): calls AD(data).
//
// MixKeyAndHash(key_data): calls AD(key) without setting isKeyed to true.
//
// MixKhAndHash(local, remote): calls AD(ECDH(local, remote)) without setting isKeyed to true.
//
// GetHandshakeHash(): calls PRF(32) to get the handshake hash used for channel
// binding as per the Noise spec (section 11.2).
//
// SendAndHash(data): if isKeyed is true, then calls send_ENC(data) followed by
// send_MAC(16). if isKeyed is false, then calls send_CLR(data).
//
// RecvAndHash(data): if isKeyed is true, then calls recv_ENC(data) followed by
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
/// The session state for a Disco connection. This ultimately wraps a Strobe
/// state and handles the different Noise protocol messages by updating the
/// Strobe state accordingly. The handshake script is determined by the
/// handshake name (e.g. XX, XK1, KK1) and the elliptic curve protocol is
/// determined by the protocol name (e.g. 25519 for Curve25519, etc).
#[derive(Clone)]
pub enum Session<'a, T, P, S>
where
    T: KeyType + KeyGenerator<'a, PublicKey = P, SecretKey = S> + KeyAgreement<'a> + Clone,
    P: TaggedData<'a> + Clone + Default,
    S: TaggedData<'a> + Clone + Default,
{
    /// Before the first message is sent, after the strobe is initialized
    Initialized {
        /// Strobe state
        strobe: Strobe,
        /// Disco parameters
        params: Params<'a, T>,
        /// True if initiator, false if responder
        initiator: bool,
        /// True if transport state will handle out-of-order messages
        out_of_order: bool,
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
    },

    /// Sending/receiving the first message transitions to this state and we
    /// stay in this state until the handshake script is complete
    Handshake {
        /// Strobe state
        strobe: Strobe,
        /// Disco parameters
        params: Params<'a, T>,
        /// Handshake state
        handshake_state: HandshakeState,
        /// True if initiator, false if responder
        initiator: bool,
        /// True if transport state will handle out-of-order messages
        out_of_order: bool,
        /// True if a DH operation has been completed
        is_keyed: bool,
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
    },

    /// Completing the handshake script transitions to this state which has
    /// one half-duplex strobe for each direction
    Transport {
        /// Strobe state for sending messages
        strobe_out: Strobe,
        /// Strobe state for receiving messages
        strobe_in: Strobe,
        /// Disco parameters
        params: Params<'a, T>,
        /// True if initiator, false if responder
        initiator: bool,
        /// True if transport state will handle out-of-order messages
        out_of_order: bool,
        /// Optional remote static public key
        rs: P,
        /// Remote ephemeral public key
        re: P,
    }
}

impl<'a, T, P, S> Session<'a, T, P, S>
where
    T: KeyType + KeyGenerator<'a, PublicKey = P, SecretKey = S> + KeyAgreement<'a> + Clone,
    P: TaggedData<'a> + Clone + Default,
    S: TaggedData<'a> + Clone + Default,
{

    fn strobe_tag_to_message(
        strobe: &mut Strobe,
        is_keyed: bool,
        tag: &Tag,
        out_buf: &mut [u8],
        out_offset: usize,
    ) -> Result<usize> {
        // get tag bytes
        let tag_len = tag.len();
        let mut tag_buf = [0u8; 9];
        tag.bytes(&mut tag_buf[0..tag_len]);

        // strobe the strobe tag bytes into the message
        let mut out_idx = out_offset;
        for tag_idx in (0..tag_len).step_by(3) {
            // copy the next three bytes of tag into the message buffer
            out_buf[out_idx..out_idx+3].copy_from_slice(&tag_buf[tag_idx..tag_idx+3]);

            // if keyed, then send_enc and send_mac, otherwise send_clr
            out_idx += if is_keyed {
                // send the three bytes of tag data encrypted
                //println!("SEND_ENC:\n\tPT: {:02x?}", &out_buf[out_idx..out_idx+3]);
                strobe.send_enc(&mut out_buf[out_idx..out_idx+3], false);
                //println!("\tCT: {:02x?})", &out_buf[out_idx..out_idx+3]);
                // send the mac
                strobe.send_mac(&mut out_buf[out_idx+3..out_idx+19], false);
                //println!("SEND_MAC({:02x?})", &out_buf[out_idx+3..out_idx+19]);
                19
            } else {
                // mix the data into the strobe state
                //println!("AD({:02x?})", &out_buf[out_idx..out_idx+3]);
                strobe.ad(&out_buf[out_idx..out_idx+3], false);
                // send the data in the clear
                //println!("SEND_CLR({:02x?})", &out_buf[out_idx..out_idx+3]);
                strobe.send_clr(&out_buf[out_idx..out_idx+3], false);
                3
            }
        }

        // just return how many bytes we wrote
        Ok(out_idx - out_offset)
    }

    fn strobe_to_message(
        strobe: &mut Strobe,
        is_keyed: bool,

        // input
        in_data: &(impl TaggedData<'a> + ?Sized),

        // output
        out_buf: &mut [u8], // buffer to write the data to
        out_offset: usize,  // the offset into the buffer to start writing to

    ) -> Result<usize> {

        let mut out_idx = out_offset;

        // create the tag
        let mut strobe_tag = if is_keyed {
            TagBuilder::from_tag("strobe.enc.data_recv").build().map_err(|_| ProtocolError::InvalidTag)?
        } else {
            TagBuilder::from_tag("strobe.clr.data_recv").build().map_err(|_| ProtocolError::InvalidTag)?
        };

        // the strobe tag len is zero if the in_data len is zero, otherwise
        // include the length of the tag as well
        let strobe_tag_len = if in_data.length() > 0 {
            in_data.get_tag().len() + in_data.length()
        } else {
            0
        };

        // set the data length
        strobe_tag.set_data_length(strobe_tag_len);

        // output the strobe tag bytes
        out_idx += Self::strobe_tag_to_message(strobe, is_keyed, &strobe_tag, out_buf, out_idx)?;

        if strobe_tag.get_data_length() == 0 {
            // there's no data so return early
            // return just the number of bytes we read
            return Ok(out_idx - out_offset);
        }

        // output the data tag bytes
        out_idx += Self::strobe_tag_to_message(strobe, is_keyed, in_data.get_tag(), out_buf, out_idx)?;

        // copy the data to the message
        let data_len = in_data.length();
        out_buf[out_idx..out_idx+data_len].copy_from_slice(&in_data.as_ref()[0..data_len]);

        // strobe the data into the message and update out_idx
        out_idx += if is_keyed {
            // send the data encrypted
            //println!("SEND_ENC:\n\tPT: {:02x?}", &out_buf[out_idx..out_idx+data_len]);
            strobe.send_enc(&mut out_buf[out_idx..out_idx+data_len], false);
            //println!("\tCT: {:02x?}", &out_buf[out_idx..out_idx+data_len]);
            // send the mac
            strobe.send_mac(&mut out_buf[out_idx+data_len..out_idx+data_len+16], false);
            //println!("SEND_MAC({:02x?})", &out_buf[out_idx+data_len..out_idx+data_len+16]);
            data_len + 16
        } else {
            // mix the data into the strobe state
            //println!("AD({:02x?})", &out_buf[out_idx..out_idx+data_len]);
            strobe.ad(&out_buf[out_idx..out_idx+data_len], false);
            // send the data in the clear
            //println!("SEND_CLR({:02x?})", &out_buf[out_idx..out_idx+data_len]);
            strobe.send_clr(&out_buf[out_idx..out_idx+data_len], false);
            data_len
        };
       
        // return just the number of bytes we wrote
        Ok(out_idx - out_offset)
    }

    fn strobe_tag_from_message(
        strobe: &mut Strobe,
        is_keyed: bool,
        in_buf: &[u8],
        in_offset: usize,
        tag: &mut Tag,
    ) -> Result<usize> {

        let mut in_idx = in_offset;
        let mut tag_len = 0;
        let mut tag_buf = [0u8; 9];
        let mut mac_buf = [0u8; 16];
        for tag_idx in (0..9).step_by(3) {
            // copy the 3 bytes of the tag
            tag_buf[tag_idx..tag_idx+3].copy_from_slice(&in_buf[in_idx..in_idx+3]);

            // read three tag bytes
            in_idx += 3;

            // recv this part of the tag
            in_idx += if is_keyed {
                // recv and decrypt the three bytes of encrypted tag data
                //println!("RECV_ENC:\n\tCT: {:02x?}", &tag_buf[tag_idx..tag_idx+3]);
                strobe.recv_enc(&mut tag_buf[tag_idx..tag_idx+3], false);
                //println!("\tPT: {:02x?}", &tag_buf[tag_idx..tag_idx+3]);
                // check the mac
                //println!("RECV_MAC({:02x?})", &in_buf[in_idx..in_idx+16]);
                mac_buf.copy_from_slice(&in_buf[in_idx..in_idx+16]);
                strobe.recv_mac(&mut mac_buf).map_err(|_| ProtocolError::InvalidMac)?;
                16
            } else {
                // mix the first 3 bytes into the strobe state
                //println!("AD({:02x?})", &tag_buf[tag_idx..tag_idx+3]);
                strobe.ad(&tag_buf[tag_idx..tag_idx+3], false);
                // recv the data in the clear
                //println!("RECV_CLR({:02x?})", &tag_buf[tag_idx..tag_idx+3]);
                strobe.recv_clr(&tag_buf[tag_idx..tag_idx+3], false);
                0
            };

            // update our tag lenth
            tag_len += 3;

            // does the tag have another 3 bytes?
            if tag_buf[tag_idx+2] & 0x80 == 0u8 {
                // we just processed the last 3 bytes of the tag so exit the for loop
                break;
            }
        }

        // create the tag from the tag bytes
        *tag = TagBuilder::from_bytes(&tag_buf[0..tag_len])
            .build().map_err(|_| ProtocolError::InvalidTag)?;

        // return just the number of bytes we read
        Ok(in_idx - in_offset)
    }

    fn strobe_from_message(
        strobe: &mut Strobe,
        is_keyed: bool,

        // input
        in_buf: &[u8],      // buffer to read the message from
        in_offset: usize,   // offest in the buffer to start reading from

        // output
        out_data: &mut (impl TaggedData<'a> + ?Sized),

    ) -> Result<usize> {

        let mut in_idx = in_offset;

        // recv the strobe tag
        let mut strobe_tag = Tag::default();
        in_idx += Self::strobe_tag_from_message(strobe, is_keyed, in_buf, in_idx, &mut strobe_tag)?;

        // make sure the class is "strobe"
        if strobe_tag.class() != idx('f') {
            return Err(Error::Protocol(ProtocolError::InvalidTag));
        }

        // make sure the subclass is either enc or clr
        if strobe_tag.subclass() != idx('e') && strobe_tag.subclass() != idx('c') {
            return Err(Error::Protocol(ProtocolError::InvalidTag));
        }

        // make sure the subsubclass is recv_data
        if strobe_tag.subsubclass() != 1u8 {
            return Err(Error::Protocol(ProtocolError::InvalidTag));
        }

        if strobe_tag.get_data_length() == 0 {
            // there's no data so return early
            out_data.set_length(0)?;
            // return just the number of bytes we read
            return Ok(in_idx - in_offset);
        }

        // recv the data tag
        let mut data_tag = Tag::default();
        in_idx += Self::strobe_tag_from_message(strobe, is_keyed, in_buf, in_idx, &mut data_tag)?;

        // check that the out_data is zeroed
        if !out_data.is_zero() {
            return Err(Error::Protocol(ProtocolError::NonEmptyBuffer));
        }

        // recv the data bytes

        // get the data length
        let data_len = data_tag.get_data_length();

        // make sure there's enough room in the TaggedData for the data
        if out_data.max_length() < data_len {
            return Err(Error::Protocol(ProtocolError::InvalidBufferLen));
        }

        // copy the message data over
        out_data.as_mut()[0..data_len].copy_from_slice(&in_buf[in_idx..in_idx+data_len]);
        out_data.set_length(data_len)?;
        out_data.set_tag(&data_tag);

        // read the data bytes
        in_idx += data_len;

        // recv the message
        let mut mac_buf = [0u8; 16];
        in_idx += if is_keyed {
            // recv and decrypt the data
            //println!("RECV_ENC:\n\tCT: {:02x?}", &out_data.as_ref()[0..data_len]);
            strobe.recv_enc(&mut out_data.as_mut()[0..data_len], false);
            //println!("\tPT: {:02x?}", &out_data.as_ref()[0..data_len]);
            // check the mac
            //println!("RECV_MAC({:02x?})", &in_buf[in_idx..in_idx+16]);
            mac_buf.copy_from_slice(&in_buf[in_idx..in_idx+16]);
            strobe.recv_mac(&mut mac_buf).map_err(|_| ProtocolError::InvalidMac)?;
            16
        } else {
            // mix the data into the strobe state
            //println!("AD({:02x?})", &out_data.as_ref()[0..data_len]);
            strobe.ad(&out_data.as_ref()[0..data_len], false);
            // recv the data in the clear
            //println!("RECV_CLR({:02x?})", &out_data.as_ref()[0..data_len]);
            strobe.recv_clr(&out_data.as_ref()[0..data_len], false);
            0
        };

        // return just the number of bytes we read
        Ok(in_idx - in_offset)
    }


    // this uses the AD operation to mix the tag and the data bytes into the
    // given strobe state
    fn strobe_tagged_data(strobe: &mut Strobe, data: &(impl TaggedData<'a> + ?Sized)) {
        let mut buf = [0u8; 9];

        // get the tag bytes and len
        let mut len = data.get_tag().bytes(&mut buf);

        // update the strobe state with the tag bytes
        //println!("MIX AD({:02x?})", &buf[0..len]);
        strobe.ad(&buf[0..len], false);

        // update the strobe state with the data bytes
        len = data.length();
        //println!("MIX AD({:02x?})", &data.as_ref()[0..len]);
        strobe.ad(&data.as_ref()[0..len], true);
    }

    // This is the split() operation detailed in the Disco Noise
    // Extension specification (https://discocrypto.com/disco.html)
    fn split(
        strobe: &mut Strobe,
        params: &Params<'a, T>,
        initiator: bool,
        out_of_order: bool, 
        rs: P,
        re: P,
    ) -> Self {
        // clone the strobe
        let mut so = strobe.clone();
        let mut si = so.clone();

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

        // ratchet both to prevent rollback
        so.ratchet(16, false);
        si.ratchet(16, false);

        // return valid Transport state
        Session::Transport {
            strobe_out: so,
            strobe_in: si,
            params: params.clone(),
            initiator: initiator,
            out_of_order: out_of_order,
            rs: rs,
            re: re,
        }
    }

    /// Send an outgoing message
    pub fn send_message(&mut self, in_data: &impl TaggedData<'a>, out_buf: &mut [u8]) -> Result<usize> {
        match self {

            // first time either send/recv has been called so generate ephemeral
            // if needed, transition to handshake state and continue
            Session::Initialized {
                strobe, params, initiator, out_of_order, ss, sp, ep, es, rs } => {

                // get the handshake pattern
                let h = HandshakeState::new(params.handshake, *initiator);

                // generate ephemeral keys if needed
                let (ep, es) = if ep.is_zero() && es.is_zero() {
                    params.key_type.generate(get_rng())
                } else if ep.is_zero() || es.is_zero() {
                    return Err(Error::Param(ParamError::InvalidEphemeralKeys));
                } else {
                    (ep.clone(), es.clone())
                };
              
                // transition to the Handshake state
                *self = Session::Handshake {
                    strobe: strobe.clone(),
                    params: params.clone(),
                    handshake_state: h,
                    initiator: *initiator,
                    out_of_order: *out_of_order,
                    is_keyed: false,
                    sp: sp.clone(),
                    ss: ss.clone(),
                    ep: ep,
                    es: es,
                    rs: rs.clone(),
                    re: P::default(),
                };

                // call send_message recursively now that we're in the Handshake state
                self.send_message(in_data, out_buf)
            },

            Session::Handshake {
                ref mut strobe, params, handshake_state, initiator, out_of_order,
                ref mut is_keyed, ref mut sp, ref mut ss, ref mut ep, ref mut es,
                ref mut rs, ref mut re } => {

                use HandshakeOp::*;
                use HandshakeData::*;

                // this index value tracks where the next write should start in
                // the out_buf so that multiple handshake commands can be
                // processed in a single call to this function
                let mut out_idx = 0;

                // loop, processing handshake patterns until we hit a Stop or a
                // Split command
                loop {
                    if let Some(pattern) = handshake_state.next() {
                        match pattern {

                            // do an AD that mixes the specified data into the
                            // strobe state and set is_keyed accordingly
                            Mix(d, k) => {
                                // get the data as TaggedData
                                let data: &dyn TaggedData<'a> = match d {
                                    Spub => sp,
                                    Ssec => ss,
                                    Epub => ep,
                                    Esec => es,
                                    Rs   => rs,
                                    Re   => re,
                                    P    => in_data,
                                };

                                // mix the data into the strobe state
                                Self::strobe_tagged_data(strobe, data);

                                // set is_keyed
                                *is_keyed = k;
                            },

                            // do an ECDH using the specified keys and then
                            // mix it into the strobe state and set is_keyed
                            // accordingly
                            MixDh(l, r, k) => {
                                // get the local key as TaggedData
                                let local: &dyn TaggedData<'a> = match l {
                                    Ssec => ss, 
                                    Esec => es,
                                    _ => { return Err(Error::Protocol(ProtocolError::InvalidKey)); }
                                };

                                // get the remote key as TaggedData
                                let remote: &dyn TaggedData<'a> = match r {
                                    Rs   => rs,
                                    Re   => re,
                                    _ => { return Err(Error::Protocol(ProtocolError::InvalidKey)); }
                                };

                                // make sure we have valid keys
                                if local.is_zero() || remote.is_zero() {
                                    return Err(Error::Protocol(ProtocolError::InvalidKey));
                                }

                                // get the ECDH result as TaggedData
                                //println!("ECDH:\n\tLOCAL SECRET: {:02x?}\n\tREMOTE PUBLIC: {:02x?}", local.as_ref(), remote.as_ref());
                                let ecdh = params.key_type.ecdh(local, remote).map_err(|_| ProtocolError::InvalidKey)?;
                                //println!("\tSHARED SECRET: {:02x?}\n", ecdh.as_ref());

                                // mix the data into the strobe state
                                Self::strobe_tagged_data(strobe, &ecdh);

                                // set is_keyed
                                *is_keyed = k;
                            },

                            // send tagged data either using CLR or ENC+MAC
                            // strobe operations depending on the value of
                            // is_keyed. each send is tagged with the appropriate
                            // strobe CDE tag--either strobe.enc.data_recv or
                            // strobe.clr.data_recv--to tell the recipient how
                            // to receive the data and for framing purposes.
                            SendData(d) => {
                                // get the data as TaggedData
                                let data: &dyn TaggedData<'a> = match d {
                                    Spub => sp,
                                    Ssec => ss,
                                    Epub => ep,
                                    Esec => es,
                                    Rs   => rs,
                                    Re   => re,
                                    P    => in_data,
                                };

                                // mix and send data to the out_data
                                out_idx += Self::strobe_to_message(strobe, *is_keyed, data, out_buf, out_idx)?;
                            },

                            // we're sending a message, any RecvData commands
                            // are invalid
                            RecvData(_) => { return Err(Error::Protocol(ProtocolError::InvalidState)); },

                            // the current sequence of handshake operations is
                            // done so stop here and return the data
                            Stop => { return Ok(out_idx); },

                            // the handshake process has completed and it is
                            // time to transition into the transport state
                            Split => {
                                *self = Self::split(strobe, params, *initiator, *out_of_order, rs.clone(), re.clone());
                                return Ok(out_idx);
                            },
                        }
                    } else {
                        return Err(Error::Protocol(ProtocolError::InvalidState));
                    }
                }
            },

            Session::Transport { ref mut strobe_out, .. } => {
                Self::strobe_to_message(strobe_out, true, in_data, out_buf, 0)
            }
        }
    }

    /// Read the incoming message
    pub fn recv_message(&mut self, in_buf: &[u8], out_data: &mut impl TaggedData<'a>) -> Result<usize> {
        match self {

            // first time either send/recv has been called so generate ephemeral
            // if needed, transition to handshake state and continue
            Session::Initialized {
                strobe, params, initiator, out_of_order, ss, sp, ep, es, rs } => {

                // get the handshake pattern
                let h = HandshakeState::new(params.handshake, *initiator);

                // generate ephemeral keys if needed
                let (ep, es) = if ep.is_zero() && es.is_zero() {
                    params.key_type.generate(get_rng())
                } else if ep.is_zero() || es.is_zero() {
                    return Err(Error::Param(ParamError::InvalidEphemeralKeys));
                } else {
                    (ep.clone(), es.clone())
                };
              
                // transition to the Handshake state
                *self = Session::Handshake {
                    strobe: strobe.clone(),
                    params: params.clone(),
                    handshake_state: h,
                    initiator: *initiator,
                    out_of_order: *out_of_order,
                    is_keyed: false,
                    sp: sp.clone(),
                    ss: ss.clone(),
                    ep: ep,
                    es: es,
                    rs: rs.clone(),
                    re: P::default(),
                };

                // call recv_message recursively now that we're in the Handshake state
                self.recv_message(in_buf, out_data)
            },

            Session::Handshake {
                ref mut strobe, params, handshake_state, initiator, out_of_order,
                ref mut is_keyed, ref mut sp, ref mut ss, ref mut ep, ref mut es,
                ref mut rs, ref mut re } => {

                use HandshakeOp::*;
                use HandshakeData::*;

                // this index value tracks where the next read should start
                // in the in_buf so that we can process multiple handshake
                // commands in a single call to this function
                let mut in_idx = 0;

                // loop, processing handshake patterns until we hit a Stop or a
                // Split command
                loop {
                    if let Some(pattern) = handshake_state.next() {
                        match pattern {

                            // do an AD that mixes the specified data into the
                            // strobe state and set is_keyed accordingly
                            Mix(d, k) => {
                                // get the data as TaggedData
                                let data: &dyn TaggedData<'a> = match d {
                                    Spub => sp,
                                    Ssec => ss,
                                    Epub => ep,
                                    Esec => es,
                                    Rs   => rs,
                                    Re   => re,
                                    P    => out_data,
                                };

                                // mix the data into the strobe state
                                Self::strobe_tagged_data(strobe, data);

                                // set is_keyed
                                *is_keyed = k;
                            },

                            // do an ECDH using the specified keys and then
                            // mix it into the strobe state and set is_keyed
                            // accordingly
                            MixDh(l, r, k) => {
                                // get the local key as TaggedData
                                let local: &dyn TaggedData<'a> = match l {
                                    Ssec => ss, 
                                    Esec => es,
                                    _ => { return Err(Error::Protocol(ProtocolError::InvalidKey)); }
                                };

                                // get the remote key as TaggedData
                                let remote: &dyn TaggedData<'a> = match r {
                                    Rs   => rs,
                                    Re   => re,
                                    _ => { return Err(Error::Protocol(ProtocolError::InvalidKey)); }
                                };

                                // make sure we have valid keys
                                if local.is_zero() || remote.is_zero() {
                                    return Err(Error::Protocol(ProtocolError::InvalidKey));
                                }

                                // get the ECDH result as TaggedData
                                //println!("ECDH:\n\tLOCAL SECRET: {:02x?}\n\tREMOTE PUBLIC: {:02x?}", local.as_ref(), remote.as_ref());
                                let ecdh = params.key_type.ecdh(local, remote).map_err(|_| ProtocolError::InvalidKey)?;
                                //println!("\tSHARED SECRET: {:02x?}\n", ecdh.as_ref());

                                // mix the data into the strobe state
                                Self::strobe_tagged_data(strobe, &ecdh);

                                // set is_keyed
                                *is_keyed = k;
                            },

                            // we're receiving data so any SendData commands are
                            // invalid
                            SendData(_) => { return Err(Error::Protocol(ProtocolError::InvalidState)); },

                            // receive tagged data either using CLR or ENC+MAC
                            // strobe operatios depending on the value of
                            // is_keyed. each receive processing the strobe CDE
                            // tag and checks that the destination TaggedData
                            // object is large enough to receive the data, thus
                            // enforcing framing.
                            RecvData(d) => {
                                // get the data as TaggedData
                                let data: &mut dyn TaggedData<'a> = match d {
                                    Spub => sp,
                                    Ssec => ss,
                                    Epub => ep,
                                    Esec => es,
                                    Rs   => rs,
                                    Re   => re,
                                    P    => out_data,
                                };

                                // read the CDE tag and data from the message buffer
                                in_idx += Self::strobe_from_message(strobe, *is_keyed, in_buf, in_idx, data)?;
                            },

                            // the current sequence of handshake operations is
                            // done so stop here and return the data
                            Stop => { return Ok(in_idx); },

                            // the handshake process has completed and it is
                            // time to transition into the transport state
                            Split => {
                                *self = Self::split(strobe, params, *initiator, *out_of_order, rs.clone(), re.clone());
                                return Ok(in_idx);
                            },
                        }
                    } else {
                        return Err(Error::Protocol(ProtocolError::InvalidState));
                    }
                }
            },

            Session::Transport { ref mut strobe_in, .. } => {
                Self::strobe_from_message(strobe_in, true, in_buf, 0, out_data)
            }
        }
    }

    /// Get the remote ephemeral public key if there is one
    pub fn get_remote_ephemeral(&self) -> Result<P> {
        match self {
            Session::Handshake { re, .. } => Ok(re.clone()),
            Session::Transport { ref re, .. } => Ok(re.clone()),
            _ => { Err(Error::Protocol(ProtocolError::InvalidState)) }
        }
    }

    /// Get the remote static public key if there is one
    pub fn get_remote_static(&self) -> Result<P> {
        match self {
            Session::Handshake { rs, .. } => Ok(rs.clone()),
            Session::Transport { rs, .. } => Ok(rs.clone()),
            _ => { Err(Error::Protocol(ProtocolError::InvalidState)) }
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
            _ => false
        }
    }

    /// True if data is being sent/received encrypted
    pub fn is_keyed(&self) -> bool {
        match self {
            Session::Initialized { .. } | Session::Transport { .. } => true,
            Session::Handshake { is_keyed, .. } => *is_keyed,
        }
    }
}
