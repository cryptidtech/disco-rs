/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    error::ProtocolError,
    nonce::NonceGenerator,
    tag::{Tag, TaggedData},
    transport::{Transport, TransportOrder, TransportState},
    Result,
};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use strobe_rs::Strobe;

use std::println as debug;

/// The fixed size of MAC values in the protocol
const MSG_MAC_LEN: usize = 16;

/// Specifies if the channel is full duplex, or if it is a half-duplex channel for either inbound
/// or outbout
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ChannelDuplex {
    /// Inbound half-duplex channel
    InboundHalf,
    /// Outbound half-duplex channel
    OutboundHalf,
    /// In/Out full duplex channel
    Full,
}

/// Specifies if the channel is for an initiator or a responder. This is really only useful for
/// handshaking channel state machines
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ChannelRole {
    /// Session initiator
    Initiator,
    /// Session responder
    Responder,
}

/// Channels have an internal channel state that handles stateful message exchanges such as
/// handshakes and encrypted transports
pub trait ChannelState: Iterator + Clone {
    /// get the channel role
    fn role(&self) -> &ChannelRole;
    /// get the channel duplex
    fn duplex(&self) -> &ChannelDuplex;
    /// reset the channel state
    fn reset(&mut self) -> Result<()>;
}

/// Channel manages all the channel states and nonces and sending/receiving messages
#[derive(Clone, Serialize, Deserialize)]
pub struct Channel<T, CS, N, NG>
where
    T: Tag,
    CS: ChannelState,
    N: TaggedData<T>,
    NG: NonceGenerator<T, N>,
{
    current_strobe: Strobe,
    previous_strobe: Strobe,
    msg_strobe: Option<Strobe>,
    state: CS,
    nonce_generator: NG,
    msg_order: TransportOrder,
    is_keyed: bool,
    _t: PhantomData<T>,
    _n: PhantomData<N>,
}

/// Make it easy walk through the steps of the state machine
impl<T, CS, N, NG> Iterator for Channel<T, CS, N, NG>
where
    T: Tag,
    CS: ChannelState,
    N: TaggedData<T>,
    NG: NonceGenerator<T, N>,
{
    type Item = CS::Item;
    fn next(&mut self) -> Option<Self::Item> {
        self.state.next()
    }
}

impl<T, CS, N, NG> Channel<T, CS, N, NG>
where
    T: Tag,
    CS: ChannelState,
    N: TaggedData<T>,
    NG: NonceGenerator<T, N>,
{
    /// Create a new Channel from the strobe, channel state and transport order
    pub fn new(
        strobe: &Strobe,
        state: &CS,
        nonce_generator: &NG,
        msg_order: TransportOrder,
        is_keyed: bool,
    ) -> Self {
        Self {
            current_strobe: strobe.clone(),
            previous_strobe: strobe.clone(),
            msg_strobe: None,
            state: state.clone(),
            nonce_generator: nonce_generator.clone(),
            msg_order,
            is_keyed,
            _t: PhantomData,
            _n: PhantomData,
        }
    }

    /// Start a new message
    pub fn start(&mut self) {
        // at the start of each message we clone the current strobe state, preserving the current
        // state so we can support both in-order and out-of-order message delivery
        self.msg_strobe = Some(self.current_strobe.clone());
    }

    /// Stop a new message
    pub fn stop(&mut self) {
        match self.msg_order {
            TransportOrder::InOrder => {
                // when we are delivering messages in-order, the message state must be moved back
                // to the current state so that the next message is based on the accumulated state
                self.current_strobe = self.msg_strobe.take().unwrap();
            }
            TransportOrder::OutOfOrder => {
                // when we are delivering messages out-of-order, we throw away the message state
                self.msg_strobe = None;
            }
        }
    }

    /// Returns whether this channel has had a KEY operation done on it
    pub fn is_keyed(&self) -> bool {
        self.is_keyed
    }

    /// Return the channel role
    pub fn role(&self) -> &ChannelRole {
        self.state.role()
    }

    /// Return the channel duplex mode
    pub fn duplex(&self) -> &ChannelDuplex {
        self.state.duplex()
    }

    /// Return the channel ordering
    pub fn ordering(&self) -> TransportOrder {
        self.msg_order
    }

    /// Return the next nonce
    pub fn nonce(&mut self) -> N {
        self.nonce_generator.generate()
    }

    /// Check the nonce to see if it is valid
    pub fn check_nonce(&mut self, nonce: &N) -> bool {
        self.nonce_generator.check(nonce)
    }

    /// Return a default nonce for receiving
    pub fn default_nonce(&mut self) -> N {
        self.nonce_generator.default_nonce()
    }

    /// Do a prf function on the strobe state to get pseudo-random data derived from all data mixed
    /// into the strobe state until now.
    pub fn prf(&mut self, data: &mut [u8]) {
        if let Some(s) = self.msg_strobe.as_mut() {
            (*s).prf(data, false);
            debug!("PRF({:02x?})", data);
        }
    }

    /// this uses the KEY operation to rekey with the data bytes
    pub fn key(&mut self, data: &[u8]) {
        // update the strobe state with the data bytes
        if data.len() > 0 {
            if let Some(s) = self.msg_strobe.as_mut() {
                // mix in the key data
                (*s).key(data, false);
                // mark the channel as keyed
                self.is_keyed = true;
                debug!("MIX KEY({:02x?})", data);
            }
        }
    }

    /// Split this full-duplex channel into two half-duplex channels so that sending and receiving
    /// does not have to proceed in an alternating fashion. This is the split() operation detailed
    /// in the Disco Noise Extension specification (https://discocrypto.com/disco.html).
    pub fn split(
        &mut self,
        handshake_hash: &[u8; 32],
    ) -> (
        Channel<T, TransportState, N, NG>,
        Channel<T, TransportState, N, NG>,
    ) {
        // This function follows the steps in §5 and §7.3.1 of the Disco extension spec
        // (https://www.discocrypto.com/disco.html) to support both regular and out-of-order
        // message delivery

        // Both message delivery modes follow the steps in §5

        // 0. store the current state before proceeding
        self.current_strobe = self.msg_strobe.take().unwrap();

        // 1. clone the strobe state into one for outbound and one for inbound
        let mut s_out = self.current_strobe.clone();
        let mut s_in = self.current_strobe.clone();

        // 2. for the initiator, call meta_AD("initiator") on outbount and meta_AD("responder") on
        //    the inbound. for the responder, call meta_AD("responder") on outbound and
        //    meta_AD("initiator") on inbound.
        match self.state.role() {
            ChannelRole::Initiator => {
                // initiator's outbound state is tagged as "initiator" and
                // inbound state is tagged as "responder"
                s_out.meta_ad(b"initiator", false);
                s_in.meta_ad(b"responder", false);
            }
            ChannelRole::Responder => {
                // responder's output state is tagged as "responder" and
                // inbound state is tagged as "initiator"
                s_out.meta_ad(b"responder", false);
                s_in.meta_ad(b"initiator", false);
            }
        }

        // 3. call RATCHET(16) on both inbound and outbount for both initiator and responder
        s_out.ratchet(16, false);
        s_in.ratchet(16, false);

        // 4. create the correct transport state objects based on the message delivery mode
        //
        // Out-of-order delivery follows the steps in §7.3.1
        if self.msg_order == TransportOrder::OutOfOrder {
            // 4.1 call meta_RATCHET(0) on both inbound and outbound
            s_out.meta_ratchet(0, false);
            s_in.meta_ratchet(0, false);
        }

        // create transport states for inbound and outbound
        let t_out = TransportState::new(
            Transport {},
            self.state.role(),
            &ChannelDuplex::OutboundHalf,
        );
        let t_in =
            TransportState::new(Transport {}, self.state.role(), &ChannelDuplex::InboundHalf);

        // reset the nonce generator to the handshake hash
        self.nonce_generator.reset(handshake_hash);

        // create and return two new Channels with the new ChannelState, strobe, role, duplex, and
        // ordering
        (
            // outbound half-duplex
            Channel::<T, TransportState, N, NG>::new(
                &s_out,
                &t_out,
                &self.nonce_generator,
                self.msg_order,
                self.is_keyed,
            ),
            // inbound half-duplex
            Channel::<T, TransportState, N, NG>::new(
                &s_in,
                &t_in,
                &self.nonce_generator,
                self.msg_order,
                self.is_keyed,
            ),
        )
    }

    /// Write a tag and associated data to the message. The boolean 'force_clear' forces the data
    /// to be written as cleartext even if the channel is keyed. The boolen 'meta_tag' prevents any
    /// tag data from being sent and instead it is just mixed into the strobe state using
    /// meta_AD/AD operations. This is only useful when the data being sent is a known fixed type
    /// and known fixed length because the recipient must manually create a tag with the correct
    /// type and length information to pass into the recv function when receiving the data.
    pub fn send(
        &mut self,
        send_tag: bool,
        send_data: bool,
        send_clear: bool,
        tag: &T,
        data: &[u8],
        msg: &mut [u8],
    ) -> Result<usize> {
        // make sure we're not sending a tag without any data
        if send_tag && !send_data {
            return Err(ProtocolError::InvalidSend.into());
        }

        // get the number of bytes the tag will write
        let tlen = if send_tag {
            tag.as_ref().len() + MSG_MAC_LEN
        } else {
            0 // meta tag means we're not actually sending the tag
        };

        // get the number of bytes the data will write
        let dlen = if send_data {
            tag.get_data_length()
                + if self.is_keyed && !send_clear {
                    MSG_MAC_LEN
                } else {
                    0
                }
        } else {
            0
        };

        // make sure we're not writing beyond the end of the output buffer
        if tlen + dlen > msg.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // make sure the data length in the tag matches the number of data bytes
        if tag.get_data_length() != data.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // output the tag and mac
        let tag_len = self.send_tag(send_tag, send_clear, tag, msg)?;

        // output the data and mac
        let data_len = self.send_data(
            send_data,
            send_clear,
            &data[..tag.get_data_length()],
            &mut msg[tag_len..],
        )?;

        // return the number of bytes sent
        Ok(tag_len + data_len)
    }

    /// Read a tag and associated data from the message. The boolean 'force_clear' forces the data
    /// to be read as cleartext even if the channel is keyed.
    pub fn recv(
        &mut self,
        recv_tag: bool,
        recv_data: bool,
        recv_clear: bool,
        msg: &[u8],
        tag: &mut T,
        data: &mut [u8],
    ) -> Result<usize> {
        // make sure we're not receiving a tag and no data
        if recv_tag && !recv_data {
            return Err(ProtocolError::InvalidRecv.into());
        }

        // if the tag data was sent, reset the tag before reading the tag
        if recv_tag {
            *tag = T::default();
        }

        // recv the tag
        let actual_tag_len = self.recv_tag(recv_tag, recv_clear, msg, tag)?;

        // make sure we didn't read any bytes if we aren't supposed to receive a tag
        if !recv_tag && actual_tag_len != 0 {
            return Err(ProtocolError::InvalidTag.into());
        }

        // calculate the expected data length
        let expected_data_len = if recv_data {
            tag.get_data_length()
                + if self.is_keyed && !recv_clear {
                    MSG_MAC_LEN
                } else {
                    0
                }
        } else {
            actual_tag_len + 0
        };

        // make sure we're not going to read past the end of the message buffer
        if expected_data_len > msg.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // recv the data
        let actual_data_len = self.recv_data(
            recv_data,
            recv_clear,
            &msg[actual_tag_len..],
            &mut data[..tag.get_data_length()],
        )?;

        if actual_data_len != expected_data_len {
            return Err(ProtocolError::InvalidData.into());
        }

        // return just the number of bytes we read from the msg buffer
        Ok(actual_tag_len + actual_data_len)
    }

    ///////////////// PRIVATE HELPERS

    // write a MAC to the message, if framing is true, then we use the meta operation
    fn send_mac(&mut self, framing: bool, msg: &mut [u8]) -> Result<usize> {
        // make sure we're not going to write beyond the end of the buffer
        if MSG_MAC_LEN > msg.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        if let Some(s) = self.msg_strobe.as_mut() {
            // do a meta_AD of the MAC length in network byte order
            (*s).meta_ad(&MSG_MAC_LEN.to_be_bytes(), false);
            debug!("META_AD({:02x?})", &MSG_MAC_LEN.to_be_bytes());

            // now add the MAC payload using the meta operation if it is for framing data
            if framing {
                (*s).meta_send_mac(&mut msg[..MSG_MAC_LEN], false);
                debug!("META_SEND_MAC({:02x?})", &msg[..MSG_MAC_LEN]);
            } else {
                (*s).send_mac(&mut msg[..MSG_MAC_LEN], false);
                debug!("SEND_MAC({:02x?})", &msg[..MSG_MAC_LEN]);
            }

            // return the number of bytes sent
            Ok(MSG_MAC_LEN)
        } else {
            Err(ProtocolError::InvalidState.into())
        }
    }

    // write a Tag to the message
    fn send_tag(
        &mut self,
        send_tag: bool,
        send_clear: bool,
        tag: &T,
        msg: &mut [u8],
    ) -> Result<usize> {
        // get the length of tag data to be written
        let expected_len = if send_tag {
            tag.as_ref().len()
                + if self.is_keyed && !send_clear {
                    MSG_MAC_LEN
                } else {
                    0
                }
        } else {
            0
        };

        // make sure we're not going to write beyond the end of the output buffer
        if expected_len > msg.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        if let Some(s) = self.msg_strobe.as_mut() {
            let actual_len = if send_tag {
                // get the length of the tag bytes
                let mut tag_len = tag.as_ref().len();

                // copy the tag bytes to the message
                msg[..tag_len].copy_from_slice(tag.as_ref());

                // if keyed then meta_send_enc otherwise meta_send_clr
                tag_len += if self.is_keyed && !send_clear {
                    // send the tag bytes encrypted
                    debug!("META_SEND_ENC:\n\tPT: {:02x?}", &msg[..tag_len]);
                    (*s).meta_send_enc(&mut msg[..tag_len], false);
                    debug!("\tCT: {:02x?})", &msg[..tag_len]);

                    // write a framing data MAC to the message
                    self.send_mac(true, &mut msg[tag_len..])?
                } else {
                    // mix the tag bytes into the strobe state
                    debug!("META_AD({:02x?})", &msg[..tag_len]);
                    (*s).meta_ad(&msg[..tag_len], false);

                    // send the tag bytes in the clear
                    debug!("META_SEND_CLR({:02x?})", &msg[..tag_len]);
                    (*s).meta_send_clr(&msg[..tag_len], false);

                    // no extra bytes other than the tag itself
                    0
                };

                // return the number of bytes written
                tag_len
            } else {
                // we're not sending the tag, just mixing it into the strobe state
                (*s).meta_ad(tag.as_ref(), false);
                debug!("META_AD({:02x?})", tag.as_ref());

                // no bytes written
                0
            };

            // make sure we wrote what we expected
            if expected_len != actual_len {
                return Err(ProtocolError::InvalidTag.into());
            }

            Ok(actual_len)
        } else {
            Err(ProtocolError::InvalidState.into())
        }
    }

    // write the data to the message
    fn send_data(
        &mut self,
        send_data: bool,
        send_clear: bool,
        data: &[u8],
        msg: &mut [u8],
    ) -> Result<usize> {
        // get the length of the data
        let expected_len = if send_data {
            data.len()
                + if self.is_keyed && !send_clear {
                    MSG_MAC_LEN
                } else {
                    0
                }
        } else {
            0
        };

        // make sure we're not going to write beyond the end of the buffer
        if expected_len > msg.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        if let Some(s) = self.msg_strobe.as_mut() {
            let actual_len = if send_data {
                let mut data_len = data.len();

                // copy the data to the message
                msg[..data_len].copy_from_slice(data);

                // make this a composite operation by first doing a meta_AD of the data length in
                // network byte order
                (*s).meta_ad(&data_len.to_be_bytes(), false);
                debug!("META_AD({:02x?})", &data_len.to_be_bytes());

                // if we're keyed, then we encrypt the message, otherwise send it in the clear
                data_len += if self.is_keyed && !send_clear {
                    // send the data encrypted
                    debug!("SEND_ENC:\n\tPT: {:02x?}", &msg[..data_len]);
                    (*s).send_enc(&mut msg[..data_len], false);
                    debug!("\tCT: {:02x?}", &msg[..data_len]);

                    // write the payload data MAC to the message
                    self.send_mac(false, &mut msg[data_len..])?
                } else {
                    // mix the data bytes into the strobe state
                    debug!("AD({:02x?})", &msg[..data_len]);
                    (*s).ad(&msg[..data_len], false);

                    // send the data in the clear
                    debug!("SEND_CLR({:02x?})", &msg[..data_len]);
                    (*s).send_clr(&msg[..data_len], false);

                    // no extra bytes other than the data that was written
                    0
                };

                // return the number of bytes sent
                data_len
            } else {
                // we're not actually sending the data, just going to mix it into the strobe state
                debug!("AD({:02x?})", data);
                (*s).ad(data, false);

                // didn't write any bytes
                0
            };

            // make sure we wrote what we expected
            if expected_len != actual_len {
                return Err(ProtocolError::InvalidTag.into());
            }

            Ok(actual_len)
        } else {
            Err(ProtocolError::InvalidState.into())
        }
    }

    // read a MAC to the message, if framing is true, then we use the meta operation
    fn recv_mac(&mut self, framing: bool, msg: &[u8]) -> Result<usize> {
        // make sure we're not going to read beyond the end of the buffer
        if MSG_MAC_LEN > msg.len() {
            return Err(ProtocolError::InvalidBufferLen.into());
        }

        // copy the mac locally
        let mut mac = [0u8; MSG_MAC_LEN];
        mac.copy_from_slice(&msg[..MSG_MAC_LEN]);

        if let Some(s) = self.msg_strobe.as_mut() {
            // do a meta_AD of the MAC length in network byte order
            (*s).meta_ad(&MSG_MAC_LEN.to_be_bytes(), false);
            debug!("META_AD({:02x?})", &MSG_MAC_LEN.to_be_bytes());

            // now check the MAC payload using the meta operation if it is for framing data
            if framing {
                debug!("META_RECV_MAC({:02x?})", &mac);
                (*s).meta_recv_mac(&mut mac)
                    .map_err(|_| ProtocolError::InvalidMac)?;
            } else {
                debug!("RECV_MAC({:02x?})", &mac);
                (*s).recv_mac(&mut mac)
                    .map_err(|_| ProtocolError::InvalidMac)?;
            }

            // return the number of bytes received
            Ok(MSG_MAC_LEN)
        } else {
            Err(ProtocolError::InvalidState.into())
        }
    }

    // read a tag from the message, this assumes the tag is in the default state
    fn recv_tag(
        &mut self,
        recv_tag: bool,
        recv_clear: bool,
        msg: &[u8],
        tag: &mut T,
    ) -> Result<usize> {
        if let Some(s) = self.msg_strobe.as_mut() {
            if recv_tag {
                let mut idx = 0;
                if self.is_keyed && !recv_clear {
                    // this loop copies one byte at a time to the tag until it parses
                    let tag_len = loop {
                        // the first strobe calls will have more set to false, the remaining calls it will be
                        // true for the streaming interface of strobe-rs
                        let more = idx > 0;

                        // make sure we're not going to read beyond the end of the buffer
                        if idx > msg.len() {
                            return Err(ProtocolError::InvalidBufferLen.into());
                        }

                        // make sure that we're not going to write beyond the end of the tag buffer
                        if idx >= tag.as_mut().len() {
                            return Err(ProtocolError::InvalidBufferLen.into());
                        }

                        // copy the next byte over to the tag buffer
                        tag.as_mut()[idx] = msg[idx];

                        // recv and decrypt the next byte
                        (*s).meta_recv_enc(&mut tag.as_mut()[idx..idx + 1], more);

                        // increment the index
                        idx += 1;

                        // check to see if we've read enough bytes to get a valid tag
                        if tag.try_parse(idx) {
                            break idx;
                        }
                    };

                    debug!("META_RECV_ENC:\n\tCT: {:02x?}", &msg[..tag_len]);
                    debug!("\tPT: {:02x?}", &tag.as_ref());

                    // read and check the framing MAC
                    let mac_len = self.recv_mac(true, &msg[tag_len..])?;

                    // return the number of bytes received
                    Ok(tag_len + mac_len)
                } else {
                    // this loop copies one byte at a time to the tag until it parses
                    let tag_len = loop {
                        // make sure we're not going to read beyond the end of the buffer
                        if idx > msg.len() {
                            return Err(ProtocolError::InvalidBufferLen.into());
                        }

                        // make sure that we're not going to write beyond the end of the tag buffer
                        if idx >= tag.as_mut().len() {
                            return Err(ProtocolError::InvalidBufferLen.into());
                        }

                        // copy the next byte over to the tag buffer
                        tag.as_mut()[idx] = msg[idx];

                        // increment the index
                        idx += 1;

                        // check to see if we've read enough bytes to get a valid tag
                        if tag.try_parse(idx) {
                            break idx;
                        }
                    };

                    // mix the tag bytes into the strobe state
                    debug!("META_AD({:02x?})", tag.as_ref());
                    (*s).meta_ad(tag.as_ref(), false);

                    // recv the tag bytes in the clear
                    debug!("META_RECV_CLR({:02x?})", tag.as_ref());
                    (*s).meta_recv_clr(tag.as_ref(), false);

                    // return the number of bytes received
                    Ok(tag_len)
                }
            } else {
                // no tag data was sent so we're just mixing the provided tag bytes into the strobe
                // state. the recipient must create a tag with the correct tag type and data length
                // to avoid corrupting the strobe state.
                debug!("META_AD({:02x?})", tag.as_ref());
                (*s).meta_ad(tag.as_ref(), false);
                Ok(0)
            }
        } else {
            Err(ProtocolError::InvalidState.into())
        }
    }

    // read data from the mesasge
    fn recv_data(
        &mut self,
        recv_data: bool,
        recv_clear: bool,
        msg: &[u8],
        data: &mut [u8],
    ) -> Result<usize> {
        if let Some(s) = self.msg_strobe.as_mut() {
            if recv_data {
                // get the length of data to read
                let mut data_len = data.len();

                // copy the message data over
                data[..data_len].copy_from_slice(&msg[..data_len]);

                // make this a composite operation by meta_AD the data length in network byte order
                (*s).meta_ad(&data_len.to_be_bytes(), false);
                debug!("META_AD({:02x?})", &data_len.to_be_bytes());

                data_len += if self.is_keyed && !recv_clear {
                    // recv and decrypt the data
                    debug!("RECV_ENC:\n\tCT: {:02x?}", &data[..data_len]);
                    (*s).recv_enc(&mut data[..data_len], false);
                    debug!("\tPT: {:02x?}", &data[..data_len]);

                    // read and check the payload MAC
                    self.recv_mac(false, &msg[data_len..])?
                } else {
                    // mix the data bytes into the strobe state
                    debug!("AD({:02x?})", &data[..data_len]);
                    (*s).ad(&data[..data_len], false);

                    // recv the data in the clear
                    debug!("RECV_CLR({:02x?})", &data[..data_len]);
                    (*s).recv_clr(&data[..data_len], false);

                    // no extra bytes other than the data that was received
                    0
                };

                // return the number of bytes received
                Ok(data_len)
            } else {
                // we're not actually receiving any data so we're just mixing the provided data
                // bytes into the strobe state. the recipient must pass in the correct bytes to
                // avoid corrupting the strobe state.
                debug!("AD({:02x?})", data);
                (*s).ad(data, false);

                // didn't receive any bytes
                Ok(0)
            }
        } else {
            Err(ProtocolError::InvalidState.into())
        }
    }
}
