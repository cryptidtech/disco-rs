/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{
    channel::{ChannelDuplex, ChannelRole, ChannelState},
    Result,
};
use serde::{Deserialize, Serialize};

/// The two different transport modes
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum TransportOrder {
    /// In-order message delivery
    InOrder,
    /// Out-of-order message delivery
    OutOfOrder,
}

/// Identifiers for the different keys referenced in transport mode operations
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum TransportData {
    /// Payload data
    Payload,
}

/// Different operations to perform during transport mode operations
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum TransportOp {
    /// Start a new message, handles cloning state for out-of-order nonce-based messages
    Start,
    /// Sends a nonce by mixing in its tag and then sending the value in clear as AD
    SendNonce,
    /// Receives a nonce assuming the tag and doing an AD before receivin in the clear
    RecvNonce,
    /// Does either a send_CLR(data) or send_ENC(data) + send_MAC(16) depending on is_keyed
    EncryptAndHash(TransportData),
    /// Does either a recv_CLR(data) or recv_ENC(data) + recv_MAC(16) depending on is_keyed
    DecryptAndHash(TransportData),
    /// Stop a new message, handles remembering state for in-order messages
    Stop,
}

/// The state of the transport channel so that this is resumable
#[derive(PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct TransportState {
    /// The transport operations
    transport: Transport,
    /// The index to the next handshake operation
    index: usize,
    /// The channel role
    role: ChannelRole,
    /// The channel duplex mode
    duplex: ChannelDuplex,
}

/// TransportState impl
impl TransportState {
    /// construct a new handshake state from a list of operations
    pub fn new(transport: Transport, role: &ChannelRole, duplex: &ChannelDuplex) -> Self {
        TransportState {
            transport,
            index: 0,
            role: role.clone(),
            duplex: duplex.clone(),
        }
    }
}

/// ChannelState trait impl
impl ChannelState for TransportState {
    /// get the channel role
    fn role(&self) -> &ChannelRole {
        &self.role
    }
    /// get the channel duplex
    fn duplex(&self) -> &ChannelDuplex {
        &self.duplex
    }
    /// reset the channel state
    fn reset(&mut self) -> Result<()> {
        self.index = 0;
        Ok(())
    }
}

/// Make it easy walk through the steps of the state machine
impl Iterator for TransportState {
    type Item = TransportOp;

    fn next(&mut self) -> Option<Self::Item> {
        let pattern = self.transport.get_pattern(&self.duplex);

        // get the next op and wrap if needed
        let op = pattern[self.index];
        self.index += 1;
        if self.index == pattern.len() {
            self.index = 0;
        }

        Some(op)
    }
}

/// Container for the different transport message patterns
#[derive(PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct Transport {}

impl Transport {
    /// Return the appropriate TransportState
    pub fn get_pattern(&self, duplex: &ChannelDuplex) -> &[TransportOp] {
        use ChannelDuplex::*;
        use TransportData::*;
        use TransportOp::*;

        match self {
            _ => {
                match duplex {
                    InboundHalf => &[
                        Start,                   // start a new message
                        RecvNonce,               // mix in the nonce
                        DecryptAndHash(Payload), // decrypt and mix the payload
                        Stop,
                    ],
                    OutboundHalf => &[
                        Start,                   // start a new message
                        SendNonce,               // mix in the nonce
                        EncryptAndHash(Payload), // encrypt and mix the payload
                        Stop,
                    ],
                    _ => &[],
                }
            }
        }
    }
}
