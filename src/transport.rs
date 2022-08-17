/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use serde::{Deserialize, Serialize};

/// Identifiers for the different keys referenced in transport mode operations
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum TransportData {
    /// Channel nonce
    Nonce,
    /// Payload data
    Payload,
    /// Channel state
    Prf,
}

/// Different operations to perform during transport mode operations
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum TransportOp {
    /// Mix in data using AD
    MixHash(TransportData),
    /// Check the nonce value
    CheckNonce,
    /// Send the channel state
    SendChannelState,
    /// Receive the channel state
    RecvChannelState,
    /// Get a new nonce value
    GetNonce,
    /// Does either a send_CLR(data) or send_ENC(data) + send_MAC(16) depending on is_keyed
    EncryptAndHash(TransportData),
    /// Does either a recv_CLR(data) or recv_ENC(data) + recv_MAC(16) depending on is_keyed
    DecryptAndHash(TransportData),
    /// Stop marks the end of one side's state changes
    Stop,
}

/// The state of the transport channel so that this is resumable
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub struct TransportState {
    /// The transport operations
    transport: Transport,
    /// Is this an inbout stream?
    inbound: bool,
    /// The index of the next transport operation
    index: usize,
}

/// TransportState impl
impl TransportState {
    /// construct a new handshake state from a list of operations
    pub fn new(pattern: Transport, inbound: bool) -> Self {
        TransportState {
            transport: pattern,
            inbound,
            index: 0,
        }
    }
}

/// Make it easy walk through the steps of the state machine
impl Iterator for TransportState {
    type Item = TransportOp;

    fn next(&mut self) -> Option<Self::Item> {
        let pattern = self.transport.get_pattern(self.inbound);

        // get the next op and wrap if needed
        let op = pattern[self.index];
        self.index += 1;
        if self.index == pattern.len() {
            self.index = 0;
        }

        Some(op)
    }
}

/// The handshake patterns we support for now
#[derive(PartialEq, Copy, Clone, Debug, Deserialize, Serialize)]
pub enum Transport {
    /// In-order tranport
    InOrder,
    /// Unordered transport
    OutOfOrder,
}

impl Transport {
    /// Return the appropriate TransportState
    pub fn get_pattern(&self, inbound: bool) -> &[TransportOp] {
        use TransportData::*;
        use TransportOp::*;

        match self {
            // In-order Strobe Transport
            // =========================
            // In this mode, each message must be processed in order. The nonces are used to
            // enforce this and an error will occur if a message is processed out of order. The
            // nonces are not transmitted with the messages.
            Transport::InOrder => {
                if inbound {
                    &[
                        RecvChannelState,        // receive the session identifier in the clear
                        GetNonce,                // get the next nonce
                        MixHash(Nonce),          // update the strobe state but don't rx nonce
                        DecryptAndHash(Payload), // decrypt and mix the payload
                        Stop,
                    ]
                } else {
                    &[
                        SendChannelState,        // send the session identifier in the clear
                        GetNonce,                // get the next nonce
                        MixHash(Nonce),          // update the strobe state but don't tx nonce
                        EncryptAndHash(Payload), // encrypt and mix the payload
                        Stop,
                    ]
                }
            }

            // Out-of-order Strobe Transport
            // =============================
            // In this mode, the messages may be processed out of order. The nonces are transmitted
            // with each message. The nonce generator must check which nonces have been seen before
            // to protect against replay attacks. The channel state used to identify the session
            // only changes when a rekey happens so to prevent correlation you should rekey often,
            // if not every message (rekey_in = 1).
            Transport::OutOfOrder => {
                if inbound {
                    &[
                        RecvChannelState,        // receive the session identifier in the clear
                        DecryptAndHash(Nonce),   // decrypt and mix nonce and rx it
                        CheckNonce,              // check the nonce is valid
                        DecryptAndHash(Payload), // decrypt and mix the payload
                        Stop,
                    ]
                } else {
                    &[
                        SendChannelState,        // send the session identifier in the clear
                        GetNonce,                // get the next nonce
                        EncryptAndHash(Nonce),   // encrypt and mix the nonce and tx it
                        EncryptAndHash(Payload), // encrypt and mix the payload
                        Stop,
                    ]
                }
            }
        }
    }
}
