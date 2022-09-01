/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
/// Part of the initialization of a Disco session is the possibility of both endpoints mixing in
/// any amount of "prologue" data during the handshake phase. This trait must be defined for your
/// implementation to provide prologue data to the handshaking.

/// the trait for a prologue data provider
pub trait Prologue: AsRef<[u8]> + AsMut<[u8]> + Clone + Default {}
