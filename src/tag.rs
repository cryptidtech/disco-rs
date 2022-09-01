/*
    Copyright David Huseby, All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
/// Disco streams consist of "tagged data" where a tag is sent before the data and the tag
/// describes the data that follows. The tag specifies the type of data and the length of data.
/// Disco is written in terms of a Tag trait and byte array.

/// Tag trait used throughout Disco to describe all of the data that Disco works with. Tags really
/// just need to be able to encode an arbitrary data type and data length while being able to
/// deserialize from a &[u8] while also supporing AsRef<[u8]> so that the tag's bytes can be copied
/// to a message output buffer. This crate copies one by at a time into the byte array
/// returned by AsMut<[u8]> and calls try_parse() to initiatlize the tag from the bytes. This
/// allows for a tag to be decrypted, one byte at a time, until we have a valid tag so make sure
/// that your tagging impl works this way.
pub trait Tag: AsRef<[u8]> + AsMut<[u8]> + Clone + Default {
    /// Sets the length of the associated data
    fn set_data_length(&mut self, size: usize);
    /// Gets the length of the associated data
    fn get_data_length(&self) -> usize;
    /// Tries to parse the tag from the bytes written to it, len specifies how many bytes
    fn try_parse(&mut self, len: usize) -> bool;
}

/// Disco operates on pieces of tagged data, this type owns the Tag but contains only a read-only
/// reference to the data buffer. This is designed so the crate can work on tagged data items
/// whether or not the caller gives us a raw buffer or not.
pub trait TaggedData<T: Tag>: AsRef<[u8]> + AsMut<[u8]> + Clone + Default {
    /// Get the tag
    fn get_tag(&self) -> &T;
    /// Get a mutable reference to the tag
    fn get_tag_mut(&mut self) -> &mut T;
}
