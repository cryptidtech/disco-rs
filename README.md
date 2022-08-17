# Disco-rs

This crate is a no-std, pure Rust impl of the [Disco Noise Protocol
Extension](https://discocrypto.com/). It is implemented in an entirely
generic way so that the underlying encryption libraries are pluggable by
the integrator (that's you). This has **not** been audited formally yet
so it should be considered experimental and not ready for production
use.

This implementation is notable in that it supports some of the [Advanced
Features](http://noiseprotocol.org/noise.html#advanced-features) listed
in §11 of the Noise specification. Specifically, this crate supports
channel binding, re-key, and out-of-order transport messages. The main
difficulty with out-of-order transport messages is tracking which nonces
you have seen to defend against replay attacks. For small numbers of
messages in a session, this is trivial, but long-lived sessions with
many millions or billions of messages make tracking nonces extremely
difficult. The example implementation in the `test` folder uses a
simplistic sliding window approach to tracking nonces for demonstration
purposes.

One other novel detail in this implementation is the use of the "channel
states" as a 32-byte session identifier at the start of every message.
This crate is built with full support for serde to serialize and
deserialize the sessions to disk. Because the serialization stores the
full internal keccak state, you must treat it like a secret key or other
similarly secret data. Before serializing a session to persistent
storage, call the `get_channel_state(true)` function to get the 32-byte
inbound channel state and use that to index to the stored session data.
Then when you receive an encrypted disco message, you can read the first
32-bytes and know which Disco session to deserialize from storage for
processing the message.

This is not a plug-and-play solution. You will need to do some coding to
make this work for you. There are five traits in this crate that you
must impl with your own chosen cryptography library. They can be found
in `src/tag.rs`: `Tag` and `TaggedData`, `src/key.rs`: `KeyType`,
`KeyGenerator`, and `KeyAgreement`, and in `src/nonce.rs`:
`NonceGenerator`. That said, for the impatient among you, the `tests`
folder has an example impl and tests of these traits using the common
`x25519_dalek` crate. It's not difficult to plug in your favorite
cryptography library, but it is also not trivial. If you don't have a
very good understanding of Noise and Disco, they you should probably
look elsewhere.

## Handshakes

This crate supports all of the handshake patterns listed in the [Disco
extension documentation](https://discocrypto.com): N, K, X, KK, XX, IK,
NK, NX, and NNpsk2. It also supports a number of other handshake
patterns that are often useful: Npsk0, Kpsk0, Xpsk1, NN, IX,XK1, and
KK1. You can always add your own favorite handshake to the crate by
editing `src/params.rs` to include it. That file is well documented and
I think it is easy to figure out how to define a new handshake using the
existing code. Please be sure to add tests for any new handshakes in
either `tests/one_way.rs` or `tests/two_way.rs` depending on which
handshake you add.

## Feedback

If you are using this crate, I encourage you to drop me a line and send
any feedback my way. If you find any issues or have feature requests,
please send a PR or file an Issue.
