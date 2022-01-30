# Disco-rs

This crate is a no-std, pure Rust impl of the
[Disco Noise Protocol Extension](https://discocrypto.com/). It is implemented
in an entirely generic way so that the underlying encryption libraries are
pluggable by the integrator (that's you). This has **not** been audited
formally yet so it should be considered experimental and not ready for
production use.

**NOTE:** This is not a plug-and-play solution. You will need to do some coding
to make this work for you. There are four traits in this crate that you must
impl with your own chosen cryptography library. They are all defined in
the file src/key.rs: `TaggedData`, `KeyType`, `KeyGenerator`, and
`KeyAgreement`. That said, for the impatient among you, the `example` folder
has an impl and tests that demonstrate being able to support Curve25519, NIST
K256, and NIST P256 crypto libraries, selectable at runtime. It's not difficult
to plug your own favorite cryptography library in, but it isn't trivial. The
`TaggedData` impl is in `example/src/tagged.rs` file. The remaining trait impls
are in the file `examples/src/key/soft.rs`.

## Handshakes

This crate supports all of the handshake patterns listed in the Disco extension
documentation: N, K, X, KK, XX, IK, NK, NX and NNpsk2. It also supports a few
additional handshake patterns that are often useful: NN, XK1, and KK1. You can
always add your own favorite handshake to the crate by editing `src/params.rs`
to include it. That file is well documented and I think it is easy to figure
out how to define a new handshake using the existing code.

## Feedback

If you are using this crate, I encourage you to drop me a line and send any
feeback my way. If you find any issues or have feature requests, please send
a PR or file an Issue.
