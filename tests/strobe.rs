mod strobe {
    use strobe_rs::{SecParam, Strobe};

    #[test]
    fn round_trip() {
        // generate a strobes for alice and bob
        let mut sa = Strobe::new(b"strobe", SecParam::B256);
        let mut sb = Strobe::new(b"strobe", SecParam::B256);

        // key both with the magic passphrase
        sa.key(b"abra cadabra", false);
        sb.key(b"abra cadabra", false);

        let mut msg = b"test message".to_vec();

        // encrypt
        sa.send_enc(msg.as_mut_slice(), false);

        // decrypt
        sb.recv_enc(msg.as_mut_slice(), false);

        assert_eq!(&msg, b"test message");
    }

    #[test]
    fn sleeping() {
        // generate a strobes for alice and bob
        let mut sa0 = Strobe::new(b"strobe", SecParam::B256);
        let mut sb0 = Strobe::new(b"strobe", SecParam::B256);

        // key both with the magic passphrase
        sa0.key(b"abra cadabra", false);
        sb0.key(b"abra cadabra", false);

        let mut msg1 = b"test message".to_vec();
        let mut msg2 = b"another message".to_vec();

        // serialize sb0 to a vec
        let ssb1 = serde_cbor::to_vec(&sb0).unwrap();

        // encrypt
        sa0.send_enc(msg1.as_mut_slice(), false);

        // make sure it is encrypted
        assert_ne!(&msg1, b"test message");

        // serialize sa0 to a vec
        let ssa1 = serde_cbor::to_vec(&sa0).unwrap();

        // revive sb1 from the vec
        let mut sb1: Strobe = serde_cbor::from_slice(&ssb1).unwrap();

        // decrypt
        sb1.recv_enc(msg1.as_mut_slice(), false);

        // make sure it was decrypted correctly
        assert_eq!(&msg1, b"test message");

        // encrypt again in the other direction
        sb1.send_enc(msg2.as_mut_slice(), false);

        // make sure it is encrypted
        assert_ne!(&msg2, b"another message");

        // revive sa1 from the vec
        let mut sa1: Strobe = serde_cbor::from_slice(&ssa1).unwrap();

        // decrypt again in the other direction
        sa1.recv_enc(msg2.as_mut_slice(), false);

        // make sure it is decrypted
        assert_eq!(&msg2, b"another message");
    }
}
