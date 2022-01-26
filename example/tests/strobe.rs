use strobe_rs::{Strobe, SecParam};

#[test]
fn test_strobe() {
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


