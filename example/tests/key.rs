use disco_rs::{
    key::{KeyAgreement, KeyGenerator},
};
use disco_ecdh_example::key::soft::AsymKeyType;

#[allow(dead_code)]
mod inner;
use inner::get_rng;

#[test]
fn test_x25518_dh() {

    // Initiator generates ephemeral key and test static key
    let x25519 = AsymKeyType::X25519;
    let (i_e_pub, i_e_sec) = x25519.generate(get_rng());
    let (i_s_pub, i_s_sec) = x25519.generate(get_rng());

    // Responder generates ephemeral key and test static key
    let (r_e_pub, r_e_sec) = x25519.generate(get_rng());
    let (r_s_pub, r_s_sec) = x25519.generate(get_rng());

    // Responder does the first DH using initiator ephemeral public key
    // and responder ephemeral secret key
    let r_first_dh = x25519.ecdh(&r_e_sec, &i_e_pub).unwrap();

    // Initiator does the first DH using the responder ephemeral public key
    // and initiator ephemeral secret key
    let i_first_dh = x25519.ecdh(&i_e_sec, &r_e_pub).unwrap();

    // Both initiator and responder have the same shared secret
    assert_eq!(r_first_dh, i_first_dh);

    // The responder sends the responder static public key to initiator,
    // encrypted using the shared secret calculated from the first DH

    // Responder does the second DH using the initiator ephemeral public
    // key and the responder static secret key
    let r_second_dh = x25519.ecdh(&r_e_sec, &i_s_pub).unwrap();

    // Initiator does the second DH using the responder static public key
    // and the initiator ephemeral secret key
    let i_second_dh = x25519.ecdh(&i_s_sec, &r_e_pub).unwrap();

    // Both initiator and responder have the same shared secret again
    assert_eq!(r_second_dh, i_second_dh);

    // The initiator sends the initiator static public key to responder,
    // encrypted using the shared secret calculated from the second DH

    // Responder does the third DH using the initiator static public key
    // and the responder static ephemeral key
    let r_third_dh = x25519.ecdh(&r_s_sec, &i_e_pub).unwrap();

    // Initiator does the third DH using the responder ephemeral public key
    // and the initiator static secret key
    let i_third_dh = x25519.ecdh(&i_e_sec, &r_s_pub).unwrap();

    // Both initiator and responder have the same shared secret again
    assert_eq!(r_third_dh, i_third_dh);
}

#[test]
fn test_k256_dh() {

    // Initiator generates ephemeral key and test static key
    let k256 = AsymKeyType::K256;
    let (i_e_pub, i_e_sec) = k256.generate(get_rng());
    let (i_s_pub, i_s_sec) = k256.generate(get_rng());

    // Responder generates ephemeral key and test static key
    let (r_e_pub, r_e_sec) = k256.generate(get_rng());
    let (r_s_pub, r_s_sec) = k256.generate(get_rng());

    // Responder does the first DH using initiator ephemeral public key
    // and responder ephemeral secret key
    let r_first_dh = k256.ecdh(&r_e_sec, &i_e_pub).unwrap();

    // Initiator does the first DH using the responder ephemeral public key
    // and initiator ephemeral secret key
    let i_first_dh = k256.ecdh(&i_e_sec, &r_e_pub).unwrap();

    // Both initiator and responder have the same shared secret
    assert_eq!(r_first_dh, i_first_dh);

    // The responder sends the responder static public key to initiator,
    // encrypted using the shared secret calculated from the first DH

    // Responder does the second DH using the initiator ephemeral public
    // key and the responder static secret key
    let r_second_dh = k256.ecdh(&r_e_sec, &i_s_pub).unwrap();

    // Initiator does the second DH using the responder static public key
    // and the initiator ephemeral secret key
    let i_second_dh = k256.ecdh(&i_s_sec, &r_e_pub).unwrap();

    // Both initiator and responder have the same shared secret again
    assert_eq!(r_second_dh, i_second_dh);

    // The initiator sends the initiator static public key to responder,
    // encrypted using the shared secret calculated from the second DH

    // Responder does the third DH using the initiator static public key
    // and the responder static ephemeral key
    let r_third_dh = k256.ecdh(&r_s_sec, &i_e_pub).unwrap();

    // Initiator does the third DH using the responder ephemeral public key
    // and the initiator static secret key
    let i_third_dh = k256.ecdh(&i_e_sec, &r_s_pub).unwrap();

    // Both initiator and responder have the same shared secret again
    assert_eq!(r_third_dh, i_third_dh);
}

#[test]
fn test_p256_dh() {

    // Initiator generates ephemeral key and test static key
    let p256 = AsymKeyType::P256;
    let (i_e_pub, i_e_sec) = p256.generate(get_rng());
    let (i_s_pub, i_s_sec) = p256.generate(get_rng());

    // Responder generates ephemeral key and test static key
    let (r_e_pub, r_e_sec) = p256.generate(get_rng());
    let (r_s_pub, r_s_sec) = p256.generate(get_rng());

    // Responder does the first DH using initiator ephemeral public key
    // and responder ephemeral secret key
    let r_first_dh = p256.ecdh(&r_e_sec, &i_e_pub).unwrap();

    // Initiator does the first DH using the responder ephemeral public key
    // and initiator ephemeral secret key
    let i_first_dh = p256.ecdh(&i_e_sec, &r_e_pub).unwrap();

    // Both initiator and responder have the same shared secret
    assert_eq!(r_first_dh, i_first_dh);

    // The responder sends the responder static public key to initiator,
    // encrypted using the shared secret calculated from the first DH

    // Responder does the second DH using the initiator ephemeral public
    // key and the responder static secret key
    let r_second_dh = p256.ecdh(&r_e_sec, &i_s_pub).unwrap();

    // Initiator does the second DH using the responder static public key
    // and the initiator ephemeral secret key
    let i_second_dh = p256.ecdh(&i_s_sec, &r_e_pub).unwrap();

    // Both initiator and responder have the same shared secret again
    assert_eq!(r_second_dh, i_second_dh);

    // The initiator sends the initiator static public key to responder,
    // encrypted using the shared secret calculated from the second DH

    // Responder does the third DH using the initiator static public key
    // and the responder static ephemeral key
    let r_third_dh = p256.ecdh(&r_s_sec, &i_e_pub).unwrap();

    // Initiator does the third DH using the responder ephemeral public key
    // and the initiator static secret key
    let i_third_dh = p256.ecdh(&i_e_sec, &r_s_pub).unwrap();

    // Both initiator and responder have the same shared secret again
    assert_eq!(r_third_dh, i_third_dh);
}

/*
fn print_key(data: &[u8]) {
    let mut i = 0;
    for b in data {
        if i == 0 {
            print!("        ");
        }
        print!("0x{:02x},", b);
        i += 1;
        if i == 11 {
            i = 0;
            println!("");
        }
    }
    println!("");
}

#[test]
fn gen_x25519() {
    // Initiator generates ephemeral key and test static key
    let x25519 = AsymKeyType::X25519;
    let (e_pub, e_sec) = x25519.generate(get_rng());
    let (s_pub, s_sec) = x25519.generate(get_rng());

    println!("(");
    println!("    /* static public */");
    println!("    TaggedSliceBuilder::new(\"key.x25519.public\", 32).from_bytes(&[");
    print_key(s_pub.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* static secret */");
    println!("    TaggedSliceBuilder::new(\"key.x25519.secret\", 32).from_bytes(&[");
    print_key(s_sec.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* ephemeral public */");
    println!("    TaggedSliceBuilder::new(\"key.x25519.public\", 32).from_bytes(&[");
    print_key(e_pub.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* ephemeral secret */");
    println!("    TaggedSliceBuilder::new(\"key.x25519.secret\", 32).from_bytes(&[");
    print_key(e_sec.as_ref());
    println!("    ]).build().unwrap(),");
    println!(")");
}

#[test]
fn gen_k256() {
    // Initiator generates ephemeral key and test static key
    let k256 = AsymKeyType::K256;
    let (e_pub, e_sec) = k256.generate(get_rng());
    let (s_pub, s_sec) = k256.generate(get_rng());

    println!("(");
    println!("    /* static public */");
    println!("    TaggedSliceBuilder::new(\"key.k256.public\", 33).from_bytes(&[");
    print_key(s_pub.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* static secret */");
    println!("    TaggedSliceBuilder::new(\"key.k256.secret\", 32).from_bytes(&[");
    print_key(s_sec.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* ephemeral public */");
    println!("    TaggedSliceBuilder::new(\"key.k256.public\", 33).from_bytes(&[");
    print_key(e_pub.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* ephemeral secret */");
    println!("    TaggedSliceBuilder::new(\"key.k256.secret\", 32).from_bytes(&[");
    print_key(e_sec.as_ref());
    println!("    ]).build().unwrap(),");
    println!(")");
}

#[test]
fn gen_p256() {
    // Initiator generates ephemeral key and test static key
    let p256 = AsymKeyType::P256;
    let (e_pub, e_sec) = p256.generate(get_rng());
    let (s_pub, s_sec) = p256.generate(get_rng());

    println!("(");
    println!("    /* static public */");
    println!("    TaggedSliceBuilder::new(\"key.p256.public\", 33).from_bytes(&[");
    print_key(s_pub.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* static secret */");
    println!("    TaggedSliceBuilder::new(\"key.p256.secret\", 32).from_bytes(&[");
    print_key(s_sec.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* ephemeral public */");
    println!("    TaggedSliceBuilder::new(\"key.p256.public\", 33).from_bytes(&[");
    print_key(e_pub.as_ref());
    println!("    ]).build().unwrap(),");
    println!("    /* ephemeral secret */");
    println!("    TaggedSliceBuilder::new(\"key.p256.secret\", 32).from_bytes(&[");
    print_key(e_sec.as_ref());
    println!("    ]).build().unwrap(),");
    println!(")");
}
*/

