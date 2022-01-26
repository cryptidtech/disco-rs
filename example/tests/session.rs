use cde::{idx, TagBuilder};
use disco_rs::{
    builder::Builder,
    key::TaggedData,
    params::Params,
};
use disco_ecdh_example::{
    tagged::{TaggedSlice, TaggedSliceBuilder},
    key::soft::{AsymKeyType, x25519},
};
use std::str::FromStr;
use zeroize::Zeroize;

#[allow(dead_code)]
mod inner;
use inner::*;

type AliceKeys = (TaggedSlice<33>, TaggedSlice<32>, TaggedSlice<33>, TaggedSlice<32>);
type BobKeys = (TaggedSlice<33>, TaggedSlice<32>, TaggedSlice<33>, TaggedSlice<32>);

#[test]
fn xx_x25519_handshake() {
    // Noise, XX handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_XX_25519_STROBEv1.0.2").unwrap();

    xx_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn xx_k256_handshake() {
    // Noise, XX handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_XX_K256_STROBEv1.0.2").unwrap();

    xx_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn xx_p256_handshake() {
    // Noise, XX handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_XX_P256_STROBEv1.0.2").unwrap();

    xx_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn xx_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    /*****************/
    /*  Alice Setup  */
    /*****************/

    let (asp, ass, aep, aes) = alice;

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .out_of_order(false)
        .build_initiator().unwrap();

    // message buffer
    let mut alice_to_bob = [0u8; 1024];

    // payloads
    let mut alice_in_payload = TaggedSlice::<1024>::default();
    let mut alice_out_payload = TaggedSlice::<1024>::default();

    /*****************/
    /*   Bob Setup   */
    /*****************/

    let (bsp, bss, bep, bes) = bob;

    // generate the disco state for bob
    let mut bob = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&bss)
        .local_static_public_key(&bsp)
        .local_ephemeral_secret_key(&bes)
        .local_ephemeral_public_key(&bep)
        .out_of_order(false)
        .build_responder().unwrap();

    // message buffer
    let mut bob_to_alice = [0u8; 1024];

    // payloads
    let mut bob_in_payload = TaggedSlice::<1024>::default();
    let mut bob_out_payload = TaggedSlice::<1024>::default();

    /***********/
    /*  Alice  */
    /***********/

    // send the first handshake message without a payload
    // -> e
    //println!("\n-> e");
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

        /*
        print!("\nsent: ({}) [ ", len);
        for b in &alice_to_bob[0..len] {
            print!("{:02x}, ", b);
        }
        println!("]\n");
        */

        let tag = TagBuilder::from_bytes(&alice_to_bob).build().unwrap();
        assert_eq!(tag.class(), idx('f'));      /* strobe */
        assert_eq!(tag.subclass(), idx('c'));   /* clr */
        assert_eq!(tag.subsubclass(), 1);       /* data recv */
        assert_eq!(alice.is_keyed(), false);
    }

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    {
        let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();
        //println!("{}", len);

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert_eq!(bob.is_keyed(), false);
    }

   
    // send second handshake message without payload
    // <- e, ee, s, es
    //println!("\n<- e, ee, s, es");
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        /*
        print!("\nsent: ({}) [ ", len);
        for b in &bob_to_alice[0..len] {
            print!("{:02x}, ", b);
        }
        println!("]\n");
        */

        // make sure we're in encrypted mode
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();
        //println!("{}", len);

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_keyed());
    }

    // send the third handshake message with encrypted payload
    // -> s, se
    //println!("\n-> s, se");
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

        /*
        print!("\nsent: ({}) [ ", len);
        for b in &alice_to_bob[0..len] {
            print!("{:02x}, ", b);
        }
        println!("]\n");
        */

        assert!(alice.is_transport());
        assert!(alice.is_keyed());
    }

    /***********/
    /*   Bob   */
    /***********/

    // receive the third message and verify encrypted payload
    {
        // clear the incoming payload
        bob_in_payload.zeroize();

        let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();
        //println!("{}", len);

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    // send an encrypted payload in transport mode
    //println!("\n<-");
    {
        // set the payload
        bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"world")
            .build().unwrap();

        // clear the buffer
        bob_to_alice.zeroize();
        
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        /*
        print!("\nsent: ({}) [ ", len);
        for b in &bob_to_alice[0..len] {
            print!("{:02x}, ", b);
        }
        println!("]\n");
        */
        
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        // clear the incoming payload
        alice_in_payload.zeroize();

        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();
        //println!("{}", len);

        assert_eq!(alice_in_payload.length(), 5);
        assert_eq!(bob_out_payload, alice_in_payload);
        assert!(alice.is_keyed());
    }
}

