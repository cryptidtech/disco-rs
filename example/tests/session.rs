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
fn n_x25519_handshake() {
    // Noise, N handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_N_25519_STROBEv1.0.2").unwrap();

    n_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn n_k256_handshake() {
    // Noise, N handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_N_K256_STROBEv1.0.2").unwrap();

    n_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn n_p256_handshake() {
    // Noise, N handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_N_P256_STROBEv1.0.2").unwrap();

    n_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn n_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
        .out_of_order(false)
        .build_initiator().unwrap();

    /*****************/
    /*   Bob Setup   */
    /*****************/

    // generate the disco state for bob
    let mut bob = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&bss)
        .local_static_public_key(&bsp)
        .local_ephemeral_secret_key(&bes)
        .local_ephemeral_public_key(&bep)
        .out_of_order(false)
        .build_responder().unwrap();

    /***********/
    /*  Alice  */
    /***********/

    // send the first handshake message without a payload
    // -> e, es
    let alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
        .from_bytes(b"hello")
        .build().unwrap();

    let mut alice_to_bob = [0u8; 1024];
    let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

    assert!(alice.is_keyed());
    assert!(alice.is_transport());

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    let mut bob_in_payload = TaggedSlice::<1024>::default();
    let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();

    assert_eq!(bob_in_payload.length(), 5);
    assert_eq!(alice_out_payload, bob_in_payload);
    assert!(bob.is_keyed());
    assert!(bob.is_transport());
}

#[test]
fn k_x25519_handshake() {
    // Noise, K handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_K_25519_STROBEv1.0.2").unwrap();

    k_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn k_k256_handshake() {
    // Noise, K handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_K_K256_STROBEv1.0.2").unwrap();

    k_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn k_p256_handshake() {
    // Noise, N handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_K_P256_STROBEv1.0.2").unwrap();

    k_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn k_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
        .out_of_order(false)
        .build_initiator().unwrap();

    /*****************/
    /*   Bob Setup   */
    /*****************/

    // generate the disco state for bob
    let mut bob = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&bss)
        .local_static_public_key(&bsp)
        .local_ephemeral_secret_key(&bes)
        .local_ephemeral_public_key(&bep)
        .remote_static_public_key(&asp)
        .out_of_order(false)
        .build_responder().unwrap();

    /***********/
    /*  Alice  */
    /***********/

    // send the first handshake message without a payload
    // -> e, es, ss
    let alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
        .from_bytes(b"hello")
        .build().unwrap();

    let mut alice_to_bob = [0u8; 1024];
    let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

    assert!(alice.is_keyed());
    assert!(alice.is_transport());

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    let mut bob_in_payload = TaggedSlice::<1024>::default();
    let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();

    assert_eq!(bob_in_payload.length(), 5);
    assert_eq!(alice_out_payload, bob_in_payload);
    assert!(bob.is_keyed());
    assert!(bob.is_transport());
}

#[test]
fn x_x25519_handshake() {
    // Noise, X handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_X_25519_STROBEv1.0.2").unwrap();

    x_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn x_k256_handshake() {
    // Noise, X handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_X_K256_STROBEv1.0.2").unwrap();

    x_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn x_p256_handshake() {
    // Noise, X handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_X_P256_STROBEv1.0.2").unwrap();

    x_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn x_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
        .out_of_order(false)
        .build_initiator().unwrap();

    /*****************/
    /*   Bob Setup   */
    /*****************/

    // generate the disco state for bob
    let mut bob = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&bss)
        .local_static_public_key(&bsp)
        .local_ephemeral_secret_key(&bes)
        .local_ephemeral_public_key(&bep)
        .out_of_order(false)
        .build_responder().unwrap();

    /***********/
    /*  Alice  */
    /***********/

    // send the first handshake message without a payload
    // -> e, es, s, ss
    let alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
        .from_bytes(b"hello")
        .build().unwrap();

    let mut alice_to_bob = [0u8; 1024];
    let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

    assert!(alice.is_keyed());
    assert!(alice.is_transport());

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    let mut bob_in_payload = TaggedSlice::<1024>::default();
    let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();

    assert_eq!(bob_in_payload.length(), 5);
    assert_eq!(alice_out_payload, bob_in_payload);
    assert!(bob.is_keyed());
    assert!(bob.is_transport());
}

#[test]
fn nn_x25519_handshake() {
    // Noise, NN handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NN_25519_STROBEv1.0.2").unwrap();

    xx_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn nn_k256_handshake() {
    // Noise, NN handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NN_K256_STROBEv1.0.2").unwrap();

    xx_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn nn_p256_handshake() {
    // Noise, NN handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NN_P256_STROBEv1.0.2").unwrap();

    xx_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

#[test]
fn kk_x25519_handshake() {
    // Noise, KK handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_KK_25519_STROBEv1.0.2").unwrap();

    kk_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn kk_k256_handshake() {
    // Noise, KK handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_KK_K256_STROBEv1.0.2").unwrap();

    kk_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn kk_p256_handshake() {
    // Noise, KK handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_KK_P256_STROBEv1.0.2").unwrap();

    kk_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn kk_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
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

    // generate the disco state for bob
    let mut bob = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&bss)
        .local_static_public_key(&bsp)
        .local_ephemeral_secret_key(&bes)
        .local_ephemeral_public_key(&bep)
        .remote_static_public_key(&asp)
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
    // -> e, es, ss
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

        let tag = TagBuilder::from_bytes(&alice_to_bob).build().unwrap();
        assert_eq!(tag.class(), idx('f'));      /* strobe */
        assert_eq!(tag.subclass(), idx('c'));   /* clr */
        assert_eq!(tag.subsubclass(), 1);       /* data recv */
        assert!(alice.is_keyed());
    }

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    {
        let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert!(bob.is_keyed());
    }

   
    // send the second message without a payload
    // <- e, ee, se
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        // make sure we're in encrypted mode
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_transport());
        assert!(alice.is_keyed());
    }

    // send the third message with "hello" payload
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    // send an encrypted payload in transport mode
    {
        // set the payload
        bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"world")
            .build().unwrap();

        // clear the buffer
        bob_to_alice.zeroize();
        
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

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

        assert_eq!(alice_in_payload.length(), 5);
        assert_eq!(bob_out_payload, alice_in_payload);
        assert!(alice.is_keyed());
    }
}

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
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert_eq!(bob.is_keyed(), false);
    }

   
    // send the second message without a payload
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        // make sure we're in encrypted mode
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_keyed());
    }

    // send the third message with "hello" payload
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    // send an encrypted payload in transport mode
    {
        // set the payload
        bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"world")
            .build().unwrap();

        // clear the buffer
        bob_to_alice.zeroize();
        
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

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

        assert_eq!(alice_in_payload.length(), 5);
        assert_eq!(bob_out_payload, alice_in_payload);
        assert!(alice.is_keyed());
    }
}

#[test]
fn ik_x25519_handshake() {
    // Noise, IK handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_IK_25519_STROBEv1.0.2").unwrap();

    ik_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn ik_k256_handshake() {
    // Noise, IK handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_IK_K256_STROBEv1.0.2").unwrap();

    ik_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn ik_p256_handshake() {
    // Noise, IK handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_IK_P256_STROBEv1.0.2").unwrap();

    ik_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn ik_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
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
    // -> e, es, s, ss
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

        let tag = TagBuilder::from_bytes(&alice_to_bob).build().unwrap();
        assert_eq!(tag.class(), idx('f'));      /* strobe */
        assert_eq!(tag.subclass(), idx('c'));   /* clr */
        assert_eq!(tag.subsubclass(), 1);       /* data recv */
        assert!(alice.is_keyed());
    }

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    {
        let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert!(bob.is_keyed());
    }

   
    // send the second message without a payload
    // <- e, ee, se
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        // make sure we're in encrypted mode
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_transport());
        assert!(alice.is_keyed());
    }

    // send the third message with "hello" payload
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    // send an encrypted payload in transport mode
    {
        // set the payload
        bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"world")
            .build().unwrap();

        // clear the buffer
        bob_to_alice.zeroize();
        
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

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

        assert_eq!(alice_in_payload.length(), 5);
        assert_eq!(bob_out_payload, alice_in_payload);
        assert!(alice.is_keyed());
    }
}

#[test]
fn nk_x25519_handshake() {
    // Noise, NK handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NK_25519_STROBEv1.0.2").unwrap();

    nk_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn nk_k256_handshake() {
    // Noise, NK handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NK_K256_STROBEv1.0.2").unwrap();

    nk_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn nk_p256_handshake() {
    // Noise, NK handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NK_P256_STROBEv1.0.2").unwrap();

    nk_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn nk_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
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
    // -> e, es, s, ss
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

        let tag = TagBuilder::from_bytes(&alice_to_bob).build().unwrap();
        assert_eq!(tag.class(), idx('f'));      /* strobe */
        assert_eq!(tag.subclass(), idx('c'));   /* clr */
        assert_eq!(tag.subsubclass(), 1);       /* data recv */
        assert!(alice.is_keyed());
    }

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    {
        let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert!(bob.is_keyed());
    }

   
    // send the second message without a payload
    // <- e, ee, se
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        // make sure we're in encrypted mode
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_transport());
        assert!(alice.is_keyed());
    }

    // send the third message with "hello" payload
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    // send an encrypted payload in transport mode
    {
        // set the payload
        bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"world")
            .build().unwrap();

        // clear the buffer
        bob_to_alice.zeroize();
        
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

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

        assert_eq!(alice_in_payload.length(), 5);
        assert_eq!(bob_out_payload, alice_in_payload);
        assert!(alice.is_keyed());
    }
}

#[test]
fn nx_x25519_handshake() {
    // Noise, NX handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NX_25519_STROBEv1.0.2").unwrap();

    nx_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn nx_k256_handshake() {
    // Noise, NX handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NX_K256_STROBEv1.0.2").unwrap();

    nx_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn nx_p256_handshake() {
    // Noise, NX handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NX_P256_STROBEv1.0.2").unwrap();

    nx_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn nx_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

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
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

        let tag = TagBuilder::from_bytes(&alice_to_bob).build().unwrap();
        assert_eq!(tag.class(), idx('f'));      /* strobe */
        assert_eq!(tag.subclass(), idx('c'));   /* clr */
        assert_eq!(tag.subsubclass(), 1);       /* data recv */
    }

    /***********/
    /*   Bob   */
    /***********/

    // receive the first message and verify empty payload
    {
        let _len = bob.recv_message(&alice_to_bob, &mut bob_in_payload).unwrap();

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
    }

   
    // send the second message without a payload
    // <- e, ee, s, es
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        // make sure we're in encrypted mode
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_transport());
        assert!(alice.is_keyed());
    }

    // send the third message with "hello" payload
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    // send an encrypted payload in transport mode
    {
        // set the payload
        bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"world")
            .build().unwrap();

        // clear the buffer
        bob_to_alice.zeroize();
        
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

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

        assert_eq!(alice_in_payload.length(), 5);
        assert_eq!(bob_out_payload, alice_in_payload);
        assert!(alice.is_keyed());
    }
}

#[test]
fn xk1_x25519_handshake() {
    // Noise, XK1 handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_XK1_25519_STROBEv1.0.2").unwrap();

    xk1_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn xk1_k256_handshake() {
    // Noise, XK1 handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_XK1_K256_STROBEv1.0.2").unwrap();

    xk1_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn xk1_p256_handshake() {
    // Noise, XK1 handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_XK1_P256_STROBEv1.0.2").unwrap();

    xk1_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn xk1_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
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
    let bob_out_payload = TaggedSlice::<1024>::default();

    /***********/
    /*  Alice  */
    /***********/

    // -> e
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert_eq!(bob.is_keyed(), false);
    }

   
    // <- e, ee, es
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        // make sure we're in encrypted mode
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_keyed());
    }

    // -> s, se
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }
}

#[test]
fn kk1_x25519_handshake() {
    // Noise, KK1 handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_KK1_25519_STROBEv1.0.2").unwrap();

    kk1_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn kk1_k256_handshake() {
    // Noise, KK1 handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_KK1_K256_STROBEv1.0.2").unwrap();

    kk1_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn kk1_p256_handshake() {
    // Noise, KK1 handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_KK1_P256_STROBEv1.0.2").unwrap();

    kk1_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn kk1_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    let (asp, ass, aep, aes) = alice;
    let (bsp, bss, bep, bes) = bob;

    /*****************/
    /*  Alice Setup  */
    /*****************/

    // generate the disco state for alice
    let mut alice = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&ass)
        .local_static_public_key(&asp)
        .local_ephemeral_secret_key(&aes)
        .local_ephemeral_public_key(&aep)
        .remote_static_public_key(&bsp)
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

    // generate the disco state for bob
    let mut bob = Builder::<AsymKeyType, x25519::PublicKeySlice, x25519::SecretKeySlice>::new(params)
        .local_static_secret_key(&bss)
        .local_static_public_key(&bsp)
        .local_ephemeral_secret_key(&bes)
        .local_ephemeral_public_key(&bep)
        .remote_static_public_key(&asp)
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
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert_eq!(bob.is_keyed(), false);
    }

   
    // send second handshake message without payload
    // <- e, ee, es, se, ss
    {
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

        // make sure we're in encrypted mode
        assert!(bob.is_keyed());
    }

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    {
        let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

        let re = alice.get_remote_ephemeral().unwrap();
        assert_eq!(re, bep);
        assert_eq!(alice_in_payload.length(), 0);
        assert!(alice.is_keyed());
    }

    // send the third handshake message with encrypted payload
    // -> s, se
    {
        // set the payload
        alice_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"hello")
            .build().unwrap();

        // clear the buffer
        alice_to_bob.zeroize();
        
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        assert_eq!(bob_in_payload.length(), 5);
        assert_eq!(alice_out_payload, bob_in_payload);
        assert!(bob.is_transport());
        assert!(bob.is_keyed());
    }

    // send an encrypted payload in transport mode
    {
        // set the payload
        bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
            .from_bytes(b"world")
            .build().unwrap();

        // clear the buffer
        bob_to_alice.zeroize();
        
        let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

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

        assert_eq!(alice_in_payload.length(), 5);
        assert_eq!(bob_out_payload, alice_in_payload);
        assert!(alice.is_keyed());
    }
}

#[test]
fn nnpsk2_x25519_handshake() {
    // Noise, NNpsk2 handshake, Curve25519 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NNpsk2_25519_STROBEv1.0.2").unwrap();

    nnpsk2_handshake(alice_x25519_keys(), bob_x25519_keys(), &params);
}

#[test]
fn nnpsk2_k256_handshake() {
    // Noise, NNpsk2 handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NNpsk2_K256_STROBEv1.0.2").unwrap();

    nnpsk2_handshake(alice_k256_keys(), bob_k256_keys(), &params);
}

#[test]
fn nnpsk2_p256_handshake() {
    // Noise, NNpsk2 handshake, NIST K256 keys, and Strobe
    let params = Params::<AsymKeyType>::from_str("Noise_NNpsk2_P256_STROBEv1.0.2").unwrap();

    nnpsk2_handshake(alice_p256_keys(), bob_p256_keys(), &params);
}

fn nnpsk2_handshake(alice: AliceKeys, bob: BobKeys, params: &Params<AsymKeyType>) {

    // get the pre-shared key
    let psk = psk();

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
        .pre_shared_key(&psk)
        .out_of_order(false)
        .build_initiator().unwrap();

    // message buffer
    let mut alice_to_bob = [0u8; 1024];

    // payloads
    let mut alice_in_payload = TaggedSlice::<1024>::default();
    let alice_out_payload = TaggedSlice::<1024>::default();

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
        .pre_shared_key(&psk)
        .out_of_order(false)
        .build_responder().unwrap();

    // message buffer
    let mut bob_to_alice = [0u8; 1024];

    // payloads
    let mut bob_in_payload = TaggedSlice::<1024>::default();

    /***********/
    /*  Alice  */
    /***********/

    // -> e
    {
        let _len = alice.send_message(&alice_out_payload, &mut alice_to_bob).unwrap();

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

        let re = bob.get_remote_ephemeral().unwrap();
        assert_eq!(re, aep);
        assert_eq!(bob_in_payload.length(), 0);
        assert_eq!(bob.is_keyed(), false);
    }

   
    // <- e, ee, psk
    
    // set the payload
    let bob_out_payload = TaggedSliceBuilder::new("undefined.undefined", 5)
        .from_bytes(b"hello")
        .build().unwrap();

    let _len = bob.send_message(&bob_out_payload, &mut bob_to_alice).unwrap();

    // make sure we're in encrypted mode
    assert!(bob.is_keyed());
    assert!(bob.is_transport());

    /***********/
    /*  Alice  */
    /***********/

    // receive the second message and verify empty payload
    let _len = alice.recv_message(&bob_to_alice, &mut alice_in_payload).unwrap();

    let re = alice.get_remote_ephemeral().unwrap();
    assert_eq!(re, bep);
    assert_eq!(alice_in_payload.length(), 5);
    assert_eq!(alice_in_payload, bob_out_payload);
    assert!(alice.is_keyed());
    assert!(alice.is_transport());
}


