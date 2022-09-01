mod common;
mod xeddsa;
mod one_way {
    use crate::{
        common::{recv, send},
        xeddsa::{
            DiscoBuilder, DiscoKeys, DiscoNonceGenerator, DiscoParams, DiscoPrologue, DiscoSession,
        },
    };
    use disco_rs::{session::MSG_MAX_LEN, transport::TransportOrder};
    use std::str::FromStr;
    use zeroize::Zeroize;

    mod in_order {
        use super::TransportOrder;
        const O: TransportOrder = TransportOrder::InOrder;

        mod without_prologue {
            use super::{super::*, O};
            const P: &'static str = "";

            #[test]
            fn n() {
                do_n(O, P);
            }
            #[test]
            fn k() {
                do_k(O, P);
            }
            #[test]
            fn x() {
                do_x(O, P);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P);
            }
        }

        mod with_prologue {
            use super::{super::*, O};
            const P: &'static str = "the prologue";

            #[test]
            fn n() {
                do_n(O, P);
            }
            #[test]
            fn k() {
                do_k(O, P);
            }
            #[test]
            fn x() {
                do_x(O, P);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P);
            }
        }
    }

    mod out_of_order {
        use super::TransportOrder;
        const O: TransportOrder = TransportOrder::OutOfOrder;

        mod without_prologue {
            use super::{super::*, O};
            const P: &'static str = "";

            #[test]
            fn n() {
                do_n(O, P);
            }
            #[test]
            fn k() {
                do_k(O, P);
            }
            #[test]
            fn x() {
                do_x(O, P);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P);
            }
        }

        mod with_prologue {
            use super::{super::*, O};
            const P: &'static str = "the prologue";

            #[test]
            fn n() {
                do_n(O, P);
            }
            #[test]
            fn k() {
                do_k(O, P);
            }
            #[test]
            fn x() {
                do_x(O, P);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P);
            }
        }
    }

    fn do_n(order: TransportOrder, prologue: &str) {
        // only need responder keys
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_N_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new();

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> e, es

        // the initiator does not have a static key pair and receives the responder's static public
        // key before initiating the handshake.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(order, &mut initiator, &mut responder);
    }

    fn do_k(order: TransportOrder, prologue: &str) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_K_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new();

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> s
        // <- s
        // ...
        // -> e, es, ss

        // the initiator has a static key pair and receives the responder's static public key
        // before initiating the handshake.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key
        // before initiating the handshake.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&i.sp)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(order, &mut initiator, &mut responder);
    }

    fn do_x(order: TransportOrder, prologue: &str) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_X_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new();

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> e, es, s, ss

        // the initiator has a static key pair and receives the responder's static public key
        // before initiating the handshake. the initiator sends their static public key in the first
        // message after encryption begins.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key pair
        // in the first message after encryption begins.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(order, &mut initiator, &mut responder);
    }

    fn do_npsk0(order: TransportOrder, prologue: &str) {
        // only need responder keys
        let r = DiscoKeys::r_keys();
        let psk = DiscoKeys::psk();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_Npsk0_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new();

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> psk, e, es

        // the initiator does not have a static key pair and receives the responder's static public
        // key before initiating the handshake.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .pre_shared_key(&psk)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .pre_shared_key(&psk)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(order, &mut initiator, &mut responder);
    }

    fn do_kpsk0(order: TransportOrder, prologue: &str) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();
        let psk = DiscoKeys::psk();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_Kpsk0_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new();

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> s
        // <- s
        // ...
        // -> psk, e, es, ss

        // the initiator has a static key pair and receives the responder's static public key
        // before initiating the handshake.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .pre_shared_key(&psk)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key
        // before initiating the handshake.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&i.sp)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .pre_shared_key(&psk)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(order, &mut initiator, &mut responder);
    }

    fn do_xpsk1(order: TransportOrder, prologue: &str) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();
        let psk = DiscoKeys::psk();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_Xpsk1_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new();

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> e, es, s, ss, psk

        // the initiator has a static key pair and receives the responder's static public key
        // before initiating the handshake. the initiator sends their static public key in the first
        // message after encryption begins.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .pre_shared_key(&psk)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key pair
        // in the first message after encryption begins.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .pre_shared_key(&psk)
            .msg_order(&order)
            .with_prologue(prologue)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(order, &mut initiator, &mut responder);
    }

    fn do_it(order: TransportOrder, initiator: &mut DiscoSession, responder: &mut DiscoSession) {
        let mut plaintext = [0u8; MSG_MAX_LEN];
        let mut ciphertext = [0u8; MSG_MAX_LEN];

        // the overall stream to send
        plaintext[0..25].copy_from_slice(b"hello world, this is fun!");

        // the order in which to send/recv the stream messages
        let in_order = vec![0, 1, 2, 3, 4, 5];
        let out_of_order = vec![0, 2, 5, 3, 1, 4];

        // the start and end indexes of each message in the stream, the first message is empty
        // since the first message is sent unencrypted
        let pt: Vec<(usize, usize)> = vec![(0, 0), (0, 6), (6, 13), (13, 18), (18, 21), (21, 25)];

        // the vector to record the start and end indexes of the ciphertext messages in the stream
        let mut ct: Vec<(usize, usize)> = Vec::new();

        // get the order in which ciphertexts are received and processed
        let recv_order = match order {
            TransportOrder::InOrder => &in_order,
            TransportOrder::OutOfOrder => &out_of_order,
        };

        send(
            initiator,
            &in_order,
            &plaintext,
            &pt,
            &mut ciphertext,
            &mut ct,
        );

        plaintext.zeroize();

        recv(responder, recv_order, &mut plaintext, &ciphertext, &ct);

        match order {
            TransportOrder::InOrder => assert_eq!(b"hello world, this is fun!", &plaintext[0..25]),
            TransportOrder::OutOfOrder => {
                assert_eq!(b"world, fun!this hello is ", &plaintext[0..25])
            }
        }
    }
}
