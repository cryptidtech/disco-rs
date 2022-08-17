mod common;
mod xeddsa;
mod one_way {
    use crate::{
        common::{recv, send},
        xeddsa::{
            DiscoBuilder, DiscoKeys, DiscoNonceGenerator, DiscoParams, DiscoPrologue, DiscoSession,
        },
    };
    use disco_rs::session::MSG_MAX_LEN;
    use std::str::FromStr;
    use zeroize::Zeroize;

    mod in_order {
        const O: bool = false;

        mod without_prologue {
            use super::{super::*, O};
            const P: &'static str = "";
            const R: u64 = u64::max_value() - 1;

            #[test]
            fn n() {
                do_n(O, P, R);
            }
            #[test]
            fn k() {
                do_k(O, P, R);
            }
            #[test]
            fn x() {
                do_x(O, P, R);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P, R);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P, R);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P, R);
            }
        }

        mod with_prologue {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = u64::max_value() - 1;

            #[test]
            fn n() {
                do_n(O, P, R);
            }
            #[test]
            fn k() {
                do_k(O, P, R);
            }
            #[test]
            fn x() {
                do_x(O, P, R);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P, R);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P, R);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P, R);
            }
        }

        mod with_rekey {
            use super::{super::*, O};
            const P: &'static str = "";
            const R: u64 = 2; //rekey every 2 messages

            #[test]
            fn n() {
                do_n(O, P, R);
            }
            #[test]
            fn k() {
                do_k(O, P, R);
            }
            #[test]
            fn x() {
                do_x(O, P, R);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P, R);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P, R);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P, R);
            }
        }
    }

    mod out_of_order {
        const O: bool = true;

        mod without_prologue {
            use super::{super::*, O};
            const P: &'static str = "";
            const R: u64 = u64::max_value() - 1;

            #[test]
            fn n() {
                do_n(O, P, R);
            }
            #[test]
            fn k() {
                do_k(O, P, R);
            }
            #[test]
            fn x() {
                do_x(O, P, R);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P, R);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P, R);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P, R);
            }
        }

        mod with_prologue {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = u64::max_value() - 1;

            #[test]
            fn n() {
                do_n(O, P, R);
            }
            #[test]
            fn k() {
                do_k(O, P, R);
            }
            #[test]
            fn x() {
                do_x(O, P, R);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P, R);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P, R);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P, R);
            }
        }

        mod with_rekey {
            use super::{super::*, O};
            const P: &'static str = "";
            const R: u64 = 2; //rekey every 2 messages

            #[test]
            fn n() {
                do_n(O, P, R);
            }
            #[test]
            fn k() {
                do_k(O, P, R);
            }
            #[test]
            fn x() {
                do_x(O, P, R);
            }
            #[test]
            fn npsk0() {
                do_npsk0(O, P, R);
            }
            #[test]
            fn kpsk0() {
                do_kpsk0(O, P, R);
            }
            #[test]
            fn xpsk1() {
                do_xpsk1(O, P, R);
            }
        }
    }

    fn do_n(ooo: bool, prologue: &str, rekey: u64) {
        // only need responder keys
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_N_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> e, es

        // the initiator does not have a static key pair and receives the responder's static public
        // key before initiating the handshake.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, &mut initiator, &mut responder);
    }

    fn do_k(ooo: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_K_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

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
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key
        // before initiating the handshake.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&i.sp)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, &mut initiator, &mut responder);
    }

    fn do_x(ooo: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_X_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

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
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key pair
        // in the first message after encryption begins.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, &mut initiator, &mut responder);
    }

    fn do_npsk0(ooo: bool, prologue: &str, rekey: u64) {
        // only need responder keys
        let r = DiscoKeys::r_keys();
        let psk = DiscoKeys::psk();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_Npsk0_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

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
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .pre_shared_key(&psk)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, &mut initiator, &mut responder);
    }

    fn do_kpsk0(ooo: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();
        let psk = DiscoKeys::psk();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_Kpsk0_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

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
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key
        // before initiating the handshake.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&i.sp)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .pre_shared_key(&psk)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, &mut initiator, &mut responder);
    }

    fn do_xpsk1(ooo: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();
        let psk = DiscoKeys::psk();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_Xpsk1_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

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
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and receives the initiator's static public key pair
        // in the first message after encryption begins.
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&r.sp)
            .local_static_secret_key(&r.ss)
            .pre_shared_key(&psk)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, &mut initiator, &mut responder);
    }

    fn do_it(ooo: bool, initiator: &mut DiscoSession, responder: &mut DiscoSession) {
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
        let recv_order = if ooo { &out_of_order } else { &in_order };

        send(
            initiator,
            &in_order,
            &plaintext,
            &pt,
            &mut ciphertext,
            &mut ct,
            1,
        );

        plaintext.zeroize();

        recv(responder, recv_order, &mut plaintext, &ciphertext, &ct, 1);

        if ooo {
            assert_eq!(b"world, fun!this hello is ", &plaintext[0..25]);
        } else {
            assert_eq!(b"hello world, this is fun!", &plaintext[0..25]);
        }
    }
}
