mod common;
mod xeddsa;
mod two_way {
    use crate::{
        common::{recv, send, send_and_recv},
        xeddsa::{
            DiscoBuilder, DiscoKeys, DiscoNonceGenerator, DiscoParams, DiscoPrologue, DiscoSession,
        },
    };
    use disco_rs::session::MSG_MAX_LEN;
    use std::str::FromStr;

    mod in_order {
        const O: bool = false;

        mod without_prologue {
            use super::{super::*, O};
            const P: &'static str = "";
            const R: u64 = u64::max_value() - 1;
            const S: bool = false;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }

        mod with_prologue {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = u64::max_value() - 1;
            const S: bool = false;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }

        mod with_rekey {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = 2; // rekey every 2 msgs
            const S: bool = false;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }

        mod serialized_sessions {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = 2; // rekey every 2 msgs
            const S: bool = true;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }
    }

    mod out_of_order {
        const O: bool = false;

        mod without_prologue {
            use super::{super::*, O};
            const P: &'static str = "";
            const R: u64 = u64::max_value() - 1;
            const S: bool = false;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }

        mod with_prologue {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = u64::max_value() - 1;
            const S: bool = false;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }

        mod with_rekey {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = 2; // rekey every 2 msgs
            const S: bool = false;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }
        mod serialized_sessions {
            use super::{super::*, O};
            const P: &'static str = "the prologue";
            const R: u64 = 2; // rekey every 2 msgs
            const S: bool = true;

            #[test]
            fn nn() {
                do_nn(O, S, P, R);
            }
            #[test]
            fn kk() {
                do_kk(O, S, P, R);
            }
            #[test]
            fn xx() {
                do_xx(O, S, P, R);
            }
            #[test]
            fn ik() {
                do_ik(O, S, P, R);
            }
            #[test]
            fn ix() {
                do_ix(O, S, P, R);
            }
            #[test]
            fn nk() {
                do_nk(O, S, P, R);
            }
            #[test]
            fn nx() {
                do_nx(O, S, P, R);
            }
            #[test]
            fn xk1() {
                do_xk1(O, S, P, R);
            }
            #[test]
            fn kk1() {
                do_kk1(O, S, P, R);
            }
            #[test]
            fn nnpsk2() {
                do_nnpsk2(O, S, P, R);
            }
        }
    }

    fn do_nn(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_NN_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> e, ee

        // the initiator does not have a static key pair
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder does not have a static key pair
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_kk(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_KK_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> s
        // <- s
        // ...
        // -> e, es, ss
        // <- e, ee, se

        // the initiator has a static key pair and receives the responder&'s static public key
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

        // the responder has a static key pair and receives the initiator&'s static public key
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_xx(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_XX_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> e
        // <- e, ee, s, es
        // -> s, se

        // the initiator has a static key pair and sends their static public key in the first
        // message after encryption begins.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and sends their static public key to the initiator in
        // the first encrypted respond and receives the initiator&'s static public key in the second
        // message from them.
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_ik(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_IK_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> e, es, s, ss
        // <- e, ee, se

        // the initiator has a static key pair and receives the responder&'s static public key
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

        // the responder has a static key pair and receives the initiator&'s static public key
        // during the handshake.
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_ix(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_IX_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> e, s
        // <- e, ee, se, s, es

        // the initiator has a static key pair and sends their static public key in the first
        // message before encryption starts
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and sends their static public key to the initiator
        // in the first response after encryption begins.
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_nk(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_NK_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> e, es
        // <- e, ee

        // the initiator does not have a static key pair but receives the responder&'s static public
        // key before handshaking begins.
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_nx(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_NX_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> e, es
        // <- e, ee, s, es

        // the initiator does not have a static key pair and receives the responder&'s static public
        // key in the first response after encryption has begun.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and transmits it in the first response after
        // encryption has begun.
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_xk1(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_XK1_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // ...
        // -> e
        // <- e, ee, es
        // -> s, se

        // the initiator has a static key pair, receives the responder&'s static public key before
        // handshaking and transmits its static public key in the second message after encryption
        // has begun.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and sends their static public key to the initiator
        // before the handshaking and receives the their static public key in the second message
        // after encryption has begun.
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_kk1(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // get initiator and responder keys
        let i = DiscoKeys::i_keys();
        let r = DiscoKeys::r_keys();

        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_KK1_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // <- s
        // -> s
        // ...
        // -> e
        // <- e, ee, se, es

        // the initiator has a static key pair and both sides exchange them before the handshake.
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .remote_static_public_key(&r.sp)
            .local_static_public_key(&i.sp)
            .local_static_secret_key(&i.ss)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder has a static key pair and both sides exchange them before the handshake.
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

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_nnpsk2(ooo: bool, sleep: bool, prologue: &str, rekey: u64) {
        // create the params with the correct protocol string
        let params = DiscoParams::from_str("Noise_NNpsk2_25519_STROBEv1.0.2").unwrap();

        // create the nonce generator
        let nonces = DiscoNonceGenerator::new(16);

        // get the pre-shared key
        let psk = DiscoKeys::psk();

        // create the prologue
        let prologue = &DiscoPrologue::from_str(prologue).unwrap();

        // -> e
        // <- e, ee, psk

        // the initiator does not have a static key pair
        let mut initiator = DiscoBuilder::new(&params, &nonces)
            .pre_shared_key(&psk)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_initiator()
            .expect("failed to build initiator session");

        // the responder does not have a static key pair
        let mut responder = DiscoBuilder::new(&params, &nonces)
            .pre_shared_key(&psk)
            .out_of_order(ooo)
            .with_prologue(prologue)
            .rekey_in(rekey)
            .build_responder()
            .expect("failed to build responder session");

        assert!(!initiator.is_keyed());
        assert!(!responder.is_keyed());

        do_it(ooo, sleep, &mut initiator, &mut responder);
    }

    fn do_it(ooo: bool, sleep: bool, initiator: &mut DiscoSession, responder: &mut DiscoSession) {
        let mut plaintext = [0u8; MSG_MAX_LEN];
        let mut i_plaintext_recv = [0u8; MSG_MAX_LEN];
        let mut i2r_ciphertext = [0u8; MSG_MAX_LEN];
        let mut r_plaintext_recv = [0u8; MSG_MAX_LEN];
        let mut r2i_ciphertext = [0u8; MSG_MAX_LEN];

        // the overall stream to send
        plaintext[0..25].copy_from_slice(b"hello world, this is fun!");

        // the order in which to send/recv the stream messages
        let in_order = vec![0, 1, 2, 3, 4, 5];
        let out_of_order = vec![0, 2, 5, 3, 1, 4];

        // the start and end indexes of each message in the stream, the first message is empty
        // since the first message is sent unencrypted
        let pt: Vec<(usize, usize)> = vec![(0, 0), (0, 6), (6, 13), (13, 18), (18, 21), (21, 25)];

        // the vector to record the start and end indexes of the ciphertext messages in the stream
        let mut i2r_ct: Vec<(usize, usize)> = Vec::new();
        let mut r2i_ct: Vec<(usize, usize)> = Vec::new();

        // get the order in which ciphertexts are received and processed
        let recv_order = if ooo { &out_of_order } else { &in_order };

        // ping pong messages back and forth until both initiator and responder transition from
        // handshaking to transport mode
        while initiator.is_handshaking() || responder.is_handshaking() {
            // initiator ---> responder
            send_and_recv(initiator, responder);
            // initiator <--- responder
            send_and_recv(responder, initiator);
        }

        assert!(initiator.is_transport());
        assert!(responder.is_transport());

        let mut initiator_id = [0u8; 32];
        let mut responder_id = [0u8; 32];

        // now that we're in transport mode we can do in-order or out-of order message delivery in
        // both directions

        let mut i: &mut DiscoSession = initiator;
        let mut r: &mut DiscoSession = responder;

        // initiator ---> responder

        send(
            i,
            &in_order,
            &plaintext,
            &pt,
            &mut i2r_ciphertext,
            &mut i2r_ct,
            0,
        );

        // get the inbound channel state from the responder
        r.get_channel_state(true, &mut responder_id).unwrap();
        // make sure it matches the channel state in the message
        assert_eq!(responder_id, i2r_ciphertext[..32]);

        let sleeping_responder = serde_cbor::to_vec(r).unwrap();
        assert!(sleeping_responder.len() > 0);
        let mut r1: DiscoSession = serde_cbor::from_slice(&sleeping_responder).unwrap();

        // if sleeping, switch to the session that has been serialized and deserialized
        r = if sleep { &mut r1 } else { responder };

        recv(
            r,
            recv_order,
            &mut r_plaintext_recv,
            &i2r_ciphertext,
            &i2r_ct,
            0,
        );

        // initiator <--- responder

        send(
            r,
            &in_order,
            &plaintext,
            &pt,
            &mut r2i_ciphertext,
            &mut r2i_ct,
            0,
        );

        // get the inbound channel state from the responder
        i.get_channel_state(true, &mut initiator_id).unwrap();
        // make sure it matches the channel state in the message
        assert_eq!(initiator_id, r2i_ciphertext[..32]);

        let sleeping_initiator = serde_cbor::to_vec(i).unwrap();
        assert!(sleeping_initiator.len() > 0);
        let mut i1: DiscoSession = serde_cbor::from_slice(&sleeping_initiator).unwrap();

        // if sleeping, switch to the session that has been serialized and deserialized
        i = if sleep { &mut i1 } else { initiator };

        recv(
            i,
            &recv_order,
            &mut i_plaintext_recv,
            &r2i_ciphertext,
            &r2i_ct,
            0,
        );

        if ooo {
            assert_eq!(b"world, fun!this hello is ", &i_plaintext_recv[0..25]);
            assert_eq!(b"world, fun!this hello is ", &r_plaintext_recv[0..25]);
        } else {
            assert_eq!(b"hello world, this is fun!", &i_plaintext_recv[0..25]);
            assert_eq!(b"hello world, this is fun!", &r_plaintext_recv[0..25]);
        }
    }
}
