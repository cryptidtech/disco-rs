mod xeddsa;
mod keys {
    use crate::xeddsa::{get_rng, DiscoXeddsa};
    use disco_rs::key::{KeyAgreement, KeyGenerator};

    #[test]
    fn diffie_hellman() {
        let mut xeddsa = DiscoXeddsa::default();
        let kt = xeddsa.clone();

        // Initiator generates ephemeral key and test static key
        let (i_e_pub, i_e_sec) = xeddsa.generate(&kt, get_rng());
        let (i_s_pub, i_s_sec) = xeddsa.generate(&kt, get_rng());

        // Responder generates ephemeral key and test static key
        let (r_e_pub, r_e_sec) = xeddsa.generate(&kt, get_rng());
        let (r_s_pub, r_s_sec) = xeddsa.generate(&kt, get_rng());

        // Responder does the first DH using initiator ephemeral public key
        // and responder ephemeral secret key
        let r_first_dh = xeddsa.get_shared_secret(&kt, &r_e_sec, &i_e_pub).unwrap();

        // Initiator does the first DH using the responder ephemeral public key
        // and initiator ephemeral secret key
        let i_first_dh = xeddsa.get_shared_secret(&kt, &i_e_sec, &r_e_pub).unwrap();

        // Both initiator and responder have the same shared secret
        assert_eq!(r_first_dh, i_first_dh);

        // The responder sends the responder static public key to initiator,
        // encrypted using the shared secret calculated from the first DH

        // Responder does the second DH using the initiator ephemeral public
        // key and the responder static secret key
        let r_second_dh = xeddsa.get_shared_secret(&kt, &r_e_sec, &i_s_pub).unwrap();

        // Initiator does the second DH using the responder static public key
        // and the initiator ephemeral secret key
        let i_second_dh = xeddsa.get_shared_secret(&kt, &i_s_sec, &r_e_pub).unwrap();

        // Both initiator and responder have the same shared secret again
        assert_eq!(r_second_dh, i_second_dh);

        // The initiator sends the initiator static public key to responder,
        // encrypted using the shared secret calculated from the second DH

        // Responder does the third DH using the initiator static public key
        // and the responder static ephemeral key
        let r_third_dh = xeddsa.get_shared_secret(&kt, &r_s_sec, &i_e_pub).unwrap();

        // Initiator does the third DH using the responder ephemeral public key
        // and the initiator static secret key
        let i_third_dh = xeddsa.get_shared_secret(&kt, &i_e_sec, &r_s_pub).unwrap();

        // Both initiator and responder have the same shared secret again
        assert_eq!(r_third_dh, i_third_dh);
    }
}
