mod xeddsa;
mod params {
    use crate::xeddsa::{DiscoParams, DiscoXeddsa};
    use disco_rs::{
        error::{Error, ParamError},
        handshake::*,
        params::*,
    };
    use std::str::FromStr;

    const HANDSHAKES: [&str; 15] = [
        "N", "K", "X", "Npsk0", "Kpsk0", "Xpsk1", "NN", "KK", "XX", "IK", "NK", "NX", "XK1", "KK1",
        "NNpsk2",
    ];

    #[test]
    fn test_protocol_string() {
        let p: Protocol = "Noise".parse().unwrap();
        assert_eq!(format!("{}", p), "Noise");
    }

    #[test]
    #[should_panic]
    fn test_protocol_failure() {
        let _: Protocol = "Disco".parse().unwrap();
    }

    #[test]
    fn test_handshake_string() {
        for h in HANDSHAKES {
            let handshake: Handshake = h.parse().unwrap();
            assert_eq!(format!("{}", handshake), h.to_string());
        }
    }

    #[test]
    #[should_panic]
    fn test_handshake_failure() {
        let _: Handshake = "KN".parse().unwrap();
    }

    #[test]
    fn test_key_exchange_string() {
        let key_type: DiscoXeddsa = "25519".parse().unwrap();
        assert_eq!(format!("{}", key_type), "25519".to_string());
    }

    #[test]
    #[should_panic]
    fn test_key_exchange_failure() {
        let _: DiscoXeddsa = "k256".parse().unwrap();
    }

    #[test]
    fn test_version_string() {
        let v: StrobeVersion = "STROBEv1.0.2".parse().unwrap();
        assert_eq!(format!("{}", v), "STROBEv1.0.2".to_string());
    }

    #[test]
    #[should_panic]
    fn test_version_failure() {
        let _: StrobeVersion = "FOOBAR".parse().unwrap();
    }

    #[test]
    fn test_params_string() {
        for h in HANDSHAKES {
            let s = format!("Noise_{}_25519_STROBEv1.0.2", h);
            let d: DiscoParams = s.parse().unwrap();
            assert_eq!(format!("{}", d), s);
        }
    }

    #[test]
    fn test_params_failures() {
        let p = DiscoParams::from_str("Disco_XX_25519_STROBEv1.0.2");
        assert!(p.is_err());
        assert_eq!(p.err(), Some(Error::Param(ParamError::InvalidProtocol)));
    }
}
