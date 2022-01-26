use disco_rs::{
    error::{Error, ParamError},
    params::*,
};
use disco_ecdh_example::key::soft::AsymKeyType;
use std::str::FromStr;

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
    let xx: Handshake = "XX".parse().unwrap();
    assert_eq!(format!("{}", xx), "XX".to_string());
    let xk1: Handshake = "XK1".parse().unwrap();
    assert_eq!(format!("{}", xk1), "XK1".to_string());
    let kk1: Handshake = "KK1".parse().unwrap();
    assert_eq!(format!("{}", kk1), "KK1".to_string());
}

#[test]
#[should_panic]
fn test_handshake_failure() {
    let _: Handshake = "NK".parse().unwrap();
}

#[test]
fn test_key_exchange_string() {
    let x25519: AsymKeyType = "25519".parse().unwrap();
    assert_eq!(format!("{}", x25519), "25519".to_string());
    let p256: AsymKeyType = "P256".parse().unwrap();
    assert_eq!(format!("{}", p256), "P256".to_string());
}

#[test]
#[should_panic]
fn test_key_exchange_failure() {
    let _: AsymKeyType = "k256".parse().unwrap();
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
    let d: Params<AsymKeyType> = "Noise_XX_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XX_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XX_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XX_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XX_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XX_K256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XK1_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XK1_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XK1_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XK1_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_KK1_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK1_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_KK1_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK1_P256_STROBEv1.0.2".to_string());
}

#[test]
fn test_params_failures() {
    let p = Params::<AsymKeyType>::from_str("Disco_XX_25519_STROBEv1.0.2");
    assert!(p.is_err());
    assert_eq!(p.err(), Some(Error::Param(ParamError::InvalidProtocol)));

    let p = Params::<AsymKeyType>::from_str("Noise_NK_25519_STROBEv1.0.2");
    assert!(p.is_err());
    assert_eq!(p.err(), Some(Error::Param(ParamError::InvalidHandshake)));

    let p = Params::<AsymKeyType>::from_str("Noise_XK1_BLS12381_STROBEv1.0.2");
    assert!(p.is_err());
    assert_eq!(p.err(), Some(Error::Param(ParamError::InvalidKeyType)));

    let p = Params::<AsymKeyType>::from_str("Noise_KK1_P256_STROBEv2.0.0");
    assert!(p.is_err());
    assert_eq!(p.err(), Some(Error::Param(ParamError::InvalidStrobeVersion)));
}

