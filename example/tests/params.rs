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
    let _: Handshake = "KN".parse().unwrap();
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
    // N
    let d: Params<AsymKeyType> = "Noise_N_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_N_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_N_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_N_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_N_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_N_K256_STROBEv1.0.2".to_string());

    // K
    let d: Params<AsymKeyType> = "Noise_K_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_K_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_K_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_K_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_K_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_K_K256_STROBEv1.0.2".to_string());

    // X
    let d: Params<AsymKeyType> = "Noise_X_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_X_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_X_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_X_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_X_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_X_K256_STROBEv1.0.2".to_string());

    // NN
    let d: Params<AsymKeyType> = "Noise_NN_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NN_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NN_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NN_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NN_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NN_K256_STROBEv1.0.2".to_string());

    // KK
    let d: Params<AsymKeyType> = "Noise_KK_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_KK_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_KK_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK_K256_STROBEv1.0.2".to_string());

    // XX
    let d: Params<AsymKeyType> = "Noise_XX_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XX_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XX_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XX_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XX_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XX_K256_STROBEv1.0.2".to_string());

    // IK
    let d: Params<AsymKeyType> = "Noise_IK_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_IK_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_IK_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_IK_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_IK_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_IK_K256_STROBEv1.0.2".to_string());

    // NK
    let d: Params<AsymKeyType> = "Noise_NK_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NK_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NK_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NK_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NK_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NK_K256_STROBEv1.0.2".to_string());

    // NX
    let d: Params<AsymKeyType> = "Noise_NX_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NX_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NX_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NX_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NX_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NX_K256_STROBEv1.0.2".to_string());

    // XK1
    let d: Params<AsymKeyType> = "Noise_XK1_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XK1_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XK1_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XK1_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_XK1_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_XK1_K256_STROBEv1.0.2".to_string());

    // KK1
    let d: Params<AsymKeyType> = "Noise_KK1_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK1_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_KK1_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK1_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_KK1_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_KK1_K256_STROBEv1.0.2".to_string());

    // NNpsk2
    let d: Params<AsymKeyType> = "Noise_NNpsk2_25519_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NNpsk2_25519_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NNpsk2_P256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NNpsk2_P256_STROBEv1.0.2".to_string());
    let d: Params<AsymKeyType> = "Noise_NNpsk2_K256_STROBEv1.0.2".parse().unwrap();
    assert_eq!(format!("{}", d), "Noise_NNpsk2_K256_STROBEv1.0.2".to_string());
}

#[test]
fn test_params_failures() {
    let p = Params::<AsymKeyType>::from_str("Disco_XX_25519_STROBEv1.0.2");
    assert!(p.is_err());
    assert_eq!(p.err(), Some(Error::Param(ParamError::InvalidProtocol)));
}

