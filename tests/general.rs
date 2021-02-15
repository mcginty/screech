#![cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
#![allow(clippy::needless_range_loop)]
#![allow(non_snake_case)]

use hex::FromHex;
use snow::{
    resolvers::{CryptoResolver, DefaultResolver},
    Builder,
};

use rand_core::{impls, CryptoRng, RngCore};
use snow::{params::*, types::*};
use x25519_dalek as x25519;

#[derive(Default)]
struct CountingRng(u64);

impl RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CountingRng {}
impl Random for CountingRng {}

fn get_inc_key(start: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = start + i as u8;
    }
    k
}

#[allow(unused)]
struct TestResolver {
    next_byte: u8,
    parent:    DefaultResolver,
}

#[allow(unused)]
impl TestResolver {
    pub fn new(next_byte: u8) -> Self {
        TestResolver { next_byte, parent: DefaultResolver }
    }

    pub fn next_byte(&mut self, next_byte: u8) {
        self.next_byte = next_byte;
    }
}

impl CryptoResolver for TestResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        let rng = CountingRng(self.next_byte as u64);
        Some(Box::new(rng))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        self.parent.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.parent.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.parent.resolve_cipher(choice)
    }
}

#[test]
fn test_protocol_name() {
    let protocol_spec: NoiseParams = "Noise_NK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

    assert_eq!(protocol_spec.base, BaseChoice::Noise);
    assert_eq!(protocol_spec.handshake.pattern, HandshakePattern::NK);
    assert_eq!(protocol_spec.cipher, CipherChoice::ChaChaPoly);
    assert_eq!(protocol_spec.hash, HashChoice::Blake2s);

    let protocol_spec: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly_FAKE2X".parse();
    if protocol_spec.is_ok() {
        panic!("invalid protocol was parsed inaccurately");
    }

    let protocol_spec: Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly".parse();
    if protocol_spec.is_ok() {
        panic!("invalid protocol was parsed inaccurately");
    }
}

#[test]
fn test_noise_state_change() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    assert!(h_i.is_handshake_finished());
    assert!(h_r.is_handshake_finished());
    let _ = h_i.into_transport_mode().unwrap();
    let _ = h_r.into_transport_mode().unwrap();
}

#[test]
fn test_sanity_chachapoly_session() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_sanity_aesgcm_session() {
    let params: NoiseParams = "Noise_NN_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_Npsk0_chachapoly_expected_value() {
    let params: NoiseParams = "Noise_Npsk0_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params)
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))
        .psk(0, &get_inc_key(1))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 200];
    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 48);

    let expected = Vec::<u8>::from_hex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254deb8a4f6190117dea09aad7546a4658c").unwrap();

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn test_Npsk0_aesgcm_expected_value() {
    let params: NoiseParams = "Noise_Npsk0_25519_AESGCM_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params)
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))
        .psk(0, &get_inc_key(1))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 200];
    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 48);

    let expected = Vec::<u8>::from_hex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662542044ae563929068930dcf04674526cb9").unwrap();

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn test_Npsk0_expected_value() {
    let params: NoiseParams = "Noise_Npsk0_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params)
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))
        .psk(0, &get_inc_key(1))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 200];
    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 48);

    let expected = Vec::<u8>::from_hex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254deb8a4f6190117dea09aad7546a4658c").unwrap();

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
fn test_Xpsk0_expected_value() {
    let params: NoiseParams = "Noise_Xpsk0_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params)
        .local_private_key(&get_inc_key(0))
        .remote_public_key(&x25519::x25519(get_inc_key(32), x25519::X25519_BASEPOINT_BYTES))
        .psk(0, &get_inc_key(1))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(64))
        .build_initiator()
        .unwrap();

    let mut buf = [0u8; 200];
    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 96);

    let expected = Vec::<u8>::from_hex("79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51ad51eef529db0dd9127d4aa59a9183e118337d75a4e55e7e00f85c3d20ede536dd0112eec8c3b2a514018a90ab685b027dd24aa0c70b0c0f00524cc23785028b9").unwrap();

    println!("\nreality:  {}", hex::encode(&buf[..len]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..len], &expected[..]);
}

#[test]
#[cfg(feature = "hfs")]
#[cfg(feature = "nist3_kyber1024")]
fn test_NNhfs_sanity_session() {
    // Due to how oqs is implemented, we cannot do deterministic testing of the protocol.
    // Instead, we will see if the protocol runs smoothly.
    let params: NoiseParams = "Noise_NNhfs_25519+Kyber1024_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 4096];
    let mut buffer_out = [0u8; 4096];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_XXpsk0_expected_value() {
    let params: NoiseParams = "Noise_XXpsk0_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone())
        .local_private_key(&get_inc_key(0))
        .remote_public_key(&x25519::x25519(get_inc_key(1), x25519::X25519_BASEPOINT_BYTES))
        .prologue(&[1u8, 2, 3])
        .psk(0, &get_inc_key(4))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(32))
        .build_initiator()
        .unwrap();
    let mut h_r = Builder::new(params)
        .local_private_key(&get_inc_key(1))
        .remote_public_key(&x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES))
        .prologue(&[1u8, 2, 3])
        .psk(0, &get_inc_key(4))
        .fixed_ephemeral_key_for_testing_only(&get_inc_key(33))
        .build_responder()
        .unwrap();

    let mut buf = [0u8; 1024];
    let mut buf2 = [0u8; 1024];

    let len = h_i.write_message(b"abc", &mut buf).unwrap();
    assert_eq!(len, 51);
    let len = h_r.read_message(&buf[..len], &mut buf2).unwrap();
    assert_eq!(&buf2[..len], b"abc");

    let len = h_r.write_message(b"defg", &mut buf).unwrap();
    assert_eq!(len, 100);
    let len = h_i.read_message(&buf[..len], &mut buf2).unwrap();
    assert_eq!(&buf2[..len], b"defg");

    let len = h_i.write_message(&[], &mut buf).unwrap();
    assert_eq!(len, 64);
    let len = h_r.read_message(&buf[..len], &mut buf2).unwrap();
    assert_eq!(len, 0);

    let expected = Vec::<u8>::from_hex("072b7bbd237ac602c4aa938db36998f31ca4750752d1758d59850c627d0bdbc51205592c3baa101b4a31f062695b7c1dbee99d5123fbd2ad03052078c570e028").unwrap();
    println!("\nreality:  {}", hex::encode(&buf[..64]));
    println!("expected: {}", hex::encode(&expected));
    assert_eq!(&buf[..64], &expected[..]);
}

#[test]
fn test_NNpsk0_sanity_session() {
    let params: NoiseParams = "Noise_NNpsk0_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).psk(0, &[32u8; 32]).build_initiator().unwrap();
    let mut h_r = Builder::new(params).psk(0, &[32u8; 32]).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_XXpsk3_sanity_session() {
    let params: NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_SHA256".parse().unwrap();
    let b_i = Builder::new(params.clone());
    let b_r = Builder::new(params);
    let static_i = b_i.generate_keypair().unwrap();
    let static_r = b_r.generate_keypair().unwrap();
    let mut h_i = b_i
        .psk(3, &[32u8; 32])
        .local_private_key(&static_i.private)
        .remote_public_key(&static_r.public)
        .build_initiator()
        .unwrap();
    let mut h_r = b_r
        .psk(3, &[32u8; 32])
        .local_private_key(&static_r.private)
        .remote_public_key(&static_i.public)
        .build_responder()
        .unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_i.write_message(b"hij", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_rekey() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    // test message initiator->responder before rekeying initiator
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey outgoing on initiator
    h_i.rekey_outgoing();
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    assert!(h_r.read_message(&buffer_msg[..len], &mut buffer_out).is_err());

    // rekey incoming on responder
    h_r.rekey_incoming();
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey outgoing on responder
    h_r.rekey_outgoing();
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    assert!(h_i.read_message(&buffer_msg[..len], &mut buffer_out).is_err());

    // rekey incoming on initiator
    h_i.rekey_incoming();
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_rekey_manually() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let mut h_i = h_i.into_transport_mode().unwrap();
    let mut h_r = h_r.into_transport_mode().unwrap();

    // test message initiator->responder before rekeying initiator
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey initiator (on initiator)
    h_i.rekey_manually(Some(&[1u8; 32]), None);
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    assert!(h_r.read_message(&buffer_msg[..len], &mut buffer_out).is_err());

    // rekey initiator (on responder)
    h_r.rekey_manually(Some(&[1u8; 32]), None);
    let len = h_i.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");

    // rekey responder (on responder)
    h_r.rekey_manually(None, Some(&[1u8; 32]));
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    assert!(h_i.read_message(&buffer_msg[..len], &mut buffer_out).is_err());

    // rekey responder (on initiator)
    h_i.rekey_manually(None, Some(&[1u8; 32]));
    let len = h_r.write_message(b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_handshake_message_exceeds_max_len() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params).build_initiator().unwrap();

    let mut buffer_out = [0u8; 65535 * 2];
    assert!(h_i.write_message(&[0u8; 65530], &mut buffer_out).is_err());
}

#[test]
fn test_handshake_message_undersized_output_buffer() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params).build_initiator().unwrap();

    let mut buffer_out = [0u8; 200];
    assert!(h_i.write_message(&[0u8; 400], &mut buffer_out).is_err());
}

#[test]
fn test_transport_message_exceeds_max_len() {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut noise = Builder::new(params).remote_public_key(&[1u8; 32]).build_initiator().unwrap();

    let mut buffer_out = [0u8; 65535 * 2];
    noise.write_message(&[0u8; 0], &mut buffer_out).unwrap();
    let mut noise = noise.into_transport_mode().unwrap();
    assert!(noise.write_message(&[0u8; 65534], &mut buffer_out).is_err());
}

#[test]
fn test_transport_message_undersized_output_buffer() {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut noise = Builder::new(params).remote_public_key(&[1u8; 32]).build_initiator().unwrap();

    let mut buffer_out = [0u8; 200];
    noise.write_message(&[0u8; 0], &mut buffer_out).unwrap();
    let mut noise = noise.into_transport_mode().unwrap();
    assert!(noise.write_message(&[0u8; 300], &mut buffer_out).is_err());
}

#[test]
fn test_oneway_initiator_enforcements() {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut noise = Builder::new(params).remote_public_key(&[1u8; 32]).build_initiator().unwrap();

    let mut buffer_out = [0u8; 1024];
    noise.write_message(&[0u8; 0], &mut buffer_out).unwrap();
    let mut noise = noise.into_transport_mode().unwrap();
    assert!(noise.read_message(&[0u8; 1024], &mut buffer_out).is_err());
}

#[test]
fn test_oneway_responder_enforcements() {
    let params: NoiseParams = "Noise_N_25519_ChaChaPoly_SHA256".parse().unwrap();
    let resp_builder = Builder::new(params.clone());
    let rpk = resp_builder.generate_keypair().unwrap();

    let mut resp = resp_builder.local_private_key(&rpk.private).build_responder().unwrap();
    let mut init = Builder::new(params).remote_public_key(&rpk.public).build_initiator().unwrap();

    let mut buffer_resp = [0u8; 65535];
    let mut buffer_init = [0u8; 65535];
    let len = init.write_message(&[0u8; 0], &mut buffer_init).unwrap();
    resp.read_message(&buffer_init[..len], &mut buffer_resp).unwrap();
    let mut init = init.into_transport_mode().unwrap();
    let mut resp = resp.into_transport_mode().unwrap();

    assert!(init.read_message(&[0u8; 1024], &mut buffer_init).is_err());
    assert!(resp.write_message(&[0u8; 1024], &mut buffer_resp).is_err());
}

#[test]
fn test_buffer_issues() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 2];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_err());
}

#[test]
fn test_read_buffer_issues() {
    let params: NoiseParams = "Noise_XK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

    let builder_r = snow::Builder::new(params.clone());
    let keypair_r = builder_r.generate_keypair().unwrap();
    let mut h_r = builder_r.local_private_key(&keypair_r.private).build_responder().unwrap();

    let builder_i = snow::Builder::new(params);
    let key_i = builder_i.generate_keypair().unwrap().private;
    let mut h_i = builder_i
        .local_private_key(&key_i)
        .remote_public_key(&keypair_r.public)
        .build_initiator()
        .unwrap();

    let mut buffer_msg = [0u8; 65535];
    let mut buffer_out = [0u8; 65535];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_ok());

    let len = h_r.write_message(b"abc", &mut buffer_msg).unwrap();
    let res = h_i.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_ok());

    let _len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    let res = h_r.read_message(&buffer_msg[..2], &mut buffer_out);

    assert!(res.is_err());
}

#[test]
fn test_buffer_issues_encrypted_handshake() {
    let params: NoiseParams = "Noise_IKpsk2_25519_ChaChaPoly_SHA256".parse().unwrap();

    let b_i = Builder::new(params.clone());
    let b_r = Builder::new(params);

    let static_i = b_i.generate_keypair().unwrap();
    let static_r = b_r.generate_keypair().unwrap();

    let mut h_i = b_i
        .psk(2, &[32u8; 32])
        .local_private_key(&static_i.private)
        .remote_public_key(&static_r.public)
        .build_initiator()
        .unwrap();
    let mut h_r = b_r
        .psk(2, &[32u8; 32])
        .local_private_key(&static_r.private)
        .remote_public_key(&static_i.public)
        .build_responder()
        .unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 2];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_out);

    assert!(res.is_err());
}

#[test]
fn test_send_trait() {
    use std::{sync::mpsc::channel, thread};

    let (tx, rx) = channel();
    thread::spawn(move || {
        let session = Builder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
            .build_initiator()
            .unwrap();
        tx.send(session).unwrap();
    });
    let _session = rx.recv().expect("failed to receive noise session");
}

#[test]
fn test_checkpointing() {
    let params: NoiseParams = "Noise_XXpsk2_25519_ChaChaPoly_SHA256".parse().unwrap();

    let b_i = Builder::new(params.clone());
    let b_r = Builder::new(params);

    let static_i = b_i.generate_keypair().unwrap();
    let static_r = b_r.generate_keypair().unwrap();

    let mut h_i = b_i
        .psk(2, &[32u8; 32])
        .local_private_key(&static_i.private)
        .remote_public_key(&static_r.public)
        .build_initiator()
        .unwrap();
    let mut h_r = b_r
        .psk(2, &[32u8; 32])
        .local_private_key(&static_r.private)
        .remote_public_key(&static_i.public)
        .build_responder()
        .unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_bad = [0u8; 48];

    let res = h_i.write_message(b"abc", &mut buffer_bad);
    assert!(res.is_err(), "write_message() should have failed for insufficiently-sized buffer");

    let len = h_i
        .write_message(b"abc", &mut buffer_msg)
        .expect("write_message() should have succeeded for correctly-sized buffer");

    let mut buffer_bad = [0u8; 2];
    let mut buffer_ok = [0u8; 200];
    let res = h_r.read_message(&buffer_msg[..len], &mut buffer_bad);
    assert!(res.is_err(), "read_message() should have failed for insufficiently-sized buffer");

    let _res = h_r
        .read_message(&buffer_msg[..len], &mut buffer_ok)
        .expect("read_message() should have succeeded");
}

#[test]
fn test_get_remote_static() {
    let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i =
        Builder::new(params.clone()).local_private_key(&get_inc_key(0)).build_initiator().unwrap();
    let mut h_r =
        Builder::new(params).local_private_key(&get_inc_key(1)).build_responder().unwrap();

    let mut buf = [0u8; 1024];
    let mut buf2 = [0u8; 1024];

    // XX(s, rs):
    assert!(h_i.get_remote_static().is_none());
    assert!(h_r.get_remote_static().is_none());

    // -> e
    let len = h_i.write_message(&[], &mut buf).unwrap();
    let _ = h_r.read_message(&buf[..len], &mut buf2).unwrap();

    assert!(h_i.get_remote_static().is_none());
    assert!(h_r.get_remote_static().is_none());

    // <- e, ee s, es
    let len = h_r.write_message(&[], &mut buf).unwrap();
    let _ = h_i.read_message(&buf[..len], &mut buf2).unwrap();

    assert_eq!(
        h_i.get_remote_static().unwrap(),
        &x25519::x25519(get_inc_key(1), x25519::X25519_BASEPOINT_BYTES)
    );
    assert!(h_r.get_remote_static().is_none());

    // -> s, se
    let len = h_i.write_message(&[], &mut buf).unwrap();
    let _ = h_r.read_message(&buf[..len], &mut buf2).unwrap();

    assert_eq!(
        h_i.get_remote_static().unwrap(),
        &x25519::x25519(get_inc_key(1), x25519::X25519_BASEPOINT_BYTES)
    );
    assert_eq!(
        h_r.get_remote_static().unwrap(),
        &x25519::x25519(get_inc_key(0), x25519::X25519_BASEPOINT_BYTES)
    );
}

#[test]
fn test_set_psk() {
    let params: NoiseParams = "Noise_XXpsk3_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i =
        Builder::new(params.clone()).local_private_key(&get_inc_key(0)).build_initiator().unwrap();
    let mut h_r =
        Builder::new(params).local_private_key(&get_inc_key(1)).build_responder().unwrap();

    let mut buf = [0u8; 1024];
    let mut buf2 = [0u8; 1024];

    let psk = get_inc_key(3);

    // XX(s, rs):
    // -> e
    let len = h_i.write_message(&[], &mut buf).unwrap();
    let _ = h_r.read_message(&buf[..len], &mut buf2).unwrap();

    // <- e, ee s, es
    let len = h_r.write_message(&[], &mut buf).unwrap();
    let _ = h_i.read_message(&buf[..len], &mut buf2).unwrap();

    h_i.set_psk(3, &psk).unwrap();
    h_r.set_psk(3, &psk).unwrap();

    // -> s, se, psk
    let len = h_i.write_message(&[], &mut buf).unwrap();
    let _ = h_r.read_message(&buf[..len], &mut buf2).unwrap();
}

#[test]
fn test_stateless_sanity_session() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let h_i = h_i.into_stateless_transport_mode().unwrap();
    let h_r = h_r.into_stateless_transport_mode().unwrap();

    let len = h_i.write_message(1337, b"hack the planet", &mut buffer_msg).unwrap();
    let len = h_r.read_message(1337, &buffer_msg[..len], &mut buffer_out).unwrap();
    assert_eq!(&buffer_out[..len], b"hack the planet");
}

#[test]
fn test_handshake_read_oob_error() {
    let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap();
    let mut h_i = Builder::new(params.clone()).build_initiator().unwrap();
    let mut h_r = Builder::new(params).build_responder().unwrap();

    let mut buffer_msg = [0u8; 200];
    let mut buffer_out = [0u8; 200];
    let len = h_i.write_message(b"abc", &mut buffer_msg).unwrap();
    h_r.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    let len = h_r.write_message(b"defg", &mut buffer_msg).unwrap();
    h_i.read_message(&buffer_msg[..len], &mut buffer_out).unwrap();

    // This shouldn't panic, but it *should* return an error.
    let _ = h_i.read_message(&buffer_msg[..len], &mut buffer_out);
}
