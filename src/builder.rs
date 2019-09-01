use crate::constants::{PSKLEN, MAXDHLEN};
use crate::handshakestate::HandshakeState;
use crate::cipherstate::{CipherState, CipherStates};
use crate::utils::Toggle;
use crate::params::NoiseParams;
use crate::resolvers::CryptoResolver;
use crate::error::{Error, InitStage, Prerequisite};
use subtle::ConstantTimeEq;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::vec;

/// A keypair object returned by [`Builder::generate_keypair()`]
///
/// [`generate_keypair()`]: #method.generate_keypair
pub struct Keypair {
    /// The private asymmetric key
    pub private: Vec<u8>,
    /// The public asymmetric key
    pub public: Vec<u8>,
}


impl PartialEq for Keypair {
    fn eq(&self, other: &Keypair) -> bool {
        let priv_eq = self.private.ct_eq(&other.private);
        let pub_eq = self.public.ct_eq(&other.public);

        (priv_eq & pub_eq).into()
    }
}

/// Generates a [`HandshakeState`] and also validates that all the prerequisites for
/// the given parameters are satisfied.
///
/// # Examples
///
/// ```
/// # use snow::Builder;
/// # let my_long_term_key = [0u8; 32];
/// # let their_pub_key = [0u8; 32];
/// # #[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
/// let noise = Builder::new("Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap())
///     .local_private_key(&my_long_term_key)
///     .remote_public_key(&their_pub_key)
///     .prologue("noise is just swell".as_bytes())
///     .build_initiator()
///     .unwrap();
/// ```
pub struct Builder<'builder> {
    params:   NoiseParams,
    resolver: Box<dyn CryptoResolver>,
    s:        Option<&'builder [u8]>,
    e_fixed:  Option<&'builder [u8]>,
    rs:       Option<&'builder [u8]>,
    psks:     [Option<&'builder [u8]>; 10],
    plog:     Option<&'builder [u8]>,
}

impl<'builder> Builder<'builder> {
    /// Create a Builder with the default crypto resolver.
    #[cfg(all(feature = "default-resolver", not(any(feature = "ring-accelerated"))))]
    pub fn new(params: NoiseParams) -> Self {
        use crate::resolvers::DefaultResolver;

        Self::with_resolver(params, Box::new(DefaultResolver::default()))
    }

    /// Create a Builder with the ring resolver and default resolver as a fallback.
    #[cfg(feature = "ring-accelerated")]
    pub fn new(params: NoiseParams) -> Self {
        use crate::resolvers::{FallbackResolver, DefaultResolver, RingResolver};

        Self::with_resolver(params, Box::new(FallbackResolver::new(Box::new(RingResolver), Box::new(DefaultResolver))))
    }

    /// Create a Builder with a custom crypto resolver.
    pub fn with_resolver(params: NoiseParams, resolver: Box<dyn CryptoResolver>) -> Self {
        Builder {
            params,
            resolver,
            s: None,
            e_fixed: None,
            rs: None,
            plog: None,
            psks: [None; 10],
        }
    }

    /// Specify a PSK (only used with `NoisePSK` base parameter)
    pub fn psk(mut self, location: u8, key: &'builder [u8]) -> Self {
        self.psks[location as usize] = Some(key);
        self
    }

    /// Your static private key (can be generated with [`generate_keypair()`]).
    ///
    /// [`generate_keypair()`]: #method.generate_keypair
    pub fn local_private_key(mut self, key: &'builder [u8]) -> Self {
        self.s = Some(key);
        self
    }

    #[doc(hidden)]
    pub fn fixed_ephemeral_key_for_testing_only(mut self, key: &'builder [u8]) -> Self {
        self.e_fixed = Some(key);
        self
    }

    /// Arbitrary data to be hashed in to the handshake hash value.
    pub fn prologue(mut self, key: &'builder [u8]) -> Self {
        self.plog = Some(key);
        self
    }

    /// The responder's static public key.
    pub fn remote_public_key(mut self, pub_key: &'builder [u8]) -> Self {
        self.rs = Some(pub_key);
        self
    }

    // TODO: performance issue w/ creating a new RNG and DH instance per call.
    /// Generate a new asymmetric keypair (for use as a static key).
    pub fn generate_keypair(&self) -> Result<Keypair, Error> {
        let mut rng     = self.resolver.resolve_rng().ok_or(InitStage::GetRngImpl)?;
        let mut dh      = self.resolver.resolve_dh(&self.params.dh).ok_or(InitStage::GetDhImpl)?;
        let mut private = vec![0u8; dh.priv_len()];
        let mut public  = vec![0u8; dh.pub_len()];
        dh.generate(&mut *rng);

        private.copy_from_slice(dh.privkey());
        public.copy_from_slice(dh.pubkey());

        Ok(Keypair { private, public })
    }

    /// Build a [`HandshakeState`] for the side who will initiate the handshake (send the first message)
    pub fn build_initiator(self) -> Result<HandshakeState, Error> {
        self.build(true)
    }

    /// Build a [`HandshakeState`] for the side who will be responder (receive the first message)
    pub fn build_responder(self) -> Result<HandshakeState, Error> {
        self.build(false)
    }

    fn build(self, initiator: bool) -> Result<HandshakeState, Error> {
        if self.s.is_none() && self.params.handshake.pattern.needs_local_static_key(initiator) {
            bail!(Prerequisite::LocalPrivateKey);
        }

        if self.rs.is_none() && self.params.handshake.pattern.need_known_remote_pubkey(initiator) {
            bail!(Prerequisite::RemotePublicKey);
        }

        let rng = self.resolver.resolve_rng().ok_or(InitStage::GetRngImpl)?;
        let cipher = self.resolver.resolve_cipher(&self.params.cipher).ok_or(InitStage::GetCipherImpl)?;
        let hash = self.resolver.resolve_hash(&self.params.hash).ok_or(InitStage::GetHashImpl)?;
        let mut s_dh = self.resolver.resolve_dh(&self.params.dh).ok_or(InitStage::GetDhImpl)?;
        let mut e_dh = self.resolver.resolve_dh(&self.params.dh).ok_or(InitStage::GetDhImpl)?;
        let cipher1 = self.resolver.resolve_cipher(&self.params.cipher).ok_or(InitStage::GetCipherImpl)?;
        let cipher2 = self.resolver.resolve_cipher(&self.params.cipher).ok_or(InitStage::GetCipherImpl)?;
        let handshake_cipherstate = CipherState::new(cipher);
        let cipherstates = CipherStates::new(CipherState::new(cipher1), CipherState::new(cipher2))?;

        let s = match self.s {
            Some(k) => {
                (&mut *s_dh).set(k);
                Toggle::on(s_dh)
            },
            None => {
                Toggle::off(s_dh)
            }
        };

        if let Some(fixed_k) = self.e_fixed {
            (&mut *e_dh).set(fixed_k);
        }
        let e = Toggle::off(e_dh);

        let mut rs_buf = [0u8; MAXDHLEN];
        let rs = match self.rs {
            Some(v) => {
                rs_buf[..v.len()].copy_from_slice(&v[..]);
                Toggle::on(rs_buf)
            },
            None => Toggle::off(rs_buf),
        };

        let re = Toggle::off([0u8; MAXDHLEN]);

        let mut psks = [None::<[u8; PSKLEN]>; 10];
        for (i, psk) in self.psks.iter().enumerate() {
            if let Some(key) = *psk {
                if key.len() != PSKLEN {
                    bail!(InitStage::ValidatePskLengths);
                }
                let mut k = [0u8; PSKLEN];
                k.copy_from_slice(key);
                psks[i] = Some(k);
            }
        }

        let hs = HandshakeState::new(rng, handshake_cipherstate, hash,
                                     s, e, self.e_fixed.is_some(), rs, re,
                                     initiator,
                                     self.params,
                                     psks,
                                     self.plog.unwrap_or_else(|| &[0u8; 0] ),
                                     cipherstates)?;
        Ok(hs)
    }
}

#[cfg(test)]
#[cfg(any(feature = "default-resolver", feature = "ring-accelerated"))]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let _noise = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap())
            .prologue(&[2,2,2,2,2,2,2,2])
            .local_private_key(&[0u8; 32])
            .build_initiator().unwrap();
    }

    #[test]
    fn test_builder_keygen() {
        let builder = Builder::new("Noise_NN_25519_ChaChaPoly_SHA256".parse().unwrap());
        let key1 = builder.generate_keypair();
        let key2 = builder.generate_keypair();
        assert!(key1.unwrap() != key2.unwrap());
    }

    #[test]
    fn test_builder_bad_spec() {
        let params: ::std::result::Result<NoiseParams, _> = "Noise_NK_25519_ChaChaPoly_BLAH256".parse();

        if let Ok(_) = params {
            panic!("NoiseParams should have failed");
        }
    }

    #[test]
    fn test_builder_missing_prereqs() {
        let noise = Builder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap())
            .prologue(&[2,2,2,2,2,2,2,2])
            .local_private_key(&[0u8; 32])
            .build_initiator(); // missing remote key, should result in Err

        if let Ok(_) = noise {
            panic!("builder should have failed on build");
        }
    }

    #[test]
    fn test_partialeq_impl() {
        let keypair_1 = Keypair {
            private: vec![0x01; 32],
            public: vec![0x01; 32],
        };

        let mut keypair_2 = Keypair {
            private: vec![0x01; 32],
            public: vec![0x01; 32],
        };
        
        // If both private and public are the same, return true
        assert_eq!(keypair_1 == keypair_2, true);

        // If either public or private are different, return false

        // Wrong private
        keypair_2.private = vec![0x50; 32];
        assert_eq!(keypair_1 == keypair_2, false);
        // Reset to original
        keypair_2.private = vec![0x01; 32];
        // Wrong public
        keypair_2.public = vec![0x50; 32];
        assert_eq!(keypair_1 == keypair_2, false);
    }
}

