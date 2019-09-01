//! The wrappers around the default collection of cryptography and entropy providers.

use alloc::boxed::Box;

/// The default primitive resolver.
#[cfg(feature = "default-resolver")]   mod default;
/// A ring primitive resolver.
#[cfg(feature = "ring-resolver")]      mod ring;

use crate::params::{CipherChoice, DHChoice, HashChoice};
use crate::types::{Cipher, Dh, Hash, Random};

#[cfg(feature = "default-resolver")]   pub use self::default::DefaultResolver;
#[cfg(feature = "ring-resolver")]      pub use self::ring::RingResolver;

/// An object that resolves the providers of Noise crypto choices
pub trait CryptoResolver {
    /// Provide an implementation of the Random trait or None if none available.
    fn resolve_rng(&self) -> Option<Box<dyn Random>>;

    /// Provide an implementation of the Dh trait for the given DHChoice or None if unavailable.
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>>;

    /// Provide an implementation of the Hash trait for the given HashChoice or None if unavailable.
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>>;

    /// Provide an implementation of the Cipher trait for the given CipherChoice or None if unavailable.
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>>;
}

/// A helper struct that helps to opportunistically use one resolver, but
/// can fallback to another if the first didn't have an implementation for
/// a given primitive.
pub struct FallbackResolver {
    preferred: Box<dyn CryptoResolver>,
    fallback: Box<dyn CryptoResolver>,
}

impl FallbackResolver {
    /// Create a new `FallbackResolver` that holds the primary and secondary resolver.
    pub fn new(preferred: Box<dyn CryptoResolver>, fallback: Box<dyn CryptoResolver>) -> Self {
        Self { preferred, fallback }
    }
}

impl CryptoResolver for FallbackResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.preferred.resolve_rng().or_else(|| self.fallback.resolve_rng())
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        self.preferred.resolve_dh(choice).or_else(|| self.fallback.resolve_dh(choice))
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.preferred.resolve_hash(choice).or_else(|| self.fallback.resolve_hash(choice))
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.preferred.resolve_cipher(choice).or_else(|| self.fallback.resolve_cipher(choice))
    }
}
