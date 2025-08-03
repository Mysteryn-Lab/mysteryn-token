/// Example implementation of custom key algorithms lists.
use mysteryn_crypto::{
    attributes::{KeyAttributes, SignatureAttributes},
    key_traits::*,
    multicodec::{known_algorithm_name, multicodec_prefix},
    multikey::{MultikeyPublicKey, MultikeySecretKey, Multisig},
    result::{Error, Result},
};
use mysteryn_keys::secp256k1::{Secp256k1PublicKey, Secp256k1SecretKey, Secp256k1Signature};
use mysteryn_token::token;
use serde::{Deserialize, Serialize};

// A custom key. It is taken from the `mysteryn_keys` as an example, but it can
// be in any other source.
use mysteryn_keys::bls12381g1::{Bls12381G1PublicKey, Bls12381G1SecretKey, Bls12381G1Signature};

// 1. Define a custom key factory.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomKeyFactory;

impl KeyFactory for CustomKeyFactory {
    fn new_secret(algorithm: u64, _attributes: &KeyAttributes) -> Result<Box<dyn SecretKeyTrait>> {
        match algorithm {
            multicodec_prefix::SECP256K1_SECRET => Ok(Box::new(Secp256k1SecretKey::new())),
            multicodec_prefix::BLS12381G1_SECRET => Ok(Box::new(Bls12381G1SecretKey::new())),
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn secret_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        _attributes: &KeyAttributes,
    ) -> Result<Box<dyn SecretKeyTrait>> {
        match algorithm {
            multicodec_prefix::SECP256K1_SECRET => {
                Ok(Box::new(Secp256k1SecretKey::try_from(bytes)?))
            }
            multicodec_prefix::BLS12381G1_SECRET => {
                Ok(Box::new(Bls12381G1SecretKey::try_from(bytes)?))
            }
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn public_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        _attributes: &KeyAttributes,
    ) -> Result<Box<dyn PublicKeyTrait>> {
        match algorithm {
            multicodec_prefix::SECP256K1 => Ok(Box::new(Secp256k1PublicKey::try_from(bytes)?)),
            multicodec_prefix::BLS12381G1 => Ok(Box::new(Bls12381G1PublicKey::try_from(bytes)?)),
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn signature_from_bytes(
        algorithm: u64,
        bytes: &[u8],
        _attributes: &SignatureAttributes,
    ) -> Result<Box<dyn SignatureTrait>> {
        match algorithm {
            multicodec_prefix::SECP256K1 => Ok(Box::new(Secp256k1Signature::try_from(bytes)?)),
            multicodec_prefix::BLS12381G1 => Ok(Box::new(Bls12381G1Signature::try_from(bytes)?)),
            _ => Err(Error::ValidationError(format!(
                "algorithm 0x{algorithm:02x} is not supported"
            ))),
        }
    }

    fn list_supported() -> Vec<SupportedAlgorithm> {
        vec![
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::ES256K.to_string(),
                secret_codec: multicodec_prefix::SECP256K1_SECRET,
                codec: multicodec_prefix::SECP256K1,
                key_exchange: false,
                public_verify: true,
            },
            SupportedAlgorithm {
                algorithm_name: known_algorithm_name::Bls12381G1.to_string(),
                secret_codec: multicodec_prefix::BLS12381G1_SECRET,
                codec: multicodec_prefix::BLS12381G1,
                key_exchange: false,
                public_verify: true,
            },
        ]
    }
}

// 2. Define final key and signature types.

/// Multikey secret key
pub type SecretKey = MultikeySecretKey<CustomKeyFactory>;
/// Multikey public key
#[allow(dead_code)]
pub type PublicKey = MultikeyPublicKey<CustomKeyFactory>;
/// Multisig signature
#[allow(dead_code)]
pub type Signature = Multisig<CustomKeyFactory>;
/// Token
pub type Token = token::Token<CustomKeyFactory>;
/// Token
#[allow(dead_code)]
pub type CanonicalPayload = token::CanonicalPayload<CustomKeyFactory>;
