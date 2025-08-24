//! Simplify capability-based authorization.
//!
//! Delegable Web Token (DWT) offers a modern approach for distributed and decentralized
//! authorization in web applications.
//!
//! # Examples
//!
//! To generate a signed token, you need to provide keys implementation.
//! For more information on providing a signing key, see the
//! [`mysteryn_crypto`] module documentation.
//!
//! ```rust
//! use mysteryn_crypto::{prelude::*, multikey::*, default_key_variant::*, Result};
//!
//! /// Multikey secret key
//! pub type SecretKey = MultikeySecretKey<DefaultSecretKeyVariant, DefaultPublicKeyVariant>;
//! /// Multikey public key
//! pub type PublicKey = MultikeyPublicKey<DefaultPublicKeyVariant>;
//! /// Multisig signature
//! pub type Signature = Multisig<DefaultSignatureVariant>;
//! ```
//!
//! This crate offers the [`TokenBuilder`] abstraction to generate
//! signed tokens.
//!
//! ```rust
//! use mysteryn_crypto::{did::Did, MultikeySecretKey, DefaultSecretKeyVariant, DefaultPublicKeyVariant};
//! use mysteryn_token::TokenBuilder;
//! use std::str::FromStr;
//!
//! pub type SecretKey = MultikeySecretKey<DefaultSecretKeyVariant, DefaultPublicKeyVariant>;
//!
//! let secret_key = SecretKey::from_str("secret_xahgjgqfsxwdjkxun9wspqzgzve7sze7vwm0kszkya5lurz4np9cmc8k4frds9ze0g6kzsky8pmv8qxur4vfupul38mfdgrcc")?;
//! let recipient = Did::from_str("did:key:pub_xahgjw6qgrwp6kyqgpyq29vthlflt6dtl5pvlrwrnllgyy5ws5a0w3xa2tt0425k9rvcwus9j33c3u0m7a2v")?;
//! let capabilities = [
//!    ("mailto:test@test.com", "msg/receive"),
//!    ("mailto:test@test.com", "msg/send"),
//!  ];
//!  
//! let builder = TokenBuilder::default()
//!    .with_secret(&secret_key)
//!    .for_audience(&recipient)
//!    .with_capabilities(&capabilities);
//! let token = builder.build().await?;
//! ```
//!
//! The crate provides [`TokenVerifier`] to ensure a token adheres
//! to the specified [`Requirements`].
//!
//! ```rust
//! let mut verifier = Verifier::default();
//! let originator = secret_key.get_did()?;
//! let required_capabilities = Capabilities::try_from(&json!({
//!    "mailto:test@test.com": ["msg/send"]
//! }))?;
//! let requirements = Requirements {
//!     audience: recipient.to_string(),
//!     capabilities: BTreeMap::from([(originator.to_string(), required_capabilities)]),
//!     time: None,
//!     known_tokens: None,
//! };
//! let result = verifier.verify(&token, None, &requirements).await?;
//! ```
//!
//! [JWT docs]: https://jwt.io/
//! [DID spec]: https://www.w3.org/TR/did-core/
//! [DID Key spec]: https://w3c-ccg.github.io/did-method-key/

#![warn(clippy::pedantic)] // Be pedantic by default
#![warn(clippy::integer_division_remainder_used)] // Be judicious about using `/` and `%`
#![allow(non_snake_case)] // Allow notation matching the spec
#![allow(clippy::clone_on_copy)] // Be explicit about moving data
#![allow(missing_docs)] // Require all public interfaces to be documented
#![allow(clippy::missing_errors_doc)] // Require docs for function returning `Result` missing `# Errors` section
#![allow(clippy::must_use_candidate)] // Require a `#[must_use]` attribute

pub mod time;

pub mod builder;
pub mod capability;
pub mod chain;
pub mod cwt;
pub mod jwt;
//pub mod key;
pub mod prelude;
pub mod semantics;
pub mod serde;
pub mod store;
pub mod token;
pub mod verifier;

pub use mysteryn_crypto as crypto;
pub use mysteryn_crypto::result;

#[macro_use(concat_string)]
extern crate concat_string;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub mod js;

#[cfg(all(test, target_family = "wasm", target_os = "unknown"))]
mod tests {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
}
