use crate::{prelude::*, store::TokenStore, token::Token as MultiToken, verifier::Verifier};
use async_trait::async_trait;
use cid::Cid;
use mysteryn_crypto::{multikey::*, result::Error};
use mysteryn_keys::DefaultKeyFactory;
use std::str::FromStr;
use wasm_bindgen::prelude::*;

/// Multikey secret key
pub type SecretKey = MultikeySecretKey<DefaultKeyFactory>;
/// Multikey public key
#[allow(dead_code)]
pub type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
/// Multisig signature
#[allow(dead_code)]
pub type Signature = Multisig<DefaultKeyFactory>;
/// Token
pub type Token = MultiToken<DefaultKeyFactory>;

#[wasm_bindgen(module = "JsDwtStore")]
extern "C" {
    pub type JsDwtStore;

    #[wasm_bindgen(method, catch)]
    async fn read(this: &JsDwtStore, cid: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn write(
        this: &JsDwtStore,
        cid: &str,
        token: &str,
        expires_at: u64,
        meta: JsValue,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn revoke(this: &JsDwtStore, cid: &str, expires_at: u64) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn is_revoked(this: &JsDwtStore, cid: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn cleanup(this: &JsDwtStore) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn remove(this: &JsDwtStore, cid: &str) -> Result<JsValue, JsValue>;
}

#[derive(Clone)]
pub struct JsDwtStoreWrap<'a> {
    pub store: &'a JsDwtStore,
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl<'a> TokenStore for JsDwtStoreWrap<'a> {
    async fn read(&self, cid: &Cid) -> mysteryn_crypto::result::Result<Option<Vec<u8>>> {
        self.store
            .read(&cid.to_string())
            .await
            .map(|x| {
                if x.is_null() {
                    return None;
                };
                if x.is_string() {
                    let Some(s) = x.as_string() else {
                        return None;
                    };
                    let Ok(token) = Token::from_str(&s) else {
                        return None;
                    };
                    let Ok(b) = token.encode() else {
                        return None;
                    };
                    return Some(b);
                }
                let Ok(v) = serde_wasm_bindgen::from_value(x) else {
                    return None;
                };
                Some(v)
            })
            .map_err(|e| Error::IOError(format!("{e:?}")))
    }

    async fn write(
        &mut self,
        cid: &Cid,
        token: &[u8],
        expires_at: u64,
        meta: Option<&DataMap>,
    ) -> mysteryn_crypto::result::Result<()> {
        let token = Token::try_from(token).map_err(|e| Error::InvalidToken(e.to_string()))?;
        let expires = if let Some(expires) = token.expires_at() {
            if *expires == 0 {
                expires_at
            } else {
                if expires_at == 0 {
                    0
                } else {
                    (*expires).min(expires_at)
                }
            }
        } else {
            expires_at
        };
        let meta = if let Some(m) = meta {
            serde_wasm_bindgen::to_value(m).map_err(|e| Error::EncodingError(e.to_string()))?
        } else {
            JsValue::NULL
        };
        self.store
            .write(&cid.to_string(), &token.encode_dwt()?, expires, meta)
            .await
            .map(|_| ())
            .map_err(|e| Error::IOError(format!("{e:?}")))
    }

    async fn revoke(&mut self, cid: &Cid, expires_at: u64) -> mysteryn_crypto::result::Result<()> {
        self.store
            .revoke(&cid.to_string(), expires_at)
            .await
            .map(|_| ())
            .map_err(|e| Error::IOError(format!("{e:?}")))
    }

    async fn is_revoked(&self, cid: &Cid) -> mysteryn_crypto::result::Result<bool> {
        self.store
            .is_revoked(&cid.to_string())
            .await
            .map(|x| x.as_bool().unwrap_or_default())
            .map_err(|e| Error::IOError(format!("{e:?}")))
    }

    async fn cleanup(&mut self) -> mysteryn_crypto::result::Result<()> {
        self.store
            .cleanup()
            .await
            .map(|_| ())
            .map_err(|e| Error::IOError(format!("{e:?}")))
    }

    async fn remove(&mut self, cid: &Cid) -> mysteryn_crypto::result::Result<()> {
        self.store
            .remove(&cid.to_string())
            .await
            .map(|_| ())
            .map_err(|e| Error::IOError(format!("{e:?}")))
    }
}

/// Invoke the token from a payload and sign with a secret key
/// @throws
#[wasm_bindgen]
pub async fn invokeToken(
    payload: JsValue,
    secret_key: &str,
    token_store: Option<JsDwtStore>,
) -> Result<JsValue, JsError> {
    let jwt_payload: crate::jwt::Payload = serde_wasm_bindgen::from_value(payload)?;
    let canonical_payload = CanonicalPayload::try_from(&jwt_payload)?;
    let secret = SecretKey::from_str(secret_key)?;
    if let Some(s) = token_store {
        let store = JsDwtStoreWrap { store: &s };
        let token = TokenBuilder::new(store)
            .with_secret(&secret)
            .with_payload(&canonical_payload)
            .build()
            .await?;
        Ok(JsValue::from_str(&token.encode_dwt()?))
    } else {
        let token = TokenBuilder::default()
            .with_secret(&secret)
            .with_payload(&canonical_payload)
            .build()
            .await?;
        Ok(JsValue::from_str(&token.encode_dwt()?))
    }
}

/// Verify the token. On success, returns `VerificationInfo` with granted capabilities.
/// @throws
#[wasm_bindgen]
pub async fn verifyToken(
    token_or_cid_string: &str,
    requirements: JsValue,
    secret_key: Option<String>,
    token_store: Option<JsDwtStore>,
) -> Result<JsValue, JsError> {
    let secret = if let Some(s) = secret_key {
        Some(SecretKey::from_str(&s)?)
    } else {
        None
    };
    let req = serde_wasm_bindgen::from_value(requirements)?;
    if let Some(s) = token_store {
        let store = JsDwtStoreWrap { store: &s };
        let mut verifier = Verifier::new(store, DefaultAttenuator {}, &DefaultKeyFactory);
        let result = verifier
            .verify_token_string(token_or_cid_string, secret, &req)
            .await?;
        Ok(serde_wasm_bindgen::to_value(&result)?)
    } else {
        let mut verifier = Verifier::default();
        let result = verifier
            .verify_token_string(token_or_cid_string, secret, &req)
            .await?;
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }
}

/// Get the token diagnostic text
#[wasm_bindgen]
pub fn token2diag(token_string: &str) -> String {
    Token::diag_token_string(token_string)
}

/// Get the token as an object
/// @throws
#[wasm_bindgen]
pub fn token2object(token_string: &str) -> Result<JsValue, JsError> {
    let token = Token::from_str(token_string)?;
    Ok(serde_wasm_bindgen::to_value(&token)?)
}

/// Get the token CID
/// @throws
#[wasm_bindgen]
pub fn token2cid(token_or_cid_string: &str) -> Result<String, JsError> {
    if let Ok(cid) = Cid::from_str(token_or_cid_string) {
        return Ok(cid.to_string());
    }
    let token = Token::from_str(token_or_cid_string)?;
    Ok(token
        .to_cid(multihash_codetable::Code::Blake3_256)
        .map(|cid| cid.to_string())?)
}
