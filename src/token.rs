use crate::{
    capability::Capabilities,
    cwt, jwt,
    serde::{Base64Encode, DagCbor, DagJson},
    time::now,
};
use base64::Engine;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use mysteryn_crypto::{
    Identity,
    did::Did,
    key_traits::{KeyFactory, PublicKeyTrait, SecretKeyTrait, SignatureTrait},
    multibase,
    multicodec::multicodec_prefix,
    multikey::{MultikeyPublicKey, MultikeySecretKey, Multisig},
    result::{Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    fmt::{Debug, Display},
    str::FromStr,
};

pub const DELEGABLE_WEB_TOKEN_TYPE: &str = "dwt";

pub type DataMap = BTreeMap<String, Value>;

/// Canonical token payload for signing and verifying the signature.
/// Must be serialized to DAG-CBOR for signing.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
// This hack with bound is used to tell serde to not implement the "KF"
// serialize/deserialize, because the result will conflict with itself.
#[serde(bound = "KF: std::any::Any")]
pub struct CanonicalPayload<KF: KeyFactory> {
    /// The issuer DID
    pub iss: Did,
    /// The audience DID
    pub aud: Did,

    /// Claiming capabilities
    pub can: Capabilities,
    /// Proof links
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Vec<Cid>>,
    /// Embedded proofs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre: Option<Vec<Token<KF>>>,

    /// Expiry time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Not before time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// Data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dat: Option<DataMap>,
    /// Optional public key for "did:pkh"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pbk: Option<String>,
    /// Optional nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nnc: Option<String>,
}

impl<KF: KeyFactory> From<&Token<KF>> for CanonicalPayload<KF> {
    fn from(token: &Token<KF>) -> Self {
        Self {
            iss: token.iss.clone(),
            aud: token.aud.clone(),

            can: token.can.clone(),
            prf: token.prf.clone(),
            pre: token.pre.clone(),

            exp: token.exp,
            nbf: token.nbf,
            dat: token.dat.clone(),
            pbk: token.pbk.clone(),
            nnc: None,
        }
    }
}

/// The DWT token in IPLD format.
#[derive(PartialEq, Eq, Serialize, Deserialize, Clone)]
// This hack with bound is used to tell serde to not implement the "KF"
// serialize/deserialize, because the result will conflict with itself.
#[serde(bound = "KF: std::any::Any")]
pub struct Token<KF: KeyFactory> {
    pub iss: Did,
    pub aud: Did,

    pub can: Capabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prf: Option<Vec<Cid>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre: Option<Vec<Token<KF>>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dat: Option<DataMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pbk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nnc: Option<String>,

    pub sig: Multisig<KF>,
}

impl<KF: KeyFactory> Token<KF> {
    pub fn new(payload: CanonicalPayload<KF>, signature: &Multisig<KF>) -> Self {
        Self {
            iss: payload.iss,
            aud: payload.aud,

            can: payload.can,
            prf: payload.prf,
            pre: payload.pre,

            exp: payload.exp,
            nbf: payload.nbf,
            dat: payload.dat,
            pbk: payload.pbk,
            nnc: payload.nnc,

            sig: signature.clone(),
        }
    }

    /// Validate the signature and timestamps
    pub fn validate(
        &self,
        my_secret_key: Option<MultikeySecretKey<KF>>,
        now_time: Option<u64>,
    ) -> Result<()> {
        if self.is_expired(now_time) {
            return Err(Error::InvalidToken("expired".to_owned()));
        }
        if self.is_too_early() {
            return Err(Error::InvalidToken("not active yet (too early)".to_owned()));
        }

        self.verify_signature(my_secret_key)
    }

    /// Validate that the signed data was signed by the stated issuer
    pub fn verify_signature(&self, my_secret_key: Option<MultikeySecretKey<KF>>) -> Result<()> {
        // ensure that the signed data matches the canonical representation
        let canonical_payload = CanonicalPayload::from(self).to_dag_cbor()?;
        let method = self.iss.method();

        let key = if method == "pkh" || method.starts_with("pkh:") {
            let Some(key) = self.pbk.clone() else {
                return Err(Error::ValidationError("no public key".to_owned()));
            };
            let key = MultikeyPublicKey::<KF>::from_str(&key)?;
            let id = Identity::from_public_key(&key, &self.iss.hrp());
            let iss_id = self.iss.get_identity()?;
            if iss_id != id {
                return Err(Error::ValidationError(format!(
                    "public key missmatch {iss_id} != {id}"
                )));
            }
            key
        } else {
            MultikeyPublicKey::<KF>::try_from(&self.iss)?
        };

        if key.can_verify() {
            key.verify(&canonical_payload, self.sig.raw())
        } else if let Some(my_secret_key) = my_secret_key {
            my_secret_key.verify(&canonical_payload, self.sig.raw())
        } else {
            Err(Error::ValidationError(
                "cannot verify signature - secret key required".to_owned(),
            ))
        }
    }

    /// Produce a DAG-CBOR binary DWT serialization of the token
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.to_dag_cbor()
    }

    /// Produce a multibase base58-encoded DWT serialization of the token suitable for
    /// transferring in a header field
    pub fn encode_dwt(&self) -> Result<String> {
        self.cwt_cbor_base58_encode()
    }

    /// Produce a multibase base58-encoded CWT serialization of the token suitable for
    /// transferring in a header field
    pub fn encode_cwt(&self) -> Result<String> {
        let header = cwt::Header::from(self);
        let payload = CanonicalPayload::from(self);
        let cwt = crate::cwt::encode(
            &header.to_dag_cbor()?,
            &payload.to_dag_cbor()?,
            self.sig.as_bytes(),
        )?;
        Ok("z".to_string() + &bs58::encode(&cwt).into_string())
    }

    /// Produce a base64-encoded JWT serialization of the token suitable for
    /// transferring in a header field
    pub fn encode_jwt(&self) -> Result<String> {
        let header = jwt::Header::from(self)
            .jwt_json_base64_encode()
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let payload = jwt::Payload::try_from(self)?
            .jwt_json_base64_encode()
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let signature =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.sig.as_bytes());

        Ok(format!("{header}.{payload}.{signature}"))
    }

    /// Returns true if the token has past its expiration date
    pub fn is_expired(&self, now_time: Option<u64>) -> bool {
        if let Some(exp) = self.exp {
            exp < now_time.unwrap_or_else(now)
        } else {
            false
        }
    }

    pub fn signature(&self) -> &Multisig<KF> {
        &self.sig
    }

    /// Returns true if the not-before ("nbf") time is still in the future
    pub fn is_too_early(&self) -> bool {
        match self.nbf {
            Some(nbf) => nbf > now(),
            None => false,
        }
    }

    /// Returns true if this token's lifetime begins no later than the other
    pub fn lifetime_begins_no_later(&self, other: &Token<KF>) -> bool {
        match (self.nbf, other.nbf) {
            (Some(nbf), Some(other_nbf)) => nbf <= other_nbf,
            (Some(_), None) => false,
            _ => true,
        }
    }

    /// Returns true if this token expires no earlier than the other
    pub fn lifetime_ends_no_earlier(&self, other: &Token<KF>) -> bool {
        match (self.exp, other.exp) {
            (Some(exp), Some(other_exp)) => exp >= other_exp,
            (Some(_), None) => false,
            _ => true,
        }
    }

    /// Returns true if this token's lifetime fully encompasses the other
    pub fn lifetime_encompasses(&self, other: &Token<KF>) -> bool {
        self.lifetime_begins_no_later(other) && self.lifetime_ends_no_earlier(other)
    }

    pub fn algorithm(&self) -> &str {
        self.sig.algorithm_name()
    }

    pub fn issuer(&self) -> &Did {
        &self.iss
    }

    pub fn audience(&self) -> &Did {
        &self.aud
    }

    pub fn proofs(&self) -> &Option<Vec<Cid>> {
        &self.prf
    }

    pub fn embedded_proofs(&self) -> &Option<Vec<Token<KF>>> {
        &self.pre
    }

    pub fn expires_at(&self) -> &Option<u64> {
        &self.exp
    }

    pub fn not_before(&self) -> &Option<u64> {
        &self.nbf
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.can
    }

    pub fn data(&self) -> Option<&DataMap> {
        self.dat.as_ref()
    }

    pub fn to_cid(&self, hasher: Code) -> Result<Cid> {
        let token = self.encode()?;
        Ok(Cid::new_v1(
            multicodec_prefix::DAG_CBOR,
            hasher.digest(&token),
        ))
    }

    pub fn get_embedded_proof(&self, cid: &Cid, hasher: Code) -> Option<Token<KF>> {
        if let Some(proofs) = &self.pre {
            for proof in proofs {
                if let Ok(token_cid) = proof.to_cid(hasher) {
                    if token_cid == *cid {
                        return Some(proof.clone());
                    }
                }
            }
        }
        None
    }

    pub fn diag_token_string(token_str: &str) -> String {
        if token_str.contains('.') {
            // JWT token
            let mut parts = token_str.split('.').map(|str| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(str)
                    .map_err(|error| Error::EncodingError(error.to_string()))
            });

            let header = match parts.next() {
                Some(h) => match h {
                    Ok(h) => std::str::from_utf8(&h)
                        .map(std::string::ToString::to_string)
                        .map_err(|e| Error::EncodingError(e.to_string())),
                    Err(e) => Err(e),
                },
                None => Err(Error::EncodingError(
                    "missing header in token part".to_string(),
                )),
            };
            let header = match header {
                Ok(h) => h,
                Err(e) => e.to_string(),
            };

            let payload = match parts.next() {
                Some(p) => match p {
                    Ok(p) => std::str::from_utf8(&p)
                        .map(std::string::ToString::to_string)
                        .map_err(|e| Error::EncodingError(e.to_string())),
                    Err(e) => Err(e),
                },
                None => Err(Error::EncodingError(
                    "missing payload in token part".to_string(),
                )),
            };
            let payload = match payload {
                Ok(p) => p,
                Err(e) => e.to_string(),
            };

            let signature = match parts.next() {
                Some(h) => match h {
                    Ok(s) => match Multisig::<KF>::try_from(s.as_slice()) {
                        Ok(s) => Ok(format!("{s:?}")),
                        Err(e) => Err(Error::EncodingError(format!("invalid signature - {e}"))),
                    },
                    Err(e) => Err(e),
                },
                None => Err(Error::EncodingError(
                    "missing signature in token part".to_string(),
                )),
            };
            let signature = match signature {
                Ok(s) => s,
                Err(e) => e.to_string(),
            };

            let (token, cid) = match Token::<KF>::from_str(token_str) {
                Ok(token) => (
                    format!("{token:?}"),
                    if let Ok(cid) = token.to_cid(Code::Blake3_256) {
                        cid.to_string()
                    } else {
                        String::new()
                    },
                ),
                Err(e) => (e.to_string(), String::new()),
            };

            format!(
                "====================================\n---- JWT token: {token_str}\n---- Header:    {header}\n---- Payload:   {payload}\n---- Signature: {signature}\n---- CID      : {cid}\n---- Canonical: {token}\n===================================="
            )
        } else {
            // DWT or CWT token
            let mut token_type = "DWT".to_string();
            let payload = match multibase::decode(token_str) {
                Ok(token_bytes) => {
                    if crate::cwt::is_cwt(&token_bytes) {
                        token_type = "CWT".to_string();
                    }
                    cbor_diag::parse_bytes(&token_bytes)
                        .map_err(|e| Error::EncodingError(e.to_string()))
                }
                Err(e) => Err(Error::EncodingError(e.to_string())),
            };
            let payload = match payload {
                Ok(p) => p.to_diag_pretty(),
                Err(e) => e.to_string(),
            };

            let (token, cid) = match Token::<KF>::from_str(token_str) {
                Ok(token) => (
                    format!("{token:?}"),
                    if let Ok(cid) = token.to_cid(Code::Blake3_256) {
                        cid.to_string()
                    } else {
                        String::new()
                    },
                ),
                Err(e) => (e.to_string(), String::new()),
            };

            format!(
                "====================================\n---- {token_type} token: {token_str}\n---- Payload:   {payload}\n---- CID      : {cid}\n---- Canonical: {token}\n===================================="
            )
        }
    }
}

impl<KF: KeyFactory> TryFrom<&[u8]> for Token<KF> {
    type Error = Error;

    fn try_from(token_bytes: &[u8]) -> Result<Self> {
        Self::from_dag_cbor(token_bytes)
    }
}

/// Deserialize an encoded token string reference into a token
impl<KF: KeyFactory> FromStr for Token<KF> {
    type Err = Error;

    fn from_str(token_str: &str) -> Result<Self> {
        if token_str.contains('.') {
            // JWT token
            let mut parts = token_str.split('.').map(|str| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(str)
                    .map_err(|error| Error::EncodingError(error.to_string()))
            });

            let header = parts
                .next()
                .ok_or_else(|| Error::InvalidToken("missing header in token part".to_owned()))?
                .map_err(|e| Error::InvalidToken(format!("could not read header JSON: {e}")))?;

            let jwt_header = jwt::Header::from_dag_json(&header)
                .map_err(|e| Error::InvalidToken(e.to_string()))?;
            // round-trip to verify exact match
            if jwt_header
                .to_dag_json()
                .map_err(|e| Error::InvalidToken(e.to_string()))?
                != *header
            {
                return Err(Error::InvalidToken("invalid header".to_owned()));
            }
            if jwt_header.typ.to_lowercase() != DELEGABLE_WEB_TOKEN_TYPE
                && jwt_header.typ.to_lowercase() != "jwt"
            {
                return Err(Error::InvalidToken(format!(
                    "unsupported token type: {}",
                    jwt_header.typ
                )));
            }

            let signed_data = parts
                .next()
                .ok_or_else(|| Error::InvalidToken("missing payload in token part".to_owned()))?
                .map_err(|e| Error::InvalidToken(format!("could not read payload JSON: {e}")))?;

            let jwt_payload = jwt::Payload::from_dag_json(&signed_data)?;
            // round-trip to verify exact match
            if jwt_payload
                .to_dag_json()
                .map_err(|e| Error::InvalidToken(e.to_string()))?
                != *signed_data
            {
                return Err(Error::InvalidToken("invalid payload".to_owned()));
            }
            let canonical_payload = CanonicalPayload::try_from(&jwt_payload)?;

            let signature = parts
                .next()
                .ok_or_else(|| Error::InvalidToken("missing signature in token part".to_owned()))?
                .map_err(|e| Error::InvalidToken(format!("could not read signature: {e}")))?;
            let signature = Multisig::<KF>::try_from(signature.as_slice())?;

            if jwt_header.alg != signature.algorithm_name() {
                return Err(Error::InvalidToken("algorithm missmatch".to_owned()));
            }

            Ok(Token::new(canonical_payload, &signature))
        } else {
            let token_bytes = multibase::decode(token_str)?;
            if crate::cwt::is_cwt(&token_bytes) {
                // CWT token
                let (header, payload, signature) = crate::cwt::decode(&token_bytes)?;
                let cwt_header = cwt::Header::from_dag_cbor(&header)?;
                // round-trip to verify exact match
                if cwt_header
                    .to_dag_cbor()
                    .map_err(|e| Error::InvalidToken(e.to_string()))?
                    != header
                    || cwt_header.typ.to_lowercase() != DELEGABLE_WEB_TOKEN_TYPE
                {
                    return Err(Error::InvalidToken("invalid header".to_owned()));
                }
                let canoninical_payload = CanonicalPayload::from_dag_cbor(&payload)?;
                // round-trip to verify exact match
                if canoninical_payload
                    .to_dag_cbor()
                    .map_err(|e| Error::InvalidToken(e.to_string()))?
                    != *payload
                {
                    return Err(Error::InvalidToken("invalid payload".to_owned()));
                }
                let signature = Multisig::<KF>::try_from(signature.as_slice())?;
                if cwt_header.alg != signature.algorithm_name() {
                    return Err(Error::InvalidToken("algorithm missmatch".to_owned()));
                }

                Ok(Token::new(canoninical_payload, &signature))
            } else {
                // DWT token
                Token::try_from(token_bytes.as_slice())
            }
        }
    }
}

impl<KF: KeyFactory> Display for Token<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = self.encode_cwt().map_err(|_| std::fmt::Error)?;
        write!(f, "{token}")
    }
}

impl<KF: KeyFactory> PartialOrd for Token<KF> {
    fn partial_cmp(&self, other: &Self) -> std::option::Option<std::cmp::Ordering> {
        //let a = self.encode().unwrap_or_default();
        //let b = other.encode().unwrap_or_default();
        //Some(a.cmp(&b))
        Some(self.cmp(other))
    }
}

impl<KF: KeyFactory> Ord for Token<KF> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let a = self.encode().unwrap_or_default();
        let b = other.encode().unwrap_or_default();
        a.cmp(&b)
    }
}

struct CidDebugWrapper(Cid);

impl Debug for CidDebugWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<KF: KeyFactory> Debug for Token<KF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO default hasher
        let cid = CidDebugWrapper(self.to_cid(Code::Blake3_256).map_err(|_| std::fmt::Error)?);
        let prf_debug = self.prf.as_ref().map(|cids| {
            cids.iter()
                .map(|cid| CidDebugWrapper(cid.clone()))
                .collect::<Vec<CidDebugWrapper>>()
        });
        f.debug_struct("Token")
            .field("#cid", &cid)
            .field("iss", &self.iss)
            .field("aud", &self.aud)
            .field("can", &self.can)
            .field("prf", &prf_debug)
            .field("pre", &self.pre)
            .field("exp", &self.exp)
            .field("nbf", &self.nbf)
            .field("dat", &self.dat)
            .field("pbk", &self.pbk)
            .field("nnc", &self.nnc)
            .field("sig", &self.sig)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Token as MultiToken;
    use crate::{
        builder::TokenBuilder,
        capability::{Capabilities, Capability},
        serde::DagCbor,
        store::{MemoryStore, TokenStore},
        verifier::Requirements,
        verifier::Verifier,
    };
    use multihash_codetable::Code;
    use mysteryn_crypto::{multicodec::multicodec_prefix, prelude::*, result::Result};
    use mysteryn_keys::DefaultKeyFactory;
    use std::{collections::BTreeMap, str::FromStr};
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    type SecretKey = MultikeySecretKey<DefaultKeyFactory>;
    type Token = MultiToken<DefaultKeyFactory>;

    const SECRET1: &str = "secret_xahgjgqfsxwdjkxun9wspqzgzve7sze7vwm0kszkya5lurz4np9cmc8k4frds9ze0g6kzsky8pmv8qxur4vfupul38mfdgrcc";
    //const PUBLIC1: &str = "pub_xahgjw6qgrwp6kyqgpypch74uwu40vns89yhzppvxjket5wf63tty0ar3nexl5l797l2q40ypevtls9aprku";
    const SECRET2: &str = "secret_xahgjgqfsxwdjkxun9wspqzgr376fxzzk8jms55m6gkxa3dmtkyzmm6wfajarmv37qrf4gkqjg0g8qxur4v2gsj5skasefdpg";
    //const PUBLIC2: &str = "pub_xahgjw6qgrwp6kyqgpyq29vthlflt6dtl5pvlrwrnllgyy5ws5a0w3xa2tt0425k9rvcwus9j33c3u0m7a2v";
    const SECRET3: &str = "secret_xahgjgqfsxwdjkxun9wspqzgrn0pkqhum8l2tmqkgv6hwsxz7hdhdhptwk5h603d6ylrym6hqs558qxur4vfhwa808gw29q6g";
    //const PUBLIC3: &str = "pub_xahgjw6qgrwp6kyqgpypytg3jyl048vrnfvngk6wpz40pnhy4248gfx2guhwfczwm5mqywvctvd3e3pzlxyq";

    #[test]
    #[ignore]
    fn generate_keys() -> Result<()> {
        let secret1 = SecretKey::new(
            multicodec_prefix::ED25519_SECRET,
            None,
            None,
            Some("secret"),
            Some("pub"),
        )?;
        let public1 = secret1.public_key();
        println!("const SECRET1: &str = \"{secret1}\";");
        println!("const PUBLIC1: &str = \"{}\";", public1);
        let secret2 = SecretKey::new(
            multicodec_prefix::ED25519_SECRET,
            None,
            None,
            Some("secret"),
            Some("pub"),
        )?;
        let public2 = secret2.public_key();
        println!("const SECRET2: &str = \"{secret2}\";");
        println!("const PUBLIC2: &str = \"{}\";", public2);
        let secret3 = SecretKey::new(
            multicodec_prefix::ED25519_SECRET,
            None,
            None,
            Some("secret"),
            Some("pub"),
        )?;
        let public3 = secret3.public_key();
        println!("const SECRET3: &str = \"{secret3}\";");
        println!("const PUBLIC3: &str = \"{}\";", public3);
        Ok(())
    }

    async fn build_proof() -> Result<Token> {
        let secret_key = SecretKey::from_str(SECRET3).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient = recipient_secret_key.public_key();
        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";
        TokenBuilder::default()
            .with_secret(&secret_key)
            .for_audience(&recipient.get_did().unwrap())
            .with_capabilities(&capabilities)
            .build_deterministic(nonce)
            .await
    }

    async fn build_proof2() -> Result<Token> {
        let secret_key = SecretKey::from_str(SECRET3).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient = recipient_secret_key.public_key();
        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12341234";
        TokenBuilder::default()
            .with_secret(&secret_key)
            .for_audience(&recipient.get_did().unwrap())
            .with_capabilities(&capabilities)
            .build_deterministic(nonce)
            .await
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_encode_decode_dwt() {
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
        let recipient = recipient_secret_key.public_key();

        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";
        let proof = build_proof().await.expect("cannot build a proof");
        println!("proof {proof:?}");
        let proof2 = build_proof2().await.expect("cannot build a proof");
        let proof2_cid = &proof2.to_cid(Code::Blake3_256).expect("cannot parse CID");
        println!("proof2_cid {proof2_cid}");

        let mut store = MemoryStore::default();
        store
            .write(
                proof2_cid,
                &proof2.to_dag_cbor().expect("cannot encode the token"),
                proof2.expires_at().unwrap_or_default(),
                proof2.data(),
            )
            .await
            .expect("cannot store");
        let builder = TokenBuilder::new(store)
            .with_secret(&secret_key)
            .for_audience(&recipient.get_did().unwrap())
            .with_capabilities(&capabilities)
            .with_proof_cid(proof2_cid)
            .await
            .expect("cannot use CID")
            .with_proof_token(&proof)
            .expect("cannot use proof");
        let token = builder.build_deterministic(nonce).await.unwrap();

        token.verify_signature(None).unwrap();
        token.validate(None, Some(1000)).unwrap();

        let dwt = token.encode_dwt().unwrap();
        println!("{}", Token::diag_token_string(&dwt));
        assert_eq!(
            dwt,
            "z3PMDkCJyZ6a9aPz2J6313gHJdVLHomQUdTZTsHhfquWgsVBbhbvrhck1JJgijxEAwUzQHFaJjkjhqpDeWSRuHYNug1nQmfTjBjKMJqGtZdT3DfFAqDrDDAVShUTfn3SQi2BYoikKMD9Kv7HkPWhT2TdfkLUqaJMCgB4cV7CZ5D1cD8GNN3uYBrEGbsJstZiEG2okDDuPtkUZMbgKxx6JyhNhyzGRqCpqaKF78C1Ch3WnkoxixFyfiLa6EwjhkKqKDN9ZRv9mLeBHZVBXw34LK8Gia647pV9GA8g2tLXRRpbBd5fPPP8p8ZK5hsm4x5ydRcXX1GpkFAAYP4xFVx6wW52ptoAcnFzzQTvaXS8aJd4ZHyos78FLPo535NqfG1SNb8U1JAeRJdnuDZF3X6VKZRXfeT4WpekLo5241oYWEa8HuPecJ77NgnfRsvBZMXZTeDnSJN8azzRGyZeU2oQ8pqZ6ogNowuMu3TNFt1wyBeVcA8cyiJ9BtDXF63mcGLHpfKptsAcw3NGiFRoc1R2nDdXBQFyDMHSYnLxVV7h6MCU1yjP9v6JepseBTnSQGgFVUmBRbmLxiy8hHu4iFHEVhhuQan3oejcHHHnfDHM8sHDS8VLGqZiRUg7WEjLztk9AprkBb51PRvXq2sHW1grZ2tcSua4ahTJ5o4RVEaQ3ioxS7bRojgPAbrEqZqZgMECjeSj9pR89EJ4N4ccyK9jf9WtgDT3jNv4EgizZzZKKNsuyJbw1DBoz8fErRXhc9bYDAGFuLapgPUe55wXEVREjYDV99YVMoiiHhb27m9Wg3Npbw3NFdJSPSYjbrsY31io"
        );

        let decoded = Token::from_str(&dwt).unwrap();

        assert_eq!(decoded.to_string(), token.to_string());
        assert_eq!(decoded, token);
        decoded.verify_signature(None).unwrap();
        decoded.validate(None, Some(1000)).unwrap();

        let decoded_dwt = decoded.encode_dwt().unwrap();
        assert_eq!(decoded_dwt, dwt);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_encode_decode_jwt() {
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
        let recipient = recipient_secret_key.public_key();

        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";
        let proof = build_proof().await.expect("cannot build a proof");
        let proof2 = build_proof2().await.expect("cannot build a proof");
        let proof2_cid = &proof2.to_cid(Code::Blake3_256).expect("cannot parse CID");
        println!("proof2_cid {proof2_cid}");

        let mut store = MemoryStore::default();
        store
            .write(
                proof2_cid,
                &proof2.to_dag_cbor().expect("cannot encode the token"),
                proof2.expires_at().unwrap_or_default(),
                proof2.data(),
            )
            .await
            .expect("cannot store");
        let builder = TokenBuilder::new(store)
            .with_secret(&secret_key)
            .for_audience(&recipient.get_did().unwrap())
            .with_capabilities(&capabilities)
            .with_proof_cid(proof2_cid)
            .await
            .expect("cannot use CID")
            .with_proof_token(&proof)
            .expect("cannot use proof");
        let token = builder.build_deterministic(nonce).await.unwrap();

        token.verify_signature(None).unwrap();
        token.validate(None, Some(1000)).unwrap();

        let jwt = token.encode_jwt().unwrap();
        println!("{}", Token::diag_token_string(&jwt));
        assert_eq!(
            jwt,
            "eyJhbGciOiJFZERTQSIsInR5cCI6ImR3dCJ9.eyJhdWQiOiJkaWQ6a2V5OnB1Yl94YWhnanc2cWdyd3A2a3lxZ3B5cTI5dnRobGZsdDZkdGw1cHZscndybmxsZ3l5NXdzNWEwdzN4YTJ0dDA0MjVrOXJ2Y3d1czlqMzNjM3UwbTdhMnYiLCJjYW4iOnsibWFpbHRvOnRlc3RAdGVzdC5jb20iOlsibXNnL3JlY2VpdmUiLCJtc2cvc2VuZCJdfSwiaXNzIjoiZGlkOmtleTpwdWJfeGFoZ2p3NnFncndwNmt5cWdweXBjaDc0dXd1NDB2bnM4OXloenBwdnhqa2V0NXdmNjN0dHkwYXIzbmV4bDVsNzk3bDJxNDB5cGV2dGxzOWFwcmt1IiwicHJlIjpbInpleXZjNW1Zcjh1VXJZVTZ3dW9QVlJOR2NpWVEzZjVadmZueVR0MUNNWkJZREpxWDlRSkhhVFE1dXZDOW1QNXhidEplVGhNQUNHS2dOZGdzeDlrZmpZeFgzNXZ6VWs4N0ZKSHR0eEh6ejJBWXJaM0JzZ05MUDZOVWY0aEEyTlk1N29ZcWlTQkZhTHBzUjV0dlBReTlYbmlSVE5YV2ZwUnlEa1ozbU5mQ0xxa2NHSno0WVBlRnU3WW1ZenFpOW1HTHRUUXNYRmlGRTJlMmFUZHB0ZVcyb0VSVnBoeXJWRkdZZlo4N3ZkWDg3cmZtWXIyNjdBblZKVnFYM2RKZTFGU0JDV01BVFJzWkg5ZjdhcmlTNjU0Y2RiY1RNcTlUaWJUWHNWWjlINFd4dW9EMnZTWExnTVpLenZZYndMMWFBWGFzZFVzZFBoZHdDa0tadkROYmRkeDRVVzhNR2t2NHF4bnRYd0ZNYlhpU2syZDloOUI4Mzg0bmNYM0Z2ekRqNDRIaTZKWDNTdktqTSJdLCJwcmYiOlsiYmFmeXI0aWN5NmZmb3drd255a2lwaDV1bWNqcTNja3N0b3V2enRlbXQzbHR2NjJiZnh0Ynozd2ZsNG0iLCJiYWZ5cjRpaGVqenNtZzJzZjd4NzRveXBqaXRuZmpyajJkcWllcnJ3N3NsNGdyNXlvbWs0NnpzaDdkdSJdfQ.uSTtAQADAEAOty-14OZqZ7oDKAxCOCj2Sqnv44owBVRk1u86ydwQbxog_NIIH6YiGUOYaObijj9RPaMrZcStFRA7BK3XD0UIAQFxCAgxMjM0NTY3OA"
        );

        let decoded = Token::from_str(&jwt).unwrap();
        assert_eq!(decoded.to_string(), token.to_string());
        assert_eq!(decoded, token);
        decoded.verify_signature(None).unwrap();
        decoded.validate(None, Some(1000)).unwrap();

        let decoded_jwt = decoded.encode_jwt().unwrap();
        assert_eq!(decoded_jwt, jwt);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_encode_decode_cwt() {
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
        let recipient = recipient_secret_key.public_key();

        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";
        let proof = build_proof().await.expect("cannot build a proof");
        let proof2 = build_proof2().await.expect("cannot build a proof");
        let proof2_cid = &proof2.to_cid(Code::Blake3_256).expect("cannot parse CID");
        println!("proof2_cid {proof2_cid}");

        let mut store = MemoryStore::default();
        store
            .write(
                proof2_cid,
                &proof2.to_dag_cbor().expect("cannot encode the token"),
                proof2.expires_at().unwrap_or_default(),
                proof2.data(),
            )
            .await
            .expect("cannot store");
        let builder = TokenBuilder::new(store)
            .with_secret(&secret_key)
            .for_audience(&recipient.get_did().unwrap())
            .with_capabilities(&capabilities)
            .with_proof_cid(proof2_cid)
            .await
            .expect("cannot use CID")
            .with_proof_token(&proof)
            .expect("cannot use proof");
        let token = builder.build_deterministic(nonce).await.unwrap();

        token.verify_signature(None).unwrap();
        token.validate(None, Some(1000)).unwrap();

        let cwt = token.encode_cwt().unwrap();
        println!("{}", Token::diag_token_string(&cwt));
        assert_eq!(
            cwt,
            "z3foobtamUJPGasTPpZpu8tt5ESknBZbggVutqmrsbFgsxtiqwbfhxaS7TAT2VBHkdu6Pg9arbrnb2omMrGv4eChadUkKySJrJbVzWEWJbjfBrALARL2B9WF6h1BpcRWUY87Q9XZ89hhAh5yygZaBHkMib3K1SwpswUJF38odbxWT3iUnmF2yDDukU5UTMRFLRr6CR1AuCQexXWm5VrKA5BuvFX4u2MAPW5Kt4Ez7F36fbTF7LfYJuGL4rpQn9WQXrroY6SfLEnTAvhrdts7jZt1SY1Bx4gmXY88VQZvBnSpaQDDueoWK7Zs6spjPFcSKVfrTQruqeGjM8hvPUNRu5UxTR5brddZHtH4tmDmiyjVV8hBWCViNpDpcVmFNjXbZP5vXGYWRWG48JKdxHgUXBG9kidGZnzZccCbf6rqahWo7spqJ3QtLnkiDicKSU9bWTeu5kUvAMTSWxbL1TENp4CrrXsxwQRUkXurrqz9RPn5hAy4UwS5q9LUHUt7sTzQpntdfAfyh1GeH8wCMAVD9GMV5iDNyHf8eP7ZhZnQojTdrvzQdKCXNuKfwihw1x81ZTcWuKy8q7ehpc4V51w7wQYoxzfBogs32NCeycT5n1S4wCAqUXqmFF8qUQbnTEzsMuY2PeZ9EfhouYtDrn5Qr7wwJ9PdRugQcUUgG4MVVqLsioqdBfffYr4KpCTiATeHtLimNeS24GjEpfXhhPWdGGAF33QLXBgpbKe8mMABpA8Ywyjz9jiZHNcMPVxugKzTeYDDcvaLxWQEcDc5xKy85mEymyeWmo5d2jYXn6BVKpheRiSDAMBiAXwYVxTZZFnr3Rh7GBhwG7jCeC7qPDVGPLyngkhKJba8r8qgGR4w1"
        );

        let decoded = Token::from_str(&cwt).unwrap();

        assert_eq!(decoded.to_string(), token.to_string());
        assert_eq!(decoded, token);
        decoded.verify_signature(None).unwrap();
        decoded.validate(None, Some(1000)).unwrap();

        let decoded_cwt = decoded.encode_cwt().unwrap();
        assert_eq!(decoded_cwt, cwt);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_verify() {
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
        let recipient = recipient_secret_key.public_key();

        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";

        let builder = TokenBuilder::default()
            .with_secret(&secret_key)
            .for_audience(&recipient.get_did().unwrap())
            .with_capabilities(&capabilities);
        let token = builder.build_deterministic(nonce).await.unwrap();

        let requirements = Requirements {
            audience: recipient.get_did().unwrap().to_string(),
            capabilities: BTreeMap::from([(
                secret_key.get_did().unwrap().to_string(),
                Capabilities::try_from(vec![
                    Capability::from(("mailto:test@test.com", "msg/receive")),
                    Capability::from(("mailto:test@test.com", "msg/send")),
                ])
                .unwrap(),
            )]),
            data: None,
            time: None,
            known_tokens: None,
        };

        let mut verifier: Verifier<_, _, DefaultKeyFactory> = Verifier::default();
        let result = verifier.verify(&token, None, &requirements).await.unwrap();
        println!("result {:#?}", result);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_did_pkh_dwt() {
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
        let issuer = secret_key
            .public_key()
            .get_did_pkh("mys", Some("id"))
            .unwrap();
        let recipient = recipient_secret_key
            .public_key()
            .get_did_pkh("mys", Some("id"))
            .unwrap();

        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";

        let builder = TokenBuilder::default()
            .with_secret(&secret_key)
            .issued_by(&issuer)
            .for_audience(&recipient)
            .with_capabilities(&capabilities);
        let token = builder.build_deterministic(nonce).await.unwrap();

        token.verify_signature(None).unwrap();
        token.validate(None, Some(1000)).unwrap();

        let dwt = token.encode_dwt().unwrap();
        println!("{}", Token::diag_token_string(&dwt));
        assert_eq!(
            dwt,
            "z6HhM8UqAKhtcZWpDSZuoxA9HhtFJeeWTDvrq6egvLAbbEkboi5sW8uemKMJTkwj2Mfz6uRuyFmX4R7LV1SYWE694TYGKrXawhukr1wwtu3JhJTP2PAGb2bpt5tiCPJCxTvqYK6jofhhXNFMiQmP4qx7A7AEs5h4rtB1a6GCtkyguh9AMQ2jcmGRSygD98TsqHHZeSf2yMveragukELExFwqDuzgeYtVsD8bgNHv2jSDQRKTCLZmyG2pSoopkvcvAHMcMhzXTkUPzXbDeuykewmGcgeau252t3Q1WdZKbWa7foHYu6MsGzBybnWzXdJqUQSswvr9cc94RcTj9dWkxLgx2mEE5x9NkEMDJ1Fhts1VA3KweySaG12StkRtqBjSC6dfAVzoyAkCXhrhsQjcCUUrK1pXAMyMJYJABaRWtrfYiu74U4tK6ZMzTHSyuzqAERjEm56UzZnzP7MwtkDZT2Gv1V"
        );

        let decoded = Token::from_str(&dwt).unwrap();

        assert_eq!(decoded.to_string(), token.to_string());
        assert_eq!(decoded, token);
        decoded.verify_signature(None).unwrap();
        decoded.validate(None, Some(1000)).unwrap();

        let decoded_dwt = decoded.encode_dwt().unwrap();
        assert_eq!(decoded_dwt, dwt);
    }
}
