use crate::{
    capability::Capabilities,
    token::{CanonicalPayload, DELEGABLE_WEB_TOKEN_TYPE},
    token::{DataMap, Token},
};
use cid::Cid;
use mysteryn_crypto::{
    did::Did,
    key_traits::{KeyFactory, SignatureTrait},
    result::{Error, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

fn default_typ() -> String {
    DELEGABLE_WEB_TOKEN_TYPE.to_owned()
}

fn lowercase<'de, T, D>(deserializer: D) -> std::result::Result<T, D::Error>
where
    T: serde::de::DeserializeOwned,
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::deserialize(Value::String(s.to_lowercase())).map_err(serde::de::Error::custom)
}

/// Token header in the JSON serializable format.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Header {
    pub alg: String,
    #[serde(default = "default_typ", deserialize_with = "lowercase")]
    pub typ: String,
}

/// Token payload in the JSON serializable format.
/// This format is used to force DIDs and Proofs to be strings when encoding
/// with the DAG-JSON codec.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Payload {
    #[serde(alias = "issuer")]
    pub iss: String,
    #[serde(alias = "audience")]
    pub aud: String,

    #[serde(alias = "capabilities")]
    pub can: Capabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "proofs")]
    pub prf: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "embeddedProofs")]
    pub pre: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "expiresAt")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "notBefore")]
    pub nbf: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "data")]
    pub dat: Option<DataMap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "publicKey")]
    pub pbk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "nonce")]
    pub nnc: Option<String>,
}

impl<KF: KeyFactory> TryFrom<&Token<KF>> for Payload {
    type Error = Error;
    fn try_from(token: &Token<KF>) -> Result<Self> {
        Ok(Self {
            iss: token.iss.to_string(),
            aud: token.aud.to_string(),

            can: token.can.clone(),
            prf: token
                .prf
                .as_ref()
                .map(|cids| cids.iter().map(ToString::to_string).collect()),
            pre: token
                .pre
                .as_ref()
                .map(|proofs| proofs.iter().map(ToString::to_string).collect()),

            exp: token.exp,
            nbf: token.nbf,
            dat: token.dat.clone(),
            pbk: token.pbk.clone(),
            nnc: token.nnc.clone(),
        })
    }
}

impl<KF: KeyFactory> From<&Token<KF>> for Header {
    fn from(token: &Token<KF>) -> Self {
        Self {
            alg: token.sig.algorithm_name().to_owned(),
            typ: DELEGABLE_WEB_TOKEN_TYPE.to_owned(),
        }
    }
}

impl<KF: KeyFactory> TryFrom<&Payload> for CanonicalPayload<KF> {
    type Error = Error;

    fn try_from(payload: &Payload) -> Result<Self> {
        let links = if let Some(prf) = payload.prf.as_ref() {
            let mut links = vec![];
            for link in prf {
                links.push(Cid::from_str(link).map_err(|e| Error::EncodingError(e.to_string()))?);
            }
            Some(links)
        } else {
            None
        };
        let proofs = if let Some(pre) = payload.pre.as_ref() {
            let mut proofs = vec![];
            for proof_string in pre {
                let proof = Token::from_str(proof_string)?;
                proofs.push(proof);
            }
            Some(proofs)
        } else {
            None
        };

        Ok(Self {
            iss: Did::from_str(&payload.iss)?,
            aud: Did::from_str(&payload.aud)?,

            can: payload.can.clone(),
            prf: links,
            pre: proofs,

            exp: payload.exp,
            nbf: payload.nbf,
            dat: payload.dat.clone(),
            pbk: payload.pbk.clone(),
            nnc: payload.nnc.clone(),
        })
    }
}
