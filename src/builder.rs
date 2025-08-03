use crate::{
    capability::{Capability, CapabilitySemantics, ProofDelegationSemantics},
    serde::DagCbor,
    store::{DwtStore, MemoryStore},
    time::now,
    token::{CanonicalPayload, DataMap, Token},
};
use cid::Cid;
use multihash_codetable::Code;
use mysteryn_crypto::{
    attributes::SignatureAttributes,
    did::{Did, SecretDidTrait},
    key_traits::{KeyFactory, SecretKeyTrait},
    multibase,
    multicodec::multicodec_prefix,
    multikey::{MultikeyPublicKey, MultikeySecretKey, Multisig},
    result::{Error, Result},
};
use rand::{RngCore, rng};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, PartialEq, Eq)]
pub enum EmbedProofs {
    AsIs,
    AsCid,
    AsToken,
}

/// A builder API for tokens
#[must_use]
pub struct TokenBuilder<S: DwtStore, KF: KeyFactory> {
    store: S,

    issuer: Option<Did>,
    secret: Option<MultikeySecretKey<KF>>,
    public_key: Option<MultikeyPublicKey<KF>>,
    auto_public_key: bool,
    audience: Option<Did>,

    capabilities: Vec<Capability>,

    lifetime: Option<u64>,
    expiration: Option<u64>,
    not_before: Option<u64>,
    nonce: Option<String>,

    data: DataMap,
    proofs: BTreeSet<Cid>,
    embedded_proofs: BTreeSet<Token<KF>>,

    embed_proofs: EmbedProofs,
    hasher: Code,
}

impl<KF: KeyFactory> Default for TokenBuilder<MemoryStore, KF> {
    /// Create an empty builder.
    /// Before finalising the builder, you need to at least call:
    ///
    /// - `issued_by`
    /// - `to_audience` and one of
    /// - `with_lifetime` or `with_expiration`.
    ///
    /// To finalise the builder, call its `build` method.
    fn default() -> Self {
        TokenBuilder {
            store: MemoryStore::default(),

            issuer: None,
            secret: None,
            public_key: None,
            auto_public_key: true,
            audience: None,

            capabilities: Vec::new(),

            lifetime: None,
            expiration: None,
            not_before: None,
            nonce: None,

            data: BTreeMap::new(),
            proofs: BTreeSet::new(),
            embedded_proofs: BTreeSet::new(),

            embed_proofs: EmbedProofs::AsIs,
            hasher: Self::default_hasher(),
        }
    }
}

impl<S: DwtStore, KF: KeyFactory> TokenBuilder<S, KF> {
    pub fn new(store: S) -> Self {
        TokenBuilder {
            store,

            issuer: None,
            secret: None,
            public_key: None,
            auto_public_key: true,
            audience: None,

            capabilities: Vec::new(),

            lifetime: None,
            expiration: None,
            not_before: None,
            nonce: None,

            data: BTreeMap::new(),
            proofs: BTreeSet::new(),
            embedded_proofs: BTreeSet::new(),

            embed_proofs: EmbedProofs::AsIs,
            hasher: TokenBuilder::<S, KF>::default_hasher(),
        }
    }

    pub fn with_hasher(mut self, hasher: Code) -> Self {
        self.hasher = hasher;
        self
    }

    pub fn get_hasher(&self) -> Code {
        self.hasher
    }

    /// Returns the default hasher ([`Code::Blake3_256`]) used for [`Cid`] encodings.
    pub fn default_hasher() -> Code {
        Code::Blake3_256
    }

    pub fn get_store(&self) -> S {
        self.store.clone()
    }

    /// The token must be signed with the private key of the issuer to be valid.
    pub fn with_secret(mut self, secret: &MultikeySecretKey<KF>) -> Self {
        self.secret = Some(secret.clone());
        self
    }

    /// The issuer Did.
    pub fn issued_by(mut self, issuer: &Did) -> Self {
        self.issuer = Some(issuer.clone());
        self
    }

    /// Public key for "did:pkh", used to verify signature instead of "iss".
    pub fn with_public_key(mut self, public_key: &MultikeyPublicKey<KF>) -> Self {
        self.public_key = Some(public_key.clone());
        self
    }

    /// Automatically insert a public key for "did:pkh".
    pub fn with_auto_public_key(mut self, auto: bool) -> Self {
        self.auto_public_key = auto;
        self
    }

    /// Nonce string.
    pub fn with_nonce(mut self, nonce: Option<String>) -> Self {
        self.nonce = nonce;
        self
    }

    /// Random Nonce string.
    pub fn with_random_nonce(mut self) -> Self {
        let mut v = [0u8; 12];
        rng().fill_bytes(&mut v);
        self.nonce = Some(multibase::to_base58(&v)[1..].to_string());
        self
    }

    /// This is the identity this token transfers rights to.
    ///
    /// It could e.g. be the DID of a service you're posting this token as a JWT to,
    /// or it could be the DID of something that'll use this token as a proof to
    /// continue the token chain as an issuer.
    pub fn for_audience(mut self, audience: &Did) -> Self {
        self.audience = Some(audience.clone());
        self
    }

    /// The number of seconds into the future (relative to when `build()` is
    /// invoked) to set the expiration. This is ignored if an explicit expiration
    /// is set.
    pub fn with_lifetime(mut self, seconds: u64) -> Self {
        self.lifetime = Some(seconds);
        self
    }

    /// Set the POSIX timestamp (in seconds) for when the token should expire.
    /// Setting this value overrides a configured lifetime value.
    pub fn with_expiration(mut self, timestamp: u64) -> Self {
        self.expiration = Some(timestamp);
        self
    }

    /// Set the POSIX timestamp (in seconds) of when the token becomes active.
    pub fn not_before(mut self, timestamp: u64) -> Self {
        self.not_before = Some(timestamp);
        self
    }

    /// Add a data field to this token.
    pub fn with_field<T: Serialize + DeserializeOwned>(
        mut self,
        key: &str,
        data: T,
    ) -> Result<Self> {
        match serde_json::to_value(data) {
            Ok(value) => {
                self.data.insert(key.to_owned(), value);
                Ok(self)
            }
            Err(error) => Err(Error::IOError(format!(
                "Could not add data to the token: {error}"
            ))),
        }
    }

    /// Add multiple data to this token.
    pub fn with_data<T: Serialize + DeserializeOwned>(
        mut self,
        data: &[(String, T)],
    ) -> Result<Self> {
        let mut f: Vec<(String, serde_json::Value)> = Vec::new();
        for (k, v) in data {
            f.push((
                k.clone(),
                match serde_json::to_value(v) {
                    Ok(v) => v,
                    Err(error) => {
                        return Err(Error::IOError(format!(
                            "Could not add data to the token: {error}"
                        )));
                    }
                },
            ));
        }
        if !f.is_empty() {
            self.data.extend(f);
        }
        Ok(self)
    }

    /// Strategy to embed proofs to this token.
    pub fn with_embed_proofs_as(mut self, embed_proofs: EmbedProofs) -> Self {
        self.embed_proofs = embed_proofs;
        self
    }

    /// Includes a CID link to a token in the list of links for the token to be built.
    /// Note that the proof's audience must match this token's issuer
    /// or else the proof chain will be invalidated!
    pub async fn with_proof_cid(mut self, proof_cid: &cid::Cid) -> Result<Self> {
        if !self.proofs.contains(proof_cid) {
            self.proofs.insert(*proof_cid);
        }
        if self.embed_proofs == EmbedProofs::AsToken {
            for proof in &self.embedded_proofs {
                let cid = proof.to_cid(self.hasher)?;
                if cid == *proof_cid {
                    return Ok(self);
                }
            }
            let proof_bytes = self.store.require_token(proof_cid).await?;
            self.embedded_proofs
                .insert(Token::try_from(proof_bytes.as_slice())?);
        } else {
            // AsCid and AsIs
            let mut found: Option<Token<KF>> = None;
            for proof in &self.embedded_proofs {
                let cid = proof.to_cid(self.hasher)?;
                if cid == *proof_cid {
                    found = Some(proof.clone());
                    break;
                }
            }
            if let Some(found) = found {
                self.embedded_proofs.remove(&found);
            }
        }
        Ok(self)
    }

    /// Includes a token in the list of proofs for the token to be built.
    /// Note that the proof's audience must match this token's issuer
    /// or else the proof chain will be invalidated!
    pub fn with_proof_token(mut self, proof_token: &Token<KF>) -> Result<Self> {
        let cid = proof_token.to_cid(self.hasher)?;
        if !self.proofs.contains(&cid) {
            self.proofs.insert(cid);
        }
        if self.embed_proofs == EmbedProofs::AsCid {
            self.embedded_proofs.remove(proof_token);
        } else {
            // AsToken and AsIs
            if !self.embedded_proofs.contains(proof_token) {
                self.embedded_proofs.insert(proof_token.clone());
            }
        }

        Ok(self)
    }

    // Includes a collection of tokens in the list of proofs for the token to be built.
    pub async fn with_proof_cids(self, cids: &Vec<Cid>) -> Result<Self> {
        let mut s = self;
        for cid in cids {
            s = s.with_proof_cid(cid).await?;
        }

        Ok(s)
    }

    // Includes a collection of tokens in the list of proofs for the token to be built.
    pub fn with_proof_tokens(self, tokens: &Vec<Token<KF>>) -> Result<Self> {
        let mut s = self;
        for proof in tokens {
            s = s.with_proof_token(proof)?;
        }

        Ok(s)
    }

    /// Claim a capability by inheritance (from an authorizing proof) or
    /// implicitly by ownership of the resource by this token's issuer
    pub fn with_capability<C>(mut self, capability: C) -> Self
    where
        C: Into<Capability>,
    {
        self.capabilities.push(capability.into());
        self
    }

    /// Claim capabilities by inheritance (from an authorizing proof) or
    /// implicitly by ownership of the resource by this token's issuer
    pub fn with_capabilities<C>(mut self, capabilities: &[C]) -> Self
    where
        C: Into<Capability> + Clone,
    {
        let p: Vec<Capability> = capabilities
            .iter()
            .map(|c| <C as Into<Capability>>::into(c.to_owned()))
            .collect();
        self.capabilities.extend(p);
        self
    }

    /// Delegate all capabilities from a given proof to the audience of the token
    /// you're building.
    /// The proof is encoded into a [Cid].
    pub fn delegating_from_token(self, proof_token: &Token<KF>) -> Result<Self> {
        let cid = proof_token.to_cid(self.hasher)?;
        let mut s = self.with_proof_token(proof_token)?;
        let proof_delegation = ProofDelegationSemantics {};
        let capability = proof_delegation.parse(&cid.to_string(), "delegate");

        match capability {
            Some(capability) => {
                s.capabilities.push(Capability::from(&capability));
                Ok(s)
            }
            None => Err(Error::ValidationError(
                "Could not produce the delegation capability".to_string(),
            )),
        }
    }

    /// Set the new payload to build
    pub fn with_payload(mut self, payload: &CanonicalPayload<KF>) -> Self {
        self.issuer = Some(payload.iss.clone());
        self.audience = Some(payload.aud.clone());
        self.capabilities = payload.can.clone().into();
        self.lifetime = None;
        self.expiration = payload.exp;
        self.not_before = payload.nbf;
        self.data = payload.dat.clone().unwrap_or_default();
        self.proofs = payload
            .prf
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        self.embedded_proofs = payload
            .pre
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect();
        self
    }

    fn implied_expiration(&self) -> Option<u64> {
        if self.expiration.is_some() {
            self.expiration
        } else {
            self.lifetime.map(|lifetime| now() + lifetime)
        }
    }

    async fn adjust_lifetime(&self) -> Result<(Option<u64>, Option<u64>)> {
        let mut nbf = self.not_before;
        let mut exp = self.implied_expiration();
        for cid in &self.proofs {
            let token = self.embedded_proofs.iter().find(|p| {
                let Ok(c) = p.to_cid(self.hasher) else {
                    return false;
                };
                c == *cid
            });
            if let Some(token) = token {
                if let Some(proof_nbf) = token.nbf {
                    if let Some(current_nbf) = nbf {
                        nbf = Some(current_nbf.max(proof_nbf));
                    } else {
                        nbf = Some(proof_nbf);
                    }
                }
                if let Some(proof_exp) = token.exp {
                    if let Some(current_exp) = exp {
                        exp = Some(current_exp.min(proof_exp));
                    } else {
                        exp = Some(proof_exp);
                    }
                }
            } else {
                let token = Token::<KF>::try_from(self.store.require_token(cid).await?.as_slice())?;
                if let Some(proof_nbf) = token.nbf {
                    if let Some(current_nbf) = nbf {
                        nbf = Some(current_nbf.max(proof_nbf));
                    } else {
                        nbf = Some(proof_nbf);
                    }
                }
                if let Some(proof_exp) = token.exp {
                    if let Some(current_exp) = exp {
                        exp = Some(current_exp.min(proof_exp));
                    } else {
                        exp = Some(proof_exp);
                    }
                }
            }
        }
        if let Some(nbf) = nbf {
            if let Some(exp) = exp {
                if exp <= nbf {
                    return Err(Error::ValidationError(
                        "Adjusted expiration is less than not_before".to_string(),
                    ));
                }
            }
        }
        Ok((nbf, exp))
    }

    pub async fn build(mut self) -> Result<Token<KF>> {
        if self.capabilities.is_empty() {
            return Err(Error::ValidationError("Missing capabilities".to_string()));
        }
        let Some(secret) = self.secret.as_ref() else {
            return Err(Error::ValidationError("Missing secret".to_string()));
        };
        let issuer = if let Some(issuer) = self.issuer.as_ref() {
            issuer.clone()
        } else {
            secret.get_did()?
        };
        let Some(audience) = self.audience.clone() else {
            return Err(Error::ValidationError("Missing audience".to_string()));
        };
        if self.auto_public_key
            && (issuer.method() == "pkh" || issuer.method().starts_with("pkh:"))
            && self.public_key.is_none()
        {
            self.public_key = Some(MultikeyPublicKey::<KF>::try_from(secret.public_key())?);
        }
        let (nbf, exp) = self.adjust_lifetime().await?;

        let canonical_payload = CanonicalPayload {
            iss: issuer,
            aud: audience.clone(),

            can: self.capabilities.clone().try_into()?,
            prf: if self.proofs.is_empty() {
                None
            } else {
                Some(self.proofs.into_iter().collect())
            },
            pre: if self.embedded_proofs.is_empty() {
                None
            } else {
                Some(self.embedded_proofs.into_iter().collect())
            },

            exp,
            nbf,
            dat: if self.data.is_empty() {
                None
            } else {
                Some(self.data.clone())
            },
            pbk: self.public_key.map(|pk| pk.to_string()),
            nnc: self.nonce,
        };

        let data_to_sign = canonical_payload.to_dag_cbor()?;

        let mut attributes = SignatureAttributes::default();
        attributes.set_payload_encoding(Some(multicodec_prefix::DAG_CBOR));
        let pk = if audience.method() == "key" || audience.method().starts_with("key:") {
            Some(audience.get_public_key_bytes()?)
        } else {
            None
        };

        let raw_signature =
            secret.sign_exchange(data_to_sign.as_slice(), pk, Some(&mut attributes))?;
        let signature = Multisig::<KF>::try_from(secret.signature(&raw_signature)?)?;

        let token = Token::new(canonical_payload, &signature);
        if let Some(prf) = token.pre.as_ref() {
            for proof in prf {
                self.store
                    .write(
                        &proof.to_cid(self.hasher)?,
                        &proof.to_dag_cbor()?,
                        proof.expires_at().unwrap_or_default(),
                        proof.data(),
                    )
                    .await?;
            }
        }
        self.store
            .write(
                &token.to_cid(self.hasher)?,
                &token.to_dag_cbor()?,
                token.expires_at().unwrap_or_default(),
                token.data(),
            )
            .await?;

        Ok(token)
    }

    pub async fn build_deterministic(mut self, nonce: &[u8]) -> Result<Token<KF>> {
        if self.capabilities.is_empty() {
            return Err(Error::ValidationError("Missing capabilities".to_string()));
        }
        let Some(secret) = self.secret.as_ref() else {
            return Err(Error::ValidationError("Missing secret".to_string()));
        };
        let issuer = if let Some(issuer) = self.issuer.as_ref() {
            issuer.clone()
        } else {
            secret.get_did()?
        };
        let Some(audience) = self.audience.clone() else {
            return Err(Error::ValidationError("Missing audience".to_string()));
        };
        if self.auto_public_key
            && (issuer.method() == "pkh" || issuer.method().starts_with("pkh:"))
            && self.public_key.is_none()
        {
            self.public_key = Some(MultikeyPublicKey::<KF>::try_from(secret.public_key())?);
        }
        let (nbf, exp) = self.adjust_lifetime().await?;

        let canonical_payload = CanonicalPayload {
            iss: issuer,
            aud: audience.clone(),

            can: self.capabilities.clone().try_into()?,
            prf: if self.proofs.is_empty() {
                None
            } else {
                Some(self.proofs.into_iter().collect())
            },
            pre: if self.embedded_proofs.is_empty() {
                None
            } else {
                Some(self.embedded_proofs.into_iter().collect())
            },

            exp,
            nbf,
            dat: if self.data.is_empty() {
                None
            } else {
                Some(self.data.clone())
            },
            pbk: self.public_key.map(|pk| pk.to_string()),
            nnc: self.nonce,
        };

        let data_to_sign = canonical_payload.to_dag_cbor()?;

        let mut attributes = SignatureAttributes::default();
        attributes.set_payload_encoding(Some(multicodec_prefix::DAG_CBOR));
        attributes.set_nonce(Some(nonce));
        let pk = if audience.method() == "key" || audience.method().starts_with("key:") {
            Some(audience.get_public_key_bytes()?)
        } else {
            None
        };

        let raw_signature =
            secret.sign_deterministic(data_to_sign.as_slice(), pk, Some(&mut attributes))?;
        let signature = Multisig::<KF>::try_from(secret.signature(&raw_signature)?)?;

        let token = Token::new(canonical_payload, &signature);
        if let Some(prf) = token.pre.as_ref() {
            for proof in prf {
                self.store
                    .write(
                        &proof.to_cid(self.hasher)?,
                        &proof.to_dag_cbor()?,
                        proof.expires_at().unwrap_or_default(),
                        proof.data(),
                    )
                    .await?;
            }
        }
        self.store
            .write(
                &token.to_cid(self.hasher)?,
                &token.to_dag_cbor()?,
                token.expires_at().unwrap_or_default(),
                token.data(),
            )
            .await?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        builder::TokenBuilder,
        serde::DagCbor,
        store::{MemoryStore, TokenStore},
    };
    use mysteryn_crypto::prelude::*;
    use mysteryn_keys::DefaultKeyFactory;
    use std::str::FromStr;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    type SecretKey = MultikeySecretKey<DefaultKeyFactory>;

    // get it with "token/generate_keys()"
    const SECRET1: &str = "secret_xahgjgqfsxwdjkxun9wspqzgzve7sze7vwm0kszkya5lurz4np9cmc8k4frds9ze0g6kzsky8pmv8qxur4vfupul38mfdgrcc";
    //const PUBLIC1: &str = "pub_xahgjw6qgrwp6kyqgpypch74uwu40vns89yhzppvxjket5wf63tty0ar3nexl5l797l2q40ypevtls9aprku";
    const SECRET2: &str = "secret_xahgjgqfsxwdjkxun9wspqzgr376fxzzk8jms55m6gkxa3dmtkyzmm6wfajarmv37qrf4gkqjg0g8qxur4v2gsj5skasefdpg";
    //const PUBLIC2: &str = "pub_xahgjw6qgrwp6kyqgpyq29vthlflt6dtl5pvlrwrnllgyy5ws5a0w3xa2tt0425k9rvcwus9j33c3u0m7a2v";
    //const SECRET3: &str = "secret_xahgjgqfsxwdjkxun9wspqzgrn0pkqhum8l2tmqkgv6hwsxz7hdhdhptwk5h603d6ylrym6hqs558qxur4vfhwa808gw29q6g";
    //const PUBLIC3: &str = "pub_xahgjw6qgrwp6kyqgpypytg3jyl048vrnfvngk6wpz40pnhy4248gfx2guhwfczwm5mqywvctvd3e3pzlxyq";

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn should_use_memory_store_by_default() {
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
        let hasher = builder.get_hasher();
        let store = builder.get_store();
        let token = builder.build_deterministic(nonce).await.unwrap();

        token.validate(None, Some(1000)).unwrap();
        let cid = token.to_cid(hasher).unwrap();
        let token_bytes = store.read(&cid).await.unwrap().unwrap();
        assert_eq!(token_bytes, token.to_dag_cbor().unwrap());
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn should_use_external_store() {
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
        let recipient = recipient_secret_key.public_key();

        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";
        let store = MemoryStore::default();

        let builder = TokenBuilder::new(store.clone())
            .with_secret(&secret_key)
            .for_audience(&recipient.get_did().unwrap())
            .with_capabilities(&capabilities);
        let hasher = builder.get_hasher();
        let token = builder.build_deterministic(nonce).await.unwrap();

        token.validate(None, Some(1000)).unwrap();
        let cid = token.to_cid(hasher).unwrap();
        let token_bytes = store.read(&cid).await.unwrap().unwrap();
        assert_eq!(token_bytes, token.to_dag_cbor().unwrap());
    }
}
