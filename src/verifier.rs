use crate::{
    capability::{Capabilities, Capability, CapabilitySemantics},
    chain::{CapabilityInfo, ProofChain},
    semantics::{GeneralAction, GeneralResource, GeneralSemantics},
    serde::DagCbor,
    store::{DwtStore, MemoryStore},
    token::{DataMap, Token},
};
use cid::Cid;
use multihash_codetable::Code;
use mysteryn_crypto::{
    key_traits::KeyFactory,
    prelude::MultikeySecretKey,
    result::{Error, Result},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, marker::PhantomData, str::FromStr};
use tinytemplate::TinyTemplate;

#[derive(Debug, Serialize, Deserialize)]
pub struct Requirements {
    pub audience: String,
    /// Capabilities by the originator
    pub capabilities: BTreeMap<String, Capabilities>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<String>>,
    pub time: Option<u64>,
    #[serde(rename = "knownTokens")]
    pub known_tokens: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct Verified {
    pub did: String,
    pub issuer: String,
    pub capabilities: Capabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<DataMap>,
    pub cids: Vec<String>,
}

pub trait Attenuator {
    /// Perform attenuation on the token capability action. Return true to keep an action and false to remove.
    fn attenuate<KF: KeyFactory>(
        &self,
        resource: &str,
        action: &str,
        attenuation: &str,
        token: &Token<KF>,
    ) -> bool;
    /// Perform attenuation on the requirement capability action. Return true to keep an action and false to remove.
    fn attenuate_requirement<KF: KeyFactory>(
        &self,
        resource: &str,
        action: &str,
        attenuation: &str,
        token: &Token<KF>,
    ) -> bool;
}

pub struct DefaultAttenuator {}

impl Attenuator for DefaultAttenuator {
    fn attenuate<KF: KeyFactory>(
        &self,
        _: &str,
        _: &str,
        attenuation: &str,
        _: &Token<KF>,
    ) -> bool {
        attenuation.is_empty()
    }
    fn attenuate_requirement<KF: KeyFactory>(
        &self,
        _: &str,
        _: &str,
        attenuation: &str,
        _: &Token<KF>,
    ) -> bool {
        attenuation.is_empty()
    }
}

#[must_use]
pub struct Verifier<S: DwtStore, A: Attenuator, KF: KeyFactory> {
    store: S,
    attenuator: A,
    hasher: Code,
    factory: PhantomData<KF>,
}

impl<KF: KeyFactory> Default for Verifier<MemoryStore, DefaultAttenuator, KF> {
    fn default() -> Self {
        Self {
            store: MemoryStore::default(),
            attenuator: DefaultAttenuator {},
            hasher: Self::default_hasher(),
            factory: PhantomData::<KF>,
        }
    }
}

impl<S: DwtStore + Clone, A: Attenuator, KF: KeyFactory> Verifier<S, A, KF> {
    pub fn new(store: S, attenuator: A, _factory: &KF) -> Self {
        Self {
            store,
            attenuator,
            hasher: Self::default_hasher(),
            factory: PhantomData::<KF>,
        }
    }

    pub fn with_hasher(mut self, hasher: Code) -> Self {
        self.hasher = hasher;
        self
    }

    pub fn hasher(&self) -> Code {
        self.hasher
    }

    /// Returns the default hasher ([`Code::Blake3_256`]) used for [Cid] encodings.
    pub fn default_hasher() -> Code {
        Code::Blake3_256
    }

    pub fn store(&self) -> S {
        self.store.clone()
    }

    pub fn attenuator(&self) -> &A {
        &self.attenuator
    }

    /// Verify the token signature, expiration, and capabilities against requirements.
    pub async fn verify(
        &mut self,
        token: &Token<KF>,
        my_secret_key: Option<MultikeySecretKey<KF>>,
        requirements: &Requirements,
    ) -> Result<Verified> {
        if requirements.audience.is_empty() {
            return Err(Error::ValidationError("audience required".to_string()));
        }
        if requirements.capabilities.is_empty() {
            return Err(Error::ValidationError("capabilities required".to_string()));
        }

        self.check_known_tokens(requirements).await?;

        let chain =
            ProofChain::from_token(token, my_secret_key, requirements.time, &self.store).await?;
        if chain.token().audience().to_string() != requirements.audience {
            return Err(Error::InvalidToken("invalid audience".to_string()));
        }

        let tmp_data = DataMap::new();
        let data = chain.token().data().unwrap_or(&tmp_data);
        Self::check_data(requirements, data)?;

        let verified = self.check_originators(requirements, &chain, data)?;

        let c = Capabilities::try_from(
            verified
                .iter()
                .map(|c| Capability::from(c.capability.clone()))
                .collect::<Vec<Capability>>(),
        )?;

        let mut cids = Vec::new();
        merge_cids(&chain, &mut cids)?;

        Ok(Verified {
            did: requirements.audience.to_string(),
            issuer: token.issuer().to_string(),
            capabilities: c,
            data: if data.is_empty() {
                None
            } else {
                Some(data.clone())
            },
            cids,
        })
    }

    async fn check_known_tokens(&mut self, requirements: &Requirements) -> Result<()> {
        if let Some(proofs) = requirements.known_tokens.as_ref() {
            for proof_string in proofs {
                let token = Token::<KF>::from_str(proof_string)?;
                self.store
                    .write(
                        &token.to_cid(self.hasher)?,
                        &token.to_dag_cbor()?,
                        token.expires_at().unwrap_or_default(),
                        token.data(),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    fn check_data(
        requirements: &Requirements,
        data: &BTreeMap<String, serde_json::Value>,
    ) -> Result<()> {
        if let Some(required_data) = &requirements.data {
            for required_field in required_data {
                let Some(v) = data.get(required_field) else {
                    return Err(Error::InvalidToken(format!(
                        r#"no data "{required_field}""#,
                    )));
                };
                if v.is_null() {
                    return Err(Error::InvalidToken(format!(
                        r#"no data "{required_field}""#,
                    )));
                }
                if v.is_string() && v.as_str().unwrap_or_default().trim().is_empty() {
                    return Err(Error::InvalidToken(format!(
                        r#"no data "{required_field}""#,
                    )));
                }
            }
        }
        Ok(())
    }

    fn check_originators(
        &mut self,
        requirements: &Requirements,
        chain: &ProofChain<KF>,
        data: &BTreeMap<String, serde_json::Value>,
    ) -> Result<Vec<CapabilityInfo<GeneralResource, GeneralAction>>> {
        let semantics = GeneralSemantics {};
        let capabilities = chain.reduce_capabilities(&semantics, self.attenuator());
        let mut verified: Vec<CapabilityInfo<GeneralResource, GeneralAction>> = Vec::new();

        for (originator, required_capabilities) in &requirements.capabilities {
            for required_capability in required_capabilities {
                let mut tt = TinyTemplate::new();
                tt.add_template("resource", &required_capability.resource)
                    .map_err(|e| Error::InvalidToken(e.to_string()))?;
                let resource = tt
                    .render("resource", &data)
                    .unwrap_or(required_capability.resource.clone());
                tt.add_template("action", &required_capability.action)
                    .map_err(|e| Error::InvalidToken(e.to_string()))?;
                let ability = tt
                    .render("action", &data)
                    .unwrap_or(required_capability.action.clone());

                let cap = Capability::new(resource.clone(), ability.clone());
                let view = semantics.parse_capability(&cap);
                let Some(view) = view else {
                    return Err(Error::InvalidToken(format!(
                        r#"no capability "{resource} {ability}""#
                    )));
                };
                if let Some(attenuation) = view.attenuation.as_ref() {
                    if !self.attenuator.attenuate_requirement(
                        &view.resource.to_string(),
                        &view.action.to_string(),
                        attenuation,
                        chain.token(),
                    ) {
                        return Err(Error::InvalidToken(format!(
                            r#"no capability (attenuated) "{resource} {ability}""#
                        )));
                    }
                }
                let mut found = false;
                for c in &capabilities {
                    // IMPORTANT! Check the originator of the capability!
                    if c.capability.enables(&view) && c.originators.contains(originator) {
                        found = true;
                        verified.push(c.clone());
                    }
                }
                if !found {
                    return Err(Error::InvalidToken(format!(
                        r#"no capability "{resource} {ability}""#
                    )));
                }
            }
        }
        Ok(verified)
    }

    pub async fn verify_by_cid(
        &mut self,
        cid: &Cid,
        my_secret_key: Option<MultikeySecretKey<KF>>,
        requirements: &Requirements,
    ) -> Result<Verified> {
        let Some(token_bytes) = self.store.read(cid).await? else {
            return Err(Error::InvalidToken(
                "token for this cid is not found".to_string(),
            ));
        };
        let token = Token::try_from(token_bytes.as_slice())?;
        self.verify(&token, my_secret_key, requirements).await
    }

    pub async fn verify_token_bytes(
        &mut self,
        token_or_cid_bytes: &[u8],
        my_secret_key: Option<MultikeySecretKey<KF>>,
        requirements: &Requirements,
    ) -> Result<Verified> {
        let token = if let Ok(cid) = Cid::try_from(token_or_cid_bytes) {
            let Some(token_bytes) = self.store.read(&cid).await? else {
                return Err(Error::InvalidToken(
                    "token for this cid is not found".to_string(),
                ));
            };
            Token::try_from(token_bytes.as_slice())?
        } else {
            Token::try_from(token_or_cid_bytes)?
        };
        self.verify(&token, my_secret_key, requirements).await
    }

    pub async fn verify_token_string(
        &mut self,
        token_or_cid_string: &str,
        my_secret_key: Option<MultikeySecretKey<KF>>,
        requirements: &Requirements,
    ) -> Result<Verified> {
        let token = if let Ok(cid) = Cid::from_str(token_or_cid_string) {
            let Some(token_bytes) = self.store.read(&cid).await? else {
                return Err(Error::InvalidToken(
                    "token for this cid is not found".to_string(),
                ));
            };
            Token::try_from(token_bytes.as_slice())?
        } else {
            Token::from_str(token_or_cid_string)?
        };
        self.verify(&token, my_secret_key, requirements).await
    }
}

fn merge_cids<KF: KeyFactory>(chain: &ProofChain<KF>, cids: &mut Vec<String>) -> Result<()> {
    let cid = chain.token().to_cid(Code::Blake3_256)?;
    if !cids.contains(&cid.to_string()) {
        cids.push(cid.to_string());
    }
    for c in chain.proofs() {
        merge_cids(c, cids)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DefaultAttenuator, Requirements, Verifier};
    use crate::{
        builder::TokenBuilder,
        capability::Capabilities,
        serde::DagCbor,
        store::{MemoryStore, TokenStore},
        token::Token as MultiToken,
    };
    use multihash_codetable::Code;
    use mysteryn_crypto::{
        did::{PublicDidTrait, SecretDidTrait},
        key_traits::*,
        multikey::*,
        result::Result,
    };
    use mysteryn_keys::DefaultKeyFactory;
    use serde_json::json;
    use std::{collections::BTreeMap, str::FromStr};
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    type SecretKey = MultikeySecretKey<DefaultKeyFactory>;
    type Token = MultiToken<DefaultKeyFactory>;

    // get it with "token/generate_keys()"
    const SECRET1: &str = "secret_xahgjgqfsxwdjkxun9wspqzgzve7sze7vwm0kszkya5lurz4np9cmc8k4frds9ze0g6kzsky8pmv8qxur4vfupul38mfdgrcc";
    //const PUBLIC1: &str = "pub_xahgjw6qgrwp6kyqgpypch74uwu40vns89yhzppvxjket5wf63tty0ar3nexl5l797l2q40ypevtls9aprku";
    const SECRET2: &str = "secret_xahgjgqfsxwdjkxun9wspqzgr376fxzzk8jms55m6gkxa3dmtkyzmm6wfajarmv37qrf4gkqjg0g8qxur4v2gsj5skasefdpg";
    //const PUBLIC2: &str = "pub_xahgjw6qgrwp6kyqgpyq29vthlflt6dtl5pvlrwrnllgyy5ws5a0w3xa2tt0425k9rvcwus9j33c3u0m7a2v";
    const SECRET3: &str = "secret_xahgjgqfsxwdjkxun9wspqzgrn0pkqhum8l2tmqkgv6hwsxz7hdhdhptwk5h603d6ylrym6hqs558qxur4vfhwa808gw29q6g";
    //const PUBLIC3: &str = "pub_xahgjw6qgrwp6kyqgpypytg3jyl048vrnfvngk6wpz40pnhy4248gfx2guhwfczwm5mqywvctvd3e3pzlxyq";

    async fn build_proof() -> Result<Token> {
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
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

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_verify() {
        let token = build_proof().await.unwrap();
        let secret_key = SecretKey::from_str(SECRET1).unwrap();
        let originator = secret_key.get_did().unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET2).unwrap();
        let recipient = recipient_secret_key.public_key().get_did().unwrap();
        let required_capabilities = Capabilities::try_from(&json!({
            "mailto:test@test.com": ["msg/send"]
        }))
        .unwrap();

        let mut verifier: Verifier<MemoryStore, DefaultAttenuator, DefaultKeyFactory> =
            Verifier::default();
        let requirements = Requirements {
            audience: recipient.to_string(),
            capabilities: BTreeMap::from([(originator.to_string(), required_capabilities)]),
            data: None,
            time: Some(1000),
            known_tokens: None,
        };

        let result = verifier
            .verify_token_string(&token.to_string(), None, &requirements)
            .await
            .unwrap();
        println!("result {:#?}", result);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_verify_with_proof_cid() {
        let mut store = MemoryStore::default();

        let proof = build_proof().await.unwrap();
        let proof_cid = proof.to_cid(Code::Blake3_256).unwrap();
        let originator = proof.issuer();
        store
            .write(
                &proof_cid,
                &proof.to_dag_cbor().unwrap(),
                proof.expires_at().unwrap_or_default(),
                proof.data(),
            )
            .await
            .unwrap();

        let secret_key = SecretKey::from_str(SECRET2).unwrap();
        let recipient_secret_key = SecretKey::from_str(SECRET3).unwrap();
        let recipient = recipient_secret_key.public_key().get_did().unwrap();
        let capabilities = [
            ("mailto:test@test.com", "msg/receive"),
            ("mailto:test@test.com", "msg/send"),
        ];
        let nonce = b"12345678";
        let token = TokenBuilder::new(store.clone())
            .with_secret(&secret_key)
            .for_audience(&recipient)
            .with_capabilities(&capabilities)
            .with_proof_cid(&proof_cid)
            .await
            .unwrap()
            .build_deterministic(nonce)
            .await
            .unwrap();

        let required_capabilities = Capabilities::try_from(&json!({
            "mailto:test@test.com": ["msg/send"]
        }))
        .unwrap();

        let mut verifier = Verifier::new(store.clone(), DefaultAttenuator {}, &DefaultKeyFactory);
        let requirements = Requirements {
            audience: recipient.to_string(),
            capabilities: BTreeMap::from([(originator.to_string(), required_capabilities)]),
            data: None,
            time: Some(1000),
            known_tokens: None,
        };

        let result = verifier
            .verify_token_string(&token.to_string(), None, &requirements)
            .await
            .unwrap();
        println!("result {:#?}", result);
    }

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[cfg_attr(not(all(target_family = "wasm", target_os = "unknown")), tokio::test)]
    async fn test_redelegation() {
        let store = MemoryStore::default();

        let server_secret = SecretKey::from_str(SECRET1).unwrap();
        let alice_secret = SecretKey::from_str(SECRET2).unwrap();
        let bob_secret = SecretKey::from_str(SECRET3).unwrap();
        let server_did = server_secret.get_did_pkh("joy", Some("joy")).unwrap();
        let alice_did = alice_secret.get_did_pkh("joy", Some("joy")).unwrap();
        let bob_did = bob_secret.get_did_pkh("joy", Some("joy")).unwrap();
        println!("Server DID: {server_did}");
        println!("Alice DID: {alice_did}");
        println!("Bob DID: {bob_did}");
        let nonce = b"12345678";

        let server2alice_token = TokenBuilder::new(store.clone())
            .with_secret(&server_secret)
            .issued_by(&server_did)
            .for_audience(&alice_did)
            .with_capabilities(&[
                ("api/space/xxx", "space/login"),
                ("api/space/xxx", "space/edit"),
                ("api/space/xxx", "space/rename"),
                ("user/111", "auth"),
            ])
            .with_data(&[
                ("space_id".to_string(), serde_json::to_value("xxx").unwrap()),
                (
                    "user_id".to_string(),
                    serde_json::to_value("111".to_string()).unwrap(),
                ),
                (
                    "server2alice".to_string(),
                    serde_json::to_value("Hello Alice!".to_string()).unwrap(),
                ),
            ])
            .unwrap()
            .build_deterministic(nonce)
            .await
            .unwrap();

        let required_capabilities = Capabilities::try_from(&json!({
            "api/space/{space_id}": ["space/login"],
            "user/{user_id}": ["auth"],
        }))
        .unwrap();
        let required_capabilities =
            BTreeMap::from([(server_did.to_string(), required_capabilities)]);

        // verify this token cannot be used directly to login
        let mut verifier = Verifier::new(store.clone(), DefaultAttenuator {}, &DefaultKeyFactory);
        let requirements = Requirements {
            audience: server_did.to_string(),
            capabilities: required_capabilities.clone(),
            data: Some(vec!["space_id".to_string(), "user_id".to_string()]),
            time: None,
            known_tokens: None,
        };
        let result = verifier
            .verify_token_string(&server2alice_token.to_string(), None, &requirements)
            .await;
        println!("result server2alice_token {result:?}");
        assert!(result.is_err());

        // Alice can use her token.

        let alice_token = TokenBuilder::new(store.clone())
            .with_secret(&alice_secret)
            .issued_by(&alice_did)
            .for_audience(&server_did)
            .with_capabilities(&[
                ("api/space/xxx", "space/login"),
                ("api/space/xxx", "space/edit"),
                ("user/111", "auth"),
            ])
            .with_data(&[
                ("space_id".to_string(), serde_json::to_value("xxx").unwrap()),
                (
                    "user_id".to_string(),
                    serde_json::to_value("111".to_string()).unwrap(),
                ),
            ])
            .unwrap()
            .with_proof_token(&server2alice_token)
            .unwrap()
            .build_deterministic(nonce)
            .await
            .unwrap();

        let requirements = Requirements {
            audience: server_did.to_string(),
            capabilities: required_capabilities.clone(),
            data: None,
            time: None,
            known_tokens: None,
        };
        let result = verifier
            .verify_token_string(&alice_token.to_string(), None, &requirements)
            .await
            .unwrap();

        println!("result alice_token -> server {:#?}", result);

        // Alice can delegate her token.

        let alice2bob_token = TokenBuilder::new(store.clone())
            .with_secret(&alice_secret)
            .issued_by(&alice_did)
            .for_audience(&bob_did)
            .with_capabilities(&[
                ("api/space/xxx", "space/login"),
                ("api/space/xxx", "space/edit"),
            ])
            .with_proof_token(&server2alice_token)
            .unwrap()
            .build_deterministic(nonce)
            .await
            .unwrap();

        // Bob can use her token.

        let server2bob_token = TokenBuilder::new(store.clone())
            .with_secret(&server_secret)
            .issued_by(&server_did)
            .for_audience(&bob_did)
            .with_capabilities(&[
                ("api/space/yyy", "space/login"),
                ("api/space/yyy", "space/edit"),
                ("user/222", "auth"),
            ])
            .with_data(&[
                ("space_id".to_string(), serde_json::to_value("yyy").unwrap()),
                (
                    "user_id".to_string(),
                    serde_json::to_value("222".to_string()).unwrap(),
                ),
            ])
            .unwrap()
            .build_deterministic(nonce)
            .await
            .unwrap();

        let bob_token = TokenBuilder::new(store.clone())
            .with_secret(&bob_secret)
            .issued_by(&bob_did)
            .for_audience(&server_did)
            .with_capabilities(&[
                ("api/space/xxx", "space/login"),
                ("api/space/xxx", "space/edit"),
                ("user/222", "auth"),
            ])
            .with_data(&[
                ("space_id".to_string(), serde_json::to_value("xxx").unwrap()),
                (
                    "user_id".to_string(),
                    serde_json::to_value("222".to_string()).unwrap(),
                ),
            ])
            .unwrap()
            .with_proof_token(&alice2bob_token)
            .unwrap()
            .with_proof_token(&server2bob_token)
            .unwrap()
            .build_deterministic(nonce)
            .await
            .unwrap();

        let requirements = Requirements {
            audience: server_did.to_string(),
            capabilities: required_capabilities.clone(),
            data: None,
            time: None,
            known_tokens: None,
        };
        let result = verifier
            .verify_token_string(&bob_token.to_string(), None, &requirements)
            .await
            .unwrap();

        println!("result bob_token -> server {:#?}", result);
        println!("OK: bob_token accepted");

        // Bob cannot use Alice's ID

        let bob_token2 = TokenBuilder::new(store.clone())
            .with_secret(&bob_secret)
            .issued_by(&bob_did)
            .for_audience(&server_did)
            .with_capabilities(&[
                ("api/space/xxx", "space/login"),
                ("api/space/xxx", "space/edit"),
                ("user/111", "auth"),
            ])
            .with_data(&[
                ("space_id".to_string(), serde_json::to_value("xxx").unwrap()),
                (
                    "user_id".to_string(),
                    serde_json::to_value("111".to_string()).unwrap(),
                ),
            ])
            .unwrap()
            .with_proof_token(&alice2bob_token)
            .unwrap()
            .with_proof_token(&server2bob_token)
            .unwrap()
            .build_deterministic(nonce)
            .await
            .unwrap();

        let requirements = Requirements {
            audience: server_did.to_string(),
            capabilities: required_capabilities.clone(),
            data: None,
            time: None,
            known_tokens: None,
        };
        let result = verifier
            .verify_token_string(&bob_token2.to_string(), None, &requirements)
            .await;
        println!("result bob_token2 {:#?}", result);
        assert!(result.is_err());
        println!("OK: bob_token2 is not allowed");
    }
}
