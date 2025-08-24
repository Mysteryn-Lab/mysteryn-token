use crate::{
    capability::{
        Action, CapabilitySemantics, CapabilityView, ProofDelegationSemantics, ProofSelection,
        Resource,
    },
    serde::DagCbor,
    store::DwtStore,
    token::Token,
    verifier::Attenuator,
};
use async_recursion::async_recursion;
use cid::Cid;
use multihash_codetable::Code;
use mysteryn_crypto::{
    key_traits::KeyFactory,
    prelude::MultikeySecretKey,
    result::{Error, Result},
};
use std::{collections::BTreeSet, fmt::Debug};

const PROOF_DELEGATION_SEMANTICS: ProofDelegationSemantics = ProofDelegationSemantics {};

#[derive(Eq, PartialEq, Clone)]
pub struct CapabilityInfo<R: Resource, A: Action> {
    pub originators: BTreeSet<String>,
    pub not_before: Option<u64>,
    pub expires_at: Option<u64>,
    pub capability: CapabilityView<R, A>,
}

impl<R, A> Debug for CapabilityInfo<R, A>
where
    R: Resource,
    A: Action,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityInfo")
            .field("originators", &self.originators)
            .field("not_before", &self.not_before)
            .field("expires_at", &self.expires_at)
            .field("capability", &self.capability)
            .finish()
    }
}

/// A deserialized chain of ancestral proofs that are linked to a token
#[derive(Debug)]
pub struct ProofChain<KF: KeyFactory> {
    token: Token<KF>,
    proofs: Vec<ProofChain<KF>>,
    redelegations: BTreeSet<Cid>,
}

impl<KF: KeyFactory> ProofChain<KF> {
    /// Instantiate a [`ProofChain`] from a [Token], given a [`JwtStore`] and [`DidParser`]
    #[cfg_attr(target_arch = "wasm32", async_recursion(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    pub async fn from_token<S>(
        token: &Token<KF>,
        my_secret_key: Option<MultikeySecretKey<KF>>,
        now_time: Option<u64>,
        store: &S,
    ) -> Result<ProofChain<KF>>
    where
        S: DwtStore,
    {
        let token_cid = token.to_cid(Code::Blake3_256)?;
        if store.is_revoked(&token_cid).await? {
            return Err(Error::InvalidToken(concat_string!(
                "Token ",
                token_cid.to_string(),
                " was revoked"
            )));
        }
        token.validate(my_secret_key.clone(), now_time)?;

        let mut proofs: Vec<ProofChain<KF>> = Vec::new();

        if let Some(token_links) = token.proofs() {
            for cid in token_links {
                let token_bytes =
                    if let Some(token) = token.get_embedded_proof(cid, Self::default_hasher()) {
                        token.to_dag_cbor()?
                    } else {
                        store.require_token(cid).await?
                    };
                let proof_chain = Self::try_from_token_bytes(
                    &token_bytes,
                    my_secret_key.clone(),
                    now_time,
                    store,
                )
                .await?;
                proof_chain.validate_link_to(token)?;
                proofs.push(proof_chain);
            }
        }

        let mut redelegations = BTreeSet::<Cid>::new();

        for capability in token
            .capabilities()
            .iter()
            .filter_map(|p| PROOF_DELEGATION_SEMANTICS.parse_capability(&p))
        {
            match capability.resource {
                ProofSelection::Did(did) => {
                    for proof in &proofs {
                        if did == token.issuer().to_string()
                            && (proof.token.issuer().to_string() == did
                                || proof.token.audience().to_string() == did)
                        {
                            redelegations.insert(proof.token.to_cid(Self::default_hasher())?);
                        }
                    }
                }
                ProofSelection::Cid(cid) => {
                    if proofs.iter().any(|proof| {
                        if let Ok(proof_cid) = proof.token.to_cid(Self::default_hasher()) {
                            (proof.token.issuer() == token.issuer()
                                || proof.token.audience() == token.issuer())
                                && proof_cid == cid
                        } else {
                            false
                        }
                    }) {
                        redelegations.insert(cid);
                    } else {
                        return Err(Error::InvalidToken(concat_string!(
                            "Unable to redelegate proof; CID not found ",
                            cid.to_string()
                        )));
                    }
                }
            }
        }

        Ok(ProofChain {
            token: token.clone(),
            proofs,
            redelegations,
        })
    }

    /// Instantiate a [`ProofChain`] from a [`Cid`], given a [`DwtStore`] and [`DidParser`]
    /// The [`Cid`] must resolve to a JWT token string
    pub async fn from_cid<S>(
        cid: &Cid,
        my_secret_key: Option<MultikeySecretKey<KF>>,
        now_time: Option<u64>,
        store: &S,
    ) -> Result<ProofChain<KF>>
    where
        S: DwtStore,
    {
        Self::try_from_token_bytes(
            &store.require_token(cid).await?,
            my_secret_key,
            now_time,
            store,
        )
        .await
    }

    /// Instantiate a [`ProofChain`] from token bytes, given a [`DwtStore`] and [`DidParser`]
    pub async fn try_from_token_bytes<S>(
        token_bytes: &[u8],
        my_secret_key: Option<MultikeySecretKey<KF>>,
        now_time: Option<u64>,
        store: &S,
    ) -> Result<ProofChain<KF>>
    where
        S: DwtStore,
    {
        let token = Token::try_from(token_bytes)?;
        Self::from_token(&token, my_secret_key, now_time, store).await
    }

    fn validate_link_to(&self, token: &Token<KF>) -> Result<()> {
        let audience = self.token.audience();
        let issuer = token.issuer();

        if audience == issuer {
            if self.token.lifetime_encompasses(token) {
                Ok(())
            } else {
                Err(Error::InvalidToken(
                    "Invalid token link: lifetime exceeds attenuation".to_string(),
                ))
            }
        } else {
            Err(Error::InvalidToken(concat_string!(
                "Invalid token link: proof audience ",
                audience.to_string(),
                " does not match this issuer ",
                issuer.to_string()
            )))
        }
    }

    pub fn token(&self) -> &Token<KF> {
        &self.token
    }

    pub fn proofs(&self) -> &Vec<ProofChain<KF>> {
        &self.proofs
    }

    pub fn reduce_capabilities<Semantics, Att: Attenuator, R, A>(
        &self,
        semantics: &Semantics,
        attenuator: &Att,
    ) -> Vec<CapabilityInfo<R, A>>
    where
        Semantics: CapabilitySemantics<R, A>,
        R: Resource,
        A: Action,
    {
        // Get the set of inherited attenuations (excluding redelegations)
        // before further attenuating by own lifetime and capabilities:
        let ancestral_capability_infos: Vec<CapabilityInfo<R, A>> =
            self.get_ancestral_capability_infos(semantics, attenuator);

        // Get the set of capabilities that are redelegated from ancestor proofs
        let mut redelegated_capability_infos: Vec<CapabilityInfo<R, A>> =
            self.get_redelegated_capability_infos(semantics, attenuator);

        // Get the claimed attenuations of this token, cross-checking ancestral
        // attenuations to discover the originating authority
        let mut self_capability_infos: Vec<CapabilityInfo<R, A>> =
            self.get_self_capability_infos(semantics, attenuator, &ancestral_capability_infos);

        self_capability_infos.append(&mut redelegated_capability_infos);

        let mut merged_capability_infos = Vec::<CapabilityInfo<R, A>>::new();

        // Merge redundant capabilities (accounting for redelegation), ensuring
        // that discrete originators are aggregated as we go
        'merge: while let Some(capability_info) = self_capability_infos.pop() {
            for remaining_capability_info in &mut self_capability_infos {
                if remaining_capability_info
                    .capability
                    .enables(&capability_info.capability)
                {
                    remaining_capability_info
                        .originators
                        .extend(capability_info.originators);
                    continue 'merge;
                }
            }

            merged_capability_infos.push(capability_info);
        }

        merged_capability_infos
    }

    fn get_ancestral_capability_infos<Semantics, Att: Attenuator, R, A>(
        &self,
        semantics: &Semantics,
        attenuator: &Att,
    ) -> Vec<CapabilityInfo<R, A>>
    where
        Semantics: CapabilitySemantics<R, A>,
        R: Resource,
        A: Action,
    {
        self.proofs
            .iter()
            .flat_map(|ancestor_chain| {
                if let Ok(cid) = ancestor_chain.token.to_cid(Self::default_hasher()) {
                    if self.redelegations.contains(&cid) {
                        Vec::new()
                    } else {
                        ancestor_chain.reduce_capabilities(semantics, attenuator)
                    }
                } else {
                    // skip if error
                    Vec::new()
                }
            })
            .collect()
    }

    fn get_redelegated_capability_infos<Semantics, Att: Attenuator, R, A>(
        &self,
        semantics: &Semantics,
        attenuator: &Att,
    ) -> Vec<CapabilityInfo<R, A>>
    where
        Semantics: CapabilitySemantics<R, A>,
        R: Resource,
        A: Action,
    {
        self.redelegations
            .iter()
            .flat_map(|redelegation_cid| {
                let proof_chain = self.proofs.iter().find(|proof| {
                    if let Ok(cid) = proof.token.to_cid(Self::default_hasher()) {
                        &cid == redelegation_cid
                    } else {
                        false
                    }
                });
                if let Some(proof_chain) = proof_chain {
                    proof_chain
                        .reduce_capabilities(semantics, attenuator)
                        .into_iter()
                        .map(|mut info| {
                            // Redelegated capabilities should be attenuated by
                            // this token's lifetime
                            info.not_before = *self.token.not_before();
                            info.expires_at = *self.token.expires_at();
                            info
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            })
            .collect()
    }

    fn get_self_capability_infos<Semantics, Att: Attenuator, R, A>(
        &self,
        semantics: &Semantics,
        attenuator: &Att,
        ancestral_capability_infos: &Vec<CapabilityInfo<R, A>>,
    ) -> Vec<CapabilityInfo<R, A>>
    where
        Semantics: CapabilitySemantics<R, A>,
        R: Resource,
        A: Action,
    {
        let self_capabilities_iter = self
            .token
            .capabilities()
            .iter()
            .map_while(|data| semantics.parse_capability(&data))
            .filter(|cap| {
                if let Some(attenuation) = cap.attenuation.as_ref() {
                    attenuator.attenuate(
                        &cap.resource.to_string(),
                        &cap.action.to_string(),
                        attenuation,
                        &self.token,
                    )
                } else {
                    true
                }
            });

        match self.proofs.len() {
            0 => self_capabilities_iter
                .map(|capability| CapabilityInfo {
                    originators: BTreeSet::from_iter(vec![self.token.issuer().to_string()]),
                    capability,
                    not_before: *self.token.not_before(),
                    expires_at: *self.token.expires_at(),
                })
                .collect(),
            _ => self_capabilities_iter
                .map(|capability| {
                    let mut originators = BTreeSet::<String>::new();

                    for ancestral_capability_info in ancestral_capability_infos {
                        if ancestral_capability_info.capability.enables(&capability) {
                            originators.extend(ancestral_capability_info.originators.clone());
                        }
                    }

                    // Add issuer as an originator
                    originators.insert(self.token.issuer().to_string());

                    CapabilityInfo {
                        capability,
                        originators,
                        not_before: *self.token.not_before(),
                        expires_at: *self.token.expires_at(),
                    }
                })
                .collect(),
        }
    }

    /// Returns the default hasher ([`Code::Blake3_256`]) used for [Cid] encodings.
    pub fn default_hasher() -> Code {
        Code::Blake3_256
    }
}
