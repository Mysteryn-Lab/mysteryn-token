use crate::{time::now, token::DataMap};
use async_trait::async_trait;
use cid::Cid;
use lru::LruCache;
use multihash_codetable::{Code, MultihashDigest};
use mysteryn_crypto::result::{Error, Result};
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

#[cfg(not(target_arch = "wasm32"))]
pub trait StoreConditionalSend: Send {}

#[cfg(not(target_arch = "wasm32"))]
impl<U> StoreConditionalSend for U where U: Send {}

#[cfg(target_arch = "wasm32")]
pub trait StoreConditionalSend {}

#[cfg(target_arch = "wasm32")]
impl<U> StoreConditionalSend for U {}

#[cfg(not(target_arch = "wasm32"))]
pub trait StoreConditionalSendSync: Send + Sync {}

#[cfg(not(target_arch = "wasm32"))]
impl<U> StoreConditionalSendSync for U where U: Send + Sync {}

#[cfg(target_arch = "wasm32")]
pub trait StoreConditionalSendSync {}

#[cfg(target_arch = "wasm32")]
impl<U> StoreConditionalSendSync for U {}

/// This trait is meant to be implemented by a storage backend suitable for
/// persisting tokens that may be referenced as proofs by other tokens
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait TokenStore: StoreConditionalSendSync {
    /// Read a value from the store by CID, returning a Result<Option<...>> that unwraps
    /// to None if no value is found, otherwise Some
    async fn read(&self, cid: &Cid) -> Result<Option<Vec<u8>>>;

    /// Write a value to the store. `expires_at` is token expiration time,
    /// or 0 if token doesn't expire
    async fn write(
        &mut self,
        cid: &Cid,
        token: &[u8],
        expires_at: u64,
        meta: Option<&DataMap>,
    ) -> Result<()>;

    /// Revoke a token. `expires_at` is token expiration time hint
    async fn revoke(&mut self, cid: &Cid, expires_at: u64) -> Result<()>;

    /// Check if token is revoked
    async fn is_revoked(&self, cid: &Cid) -> Result<bool>;

    /// Remove expired records
    async fn cleanup(&mut self) -> Result<()>;

    /// Remove a token
    async fn remove(&mut self, cid: &Cid) -> Result<()>;
}

/// A convenience trait built on TokenStore, adding helper methods
/// for managing DWT-encoded tokens.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait DwtStore: TokenStore + Clone {
    async fn require_token(&self, cid: &Cid) -> Result<Vec<u8>> {
        match self.read(cid).await? {
            Some(token) => Ok(token),
            None => Err(Error::IOError(format!("No token found for CID {cid}"))),
        }
    }
}

impl<U> DwtStore for U where U: TokenStore + Clone {}

pub type DagLruCache = LruCache<Cid, (Vec<u8>, u64)>;

/// A basic in-memory store that implements `TokenStore`.
#[derive(Clone, Debug)]
pub struct MemoryStore {
    dags: Arc<Mutex<DagLruCache>>,
    revoked: Arc<Mutex<HashMap<Cid, u64>>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            dags: Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(5000).unwrap()))),
            revoked: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl TokenStore for MemoryStore {
    async fn read(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        if self.is_revoked(cid).await? {
            return Err(Error::ValidationError("Token is revoked".to_string()));
        }

        let mut dags = self
            .dags
            .lock()
            .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?;

        let Some((token, expires)) = dags.get(cid) else {
            return Ok(None);
        };
        if *expires != 0 && *expires <= now() {
            return Ok(None);
        }
        Ok(Some(token.clone()))
    }

    async fn write(
        &mut self,
        cid: &Cid,
        token: &[u8],
        expires_at: u64,
        _meta: Option<&DataMap>,
    ) -> Result<()> {
        let check_cid = Cid::new_v1(cid.codec(), Code::Blake3_256.digest(token));
        if check_cid != *cid {
            return Err(Error::IOError("invalid CID".to_string()));
        }
        if self.is_revoked(cid).await? {
            return Err(Error::ValidationError("Token is revoked".to_string()));
        }

        let mut dags = self
            .dags
            .lock()
            .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?;
        dags.put(*cid, (token.to_vec(), expires_at));

        Ok(())
    }

    async fn revoke(&mut self, cid: &Cid, expires_at: u64) -> Result<()> {
        if self.is_revoked(cid).await? {
            return Ok(());
        }
        let expires = {
            let mut dags = self
                .dags
                .lock()
                .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?;
            if let Some((_token, expires)) = dags.get(cid) {
                *expires
            } else {
                expires_at
            }
        };

        self.revoked
            .lock()
            .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?
            .insert(cid.clone(), expires);
        Ok(())
    }

    async fn is_revoked(&self, cid: &Cid) -> Result<bool> {
        Ok(self
            .revoked
            .lock()
            .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?
            .contains_key(cid))
    }

    async fn cleanup(&mut self) -> Result<()> {
        let mut dags = self
            .dags
            .lock()
            .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?;
        let mut keys_to_remove = vec![];
        for (cid, item) in dags.iter() {
            if item.1 != 0 && item.1 < now() {
                keys_to_remove.push(cid.clone());
            }
        }
        for cid in keys_to_remove {
            dags.pop(&cid);
        }
        self.revoked
            .lock()
            .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?
            .retain(|_, v| *v != 0 && *v < now());
        Ok(())
    }

    async fn remove(&mut self, cid: &Cid) -> Result<()> {
        {
            let mut dags = self
                .dags
                .lock()
                .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?;
            dags.pop(cid);
        }

        self.revoked
            .lock()
            .map_err(|e| Error::IOError(format!("poisoned mutex! {e}")))?
            .insert(cid.clone(), 0);
        Ok(())
    }
}
