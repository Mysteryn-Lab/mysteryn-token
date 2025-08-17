use base64::Engine;
use ipld_core::{
    ipld::Ipld,
    serde::{from_ipld, to_ipld},
};
use mysteryn_crypto::result::{Error, Result};
use serde::{Serialize, Serializer, de::DeserializeOwned};
use std::io::Cursor;

/// Utility function to enforce lower-case string values when serializing
pub fn ser_to_lower_case<S>(string: &str, serializer: S) -> Result<S::Ok>
where
    S: Serializer,
{
    serializer
        .serialize_str(&string.to_lowercase())
        .map_err(|e| Error::IOError(e.to_string()))
}

/// Helper trait to ser/de any serde-implementing value to/from DAG-JSON
pub trait DagJson: Serialize + DeserializeOwned {
    /// Encode to DAG-JSON bytes
    fn to_dag_json(&self) -> Result<Vec<u8>> {
        let ipld = to_ipld(self).map_err(|e| Error::IOError(e.to_string()))?;
        let mut json_bytes = Vec::new();

        serde_ipld_dagjson::to_writer(&mut json_bytes, &ipld)
            .map_err(|e| Error::IOError(e.to_string()))?;

        Ok(json_bytes)
    }

    /// Decode from DAG-JSON bytes
    fn from_dag_json(json_bytes: &[u8]) -> Result<Self> {
        let ipld: Ipld = serde_ipld_dagjson::from_reader(&mut Cursor::new(json_bytes))
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        from_ipld(ipld).map_err(|e| Error::EncodingError(e.to_string()))
    }
}

impl<T> DagJson for T where T: Serialize + DeserializeOwned {}

/// Helper trait to ser/de any serde-implementing value to/from DAG-CBOR
pub trait DagCbor: Serialize + DeserializeOwned {
    // Encode to DAG-CBOR bytes
    fn to_dag_cbor(&self) -> Result<Vec<u8>> {
        let ipld = to_ipld(self).map_err(|e| Error::IOError(e.to_string()))?;
        let mut cbor_bytes = Vec::new();

        serde_ipld_dagcbor::to_writer(&mut cbor_bytes, &ipld)
            .map_err(|e| Error::IOError(e.to_string()))?;

        Ok(cbor_bytes)
    }

    // Decode from DAG-CBOR bytes
    fn from_dag_cbor(cbor_bytes: &[u8]) -> Result<Self> {
        let ipld: Ipld = serde_ipld_dagcbor::from_reader(&mut Cursor::new(cbor_bytes))
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        from_ipld(ipld).map_err(|e| Error::EncodingError(e.to_string()))
    }
}

impl<T> DagCbor for T where T: Serialize + DeserializeOwned {}

/// Helper trait to encode structs as base64 as part of creating a JWT
pub trait Base64Encode: DagJson + DagCbor {
    fn jwt_json_base64_encode(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.to_dag_json()?))
    }

    fn cwt_cbor_base64_encode(&self) -> Result<String> {
        Ok("u".to_string()
            + &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.to_dag_cbor()?))
    }

    fn cwt_cbor_base58_encode(&self) -> Result<String> {
        Ok("z".to_string() + &bs58::encode(self.to_dag_cbor()?).into_string())
    }
}

impl<T> Base64Encode for T where T: DagJson + DagCbor {}
