use crate::token::{DELEGABLE_WEB_TOKEN_TYPE, Token};
use ciborium::value::Value;
use mysteryn_crypto::{
    key_traits::{KeyFactory, SignatureTrait},
    result::{Error, Result},
};
use serde::{Deserialize, Serialize};

pub const CWT_TAG: u64 = 61;
pub const SIG1_TAG: u64 = 18;
pub const SIG1_TYPE: &str = "cose-sign1";

pub type CborTokenTuple = (Vec<u8>, Vec<u8>, Vec<u8>);

/// Token header in CBOR serializable format.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Header {
    /// Signature algorithm
    pub alg: String,
    /// Token type
    pub typ: String,
}

impl<KF: KeyFactory> From<&Token<KF>> for Header {
    fn from(token: &Token<KF>) -> Self {
        Self {
            alg: token.sig.algorithm_name().to_string(),
            typ: DELEGABLE_WEB_TOKEN_TYPE.to_string(),
        }
    }
}

pub fn encode(header: &[u8], payload: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    let value = Value::Tag(
        SIG1_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(header.to_vec()),
            Value::Map(vec![(
                Value::Text("typ".to_owned()),
                Value::Text(DELEGABLE_WEB_TOKEN_TYPE.to_owned()),
            )]),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(signature.to_vec()),
        ])),
    );
    let mut v = vec![];
    ciborium::into_writer(&value, &mut v).map_err(|e| Error::EncodingError(e.to_string()))?;
    Ok(v)
}

pub fn is_cwt(token: &[u8]) -> bool {
    let mut buf = token;
    let Ok(tag) = ciborium::from_reader(&mut buf) else {
        return false;
    };
    match tag {
        ciborium::value::Value::Tag(tag, _) => tag == CWT_TAG || tag == SIG1_TAG,
        _ => false,
    }
}

pub fn decode(token: &[u8]) -> Result<CborTokenTuple> {
    cbor_decode(token).map_err(|e| Error::EncodingError(e.to_string()))
}

fn cbor_decode(
    token: &[u8],
) -> std::result::Result<CborTokenTuple, ciborium::de::Error<std::io::Error>> {
    let mut buf = token;
    let tag: ciborium::value::Value = ciborium::from_reader(&mut buf)?;
    let arr = match tag {
        ciborium::value::Value::Tag(tag, v) => {
            if tag == SIG1_TAG {
                if v.is_array() {
                    v.into_array()
                        .map_err(|_| std::io::Error::other("failed to parse SIG1_TAG: array"))?
                } else {
                    return Err(ciborium::de::Error::Semantic(
                        None,
                        "expected SIG1_TAG: array".to_owned(),
                    ));
                }
            } else if tag == CWT_TAG {
                match *v {
                    ciborium::value::Value::Tag(tag, v) => {
                        if tag == SIG1_TAG {
                            if v.is_array() {
                                v.into_array().map_err(|_| {
                                    std::io::Error::other("failed to parse SIG1_TAG: array")
                                })?
                            } else {
                                return Err(ciborium::de::Error::Semantic(
                                    None,
                                    "expected CWT > SIG1_TAG:array".to_owned(),
                                ));
                            }
                        } else {
                            return Err(ciborium::de::Error::Semantic(
                                None,
                                "expected CWT > SIG1_TAG:array".to_owned(),
                            ));
                        }
                    }
                    _ => {
                        return Err(ciborium::de::Error::Semantic(
                            None,
                            "expected CWT > SIG1_TAG:array".to_owned(),
                        ));
                    }
                }
            } else {
                return Err(ciborium::de::Error::Semantic(
                    None,
                    "expected CWT or SIG1_TAG:array".to_owned(),
                ));
            }
        }
        _ => {
            return Err(ciborium::de::Error::Semantic(
                None,
                "expected CWT or SIG1_TAG:array".to_owned(),
            ));
        }
    };
    if arr.len() < 4 {
        return Err(ciborium::de::Error::Semantic(
            None,
            "expected SIG1_TAG:array of size 4".to_owned(),
        ));
    }
    let header = match &arr[0] {
        ciborium::value::Value::Bytes(v) => v.clone(),
        _ => {
            return Err(ciborium::de::Error::Semantic(
                None,
                "expected SIG1_TAG:array header as bytes".to_owned(),
            ));
        }
    };
    let payload = match &arr[2] {
        ciborium::value::Value::Bytes(v) => v.clone(),
        _ => {
            return Err(ciborium::de::Error::Semantic(
                None,
                "expected SIG1_TAG:array payload as bytes".to_owned(),
            ));
        }
    };
    let signature = match &arr[3] {
        ciborium::value::Value::Bytes(v) => v.clone(),
        _ => {
            return Err(ciborium::de::Error::Semantic(
                None,
                "expected SIG1_TAG:array signature as bytes".to_owned(),
            ));
        }
    };
    Ok((header, payload, signature))
}

#[cfg(test)]
mod tests {
    use super::cbor_decode;
    use mysteryn_crypto::multibase;
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test;

    #[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
    #[test]
    fn test_cbor() {
        /*
        ```
          18(
          [
            / protected / << {
              / alg / 1: -7 / ECDSA 256 /
            } >>,
            / unprotected / {
              / kid / 4: h'4173796d6d657472696345434453413
                            23536' / 'AsymmetricECDSA256' /
            },
            / payload / << {
              / iss / 1: "coap://as.example.com",
              / sub / 2: "erikw",
              / aud / 3: "coap://light.example.com",
              / exp / 4: 1444064944,
              / nbf / 5: 1443944944,
              / iat / 6: 1443944944,
              / cti / 7: h'0b71'
            } >>,
            / signature / h'5427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f
                            9179bc3d7438bacaca5acd08c8d4d4f96131680c42
                            9a01f85951ecee743a52b9b63632c57209120e1c9e
                            30'
          ]
        )
        ```
         */
        let input = multibase::decode("fd28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30").unwrap();
        cbor_decode(&input).expect("cannot parse");
    }
}
