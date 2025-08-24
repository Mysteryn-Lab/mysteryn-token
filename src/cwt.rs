use crate::token::{DELEGABLE_WEB_TOKEN_TYPE, Token};
use cbor4ii::core::{
    Value,
    dec::Decode,
    enc::Encode,
    error::Len,
    types,
    utils::{BufWriter, SliceReader},
};
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
            alg: token.sig.algorithm_name().into(),
            typ: DELEGABLE_WEB_TOKEN_TYPE.into(),
        }
    }
}

pub fn encode(header: &[u8], payload: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    // Pre‑allocate a buffer that is large enough for most tokens.
    let mut buf = BufWriter::new(Vec::with_capacity(payload.len() + signature.len() + 64));
    let value = Value::Tag(
        SIG1_TAG,
        Box::new(Value::Array(vec![
            Value::Bytes(header.to_owned()),
            Value::Map(vec![(
                Value::Text("typ".to_owned()),
                Value::Text(DELEGABLE_WEB_TOKEN_TYPE.to_owned()),
            )]),
            Value::Bytes(payload.to_owned()),
            Value::Bytes(signature.to_owned()),
        ])),
    );

    value
        .encode(&mut buf)
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    Ok(buf.buffer().to_vec())
}

pub fn is_cwt(token: &[u8]) -> bool {
    let mut reader: SliceReader<'_> = SliceReader::new(token);
    let Ok(tag) = types::Tag::tag(&mut reader) else {
        return false;
    };
    tag == CWT_TAG || tag == SIG1_TAG
}

pub fn decode(token: &[u8]) -> Result<CborTokenTuple> {
    cbor_decode(token).map_err(|e| Error::EncodingError(e.to_string()))
}

// Helper that extracts the inner SIG1_TAG array.
fn expect_sig1_array(
    reader: &mut SliceReader<'_>,
) -> std::result::Result<CborTokenTuple, cbor4ii::core::error::DecodeError<std::convert::Infallible>>
{
    let len = types::Array::len(reader)?;
    let Some(len) = len else {
        return Err(cbor4ii::core::error::DecodeError::RequireLength {
            name: &"SIG1_TAG:array",
            found: Len::Small(0_u16),
        });
    };
    if len < 4 {
        return Err(cbor4ii::core::error::DecodeError::RequireLength {
            name: &"SIG1_TAG:array",
            found: Len::Small(len.try_into().unwrap_or_default()),
        });
    }
    let a = <types::Bytes<&[u8]>>::decode(reader)?.0.to_vec();
    let _ = Value::decode(reader)?; // skip unprotected header map
    let b = <types::Bytes<&[u8]>>::decode(reader)?.0.to_vec();
    let c = <types::Bytes<&[u8]>>::decode(reader)?.0.to_vec();
    Ok((a, b, c))
}

fn cbor_decode(
    token: &[u8],
) -> std::result::Result<CborTokenTuple, cbor4ii::core::error::DecodeError<std::convert::Infallible>>
{
    let mut reader: SliceReader<'_> = SliceReader::new(token);

    // The outermost value must be a tag (either SIG1_TAG or CWT_TAG).
    let tag = types::Tag::tag(&mut reader)?;

    match tag {
        SIG1_TAG => expect_sig1_array(&mut reader),
        CWT_TAG => {
            // CWT ::= Tag(SIG1_TAG, array)
            let inner_tag = types::Tag::tag(&mut reader)?;
            if inner_tag == SIG1_TAG {
                expect_sig1_array(&mut reader)
            } else {
                Err(cbor4ii::core::error::DecodeError::Mismatch {
                    name: &"SIG1_TAG:array",
                    found: 0,
                })
            }
        }
        _ => Err(cbor4ii::core::error::DecodeError::Mismatch {
            name: &"SIG1_TAG:array",
            found: 0,
        }),
    }
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
