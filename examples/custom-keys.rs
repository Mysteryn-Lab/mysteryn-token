mod custom_keys;

use custom_keys::*;
use mysteryn_crypto::{
    attributes::SignatureAttributes, did::Did, multicodec::multicodec_prefix, prelude::*,
    result::Result,
};
use mysteryn_token::prelude::*;
use std::{collections::BTreeMap, str::FromStr};
#[cfg(not(target_arch = "wasm32"))]
use tokio;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

// BLS12381G1
const SECRET: &str = "secret_xahgjgjfsxwdjkxun9wspqzgrcz99qnk5swn4730kumhav6q2n2gg5ma8pzdzxemcjcn7pv2hm2q8qxur4vgd7y52mn33mw";
// Ed25519
const UNSUPPORTED_SECRET: &str =
    "secrettest182qzvqqpqysqavehk5wzmqq47hfu3265k6j8kesw02r3grnequjs4my9phzgpmw4nte0nhe7gwds";

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(main))]
#[cfg_attr(not(target_arch = "wasm32"), tokio::main(flavor = "current_thread"))]
async fn main() -> Result<()> {
    println!("--- supported key BLS12381G1:");
    // can create
    let secret_key1 = SecretKey::new(
        multicodec_prefix::BLS12381G1_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )?;
    let public_key1 = secret_key1.public_key();
    println!("secret {}\npublic {}", secret_key1, public_key1);
    // can deserialize
    let secret_key = SecretKey::from_str(SECRET)?;
    print!("-------------->OK");
    //println!("secret {}\npublic {}", secret_key, public_key);
    let public_key = secret_key.public_key();
    println!("secret {}\npublic {}", secret_key, public_key);
    // can sign
    let data = b"test data";
    let nonce = b"12345678";
    let mut attributes = SignatureAttributes::default();
    attributes.set_nonce(Some(nonce));
    let signature = secret_key.sign_deterministic(data, None, Some(&mut attributes))?;
    println!("signed \"test data\":\nsignature {}", signature);
    assert_eq!(
        signature.to_string(),
        "z2qusDfBWovGdxjcJ3WA2Geq6CPMaWqWWsySogtx5bpHyEpJd1NWWDJ9FWUhSbB6zsTsQ7sMj2TCs8pnj4k7sD9dSS3SP2AB"
    );
    public_key.verify(data, &signature)?;

    println!("--- unsupported key P256:");
    assert!(
        SecretKey::new(
            multicodec_prefix::P256_SECRET,
            None,
            None,
            Some("secret"),
            Some("pub"),
        )
        .is_err()
    );
    assert!(SecretKey::from_str(UNSUPPORTED_SECRET).is_err());
    println!("not supported");

    let recipient =
        Did::from_str("did:key:z6Mkgv5USNQTNZDoyhu8qyfQFj13x65b2eM59RQck69bpeh7").unwrap();

    let capabilities = [
        ("mailto:test@test.com", "msg/receive"),
        ("mailto:test@test.com", "msg/send"),
    ];

    let builder = TokenBuilder::default()
        .with_secret(&secret_key)
        .for_audience(&recipient)
        .with_capabilities(&capabilities);
    let token = builder.build().await?;

    token.verify_signature(None)?;
    token.validate(None, Some(1000))?;

    let mut verifier: Verifier<_, _, CustomKeyFactory> = Verifier::default();
    let requirements = Requirements {
        audience: recipient.to_string(),
        capabilities: BTreeMap::from([(
            public_key.get_did()?.to_string(),
            Capabilities::try_from(
                [
                    ("mailto:test@test.com", "msg/receive"),
                    ("mailto:test@test.com", "msg/send"),
                ]
                .as_slice(),
            )?,
        )]),
        data: None,
        time: Some(1000),
        known_tokens: None,
    };
    verifier.verify(&token, None, &requirements).await.unwrap();

    let dwt = token.encode_dwt().unwrap();

    println!("{}", Token::diag_token_string(&dwt));
    println!("Successfully created and verified the token.");

    Ok(())
}
