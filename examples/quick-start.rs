mod keys;

use keys::*;
use mysteryn_crypto::{multicodec::multicodec_prefix, prelude::*, result::Result};
use mysteryn_keys::DefaultKeyFactory;
use mysteryn_token::prelude::*;
use std::collections::BTreeMap;
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use tokio;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen(main))]
#[cfg_attr(
    not(all(target_family = "wasm", target_os = "unknown")),
    tokio::main(flavor = "current_thread")
)]
async fn main() -> Result<()> {
    let secret_key = SecretKey::new(
        multicodec_prefix::SECP256K1_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )?;
    let public_key = secret_key.public_key();
    println!("secret {}\npublic {}", secret_key, public_key);

    let recipient_secret_key = SecretKey::new(
        multicodec_prefix::SECP256K1_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )?;
    let recipient = recipient_secret_key.public_key().get_did()?;

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

    let mut verifier: Verifier<_, _, DefaultKeyFactory> = Verifier::default();
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
