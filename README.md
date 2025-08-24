# mysteryn-token

This crate implements the Delegable Web Token (**DWT**), which is based on the principles of [Capability-based security](https://en.wikipedia.org/wiki/Capability-based_security). This type of token is used to verify and authorize user or application capabilities to perform some actions, as well it can be used to delegate capabilities to other parties.

## Getting Started

To start using `mysteryn-token`, add it to your `Cargo.toml`:

```toml
[dependencies]
mysteryn-token = "0.1.0"
```

Then, you can start building and verifying tokens. Here's a quick example of how to create and verify a token:

```rust
use mysteryn_crypto::{did::Did, MultikeySecretKey, DefaultSecretKeyVariant, DefaultPublicKeyVariant};
use mysteryn_token::TokenBuilder;
use std::str::FromStr;

pub type SecretKey = MultikeySecretKey<DefaultSecretKeyVariant, DefaultPublicKeyVariant>;

let secret_key = SecretKey::from_str("secret_xahgjgqfsxwdjkxun9wspqzgzve7sze7vwm0kszkya5lurz4np9cmc8k4frds9ze0g6kzsky8pmv8qxur4vfupul38mfdgrcc")?;
let recipient = Did::from_str("did:key:pub_xahgjw6qgrwp6kyqgpyq29vthlflt6dtl5pvlrwrnllgyy5ws5a0w3xa2tt0425k9rvcwus9j33c3u0m7a2v")?;
let capabilities = [
   ("mailto:test@test.com", "msg/receive"),
   ("mailto:test@test.com", "msg/send"),
 ];
 
let builder = TokenBuilder::default()
   .with_secret(&secret_key)
   .for_audience(&recipient)
   .with_capabilities(&capabilities);
let token = builder.build().await?;
```

## Theory

Terms:

- > A **capability** (known in some systems as a **key**) is a communicable, unforgeable [token](https://en.wikipedia.org/wiki/Access_token "Access token") of authority.
  > 
  > *From Wikipedia, the free encyclopedia*

- A **permission** is an authorization granted to do something, usually provided by an application.

### Capabilities

The **capability** is a combination of the **resource** (the object to be accessed) and one or more **actions** (or access rights), optionally limited by the **attenuation**.

The **resource** is the slash (`/`) delimited string representing a path or an URI to the object:

```txt
<subpath1>/<subpath2>...
```

The **action** is the slash (`/`) delimited string representing an action which may be performed on the object, optionally followed by the **attenuation** prefixed with a semicolon and a space (`; att`):

```txt
<actionpath1>/<actionpath2>... [; attenuation]
```

The first appearance of the semicolon followed  by a space  (`; `) is interpreted as a delimiter.

Example capability:

```txt
bookshelf/bookshelf1/book/book1:
  - take/classroom
  - take/home; from 3pm to 5pm, for 1 day
```

### Semantics

Capabilities are **permissive**, what means that the capability must be provided explicitly to allow some action, otherwise the action is not allowed.

Resources and actions are slash (`/`) delimited path segment strings.

Each resource path segment includes all of its sub-resources. A path segment can be the asterisk (`*`), what means "Any". The asterisk has a special meaning only stand-alone, and has no meaning when it is used in a text, for example "boo*f" is just a text.

Examples:

- "bookshelf" includes "bookshelf/bookshelf1" (any bookshelf)

- "bookshelf" includes "bookshelf/bookshelf1/book/book1" and "bookshelf/bookshelf1/folder/folder1" (any book or folder)

- "bookshelf/bookshelf1" includes "bookshelf/bookshelf1/book/book1" (any book or folder from the "bookshelf1")

- "bookshelf/*/book" includes "bookshelf/bookshelf1/book/book1", but does not include "bookshelf/bookshelf1/folder/folder1" (any book, but not a folder).

Action path rules are the same as resource rules. Optionally, the action can have an attenuation appended to the end as a free text after the semicolon followed by a space (`; att`). By default, attenuated actions are rejected by the semantics, so the application should implement the Attenuator trait to parse and handle them.

Examples:

- "take" includes "take/classroom" and "take/home" (any take action)

- "take" includes "take/home; at 5pm, for 1 day" (any take action with an attenuation).

- should be parsed by the application: the requirement "take/home; from 3pm to 5pm, for 1 day" includes "take/home" at 4pm

- should be parsed by the application: the requirement "take/home" includes "take/home; from 3pm to 5pm, for 1 day" at 4pm

### Canonical payload

The **Canonical payload** is a [DAG-CBOR](https://ipld.io/docs/codecs/known/dag-cbor/) encoded binary structure of the DWT, used to be signed with the digital signature.

The payload MUST contain exactly the following fields (optional fields are omitted when empty):

| Field | Type                         | Required | Description                                             |
| ----- | ---------------------------- | -------- | ------------------------------------------------------- |
| `iss` | `DID`                        | Yes      | Issuer DID (sender), binary encoded as Multidid         |
| `aud` | `DID`                        | Yes      | Audience DID (receiver), binary encoded as Multidid     |
| `can` | `Map<String, Array<String>>` | Yes      | Claimed capabilities                                    |
| `prf` | `Array<CID>`                 | No       | Links to proofs                                         |
| `pre` | `Array<DWT>`                 | No       | Embedded proofs (binary encoded DWTs)                   |
| `exp` | `Integer`                    | No       | Expiration UTC Unix timestamp in seconds (valid until)  |
| `nbf` | `Integer`                    | No       | "Not before" UTC Unix timestamp in seconds (valid from) |
| `dat` | `Map<String: Any>`           | No       | Metadata                                                |
| `nnc` | `String`                     | No       | Nonce string                                            |
| `pbk` | `String`                     | No       | Public key (may be used with "did:pkh")                 |

Example:

```js
{
  "iss": "did:key:x8tkszqqpqyswvqv65h3mja8ddzcerzd3533dledvqr74d0g8lu36eq80kdu68mvjavszrh0g4trq",
  "aud": "did:key:x8tkszqqpqysqrvw5wd24pfr4s5f40k4lae0khqfgsmzwzm6mjryghuclrclsq6knm50x3vg3p6cs",
  "can": {
    "bookshelf/bookshelf1/book": [
      "take"
    ],
    "bookshelf/bookshelf2/book": [
      "take/classroom"
    ]
  },
  "prf": [
    "z2XqYBj4diWiGs43nquiCGi58m2qKftTjsc3bP7xEtT786pCR1fVZTA7vGT7hTvvadzuicLY6zKmVFqqrZWafgufnMxyirirUbp7HRAVU4MRDjZboDPXUaFQLmhQZkpPneK27eaBRLN3ea9kgiLeecTZ8EyhnjJpXMXcPoC8gKS8Cg8DWvNwGxvyfamuvpXKJMKhrHWvTTrAj3jrSka5kR1wN9U3MYaridPz7mfha98ZSXzSqiLY3aR2mETofeBWLcsyLsejiMbv2n8CJsTGVobzuEKsvgVzPuhT72uh8JMao9DXQviT135rQArwR7y3GYSJjYPv8tHQgpHdrY8N2bmJF9vdB1jc54MGmgysPdchYWBSosJL66Z7ePtSYkD8Xt78AjR"
  ],
  "exp": 1732542921
}
```

The DWT token structure is the Canonical payload with the signature field (`sig`) added. The signature is a digital signature in the binary [Multisig][^Multisig] format.

## Design considerations

1. **Minimalistic**. The token contains only the fields used to provide the described functionality, and no placeholders.

2. **Secure**. The token uses the Multikey and the Multisig implementation from the [`mysteryn-crypto`](https://github.com/Mysteryn-Lab/mysteryn-crypto) crate, which has many algorithms, including Post-Quantum Cryptography digital signatures.

3. **Predictable**. The token encoding and decoding must always produce the same result, having the same hash or CID. Usage of the DAG-CBOR codec conforms this requirement. The provided semantics rules work as described, custom interpretations or rules should not be used.

4. **Readable**. Capabilities should be human-readable.

5. **Nonce is optional**. The Multisig implementation of  the `mysteryn-crypto` uses a random `nonce` to protect a signature. So including a `nonce` to the token is optional and doesn't affect security.

6. **Single signature**. As the signature algorithm is described by the issuer DID in the `iss` field, token is signed by only one signature.

## Build and test

### Tests

Run tests:

```bash
cargo test
```

Testing with the `WasmEdge` or `wasmtime`:

```bash
cargo test --target wasm32-wasip2 -- --nocapture
```

Testing in a browser with the `wasm-pack`:

```bash
wasm-pack test --chrome
```

Testing in a browser with the `wasm-bindgen-test-runner`:

```bash
NO_HEADLESS=1 WASM_BINDGEN_USE_BROWSER=1 cargo test --target wasm32-unknown-unknown -- --nocapture

# Windows version
set NO_HEADLESS=1 && set WASM_BINDGEN_USE_BROWSER=1 && cargo test --target wasm32-unknown-unknown
```

### WebAssembly

To build this library to the WebAssembly:

1. Install`wasm-pack`:
   
   > This version does not require your "Cargo.toml" to have `crate-type = ["cdylib", "rlib"]`.
   
   ```bash
   cargo install --git https://github.com/druide/wasm-pack.git
   ```

2. Build a web package:
   
   ```bash
   wasm-pack build --target web
   ```

3. Build a npm module:
   
   ```bash
   wasm-pack build --target nodejs
   ```

## Examples

```bash
cargo run --example quick-start

# run in the WasmEdge or wasmtime
cargo run --target wasm32-wasip2 --example quick-start

# compile and run in the WasmEdge
cargo build --target wasm32-wasip2 --release --example quick-start
wasmedge compile --optimize=z target/wasm32-wasip2/release/examples/quick-start.wasm target/wasm32-wasip2/release/examples/quick-start_aot.wasm
wasmedge run target/wasm32-wasip2/release/examples/quick-start_aot.wasm

# compile and run in the wasmtime
cargo build --target wasm32-wasip2 --release --example quick-start
wasmtime compile target/wasm32-wasip2/release/examples/quick-start.wasm -o target/wasm32-wasip2/release/examples/quick-start.cwasm
wasmtime --allow-precompiled target/wasm32-wasip2/release/examples/quick-start.cwasm
```

```bash
cargo run --example custom-keys
```

Node.js example:

```bash
# build before run: wasm-pack build --target nodejs
cd examples/nodejs
npm run reinstall
# did:key example
node .
# did:pkh example
node did-pkh
# Token store example
node store-example
```

## Use cases

### 1. User-Controlled Access Tokens

The primary use case for DWT is the delegation of capabilities. A user can receive a token from a service that grants them certain permissions. The user can then delegate a subset of those permissions to another user or service.

For example, a user might have a token that grants them read and write access to a document. They can then create a new token that delegates only read access to another user. This allows for fine-grained access control that is controlled by the user, not the service.

### 2. JWT Replacement

DWT can be used as a replacement for JWTs. To do this, the issuer creates a token with the audience (`aud`) set to the DID of the service that will be verifying the token. This token cannot be delegated by users.

User-specific data, such as a "User ID", can be included in the metadata (`dat`). Optionally, capabilities (`can`) may be used to verify the user's access rights.

```json
{
    "iss": "did:key:z6Mkvcrr72yde85HzXzeuvEocoqc9A8B6xkGaP1YGExBPuog",
    "aud": "did:key:z6Mkvcrr72yde85HzXzeuvEocoqc9A8B6xkGaP1YGExBPuog",
    "exp": 1732542921,
    "nbf": 1529496683,
    "nnc": "TXKhb0Rj3Aopskkd1kKNSMlixpn07BqMsQJid_3cf_o",
    "can": {
      "mailto:username@example.com": [
        "msg/receive",
        "msg/send"
      ]
    },
    "dat": { "user_id": 12345 }
}
```

### 3. Token Revocation

Users can revoke any of their issued tokens by default (by `iss`), as well as any of their received tokens (by `aud`). Users may also revoke any token that has their token in its delegation chain.

The issuer may delegate the right to revoke some of its issued tokens by the token's CID.

```json
{
    "iss": "did:key:z6Mkvcrr72yde85HzXzeuvEocoqc9A8B6xkGaP1YGExBPuog",
    "aud": "did:key:z6Mkvcrr72yde85HzXzeuvEocoqc9A8B6xkGaP1YGExBPuog",
    "exp": 1732542921,
    "nbf": 1529496683,
    "nnc": "TXKhb0Rj3Aopskkd1kKNSMlixpn07BqMsQJid_3cf_o",
    "can": {
      "534534gfdgdfgreteterte": [
        "revoke",
      ]
    },
    "dat": { "user_id": 12345 }
}
```
   
The issuer may also delegate the right to revoke any of its issued tokens by the issuer's DID.

```json
{
    "iss": "did:key:z6Mkvcrr72yde85HzXzeuvEocoqc9A8B6xkGaP1YGExBPuog",
    "aud": "did:key:z6Mkvcrr72yde85HzXzeuvEocoqc9A8B6xkGaP1YGExBPuog",
    "exp": 1732542921,
    "nbf": 1529496683,
    "nnc": "TXKhb0Rj3Aopskkd1kKNSMlixpn07BqMsQJid_3cf_o",
    "can": {
      "did:key:z6Mkvcrr72yde85HzXzeuvEocoqc9A8B6xkGaP1YGExBPuog": [
        "revoke",
      ]
    },
    "dat": { "user_id": 12345 }
}
```

## Links

- [mysteryn-crypto](https://github.com/Mysteryn-Lab/mysteryn-crypto)

- [Multikey Specification](https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multikey.md)

- [^Multisig](https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multisig.md)

## License

This software is licensed under the [MIT license](./LICENSE).

[^Multisig]: <https://github.com/cryptidtech/provenance-specifications/blob/main/specifications/multisig.md>
