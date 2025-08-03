import {
  createSecret,
  secret2public,
  public2did_pkh,
  invokeToken,
  token2diag,
  token2object,
  token2cid,
  verifyToken,
  secret2did_pkh
} from "mysteryn-token"

const secret = createSecret(0x1300, null, null, "secret", "pub", null)
console.log("Secret key", secret)

const key = secret2public(secret)
console.log("Public key", key)

const did = secret2did_pkh(secret, "mys", "id")
console.log("DID", did)

const recipientKey = "pub_xahgjw6qgrwp6kyqgpyqd9vnxsydeaqkkf6p6tupkq2euhjrsqfgvwsgv35zywdnze59akkg2ffxdsk8qaqq"
const recipient = public2did_pkh(recipientKey, "mys", "id")
if (recipient !== "did:pkh:mys:id_xarcsr2mduyma8l3wv39l5qhqae9mcf6y2f4yruyk0t328zqfxurgnqsgjukzk9njx7ups") {
  throw new Error("DID decoding error")
}

console.log("")

const token = await invokeToken(
  {
    iss: did,
    aud: recipient,
    can: {
      "bookshelf/bookshelf1/book": ["take"],
      "bookshelf/bookshelf2/book": ["take"]
    },
    pk: key // IMPORTANT! must include the public key to make "did:pkh" verifiable 
  },
  secret
)
console.log("Token", token)
console.log("Token CID", token2cid(token))
console.log("")
console.log("Token diag", token2diag(token))
console.log("Token object", token2object(token))

console.log("")

const verification = await verifyToken(token, {
  audience: recipient,
  capabilities: {
    [did]: {
      "bookshelf/bookshelf1/book": ["take"],
      //"bookshelf/bookshelf2/book": ["take/classroom"]
    }
  }
})

console.log("Verification", verification)
console.log("Successfully invoked and verified a token.")
