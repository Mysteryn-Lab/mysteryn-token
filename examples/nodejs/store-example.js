import {
	createSecret,
	secret2did,
	invokeToken,
	token2cid,
	verifyToken,
} from "mysteryn-token";

/** Simple in-memory token store */
class JsDwtStore {
	dags = {};
	revoked = {};

	async read(cid) {
		return this.dags[cid];
	}

	async write(cid, token) {
		this.dags[cid] = token;
	}

	async revoke(cid, expires_at) {
		this.revoked[cid] = true;
	}

	async is_revoked(cid) {
		return !!this.revoked[cid];
	}

	async cleanup() {
		//
	}
}

const store = new JsDwtStore();

const secret1 = createSecret(0x1300, null, null, "secret", "pub", null);
const did1 = secret2did(secret1);
console.log("DID 1", did1);
const secret2 = createSecret(0x1300, null, null, "secret", "pub", null);
const did2 = secret2did(secret2);
console.log("DID 2", did2);
const secret3 = createSecret(0x1300, null, null, "secret", "pub", null);
const did3 = secret2did(secret3);
console.log("DID 3", did3);

console.log("");

const proof = await invokeToken(
	{
		issuer: did1,
		audience: did2,
		capabilities: {
			"bookshelf/bookshelf1/book": ["take"],
			"bookshelf/bookshelf2/book": ["take"],
		},
	},
	secret1,
	store,
);
const proofCid = token2cid(proof);

const token = await invokeToken(
	{
		issuer: did2,
		audience: did3,
		capabilities: {
			"bookshelf/bookshelf1/book": ["take"],
			"bookshelf/bookshelf2/book": ["take"],
		},
		proofs: [proofCid],
		embeddedProofs: [proof],
	},
	secret2,
	store,
);

const verification = await verifyToken(
	token,
	{
		audience: did3,
		capabilities: {
			[did1]: {
				"bookshelf/bookshelf1/book": ["take"],
				//"bookshelf/bookshelf2/book": ["take/classroom"]
			},
		},
	},
	undefined,
	store,
);

console.log("Verified", verification);
console.log("");

console.log("Revocation of a proof token...");
await store.revoke(proofCid);

try {
	await verifyToken(
		token,
		{
			audience: did3,
			capabilities: {
				[did1]: {
					"bookshelf/bookshelf1/book": ["take"],
					//"bookshelf/bookshelf2/book": ["take/classroom"]
				},
			},
		},
		undefined,
		store,
	);
	console.error("Failed: should not validate as proof was revoked");
} catch (e) {
	console.log(`Success: detected a revoked token with error: ${e}`);
}

console.log(store)
