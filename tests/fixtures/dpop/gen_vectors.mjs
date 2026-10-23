// Regenerates vectors.json from the engine's own verifier (packages/shared/src/dpop.ts):
//   ENGINE=/path/to/Vekrel-Engine node tests/fixtures/dpop/gen_vectors.mjs > tests/fixtures/dpop/vectors.json
// Cases follow packages/shared/src/dpop.test.ts plus edge cases the Rust port must agree on.
import * as NodeCrypto from "node:crypto";

const { verifyDpopProof, computeDpopJwkThumbprint, computeDpopAccessTokenHash, normalizeDpopHtu } =
  await import(`${process.env.ENGINE}/packages/shared/src/dpop.ts`);

// apps/server/src/auth/dpop.ts mapDpopFailureReason.
const reason = (code) =>
  ({
    time_window: "time_window",
    key_mismatch: "key_mismatch",
    method_mismatch: "request_mismatch",
    url_mismatch: "request_mismatch",
    access_token_hash_mismatch: "token_mismatch",
  })[code] ?? "invalid_proof";

const b64 = (s) => Buffer.from(s).toString("base64url");
const { privateKey, publicKey } = NodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const other = NodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
const jwk = publicKey.export({ format: "jwk" });
const privJwk = privateKey.export({ format: "jwk" });
const thumb = computeDpopJwkThumbprint(jwk);
const URL1 = "https://example.com/oauth/token";
const TOKEN = "access-token-1";

const sig = (key, input) =>
  NodeCrypto.sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
// Raw header/payload JSON text, so cases can carry bytes JSON.stringify would not produce.
function proofRaw(headerJson, payloadJson, { key = privateKey, mutateSig } = {}) {
  const hp = `${b64(headerJson)}.${b64(payloadJson)}`;
  let s = sig(key, hp);
  if (mutateSig) s = mutateSig(s);
  return `${hp}.${Buffer.from(s).toString("base64url")}`;
}
const header = (over = {}) => JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk, ...over });
const payload = (over = {}) =>
  JSON.stringify({ htm: "POST", htu: URL1, jti: "proof-1", iat: 100, ...over });
const proof = (h = {}, p = {}, o) => proofRaw(header(h), payload(p), o);

// n - s: the high-S twin of a valid signature (noble lowS:false accepts it).
const N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const highS = (s) => {
  const v = BigInt(`0x${Buffer.from(s.subarray(32)).toString("hex")}`);
  const hi = v > N / 2n ? v : N - v;
  return Buffer.concat([s.subarray(0, 32), Buffer.from(hi.toString(16).padStart(64, "0"), "hex")]);
};

const base = { method: "POST", url: URL1, now: 101, expectedThumbprint: thumb };
const cases = [
  ["valid", { proof: proof() }],
  ["valid_lowercase_htm", { proof: proof({}, { htm: "post" }) }],
  ["valid_request_url_query_fragment", { proof: proof(), url: `${URL1}?a=1#f` }],
  ["valid_extra_fields_and_kid", { proof: proof({ jwk: { ...jwk, kid: "k" }, x5: 1 }, { extra: true }) }],
  ["valid_iat_float_integral", { proof: proofRaw(header(), payload().replace('"iat":100', '"iat":100.0')) }],
  ["valid_high_s", { proof: proof({}, {}, { mutateSig: highS }) }],
  ["valid_with_ath", { proof: proof({}, { ath: computeDpopAccessTokenHash(TOKEN) }), expectedAccessToken: TOKEN }],
  ["valid_skew_minus_300", { proof: proof(), now: 400 }],
  ["valid_skew_plus_300", { proof: proof(), now: -200 }],
  ["time_window_plus_301", { proof: proof(), now: 401 }],
  ["time_window_minus_301", { proof: proof(), now: -201 }],
  ["time_window_1000", { proof: proof(), now: 1000 }],
  ["bad_signature_before_time_window", { proof: proof({}, {}, { key: other }), now: 1000 }],
  ["method_mismatch", { proof: proof(), method: "GET" }],
  ["url_mismatch", { proof: proof(), url: "https://example.com/other" }],
  ["key_mismatch", { proof: proof(), expectedThumbprint: "other-thumbprint" }],
  ["key_mismatch_before_bad_signature", { proof: proof({}, {}, { key: other }), expectedThumbprint: "x" }],
  ["method_mismatch_before_bad_signature", { proof: proof({}, {}, { key: other }), method: "GET" }],
  ["ath_missing", { proof: proof(), expectedAccessToken: TOKEN }],
  ["ath_wrong", { proof: proof({}, { ath: computeDpopAccessTokenHash("other") }), expectedAccessToken: TOKEN }],
  ["ath_before_bad_signature", { proof: proof({}, {}, { key: other }), expectedAccessToken: TOKEN }],
  ["private_jwk_d", { proof: proof({ jwk: privJwk }) }],
  ["malformed_header_json", { proof: `${b64("{")}.${proof().split(".")[1]}.${proof().split(".")[2]}` }],
  ["malformed_payload_json", { proof: `${proof().split(".")[0]}.${b64("{")}.${proof().split(".")[2]}` }],
  ["missing_proof", { proof: "" }],
  ["two_parts", { proof: proof().split(".").slice(0, 2).join(".") }],
  ["empty_signature_part", { proof: `${proof().split(".").slice(0, 2).join(".")}.` }],
  ["typ_wrong", { proof: proof({ typ: "JWT" }) }],
  ["alg_es384", { proof: proof({ alg: "ES384" }) }],
  ["kty_rsa", { proof: proof({ jwk: { ...jwk, kty: "RSA" } }) }],
  ["empty_jti", { proof: proof({}, { jti: "" }) }],
  ["iat_fraction", { proof: proof({}, { iat: 100.5 }) }],
  ["iat_string", { proof: proof({}, { iat: "100" }) }],
  ["x_31_bytes", { proof: proof({ jwk: { ...jwk, x: b64(Buffer.alloc(31, 1)) } }), expectedThumbprint: undefined }],
  ["point_off_curve", { proof: proof({ jwk: { ...jwk, y: b64(Buffer.alloc(32, 1)) } }), expectedThumbprint: undefined }],
  ["signature_63_bytes", { proof: proof({}, {}, { mutateSig: (s) => s.subarray(0, 63) }) }],
  ["signature_zero_s", { proof: proof({}, {}, { mutateSig: (s) => Buffer.concat([s.subarray(0, 32), Buffer.alloc(32)]) }) }],
];

const vectors = cases.map(([name, c]) => {
  const input = { ...base, ...c };
  const r = verifyDpopProof({
    proof: input.proof,
    method: input.method,
    url: input.url,
    nowEpochSeconds: input.now,
    ...(input.expectedThumbprint ? { expectedThumbprint: input.expectedThumbprint } : {}),
    ...(input.expectedAccessToken ? { expectedAccessToken: input.expectedAccessToken } : {}),
  });
  const node = r.ok
    ? {
        ok: true,
        thumbprint: r.thumbprint,
        jti: r.jti,
        iat: r.iat,
        marker: `dpop-proof-${NodeCrypto.createHash("sha256").update(`${r.thumbprint}:${r.jti}`).digest("base64url")}`,
      }
    : { ok: false, code: r.code, dpopFailureReason: reason(r.code) };
  return { name, ...input, expectedThumbprint: input.expectedThumbprint ?? null, expectedAccessToken: input.expectedAccessToken ?? null, node };
});

const thumbprints = [jwk, { kty: "EC", crv: "P-256", x: "a\"b\\c\u0001é", y: "-_" }].map((k) => ({
  jwk: k,
  thumbprint: computeDpopJwkThumbprint(k),
}));
const htu = [
  "http://127.0.0.1:3789/api/auth/session?x=1#f",
  "http://LOCALHOST:80/a/./b/../c",
  "http://localhost:3789//double",
  "http://localhost:3789/%7e/%2e/x y",
  "http://localhost:3789/ws?wsTicket=a",
  "https://example.com:443/p",
].map((input) => ({ input, output: normalizeDpopHtu(input) }));
const ath = { token: TOKEN, ath: computeDpopAccessTokenHash(TOKEN) };

console.log(JSON.stringify({ vectors, thumbprints, htu, ath }, null, 1));
