import {
  keyToDID,
  verifyCredential,
  prepareIssueCredential,
  completeIssueCredential,
} from '@spruceid/didkit-wasm-node'
import * as secp from '@noble/secp256k1'
import * as jose from 'jose'


const privKey = secp.utils.hexToBytes(
  "910e629f10bfe69fc70fc63b7bc6cc2d6b9d4af22fcd277696e07ce4cb936e61"
);
const pubKey = secp.getPublicKey(privKey, false);

(async () => {
  const jwk = {
    kty: "EC",
    crv: "secp256k1",
    x: jose.base64url.encode(pubKey.slice(1, 33)),
    y: jose.base64url.encode(pubKey.slice(33, 66)),
  };

  const did = keyToDID("key", JSON.stringify(jwk))
  const other = await (async () => {
    const keyStr =
      '{"kty":"EC","crv":"secp256k1","x":"X7ZzK9t8i6LZgi7lcKGXLMzeV9PLH2NIPNip_g_8eso","y":"cqZciccFbybaKHxKMm8em48rSH26Cm0peOvNwvelVgM","d":"NSf9zygkwE2UoJMlzs-nf0UnIYju_d_cVG2we1EKZOQ"}';
    const key = JSON.parse(keyStr);
    const did = keyToDID("key", keyStr)

    return { key, keyStr, did };
  })();

  const baseCredentials =
    JSON.stringify({
      "@context": "https://www.w3.org/2018/credentials/v1",
      id: "http://example.org/credentials/3731",
      type: ["VerifiableCredential"],
      issuer: did,
      issuanceDate: "2020-08-19T21:41:50Z",
      credentialSubject: {
        id: other.did,
      },
    })

  const proofPreparationJson = await prepareIssueCredential(
    baseCredentials,
    JSON.stringify({
      proofPurpose: "assertionMethod",
    }),
    JSON.stringify(jwk));

  const proofPreparation = JSON.parse(proofPreparationJson);

  const sigHash = await secp.utils.sha256(jose.base64url.decode(proofPreparation.signingInput));
  const der_signature = await secp.sign(sigHash, privKey);
  const rawSignature = secp.Signature.fromDER(der_signature).toCompactRawBytes();
  const signature = jose.base64url.encode(rawSignature);

  const credential = await completeIssueCredential(
    baseCredentials,
    proofPreparationJson,
    signature);

  const verifyStr = await verifyCredential(
    credential,
    JSON.stringify({
      proofPurpose: "assertionMethod",
    }),
  );

  const verify = JSON.parse(verifyStr);

  if (verify.errors.length > 0) throw verify.errors;
})();



