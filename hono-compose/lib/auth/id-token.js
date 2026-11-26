import { decodeJson, decodeToBytes } from './base64url.js';

export class IdTokenError extends Error {}

// Validates an ID token per OpenID Connect Core §3.1.3.7 and returns its
// claims, or throws IdTokenError.
//
// The token comes straight from the token endpoint over TLS, which §3.1.3.7
// says MAY stand in for checking the signature. The signature is checked
// anyway: it costs one JWKS fetch per sign-in, and it keeps this function
// correct for a caller that got the token any other way.
//
// `getJwk(kid, { refresh })` returns the provider's public key for `kid`, or
// null. It's called with refresh: true once if the first lookup misses,
// since providers rotate keys and a cached set can lag behind.
export async function validateIdToken(token, { issuer, clientId, nonce, getJwk, nowSeconds, skewSeconds = 60 }) {
  const parts = typeof token === 'string' ? token.split('.') : [];
  if (parts.length !== 3) {
    throw new IdTokenError('malformed token');
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  let header;
  let claims;
  let signature;
  try {
    header = decodeJson(encodedHeader);
    claims = decodeJson(encodedPayload);
    signature = decodeToBytes(encodedSignature);
  } catch {
    throw new IdTokenError('malformed token');
  }

  // Only the algorithm the providers this module supports actually use. The
  // token names its own alg, so accepting whatever it says (including
  // "none") would let the token choose how it gets checked.
  if (header?.alg !== 'RS256') {
    throw new IdTokenError(`unsupported alg ${JSON.stringify(header?.alg)}`);
  }
  if (typeof header.kid !== 'string') {
    throw new IdTokenError('missing kid');
  }

  const jwk = (await getJwk(header.kid, { refresh: false })) ?? (await getJwk(header.kid, { refresh: true }));
  if (jwk == null) {
    throw new IdTokenError(`unknown kid ${header.kid}`);
  }
  let key;
  try {
    key = await crypto.subtle.importKey(
      'jwk',
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
  } catch {
    throw new IdTokenError(`unusable key ${header.kid}`);
  }
  const signed = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
  if (!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, signed))) {
    throw new IdTokenError('bad signature');
  }

  if (claims == null || typeof claims !== 'object') {
    throw new IdTokenError('malformed claims');
  }
  if (claims.iss !== issuer) {
    throw new IdTokenError('wrong issuer');
  }
  // A single audience, and it's us. §3.1.3.7 also allows extra audiences
  // the client trusts; this client trusts none, so any extra is a reject.
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (audiences.length !== 1 || audiences[0] !== clientId) {
    throw new IdTokenError('wrong audience');
  }
  if (typeof claims.exp !== 'number' || claims.exp + skewSeconds <= nowSeconds) {
    throw new IdTokenError('expired');
  }
  if (typeof claims.iat === 'number' && claims.iat - skewSeconds > nowSeconds) {
    throw new IdTokenError('issued in the future');
  }
  if (claims.nonce !== nonce) {
    throw new IdTokenError('wrong nonce');
  }
  // Some providers send the string "true" instead of a boolean.
  if (claims.email_verified !== true && claims.email_verified !== 'true') {
    throw new IdTokenError('email not verified');
  }
  return claims;
}
