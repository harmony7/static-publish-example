import { decodeJson, decodeToBytes, encodeBytes, encodeJson } from './base64url.js';

// A JSON payload with an HMAC-SHA256 signature, as `<payload>.<signature>`,
// both base64url. Used for the session and login-transaction cookies, so
// nothing about a visitor is stored server-side.
//
// Keys are { id, secret } with secret as raw bytes. The first key signs; any
// key verifies, so a new key can be put first while the old one still
// accepts existing cookies until they expire. The key id travels in the
// payload, which is safe because the signature covers it.
export class SignedValues {
  constructor(keys) {
    if (keys.length === 0) {
      throw new Error('SignedValues needs at least one key');
    }
    this.keys = keys;
    this.cryptoKeys = new Map();
  }

  async getCryptoKey(id) {
    let cryptoKey = this.cryptoKeys.get(id);
    if (cryptoKey == null) {
      const key = this.keys.find((k) => k.id === id);
      if (key == null) {
        return null;
      }
      cryptoKey = await crypto.subtle.importKey(
        'raw',
        key.secret,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign', 'verify'],
      );
      this.cryptoKeys.set(id, cryptoKey);
    }
    return cryptoKey;
  }

  // `payload` must carry its own `exp` (seconds since the epoch).
  async sign(payload) {
    const signingKey = this.keys[0];
    const encoded = encodeJson({ ...payload, kid: signingKey.id });
    const cryptoKey = await this.getCryptoKey(signingKey.id);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(encoded));
    return `${encoded}.${encodeBytes(new Uint8Array(signature))}`;
  }

  // Returns the payload, or null if the value is malformed, signed with an
  // unknown key, signed wrongly, or expired. Never throws on bad input: a
  // cookie is whatever the client sent.
  async verify(value, nowSeconds) {
    if (typeof value !== 'string') {
      return null;
    }
    const parts = value.split('.');
    if (parts.length !== 2) {
      return null;
    }
    const [encoded, signature] = parts;
    let payload;
    let signatureBytes;
    try {
      payload = decodeJson(encoded);
      signatureBytes = decodeToBytes(signature);
    } catch {
      return null;
    }
    if (payload == null || typeof payload !== 'object' || typeof payload.kid !== 'string') {
      return null;
    }
    const cryptoKey = await this.getCryptoKey(payload.kid);
    if (cryptoKey == null) {
      return null;
    }
    // crypto.subtle.verify compares in constant time.
    const valid = await crypto.subtle.verify('HMAC', cryptoKey, signatureBytes, new TextEncoder().encode(encoded));
    if (!valid) {
      return null;
    }
    if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds) {
      return null;
    }
    return payload;
  }
}
