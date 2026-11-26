// base64url (RFC 4648 §5) without padding, the encoding JWTs and these
// cookies use. btoa/atob only handle "binary strings", so bytes go through
// String.fromCharCode on the way in and charCodeAt on the way out.

export function encodeBytes(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Throws on anything that isn't base64url, rather than letting atob accept
// standard base64 or whitespace and decode it anyway.
export function decodeToBytes(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error('not base64url');
  }
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (ch) => ch.charCodeAt(0));
}

export function encodeJson(value) {
  return encodeBytes(new TextEncoder().encode(JSON.stringify(value)));
}

export function decodeJson(text) {
  return JSON.parse(new TextDecoder().decode(decodeToBytes(text)));
}

export function randomToken(byteLength = 32) {
  return encodeBytes(crypto.getRandomValues(new Uint8Array(byteLength)));
}
