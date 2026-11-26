import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { compileAllowRules } from '../hono-compose/lib/auth/allow-rules.js';
import { encodeBytes, encodeJson } from '../hono-compose/lib/auth/base64url.js';
import { IdTokenError, validateIdToken } from '../hono-compose/lib/auth/id-token.js';
import { OidcAuth } from '../hono-compose/lib/auth/index.js';
import { compileReturnUrlCheck } from '../hono-compose/lib/auth/return-url.js';
import { SignedValues } from '../hono-compose/lib/auth/signed-value.js';

const NOW = 1_800_000_000;
const CLIENT_ID = 'test-client.apps.googleusercontent.com';
const ISSUER = 'https://accounts.google.com';

describe('allow rules', () => {
  const allowed = compileAllowRules([
    { domain: 'example.net' },
    { email: 'Friend@Example.com' },
    { pattern: '*@*.example.org' },
  ]);

  for (const [email, expected] of [
    ['someone@example.net', true],
    ['someone@example.net', true],
    ['x@sub.example.net', false],
    ['x@example.net.evil.com', false],
    ['x@evilexample.net', false],
    ['friend@example.com', true],
    ['enemy@example.com', false],
    ['first.last@team.example.org', true],
    ['x@a.b.example.org', false],
    ['x@example.org', false],
    ['a@b@example.net', false],
    ['@example.net', false],
    ['', false],
  ]) {
    it(`${JSON.stringify(email)} → ${expected}`, () => {
      assert.equal(allowed({ email }), expected);
    });
  }

  it('denies an identity with no email', () => {
    assert.equal(allowed({}), false);
    assert.equal(allowed(null), false);
  });

  it('hostedDomain requires the hd claim to match', () => {
    const workspaceOnly = compileAllowRules([{ domain: 'example.net', hostedDomain: true }]);
    assert.equal(workspaceOnly({ email: 'a@example.net', hd: 'example.net' }), true);
    assert.equal(workspaceOnly({ email: 'a@example.net' }), false);
    assert.equal(workspaceOnly({ email: 'a@example.net', hd: 'other.jp' }), false);
  });

  it('rejects malformed rules', () => {
    assert.throws(() => compileAllowRules([]));
    assert.throws(() => compileAllowRules([{ domian: 'typo.jp' }]));
    assert.throws(() => compileAllowRules([{ domain: 'a.jp', email: 'b@a.jp' }]));
    assert.throws(() => compileAllowRules([{ pattern: 'no-at-sign' }]));
    assert.throws(() => compileAllowRules([null]));
  });
});

describe('return URL check', () => {
  const check = compileReturnUrlCheck(['example.com', '*.example.com']);
  const fallback = 'https://auth.example.com/';

  for (const [candidate, expected] of [
    ['https://example.com/posts/x/', 'https://example.com/posts/x/'],
    ['https://pr-5.example.com/a?b=c', 'https://pr-5.example.com/a?b=c'],
    ['https://a.b.example.com/', fallback],
    ['https://evil.com/', fallback],
    ['https://example.com.evil.com/', fallback],
    ['https://evilexample.com/', fallback],
    ['http://example.com/', fallback],
    ['javascript:alert(1)', fallback],
    ['//evil.com/', fallback],
    ['/relative', fallback],
    ['https://user:pw@example.com/', fallback],
    [null, fallback],
  ]) {
    it(`${JSON.stringify(candidate)}`, () => {
      assert.equal(check(candidate, fallback), expected);
    });
  }

  it('allows http only on localhost', () => {
    const local = compileReturnUrlCheck(['localhost']);
    assert.equal(local('http://localhost:7676/x', 'f'), 'http://localhost:7676/x');
  });
});

describe('signed values', () => {
  const key1 = { id: 'k1', secret: crypto.getRandomValues(new Uint8Array(32)) };
  const key2 = { id: 'k2', secret: crypto.getRandomValues(new Uint8Array(32)) };

  it('round-trips and expires', async () => {
    const values = new SignedValues([key1]);
    const signed = await values.sign({ email: 'a@example.net', exp: NOW + 10 });
    assert.equal((await values.verify(signed, NOW)).email, 'a@example.net');
    assert.equal(await values.verify(signed, NOW + 10), null);
  });

  it('rejects tampering, unknown keys, and junk', async () => {
    const values = new SignedValues([key1]);
    const signed = await values.sign({ email: 'a@example.net', exp: NOW + 10 });
    const [payload, signature] = signed.split('.');
    const forged = `${encodeJson({ email: 'b@example.net', exp: NOW + 10, kid: 'k1' })}.${signature}`;
    assert.equal(await values.verify(forged, NOW), null);
    assert.equal(await values.verify(`${payload}.${signature.slice(0, -2)}AA`, NOW), null);
    assert.equal(await new SignedValues([key2]).verify(signed, NOW), null);
    for (const junk of ['', 'x', 'a.b.c', '!!!.???', undefined]) {
      assert.equal(await values.verify(junk, NOW), null);
    }
  });

  it('verifies with an older key after rotation', async () => {
    const signed = await new SignedValues([key1]).sign({ exp: NOW + 10 });
    assert.notEqual(await new SignedValues([key2, key1]).verify(signed, NOW), null);
  });
});

// A stand-in identity provider: an RSA key for signing ID tokens, and a
// fetch that answers the token and JWKS endpoints.
async function makeProvider() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  );
  const jwk = { ...(await crypto.subtle.exportKey('jwk', publicKey)), kid: 'key-1' };

  async function issue(claims, { alg = 'RS256', kid = 'key-1', key = privateKey } = {}) {
    const input = `${encodeJson({ alg, kid, typ: 'JWT' })}.${encodeJson(claims)}`;
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(input));
    return `${input}.${encodeBytes(new Uint8Array(signature))}`;
  }

  return { jwk, issue, privateKey };
}

describe('ID token validation', async () => {
  const provider = await makeProvider();
  const getJwk = async (kid) => (kid === provider.jwk.kid ? provider.jwk : null);
  const goodClaims = {
    iss: ISSUER, aud: CLIENT_ID, exp: NOW + 300, iat: NOW, nonce: 'n1',
    email: 'a@example.net', email_verified: true, sub: '123',
  };
  const validate = (token) =>
    validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, nonce: 'n1', getJwk, nowSeconds: NOW });

  it('accepts a good token', async () => {
    assert.equal((await validate(await provider.issue(goodClaims))).email, 'a@example.net');
  });

  for (const [name, change] of [
    ['wrong issuer', { iss: 'https://evil.example' }],
    ['wrong audience', { aud: 'someone-else' }],
    ['extra audience', { aud: [CLIENT_ID, 'someone-else'] }],
    ['expired', { exp: NOW - 120 }],
    ['issued in the future', { iat: NOW + 600 }],
    ['wrong nonce', { nonce: 'n2' }],
    ['unverified email', { email_verified: false }],
  ]) {
    it(`rejects: ${name}`, async () => {
      await assert.rejects(validate(await provider.issue({ ...goodClaims, ...change })), IdTokenError);
    });
  }

  it('rejects alg none, unknown kid, a different key, and junk', async () => {
    const unsigned = `${encodeJson({ alg: 'none', kid: 'key-1' })}.${encodeJson(goodClaims)}.`;
    await assert.rejects(validate(unsigned), IdTokenError);
    await assert.rejects(validate(await provider.issue(goodClaims, { kid: 'key-2' })), IdTokenError);
    const other = await makeProvider();
    await assert.rejects(validate(await other.issue(goodClaims)), IdTokenError);
    await assert.rejects(validate('a.b'), IdTokenError);
    await assert.rejects(validate(undefined), IdTokenError);
  });

  it('refetches keys once when the kid is unknown', async () => {
    const calls = [];
    const rotating = async (kid, { refresh }) => {
      calls.push(refresh);
      return refresh ? provider.jwk : null;
    };
    const token = await provider.issue(goodClaims);
    await validateIdToken(token, { issuer: ISSUER, clientId: CLIENT_ID, nonce: 'n1', getJwk: rotating, nowSeconds: NOW });
    assert.deepEqual(calls, [false, true]);
  });
});

describe('OidcAuth flow', async () => {
  const provider = await makeProvider();
  const cookieKey = encodeBytes(crypto.getRandomValues(new Uint8Array(32)));
  const secrets = { client_secret: 'shh', cookie_key_1: cookieKey };

  // `email` is the account the fake provider signs in. Like a real one, it
  // echoes back the nonce from the authorization request, which signIn()
  // records in `pending`.
  function makeAuth(email) {
    const tokenRequests = [];
    const pending = { nonce: null };
    const auth = new OidcAuth(
      {
        provider: 'google',
        clientId: CLIENT_ID,
        callbackOrigin: 'https://auth.example.com',
        cookieDomain: '.example.com',
        allowedReturnHosts: ['example.com', '*.example.com'],
        allow: [{ domain: 'example.net' }],
        hostedDomainHint: 'example.net',
      },
      {
        getSecret: async (name) => secrets[name] ?? null,
        now: () => NOW,
        fetch: async (url, init) => {
          if (url === 'https://www.googleapis.com/oauth2/v3/certs') {
            return Response.json({ keys: [provider.jwk] });
          }
          if (url === 'https://oauth2.googleapis.com/token') {
            tokenRequests.push(new URLSearchParams(init.body));
            const claims = {
              iss: ISSUER, aud: CLIENT_ID, exp: NOW + 300, iat: NOW,
              email, email_verified: true, sub: '1', nonce: pending.nonce,
            };
            return Response.json({ id_token: await provider.issue(claims) });
          }
          throw new Error(`unexpected fetch ${url}`);
        },
      },
    );
    return { auth, tokenRequests, pending };
  }

  const get = (url, cookie) => new Request(url, { headers: cookie ? { cookie } : {} });
  const cookiesFrom = (response) => response.headers.getSetCookie();
  const cookiePair = (setCookie) => setCookie.split(';')[0];

  // Runs start → (provider) → callback and returns all three steps.
  async function signIn({ auth, pending }, returnUrl, { tamperState = false } = {}) {
    const start = await auth.handleRequest(
      get(`https://auth.example.com/auth/start?return=${encodeURIComponent(returnUrl)}`),
    );
    assert.equal(start.status, 302);
    const authorization = new URL(start.headers.get('location'));
    pending.nonce = authorization.searchParams.get('nonce');
    const txCookie = cookiePair(cookiesFrom(start)[0]);
    const state = tamperState ? 'forged' : authorization.searchParams.get('state');
    const callback = await auth.handleRequest(
      get(`https://auth.example.com/auth/callback?code=abc&state=${state}`, txCookie),
    );
    return { start, authorization, callback };
  }

  it('lets unprotected requests through untouched', async () => {
    const { auth } = makeAuth('a@example.net');
    assert.equal(await auth.handleRequest(get('https://example.com/')), null);
  });

  it('redirects a protected request without a session to the login page', async () => {
    const { auth } = makeAuth('a@example.net');
    const response = await auth.handleRequest(get('https://pr-5.example.com/x'), { protect: true });
    assert.equal(response.status, 302);
    assert.equal(
      response.headers.get('location'),
      'https://auth.example.com/auth/login?return=https%3A%2F%2Fpr-5.example.com%2Fx',
    );
  });

  it('signs in an allowed account, and the session works on another host', async () => {
    const flow = makeAuth('someone@example.net');
    const { authorization, callback } = await signIn(flow, 'https://pr-5.example.com/x');
    assert.equal(authorization.origin + authorization.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
    assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(authorization.searchParams.get('hd'), 'example.net');
    assert.equal(authorization.searchParams.get('redirect_uri'), 'https://auth.example.com/auth/callback');

    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get('location'), 'https://pr-5.example.com/x');
    const [sessionCookie, clearedTx] = cookiesFrom(callback);
    assert.match(sessionCookie, /^__Secure-auth-session=[^;]+; Path=\/; Max-Age=604800; HttpOnly; Secure; SameSite=Lax; Domain=\.example\.com$/);
    assert.match(clearedTx, /^__Host-auth-tx=; Path=\/; Max-Age=0;/);

    // PKCE: the verifier sent to the token endpoint hashes to the challenge.
    const verifier = flow.tokenRequests[0].get('code_verifier');
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
    assert.equal(encodeBytes(digest), authorization.searchParams.get('code_challenge'));
    assert.equal(flow.tokenRequests[0].get('client_secret'), 'shh');

    const session = cookiePair(sessionCookie);
    for (const host of ['auth.example.com', 'pr-99.example.com']) {
      assert.equal(await flow.auth.handleRequest(get(`https://${host}/`, session), { protect: true }), null);
    }
    assert.equal((await flow.auth.getSession(get('https://example.com/', session))).email, 'someone@example.net');
  });

  it('denies an account no rule allows, without setting a session', async () => {
    const { callback } = await signIn(makeAuth('someone@gmail.com'), 'https://auth.example.com/');
    assert.equal(callback.status, 403);
    assert.ok(cookiesFrom(callback).every((c) => !c.startsWith('__Secure-auth-session=')));
    assert.match(await callback.text(), /someone@gmail\.com/);
  });

  it('rejects a callback whose state does not match', async () => {
    const { callback } = await signIn(makeAuth('a@example.net'), 'https://auth.example.com/', { tamperState: true });
    assert.equal(callback.status, 400);
  });

  it('rejects a callback with no transaction cookie', async () => {
    const { auth } = makeAuth('a@example.net');
    const response = await auth.handleRequest(get('https://auth.example.com/auth/callback?code=a&state=b'));
    assert.equal(response.status, 400);
  });

  it('never redirects off-site after sign-in', async () => {
    const { auth } = makeAuth('a@example.net');
    const login = await auth.handleRequest(get('https://auth.example.com/auth/login?return=https%3A%2F%2Fevil.com%2F'));
    assert.ok(!(await login.text()).includes('evil.com'));
    const { callback } = await signIn(makeAuth('a@example.net'), 'https://evil.com/');
    assert.equal(callback.headers.get('location'), 'https://auth.example.com/');
  });

  it('sends sign-in pages on other hosts to the callback origin', async () => {
    const { auth } = makeAuth('a@example.net');
    const response = await auth.handleRequest(get('https://pr-5.example.com/auth/login?return=x'));
    assert.equal(response.headers.get('location'), 'https://auth.example.com/auth/login?return=x');
  });

  it('escapes provider error text', async () => {
    const { auth } = makeAuth('a@example.net');
    const start = await auth.handleRequest(get('https://auth.example.com/auth/start?return=x'));
    const tx = cookiePair(cookiesFrom(start)[0]);
    const response = await auth.handleRequest(
      get('https://auth.example.com/auth/callback?error=%3Cscript%3Ealert(1)%3C%2Fscript%3E', tx),
    );
    const body = await response.text();
    assert.ok(!body.includes('<script>'));
    assert.ok(body.includes('&lt;script&gt;'));
  });

  it('logout clears the session cookie on the parent domain', async () => {
    const { auth } = makeAuth('a@example.net');
    const response = await auth.handleRequest(get('https://pr-5.example.com/auth/logout'));
    assert.match(cookiesFrom(response)[0], /^__Secure-auth-session=; Path=\/; Max-Age=0;.*Domain=\.example\.com$/);
  });

  it('only answers GET and HEAD on its routes', async () => {
    const { auth } = makeAuth('a@example.net');
    const response = await auth.handleRequest(new Request('https://auth.example.com/auth/start', { method: 'POST' }));
    assert.equal(response.status, 405);
  });

  it('a session for an account whose rule was removed gets the denied page', async () => {
    const flow = makeAuth('a@example.net');
    const { callback } = await signIn(flow, 'https://auth.example.com/');
    const session = cookiePair(cookiesFrom(callback)[0]);
    flow.auth.isAllowed = compileAllowRules([{ domain: 'other.jp' }]);
    const response = await flow.auth.handleRequest(get('https://auth.example.com/', session), { protect: true });
    assert.equal(response.status, 403);
  });
});

describe('cookie security follows the callback origin', () => {
  const base = {
    provider: 'google',
    clientId: CLIENT_ID,
    allowedReturnHosts: ['localhost', 'auth.example.com'],
    allow: [{ domain: 'example.net' }],
  };
  const deps = {
    getSecret: async (name) =>
      ({ client_secret: 'shh', cookie_key_1: encodeBytes(new Uint8Array(32).fill(7)) })[name] ?? null,
    now: () => NOW,
  };
  const startCookie = async (auth, origin) => {
    const response = await auth.handleRequest(new Request(`${origin}/auth/start?return=x`));
    return response.headers.getSetCookie()[0];
  };

  it('https: Secure, with __Host- and __Secure- names', async () => {
    const auth = new OidcAuth({ ...base, callbackOrigin: 'https://auth.example.com' }, deps);
    assert.match(await startCookie(auth, 'https://auth.example.com'), /^__Host-auth-tx=.*; HttpOnly; Secure; SameSite=Lax$/);
    const logout = await auth.handleRequest(new Request('https://auth.example.com/auth/logout'));
    assert.match(logout.headers.getSetCookie()[0], /^__Secure-auth-session=;.*; Secure;/);
  });

  for (const origin of ['http://localhost:7676', 'http://127.0.0.1:7676']) {
    it(`${origin}: plain cookies that Safari keeps over http`, async () => {
      const auth = new OidcAuth({ ...base, callbackOrigin: origin }, deps);
      const cookie = await startCookie(auth, origin);
      assert.match(cookie, /^auth-tx=.*; HttpOnly; SameSite=Lax$/);
      assert.doesNotMatch(cookie, /Secure/);
      const logout = await auth.handleRequest(new Request(`${origin}/auth/logout`));
      assert.match(logout.headers.getSetCookie()[0], /^auth-session=;/);
    });
  }

  it('refuses any other http origin', () => {
    assert.throws(() => new OidcAuth({ ...base, callbackOrigin: 'http://auth.example.com' }, deps), /must be https/);
  });

  it('explicit cookie names still win', async () => {
    const auth = new OidcAuth({ ...base, callbackOrigin: 'http://localhost:7676', transactionCookieName: 'custom-tx' }, deps);
    assert.match(await startCookie(auth, 'http://localhost:7676'), /^custom-tx=/);
  });
});
