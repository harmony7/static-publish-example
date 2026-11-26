import { compileAllowRules } from './allow-rules.js';
import { decodeToBytes, encodeBytes, randomToken } from './base64url.js';
import { IdTokenError, validateIdToken } from './id-token.js';
import { deniedPage, errorPage, signInPage } from './pages.js';
import { PROVIDERS } from './providers.js';
import { compileReturnUrlCheck } from './return-url.js';
import { SignedValues } from './signed-value.js';

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1']);

const DEFAULTS = {
  pathPrefix: '/auth/',
  clientSecretName: 'client_secret',
  cookieKeyNames: ['cookie_key_1'],
  sessionMaxAgeSeconds: 7 * 24 * 60 * 60,
  transactionMaxAgeSeconds: 10 * 60,
  backends: {},
};

// Sign-in with an OpenID Connect provider, in front of whatever the caller
// serves. handleRequest() returns a Response when this module handles the
// request (its own routes, or a protected request without an allowed
// session) and null when the caller should serve it as usual.
//
// Nothing here knows about Fastly: secrets come from `deps.getSecret` and
// HTTP from `deps.fetch`, so the module runs under Node for tests. See
// fastly.js for the Compute wiring.
export class OidcAuth {
  constructor(config, { getSecret, fetch = globalThis.fetch, now = () => Math.floor(Date.now() / 1000) }) {
    const provider = typeof config.provider === 'string' ? PROVIDERS[config.provider] : config.provider;
    if (provider == null) {
      throw new Error(`auth: unknown provider ${JSON.stringify(config.provider)}`);
    }
    for (const field of ['clientId', 'callbackOrigin', 'allowedReturnHosts', 'allow']) {
      if (config[field] == null) {
        throw new Error(`auth: missing ${field}`);
      }
    }
    this.config = { ...DEFAULTS, ...config, backends: { ...DEFAULTS.backends, ...config.backends } };
    this.provider = provider;
    const callbackUrl = new URL(config.callbackOrigin);
    this.callbackOrigin = callbackUrl.origin;
    // Browsers keep a Secure cookie, or one named __Secure- or __Host-, only
    // when it's set over https. So a plain-http callback origin, allowed
    // only on localhost for local testing, gets plain cookies. Any other
    // http origin is refused, so a deployed config can't lose Secure.
    this.secureCookies = callbackUrl.protocol === 'https:';
    if (!this.secureCookies && !(callbackUrl.protocol === 'http:' && LOCAL_HOSTNAMES.has(callbackUrl.hostname))) {
      throw new Error(`auth: callbackOrigin must be https, or http on localhost: ${config.callbackOrigin}`);
    }
    this.config.sessionCookieName ??= this.secureCookies ? '__Secure-auth-session' : 'auth-session';
    this.config.transactionCookieName ??= this.secureCookies ? '__Host-auth-tx' : 'auth-tx';
    this.redirectUri = `${this.callbackOrigin}${this.config.pathPrefix}callback`;
    this.isAllowed = compileAllowRules(config.allow);
    this.checkReturnUrl = compileReturnUrlCheck(config.allowedReturnHosts);
    this.getSecret = getSecret;
    this.fetch = fetch;
    this.now = now;
    this.secrets = null;
    this.jwks = null;
  }

  async handleRequest(request, { protect = false } = {}) {
    const url = new URL(request.url);
    const { pathPrefix } = this.config;
    if (url.pathname.startsWith(pathPrefix)) {
      const route = url.pathname.slice(pathPrefix.length);
      const handler = {
        login: () => this.handleLogin(url),
        start: () => this.handleStart(url),
        callback: () => this.handleCallback(request, url),
        logout: () => this.handleLogout(),
      }[route];
      if (handler != null) {
        if (request.method !== 'GET' && request.method !== 'HEAD') {
          return new Response('Method not allowed', { status: 405, headers: { allow: 'GET, HEAD' } });
        }
        return handler();
      }
    }

    if (!protect) {
      return null;
    }
    const session = await this.getSession(request);
    if (session != null) {
      if (this.isAllowed(session)) {
        return null;
      }
      return htmlResponse(
        deniedPage({ email: session.email, startUrl: this.startUrl(request.url), providerName: this.provider.name }),
        403,
      );
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return htmlResponse(
        signInPage({ startUrl: this.startUrl(request.url), providerName: this.provider.name }),
        401,
      );
    }
    return redirectResponse(this.loginUrl(request.url));
  }

  // The verified session payload ({ email, sub, hd, iat, exp }), or null.
  // Doesn't apply the allow rules; handleRequest does that on every
  // request, so removing a rule takes effect at once.
  async getSession(request) {
    const value = readCookie(request, this.config.sessionCookieName);
    if (value == null) {
      return null;
    }
    const { signer } = await this.loadSecrets();
    return signer.verify(value, this.now());
  }

  loginUrl(returnUrl) {
    return `${this.callbackOrigin}${this.config.pathPrefix}login?return=${encodeURIComponent(returnUrl)}`;
  }

  startUrl(returnUrl) {
    return `${this.callbackOrigin}${this.config.pathPrefix}start?return=${encodeURIComponent(returnUrl)}`;
  }

  async handleLogin(url) {
    // Sign-in always starts on the callback origin, because the login
    // transaction cookie is host-only and the callback has to see it.
    if (url.origin !== this.callbackOrigin) {
      return redirectResponse(`${this.callbackOrigin}${url.pathname}${url.search}`);
    }
    const returnUrl = this.checkReturnUrl(url.searchParams.get('return'), `${this.callbackOrigin}/`);
    return htmlResponse(signInPage({ startUrl: this.startUrl(returnUrl), providerName: this.provider.name }), 200);
  }

  async handleStart(url) {
    if (url.origin !== this.callbackOrigin) {
      return redirectResponse(`${this.callbackOrigin}${url.pathname}${url.search}`);
    }
    const returnUrl = this.checkReturnUrl(url.searchParams.get('return'), `${this.callbackOrigin}/`);
    const { signer } = await this.loadSecrets();

    const state = randomToken();
    const nonce = randomToken();
    const verifier = randomToken();
    const challenge = encodeBytes(
      new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))),
    );
    const transaction = await signer.sign({
      state,
      nonce,
      verifier,
      returnUrl,
      exp: this.now() + this.config.transactionMaxAgeSeconds,
    });

    const authorizationUrl = new URL(this.provider.authorizationEndpoint);
    const params = {
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.redirectUri,
      scope: 'openid email',
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      prompt: 'select_account',
    };
    if (this.config.hostedDomainHint != null && this.provider.hostedDomainParam != null) {
      params[this.provider.hostedDomainParam] = this.config.hostedDomainHint;
    }
    for (const [name, value] of Object.entries(params)) {
      authorizationUrl.searchParams.set(name, value);
    }

    const response = redirectResponse(authorizationUrl.toString());
    response.headers.append(
      'set-cookie',
      this.serializeCookie(this.config.transactionCookieName, transaction, {
        maxAge: this.config.transactionMaxAgeSeconds,
      }),
    );
    return response;
  }

  async handleCallback(request, url) {
    const fallbackStart = this.startUrl(`${this.callbackOrigin}/`);
    const fail = (message, status = 400) => {
      const response = htmlResponse(errorPage({ message, startUrl: fallbackStart }), status);
      response.headers.append('set-cookie', this.clearCookie(this.config.transactionCookieName));
      return response;
    };

    if (url.origin !== this.callbackOrigin) {
      return fail('Sign-in has to finish on the site it started from.');
    }
    const { signer, clientSecret } = await this.loadSecrets();
    const transaction = await signer.verify(readCookie(request, this.config.transactionCookieName), this.now());
    if (transaction == null) {
      return fail('The sign-in took too long or was started in another browser. Please try again.');
    }
    const startAgain = this.startUrl(transaction.returnUrl);

    const providerError = url.searchParams.get('error');
    if (providerError != null) {
      return fail(`${this.provider.name} didn't complete the sign-in (${providerError}).`);
    }
    if (url.searchParams.get('state') !== transaction.state) {
      return fail('The sign-in response didn\'t match this browser. Please try again.');
    }
    const code = url.searchParams.get('code');
    if (code == null) {
      return fail('The sign-in response was missing its code.');
    }

    let tokenResponse;
    try {
      tokenResponse = await this.fetch(this.provider.tokenEndpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: this.redirectUri,
          client_id: this.config.clientId,
          client_secret: clientSecret,
          code_verifier: transaction.verifier,
        }).toString(),
        backend: this.config.backends.token,
      });
    } catch {
      return fail(`Couldn't reach ${this.provider.name} to finish signing in.`, 502);
    }
    if (!tokenResponse.ok) {
      return fail(`${this.provider.name} rejected the sign-in (HTTP ${tokenResponse.status}).`, 502);
    }
    let claims;
    try {
      const { id_token: idToken } = await tokenResponse.json();
      claims = await validateIdToken(idToken, {
        issuer: this.provider.issuer,
        clientId: this.config.clientId,
        nonce: transaction.nonce,
        getJwk: (kid, options) => this.getJwk(kid, options),
        nowSeconds: this.now(),
      });
    } catch (err) {
      const detail = err instanceof IdTokenError ? err.message : 'unreadable response';
      return fail(`The sign-in couldn't be verified (${detail}).`, 502);
    }

    const identity = {
      email: String(claims.email ?? '').toLowerCase(),
      sub: claims.sub,
      hd: typeof claims.hd === 'string' ? claims.hd.toLowerCase() : null,
    };
    if (!this.isAllowed(identity)) {
      const response = htmlResponse(
        deniedPage({ email: identity.email, startUrl: startAgain, providerName: this.provider.name }),
        403,
      );
      response.headers.append('set-cookie', this.clearCookie(this.config.transactionCookieName));
      return response;
    }

    const now = this.now();
    const session = await signer.sign({ ...identity, iat: now, exp: now + this.config.sessionMaxAgeSeconds });
    const response = redirectResponse(transaction.returnUrl);
    response.headers.append(
      'set-cookie',
      this.serializeCookie(this.config.sessionCookieName, session, {
        maxAge: this.config.sessionMaxAgeSeconds,
        domain: this.config.cookieDomain,
      }),
    );
    response.headers.append('set-cookie', this.clearCookie(this.config.transactionCookieName));
    return response;
  }

  handleLogout() {
    const response = htmlResponse(
      signInPage({
        startUrl: this.startUrl(`${this.callbackOrigin}/`),
        providerName: this.provider.name,
        message: 'You\'re signed out.',
      }),
      200,
    );
    response.headers.append(
      'set-cookie',
      this.clearCookie(this.config.sessionCookieName, { domain: this.config.cookieDomain }),
    );
    return response;
  }

  async loadSecrets() {
    this.secrets ??= (async () => {
      const clientSecret = await this.getSecret(this.config.clientSecretName);
      if (clientSecret == null) {
        throw new Error(`auth: secret ${this.config.clientSecretName} not found`);
      }
      const keys = [];
      for (const name of this.config.cookieKeyNames) {
        const value = await this.getSecret(name);
        if (value == null) {
          throw new Error(`auth: secret ${name} not found`);
        }
        keys.push({ id: name, secret: decodeToBytes(value.trim()) });
      }
      return { clientSecret, signer: new SignedValues(keys) };
    })();
    try {
      return await this.secrets;
    } catch (err) {
      this.secrets = null;
      throw err;
    }
  }

  async getJwk(kid, { refresh }) {
    if (this.jwks == null || refresh) {
      const response = await this.fetch(this.provider.jwksUri, {
        headers: { accept: 'application/json' },
        backend: this.config.backends.jwks,
      });
      if (!response.ok) {
        return null;
      }
      const { keys } = await response.json();
      this.jwks = Array.isArray(keys) ? keys : [];
    }
    return this.jwks.find((key) => key.kid === kid) ?? null;
  }

  serializeCookie(name, value, { maxAge, domain }) {
    let cookie = `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly`;
    if (this.secureCookies) {
      cookie += '; Secure';
    }
    cookie += '; SameSite=Lax';
    if (domain != null) {
      cookie += `; Domain=${domain}`;
    }
    return cookie;
  }

  clearCookie(name, { domain } = {}) {
    return this.serializeCookie(name, '', { maxAge: 0, domain });
  }
}

function htmlResponse(body, status) {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'private, no-store',
      'x-robots-tag': 'noindex, nofollow',
    },
  });
}

function redirectResponse(location) {
  return new Response(null, {
    status: 302,
    headers: { location, 'cache-control': 'private, no-store' },
  });
}

function readCookie(request, name) {
  const header = request.headers.get('cookie');
  if (header == null) {
    return null;
  }
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq !== -1 && part.slice(0, eq).trim() === name) {
      return part.slice(eq + 1).trim();
    }
  }
  return null;
}
