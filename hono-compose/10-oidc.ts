// The sign-in plugin, with @hono/oidc-auth: a sign-in with Google (OpenID
// Connect) in front of the whole site. The 10- prefix puts this plugin before
// other plugins in each phase. Its config comes from
// templateOptions.hono.compose.plugins.oidc.
//
// All of it is in the middleware phase, which comes before the routes of all
// plugins and before the published files, in this order:
// 1. Read the secrets from the Secret Store, and configure @hono/oidc-auth for
//    this request.
// 2. GET /auth/logout: delete the session.
// 3. oidcAuthMiddleware(): answers the callback, and sends a visitor without
//    a session to Google.
// 4. The allow rules: a visitor whose account the rules do not accept gets
//    403.
// Then the request continues. @hono/oidc-auth sets
// 'Cache-Control: private, no-cache' on the response.
import { definePlugin } from '@fastly/compute-js-static-publish/hono';
import { getAuth, initOidcAuthMiddleware, oidcAuthMiddleware, revokeSession } from '@hono/oidc-auth';
import { SecretStore } from 'fastly:secret-store';
import { compileAllowRules } from './lib/auth/allow-rules.js';

type OidcPluginOptions = {
  issuer?: string,
  clientId: string,
  callbackOrigin: string,
  cookieDomain?: string,
  allow: unknown[],
  secretStore: string,
  clientSecretName?: string,
  sessionKeyName?: string,
  sessionMaxAgeSeconds?: number,
};

const CALLBACK_PATH = '/auth/callback';
const LOGOUT_PATH = '/auth/logout';

function textResponse(body: string, status: number) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'private, no-store',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  });
}

export default definePlugin((app, options?: OidcPluginOptions) => {
  if (options == null) {
    throw new Error('oidc: templateOptions.hono.compose.plugins.oidc is required');
  }
  const isAllowed = compileAllowRules(options.allow);
  const sessionMaxAge = String(options.sessionMaxAgeSeconds ?? 7 * 24 * 60 * 60);

  // The Secret Store can be read only while the app handles a request. The
  // values are kept after the first read.
  let secrets: Promise<{ clientSecret: string, sessionKey: string }> | null = null;
  async function loadSecrets() {
    const store = new SecretStore(options!.secretStore);
    const clientSecret = (await store.get(options!.clientSecretName ?? 'client_secret'))?.plaintext();
    const sessionKey = (await store.get(options!.sessionKeyName ?? 'cookie_key_1'))?.plaintext();
    if (clientSecret == null || sessionKey == null) {
      throw new Error('oidc: a secret is missing from the Secret Store');
    }
    return { clientSecret, sessionKey: sessionKey.trim() };
  }

  // 1. Configure @hono/oidc-auth for this request.
  app.use('*', async (c, next) => {
    let loaded;
    try {
      secrets ??= loadSecrets();
      loaded = await secrets;
    } catch (err) {
      secrets = null;
      console.error(String(err));
      return textResponse('Sign-in is unavailable right now.\n', 503);
    }
    // Keep the claims that the allow rules need. The default keeps only sub
    // and email.
    c.set('oidcClaimsHook', async (orig?: Record<string, any>, claims?: Record<string, any>) => ({
      sub: (claims?.sub ?? orig?.sub ?? '') as string,
      email: (claims?.email ?? orig?.email ?? '') as string,
      email_verified: claims?.email_verified ?? orig?.email_verified ?? false,
      hd: claims?.hd ?? orig?.hd ?? null,
    }));
    return initOidcAuthMiddleware({
      OIDC_ISSUER: options.issuer ?? 'https://accounts.google.com',
      OIDC_CLIENT_ID: options.clientId,
      OIDC_CLIENT_SECRET: loaded.clientSecret,
      OIDC_AUTH_SECRET: loaded.sessionKey,
      OIDC_REDIRECT_URI: `${options.callbackOrigin}${CALLBACK_PATH}`,
      OIDC_COOKIE_DOMAIN: options.cookieDomain,
      OIDC_SCOPES: 'openid email',
      // Without a refresh token, the session ends at the refresh interval.
      // Make the interval as long as the session.
      OIDC_AUTH_REFRESH_INTERVAL: sessionMaxAge,
      OIDC_AUTH_EXPIRES: sessionMaxAge,
    })(c, next);
  });

  // 2. Delete the session. This does not need a session.
  app.get(LOGOUT_PATH, async (c) => {
    await revokeSession(c);
    return textResponse('You are signed out.\n', 200);
  });

  // 3. The callback, and a redirect to Google for a visitor without a session.
  app.use('*', oidcAuthMiddleware());

  // 4. The allow rules.
  app.use('*', async (c, next) => {
    const auth = await getAuth(c);
    const verified = auth?.email_verified === true || auth?.email_verified === 'true';
    if (auth == null || !verified || !isAllowed({ email: auth.email, hd: auth.hd })) {
      return textResponse(`${auth?.email ?? 'This account'} cannot see this site.\n`, 403);
    }
    await next();
  });
});
