// The sign-in plugin: a sign-in with Google (OpenID Connect) in front of the
// whole site. The 10- prefix puts this plugin before other plugins in each
// phase. The sign-in code is in lib/auth/, and its config comes from
// templateOptions.hono.compose.plugins.oidc.
//
// All of it is in the middleware phase, which comes before the routes of all
// plugins and before the published files:
// - The routes under /auth/ (login, start, callback, logout) are answered here.
// - Every other request needs a session that the allow rules accept. Without
//   a session, the visitor goes to the sign-in page. With a session that the
//   rules do not accept, the visitor gets 403.
// - The responses that pass get 'Cache-Control: private', so that a shared
//   cache does not keep them and give them to other visitors.
// - If the sign-in cannot run, for example because a secret is missing, the
//   request gets 503. The site is never served without a sign-in.
import { definePlugin } from '@fastly/compute-js-static-publish/hono';
import { createOidcAuth } from './lib/auth/fastly.js';

function signInUnavailableResponse() {
  return new Response('Sign-in is unavailable right now.\n', {
    status: 503,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'private, no-store',
      'X-Robots-Tag': 'noindex, nofollow',
    },
  });
}

export default definePlugin((app, options?: Parameters<typeof createOidcAuth>[0]) => {
  if (options == null) {
    throw new Error('oidc: templateOptions.hono.compose.plugins.oidc is required');
  }
  const auth = createOidcAuth(options);

  app.use('*', async (c, next) => {
    let authResponse;
    try {
      authResponse = await auth.handleRequest(c.req.raw, { protect: true });
    } catch (err) {
      console.error('oidc:', String(err));
      return signInUnavailableResponse();
    }
    if (authResponse != null) {
      return authResponse;
    }
    await next();
    c.header('Cache-Control', 'private');
  });
});
