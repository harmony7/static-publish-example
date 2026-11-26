# @hono/oidc-auth on Fastly Compute: findings

This branch replaces the sign-in code in `hono-compose/lib/auth/` with [`@hono/oidc-auth`](https://github.com/honojs/middleware/tree/main/packages/oidc-auth) 1.10.0 (which uses `oauth4webapi` 3.x), and keeps the allow rules. It was tested on 2026-11-27 with `@fastly/compute-js-static-publish` 8.1.0-beta.9, on a test service with a custom domain and subdomains.

**Result: the sign-in does not work on Compute.** The callback returns `500 Internal Server Error`. `main` keeps its own sign-in code.

## What works

- The redirect to Google, with an absolute `OIDC_REDIRECT_URI` (one callback host) and `OIDC_COOKIE_DOMAIN` (the `state`, `nonce`, `code_verifier`, and `continue` cookies on the parent domain).
- The discovery request to `accounts.google.com`, with `fetch()` and dynamic backends.
- `fetch()` with a `URLSearchParams` body, and with `redirect: 'manual'` (tested in Viceroy and in production).

## What fails

1. **`Response.clone()` does not exist on Compute** (`TypeError: res.clone is not a function`). `oauth4webapi` reads the body of an error response with `response.clone().json()`, and ignores the error. Thus every error from the token endpoint becomes `OperationProcessingError: "response" is not a conform Token Endpoint response (unexpected HTTP status code)`, without the error of the provider. `@hono/oidc-auth` does not catch that error type, so Hono returns a plain `500`.
2. **The token request gets `401 invalid_client` ("The OAuth client was not found.")** through `oauth4webapi`. The same request made by hand on the same service, with the same client ID and secret, gets past the client authentication with both `client_secret_basic` and `client_secret_post` (Google then answers `invalid_grant` for a fake code). The cause is not known yet.

## Other differences from `main`

- No allow rules: `getAuth(c)` gives `{ sub, email }`. This branch adds the allow rules, and keeps `email_verified` and `hd` with `oidcClaimsHook`.
- For Google, the library always sends `access_type=offline` and `prompt=consent`. Visitors see the consent screen at each sign-in.
- The session is a signed JWT (HS256) that contains the refresh token. It is not encrypted.
- Without a refresh token, the session ends at `OIDC_AUTH_REFRESH_INTERVAL` (default 15 minutes). This branch sets it to the session length.
- A discovery request at each sign-in: the metadata is cached for one request only.
- No sign-in page and no 403 page.
