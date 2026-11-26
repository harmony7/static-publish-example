# static-publish-example

Static pages behind a Google sign-in, on [Fastly Compute](https://www.fastly.com/products/edge-compute), with [`@fastly/compute-js-static-publish`](https://github.com/fastly/compute-js-static-publish) (Static Publisher).

- Each project is a folder of static files (HTML, CSS, JavaScript), for example a page that an AI tool made.
- Static Publisher puts the files in a Fastly KV Store, and generates a Compute app that serves them.
- Each project is a collection on its own subdomain: `quiz.apps.example.com`, `dashboard.apps.example.com`. The bare domain, `apps.example.com`, shows the list of projects.
- Visitors sign in with Google. One sign-in covers all the subdomains. Only the accounts that the allow rules accept can see the pages.

> To do: link to the blog post that builds this project step by step.

## Layout

```
static-publish-example/
├── static-publish.project.js   # The managed project: the only config file
├── public/                     # The default collection: the list of projects
├── projects/
│   ├── quiz/                   # The collection "quiz"
│   └── dashboard/              # The collection "dashboard"
├── hono-compose/               # The plugins of the app
│   ├── 10-oidc.ts              # The sign-in plugin
│   └── lib/auth/               # The sign-in code (OpenID Connect)
└── test/                       # Unit tests of lib/auth/
```

This is a **managed project**: the repository has no app code. Static Publisher generates a [Hono](https://hono.dev/) app from `static-publish.project.js` (the `hono` template), and composes it with the plugins in `hono-compose/`.

## How the sign-in works

`hono-compose/10-oidc.ts` is one middleware for every request. It runs before the published files:

```
The sign-in routes    GET /auth/login       The sign-in page
                      GET /auth/start       Go to Google
                      GET /auth/callback    Google sends the visitor back here
                      GET /auth/logout      Delete the session
All other requests    No valid session      → 302 to /auth/login (GET and HEAD), 401 (other methods)
                      Account not allowed   → 403
                      Otherwise             → the request continues, and the response
                                              gets 'Cache-Control: private'
                      The sign-in fails     → 503 (for example, a secret is missing)
```

- Every sign-in starts and ends on `callbackOrigin` (`apps.example.com`), so the Google OAuth client needs only one redirect URI. A visitor without a session on `quiz.apps.example.com` signs in on `apps.example.com`, and comes back to the quiz.
- The session cookie is set on `.apps.example.com` (`cookieDomain`), so the browser sends it to every subdomain. `/auth/logout` signs the visitor out of all of them.
- The sign-in check runs before Static Publisher looks for the collection. Thus a visitor who is not signed in gets the same redirect for every subdomain, and cannot find out which projects exist.
- The sign-in uses the authorization code flow, with PKCE, `state`, and `nonce`. The app checks the signature of the ID token (RS256, with the keys of Google), the issuer, the audience, the expiry time, and the nonce. It accepts only an email address that Google verified.
- The allow rules run on each request, not only at sign-in. Thus a change to the rules applies to sessions that already exist, after the next deploy.
- The session is a cookie signed with HMAC-SHA256. The app keeps no state on the server, and keeps no tokens from Google.

## Set up

You need Node.js, the [Fastly CLI](https://www.fastly.com/documentation/reference/tools/cli/), a Fastly account with an API token, a Google Cloud project, and a domain that you control.

1. **Install.**

   ```sh
   npm install
   (cd hono-compose && npm install)
   ```

2. **Make a Google OAuth client.** In the Google Cloud console, go to APIs & Services → Credentials → Create credentials → OAuth client ID, and choose the type "Web application". Add the redirect URI `https://apps.example.com/auth/callback`, with your domain. On the consent screen, choose **Internal** if the Cloud project and everyone who signs in are in one Google Workspace organization. Otherwise choose **External**, keep the status **Testing**, and add each person under **Test users**.

3. **Make a signing key**, and keep it for step 5:

   ```sh
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
   ```

4. **Change the values marked "Change this"** in `static-publish.project.js`: your domain, the client ID, and the allow rules.

5. **Deploy.** The first deploy creates the service, the KV Store, the backends, and the Secret Store `oidc`. It asks questions, so run it on your computer, not in CI:

   ```sh
   export FASTLY_API_TOKEN=<your token>
   npx compute-js-static-publish deploy
   ```

   - **Domain:** accept the `edgecompute.app` name. You add your own domain in step 6.
   - **The backends:** accept the defaults.
   - **`client_secret`:** the client secret of the Google OAuth client.
   - **`cookie_key_1`:** the signing key from step 3.

   The questions about the secrets can come in either order, so read the name of each one. The deploy writes the service ID into `static-publish.project.js`. Commit it.

6. **Add your domain**, its wildcard, and a TLS certificate for both:

   ```sh
   fastly domain create --fqdn=apps.example.com --service-id=<your service ID>
   fastly domain create --fqdn='*.apps.example.com' --service-id=<your service ID>
   fastly tls-subscription create --domain=apps.example.com --domain='*.apps.example.com' --cert-auth=certainly
   ```

   Then add these records to your DNS. The Fastly control panel shows the exact values for the TLS subscription:

   - `apps.example.com` and `*.apps.example.com`: a `CNAME` to Fastly, for example `s.sni.global.fastly.net`. A bare domain such as `example.com` cannot have a `CNAME`: give it `A` records to the Fastly IP addresses.
   - `_acme-challenge.apps.example.com`: a `CNAME` to a `fastly-validations.com` name. It lets Fastly prove that you control the domain, now and at each renewal. A certificate for a wildcard name always needs it.

   A few minutes after the records exist, the certificate is issued.

7. **Publish the projects.** The default collection is the list of projects. Each project is a collection, and its name is its subdomain. A name must be a DNS label: lowercase letters, digits, and `-`.

   ```sh
   npx compute-js-static-publish publish-content
   npx compute-js-static-publish publish-content --root-dir=./projects/quiz --collection-name=quiz
   npx compute-js-static-publish publish-content --root-dir=./projects/dashboard --collection-name=dashboard
   ```

Open `https://apps.example.com/`, and sign in.

## Day to day

- **A new version of a project:** save the files, and run `publish-content` for its collection again. Only the changed files are uploaded. No deploy is necessary.
- **A new project:** add a folder under `projects/`, and publish it with a new collection name. No deploy, no new Google client, no new sign-in.
- **A change to `static-publish.project.js`** (for example the allow rules), **to `hono-compose/`, or an upgrade of Static Publisher:** run `deploy`. If the app did not change, `deploy` does nothing.
- Do not give a project collection an expiration time (`--expires-in`). An expired collection stops being served.

## Options of the sign-in plugin

In `templateOptions.hono.compose.plugins.oidc`:

| Option | Default | |
| --- | --- | --- |
| `provider` | | Required. `'google'`. |
| `clientId` | | Required. The client ID of your Google OAuth client. It is not a secret. |
| `callbackOrigin` | | Required. The origin where every sign-in starts and ends. The redirect URI is `<callbackOrigin>/auth/callback`. It must be `https`, or `http` on `localhost` or `127.0.0.1` for local development. |
| `allowedReturnHosts` | | Required. The hosts that a visitor can go back to after the sign-in: a hostname, or `*.` and a domain for one level of subdomains. |
| `allow` | | Required. The accounts that can see the pages. See [Allow rules](#allow-rules). |
| `secretStore` | | Required. The resource link name of the Secret Store. |
| `backends` | `{}` | The names of the backends for the token endpoint (`token`) and the keys of Google (`jwks`). |
| `cookieDomain` | | The `Domain` of the session cookie. Without it, the cookie is for `callbackOrigin` only. It cannot be a public suffix such as `.edgecompute.app`. |
| `hostedDomainHint` | | A Google Workspace domain. Google shows the accounts of this domain first. Only a hint: the allow rules decide. |
| `clientSecretName` | `'client_secret'` | The key of the client secret in the Secret Store. |
| `cookieKeyNames` | `['cookie_key_1']` | The keys of the signing keys in the Secret Store. The first key signs new cookies. All keys can verify a cookie. |
| `sessionMaxAgeSeconds` | `604800` (7 days) | How long a session lasts. |
| `transactionMaxAgeSeconds` | `600` (10 minutes) | How long a visitor has to finish the sign-in at Google. |
| `pathPrefix` | `'/auth/'` | The prefix of the sign-in routes. |

### Allow rules

The first rule that matches allows the account. An account that matches no rule gets `403`. The comparison ignores case.

| Rule | Allows |
| --- | --- |
| `{ domain: 'example.com' }` | An email address in exactly this domain (not `sub.example.com`). |
| `{ domain: 'example.com', hostedDomain: true }` | The same, and the account is in the Google Workspace domain `example.com`. |
| `{ email: 'someone@example.com' }` | Exactly this email address. |
| `{ pattern: '*@*.example.org' }` | A pattern. In the part before `@`, `*` matches any characters except `@`. In the domain, `*` stays in one label. |

### Change the signing key

To change the signing key without signing out all visitors, add a new key in front: `cookieKeyNames: ['cookie_key_2', 'cookie_key_1']`, and add `cookie_key_2` to the Secret Store. New cookies use `cookie_key_2`, and the cookies that `cookie_key_1` signed stay valid until they expire. Then remove `cookie_key_1`. To sign out all visitors at once, replace the key.

## Local development

`managed.fastlyToml.local_server` adds resources for `fastly compute serve`. Add the backends and a local Secret Store that reads environment variables:

```js
managed: {
  // ...
  fastlyToml: {
    local_server: {
      backends: {
        oidc_token: { url: 'https://oauth2.googleapis.com', override_host: 'oauth2.googleapis.com' },
        oidc_jwks: { url: 'https://www.googleapis.com', override_host: 'www.googleapis.com' },
      },
      secret_stores: {
        oidc: [
          { key: 'client_secret', env: 'OIDC_CLIENT_SECRET' },
          { key: 'cookie_key_1', env: 'OIDC_COOKIE_KEY' },
        ],
      },
    },
    setup: { /* ... */ },
  },
},
```

For local development, set `callbackOrigin` to `http://localhost:7676`, add `localhost` to `allowedReturnHosts`, remove `cookieDomain`, and add `http://localhost:7676/auth/callback` as a redirect URI in Google. Then:

```sh
export OIDC_CLIENT_SECRET=…
export OIDC_COOKIE_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
npx compute-js-static-publish publish-content --local
npx compute-js-static-publish dev
```

## Tests

```sh
npm test
```

The unit tests of `hono-compose/lib/auth/` run in Node.js, without Fastly.
