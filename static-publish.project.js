/*
 * The project file of a managed @fastly/compute-js-static-publish project.
 * The CLI generates the Compute app from this file, in .static-publish/app.
 * Paths in this file are relative to this file.
 *
 * Replace the values marked "Change this" before the first deploy. See
 * README.md.
 */

/** @type {import('@fastly/compute-js-static-publish').StaticPublishProject} */
const project = {
  // Read by the app at runtime:
  storageMode: "kv-store",
  kvStore: {
    kvStoreName: "static-publish-example-content",
  },
  publishId: "default",
  defaultCollectionName: "live",
  staticPublisherWorkingDir: "./static-publisher",

  // Each project is a collection on its own subdomain:
  // quiz.apps.example.com serves the collection "quiz". The bare domain
  // matches no pattern, so it serves the default collection.
  collectionSelection: {
    sources: [
      { type: 'host', pattern: '{collection}.apps.example.com' }, // Change this
    ],
  },

  // The options of the plugins in hono-compose/, by plugin name.
  templateOptions: {
    hono: {
      compose: {
        plugins: {
          oidc: {
            provider: 'google',
            clientId: 'YOUR-CLIENT-ID.apps.googleusercontent.com', // Change this
            // Every sign-in starts and ends here. Google must have the
            // redirect URI <callbackOrigin>/auth/callback.
            callbackOrigin: 'https://apps.example.com', // Change this
            // The session cookie is for this domain and all its subdomains.
            cookieDomain: '.apps.example.com', // Change this
            // The hosts that a visitor can go back to after the sign-in.
            allowedReturnHosts: [ 'apps.example.com', '*.apps.example.com' ], // Change this
            // Who can see the pages.
            allow: [ { domain: 'example.com' } ], // Change this
            secretStore: 'oidc',
            backends: { token: 'oidc_token', jwks: 'oidc_jwks' },
          },
        },
      },
    },
  },

  // Read by publish-content:
  publishContent: {
    rootDir: "./public",
    server: {
      staticItems: [],
      allowedEncodings: [ 'br', 'gzip' ],
      spaFile: false,
      notFoundPageFile: false,
      autoExt: [".html", ".htm"],
      autoIndex: ["index.html", "index.htm"],
    },
  },

  // Read by the generator only:
  managed: {
    name: "static-publish-example",
    description: "Static pages behind a Google sign-in",
    authors: [""],
    template: "hono",
    // The first deploy creates the service and writes its ID here.
    serviceId: undefined,
    staticPublishVersion: "8.1.1",
    fastlyToml: {
      // The first deploy creates these resources, and asks for the values of
      // the secrets.
      setup: {
        backends: {
          oidc_token: { address: 'oauth2.googleapis.com', port: 443, description: 'Google token endpoint' },
          oidc_jwks: { address: 'www.googleapis.com', port: 443, description: 'Google signing keys' },
        },
        secret_stores: {
          oidc: {
            entries: {
              client_secret: { description: 'The client secret of the Google OAuth client' },
              cookie_key_1: { description: 'The signing key: 32 random bytes, base64url' },
            },
          },
        },
      },
    },
  },
};

export default project;
