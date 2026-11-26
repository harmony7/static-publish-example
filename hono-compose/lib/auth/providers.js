// Provider presets: the values a provider's discovery document
// (/.well-known/openid-configuration) gives, baked in so the app doesn't
// fetch discovery at runtime and needs a backend only for the token and
// JWKS hosts. The browser goes to the authorization endpoint itself.
export const PROVIDERS = {
  // From https://accounts.google.com/.well-known/openid-configuration,
  // read 2026-11-03.
  google: {
    name: 'Google',
    issuer: 'https://accounts.google.com',
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
    jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
    // Google-specific: preselects an account in this Workspace domain. A
    // hint for the account chooser only; the allow rules decide access.
    hostedDomainParam: 'hd',
  },
};
