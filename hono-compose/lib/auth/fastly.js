import { SecretStore } from 'fastly:secret-store';
import { OidcAuth } from './index.js';

// OidcAuth wired to Fastly Compute: secrets from the Secret Store linked to
// the service as `config.secretStore`. The store is opened on first use,
// not at import, since Compute can't open one during build-time
// initialization.
export function createOidcAuth(config) {
  let store = null;
  return new OidcAuth(config, {
    getSecret: async (name) => {
      store ??= new SecretStore(config.secretStore);
      const entry = await store.get(name);
      return entry?.plaintext() ?? null;
    },
  });
}

export { OidcAuth };
