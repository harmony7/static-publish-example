// Decides where a visitor goes after signing in. Only URLs on the
// configured hosts are accepted, so the login flow can't be used to send
// someone to another site. Anything else falls back to `fallback`.
//
// Host patterns are either exact ('example.com') or one wildcard label at
// the front ('*.example.com', which matches a.example.com but not
// example.com or a.b.example.com). The scheme must be https, except on
// localhost, for local testing.
export function compileReturnUrlCheck(hostPatterns) {
  const matchers = hostPatterns.map((pattern) => {
    const lower = pattern.toLowerCase();
    if (lower.startsWith('*.')) {
      const suffix = lower.slice(1);
      return (host) => host.endsWith(suffix) && !host.slice(0, -suffix.length).includes('.') && host.length > suffix.length;
    }
    if (lower.includes('*')) {
      throw new Error(`return hosts: only a leading "*." wildcard is supported: ${pattern}`);
    }
    return (host) => host === lower;
  });

  return (candidate, fallback) => {
    let url;
    try {
      url = new URL(candidate);
    } catch {
      return fallback;
    }
    const isLocal = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !(isLocal && url.protocol === 'http:')) {
      return fallback;
    }
    if (url.username !== '' || url.password !== '') {
      return fallback;
    }
    const host = url.hostname.toLowerCase();
    return matchers.some((matches) => matches(host)) ? url.toString() : fallback;
  };
}
