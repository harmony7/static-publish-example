// Compiles the configured allow rules into a function from an identity
// ({ email, hd }) to a boolean. The first matching rule allows; an identity
// that matches no rule is denied, and so is one with no email.
//
// Rule shapes:
//   { domain: 'example.com' }                     the email's domain is exactly this
//   { domain: 'example.com', hostedDomain: true } and the Workspace hd claim is too
//   { email: 'someone@example.com' }               exactly this address
//   { pattern: '*@*.example.org' }                 wildcards: in the local part, *
//                                                  matches anything but @; in the
//                                                  domain, it stays within one label
//
// Everything compares case-insensitively.
export function compileAllowRules(rules) {
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new Error('allow rules: expected a non-empty array');
  }
  const matchers = rules.map(compileRule);
  return (identity) => {
    const email = normalizeEmail(identity?.email);
    if (email == null) {
      return false;
    }
    const hd = typeof identity.hd === 'string' ? identity.hd.toLowerCase() : null;
    return matchers.some((matches) => matches(email, hd));
  };
}

function compileRule(rule) {
  if (rule == null || typeof rule !== 'object') {
    throw new Error(`allow rules: unrecognized rule ${JSON.stringify(rule)}`);
  }
  const keys = Object.keys(rule);
  if ('domain' in rule && keys.every((k) => k === 'domain' || k === 'hostedDomain')) {
    const domain = requireString(rule.domain, 'domain').toLowerCase();
    const needsHostedDomain = rule.hostedDomain === true;
    return (email, hd) =>
      domainOf(email) === domain && (!needsHostedDomain || hd === domain);
  }
  if ('email' in rule && keys.length === 1) {
    const expected = normalizeEmail(requireString(rule.email, 'email'));
    if (expected == null) {
      throw new Error(`allow rules: not an email address: ${rule.email}`);
    }
    return (email) => email === expected;
  }
  if ('pattern' in rule && keys.length === 1) {
    const regex = patternToRegex(requireString(rule.pattern, 'pattern'));
    return (email) => regex.test(email);
  }
  throw new Error(`allow rules: unrecognized rule ${JSON.stringify(rule)}`);
}

function patternToRegex(pattern) {
  const lower = pattern.toLowerCase();
  const at = lower.indexOf('@');
  if (at <= 0 || at !== lower.lastIndexOf('@') || at === lower.length - 1) {
    throw new Error(`allow rules: pattern needs exactly one @ with text on both sides: ${pattern}`);
  }
  const local = lower.slice(0, at).split('*').map(escapeRegex).join('[^@]*');
  const domain = lower.slice(at + 1).split('*').map(escapeRegex).join('[^@.]*');
  return new RegExp(`^${local}@${domain}$`);
}

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function requireString(value, name) {
  if (typeof value !== 'string' || value === '') {
    throw new Error(`allow rules: ${name} must be a non-empty string`);
  }
  return value;
}

// Exactly one @, with something on both sides. Anything else isn't an
// address this module will compare, so it can never match a rule.
function normalizeEmail(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const email = value.toLowerCase();
  const at = email.indexOf('@');
  if (at <= 0 || at !== email.lastIndexOf('@') || at === email.length - 1) {
    return null;
  }
  return email;
}

function domainOf(email) {
  return email.slice(email.indexOf('@') + 1);
}
