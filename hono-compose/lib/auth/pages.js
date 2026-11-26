// The module's own pages: self-contained HTML with inline styles and no
// scripts, so they render the same in front of any site. Every interpolated
// value goes through escapeHtml.

export function escapeHtml(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const STYLE = `
:root { --fg: #16181d; --bg: #ffffff; --muted: #5b6169; --border: #e6e8eb; --accent: hsl(210 45% 42%); color-scheme: light dark; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6e8eb; --bg: #12141a; --muted: #9298a3; --border: #2a2d35; --accent: hsl(210 70% 72%); }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 1rem;
  font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  color: var(--fg); background: var(--bg); }
main { width: 100%; max-width: 24rem; padding: 2rem 1.5rem; border: 1px solid var(--border); border-radius: 10px; text-align: center; }
h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
p { color: var(--muted); margin: 0 0 1.5rem; overflow-wrap: break-word; }
a.button { display: inline-block; padding: 0.6rem 1.2rem; border-radius: 6px; background: var(--accent); color: var(--bg); text-decoration: none; font-weight: 600; }
a.secondary { display: inline-block; margin-top: 1rem; color: var(--accent); font-size: 0.9rem; }
`;

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<main>
${body}
</main>
</body>
</html>`;
}

export function signInPage({ startUrl, providerName, message }) {
  return page(
    'Sign in',
    `<h1>Sign in to continue</h1>
<p>${escapeHtml(message ?? 'This page is only available to signed-in accounts.')}</p>
<a class="button" href="${escapeHtml(startUrl)}">Sign in with ${escapeHtml(providerName)}</a>`,
  );
}

export function deniedPage({ email, startUrl, providerName }) {
  return page(
    'Not allowed',
    `<h1>This account isn't allowed</h1>
<p>You're signed in as ${escapeHtml(email)}, which doesn't have access to this page.</p>
<a class="button" href="${escapeHtml(startUrl)}">Use another ${escapeHtml(providerName)} account</a>`,
  );
}

export function errorPage({ message, startUrl }) {
  return page(
    'Sign-in failed',
    `<h1>Sign-in didn't complete</h1>
<p>${escapeHtml(message)}</p>
<a class="button" href="${escapeHtml(startUrl)}">Try again</a>`,
  );
}
