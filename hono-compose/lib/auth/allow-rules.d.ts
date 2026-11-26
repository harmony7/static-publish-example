// Types for allow-rules.js, for the TypeScript of the plugin. The rule shapes
// are documented in allow-rules.js.
export function compileAllowRules(rules: unknown[]): (identity: { email?: unknown, hd?: unknown }) => boolean;
