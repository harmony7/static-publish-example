// Types for fastly.js, for the TypeScript of the plugin. The config fields are
// documented in index.js.
export function createOidcAuth(config: Record<string, unknown>): {
  handleRequest(request: Request, options?: { protect?: boolean }): Promise<Response | null>,
};
