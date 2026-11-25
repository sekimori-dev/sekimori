import { randomBytes } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { auth, UnauthorizedError } from "@modelcontextprotocol/sdk/client/auth.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport, StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { RemoteUpstreamConfig, StdioUpstreamConfig } from "./config.ts";
import { createOAuthProvider, type CredentialStore } from "./credentials.ts";

export type JsonSchema = {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: unknown[];
  description?: string;
};

export interface Tool {
  name: string;
  description?: string;
  inputSchema: JsonSchema;
  outputSchema?: JsonSchema;
}

export interface Upstream {
  name: string;
  tools: Tool[];
  call(tool: string, args: unknown): Promise<unknown>;
}

async function wrapClient(name: string, client: Client): Promise<Upstream> {
  const { tools } = await client.listTools();
  return {
    name,
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema as JsonSchema,
      outputSchema: t.outputSchema as JsonSchema | undefined,
    })),
    async call(tool, args) {
      const result = await client.callTool({ name: tool, arguments: (args ?? {}) as Record<string, unknown> });
      const text = Array.isArray(result.content)
        ? result.content.flatMap((c) => (c.type === "text" ? [c.text] : [])).join("\n")
        : "";
      if (result.isError) throw new Error(text || `${name}.${tool} failed`);
      return result.structuredContent ?? text;
    },
  };
}

export async function connectUpstream(config: StdioUpstreamConfig): Promise<Upstream & { close(): Promise<void> }> {
  const client = new Client({ name: "sekimori-gateway", version: "0.0.0" });
  await client.connect(
    new StdioClientTransport({
      command: config.command,
      args: config.args,
      env: { ...(process.env as Record<string, string>), ...config.env },
      stderr: "inherit",
    }),
  );
  return { ...(await wrapClient(config.name, client)), close: () => client.close() };
}

export type RemoteState = "connected" | "needs_connect" | "connecting" | "unavailable";

export interface RemoteStatus {
  name: string;
  host: string;
  state: RemoteState;
  reason?: string;
  upstream?: Upstream;
}

export type RemoteEvent =
  | { type: "upstream_connected"; upstream: string; tools: number }
  | { type: "upstream_needs_connect"; upstream: string; reason: string }
  | { type: "upstream_unavailable"; upstream: string; reason: string }
  | { type: "upstream_disconnected"; upstream: string }
  | { type: "connect_requested"; upstream: string; by: "program" | "page" };

export type Remotes = ReturnType<typeof createRemotes>;

// A 401 right after a successful refresh surfaces as StreamableHTTPError, not UnauthorizedError.
const isAuthError = (error: unknown) =>
  error instanceof UnauthorizedError || (error instanceof StreamableHTTPError && error.code === 401);

const STATE_TTL_MS = 10 * 60_000;
const REOPEN_AFTER_MS = 60_000;

// Lifecycle of remote upstreams; see docs/superpowers/specs/2026-11-25-slice-3-oauth-design.md section 5.
export function createRemotes(
  configs: RemoteUpstreamConfig[],
  options: {
    store: CredentialStore;
    redirectUris: string[];
    redirectUrl: () => string;
    // Returns the token-free link to the Connect page; with open, also opens it for the human.
    connectPage: (open: boolean) => string;
    connectTimeoutMs: number;
    audit: (event: RemoteEvent) => void;
  },
) {
  type Entry = { config: RemoteUpstreamConfig; status: RemoteStatus; client?: Client; openedAt?: number };
  const entries = new Map<string, Entry>(
    configs.map((config) => [config.name, { config, status: { name: config.name, host: new URL(config.url).host, state: "needs_connect" } }]),
  );
  const attempts = new Map<string, { name: string; provider: ReturnType<typeof createOAuthProvider>; expiresAt: number }>();
  const waiters = new Set<() => void>();

  const providerFor = (config: RemoteUpstreamConfig, state?: string) =>
    createOAuthProvider({
      store: options.store,
      upstream: config.name,
      redirectUrl: options.redirectUrl(),
      redirectUris: options.redirectUris,
      preregistered: config.oauth,
      state,
    });

  function settle(entry: Entry, status: Omit<RemoteStatus, "name" | "host">) {
    entry.status = { name: entry.config.name, host: entry.status.host, ...status };
    if (status.state === "needs_connect") options.audit({ type: "upstream_needs_connect", upstream: entry.config.name, reason: status.reason! });
    if (status.state === "unavailable") options.audit({ type: "upstream_unavailable", upstream: entry.config.name, reason: status.reason! });
    for (const wake of waiters) wake();
  }

  async function connect(entry: Entry): Promise<void> {
    const client = new Client({ name: "sekimori-gateway", version: "0.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(entry.config.url), { authProvider: providerFor(entry.config) });
    let timer: NodeJS.Timeout | undefined;
    try {
      const upstream = await Promise.race([
        client.connect(transport).then(() => wrapClient(entry.config.name, client)),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`no answer within ${options.connectTimeoutMs} ms`)), options.connectTimeoutMs);
        }),
      ]);
      entry.client = client;
      settle(entry, {
        state: "connected",
        upstream: {
          ...upstream,
          async call(tool, args) {
            try {
              return await upstream.call(tool, args);
            } catch (error) {
              if (isAuthError(error) && entry.client === client) {
                entry.client = undefined;
                void client.close();
                options.audit({ type: "upstream_disconnected", upstream: entry.config.name });
                settle(entry, { state: "needs_connect", reason: "authorization expired or was revoked" });
              }
              throw error;
            }
          },
        },
      });
      options.audit({ type: "upstream_connected", upstream: entry.config.name, tools: upstream.tools.length });
    } catch (error) {
      void client.close();
      settle(entry, isAuthError(error) ? { state: "needs_connect", reason: "not connected" } : { state: "unavailable", reason: (error as Error).message });
    } finally {
      clearTimeout(timer);
    }
  }

  const entryOf = (name: string) => {
    const entry = entries.get(name);
    if (!entry) throw new Error(`Unknown remote upstream ${name}`);
    return entry;
  };

  return {
    names: () => [...entries.keys()],

    list: (): RemoteStatus[] => [...entries.values()].map((e) => e.status),

    start: () => Promise.all([...entries.values()].map(connect)).then(() => undefined),

    // Opens the Connect page for the human at most once a minute per upstream and returns the token-free link.
    requestConnect(names: string[]): string {
      const now = Date.now();
      const due = names.map(entryOf).filter((e) => !e.openedAt || now - e.openedAt > REOPEN_AFTER_MS);
      for (const entry of due) {
        entry.openedAt = now;
        options.audit({ type: "connect_requested", upstream: entry.config.name, by: "program" });
      }
      return options.connectPage(due.length > 0);
    },

    // Called from the Connect POST; returns where the browser goes next.
    async beginConnect(name: string): Promise<string> {
      const entry = entryOf(name);
      options.audit({ type: "connect_requested", upstream: name, by: "page" });
      const state = randomBytes(18).toString("base64url");
      const provider = providerFor(entry.config, state);
      try {
        const result = await auth(provider, { serverUrl: entry.config.url });
        if (result === "AUTHORIZED" || !provider.authorizationUrl) {
          await connect(entry);
          return "/connect";
        }
        attempts.set(state, { name, provider, expiresAt: Date.now() + STATE_TTL_MS });
        settle(entry, { state: "connecting" });
        return provider.authorizationUrl.href;
      } catch (error) {
        settle(entry, { state: "unavailable", reason: (error as Error).message });
        return "/connect";
      }
    },

    // Called from the OAuth callback; false means the state was never issued, was used already, or expired.
    async finishConnect(state: string, code: string): Promise<boolean> {
      const attempt = attempts.get(state);
      attempts.delete(state);
      if (!attempt || attempt.expiresAt <= Date.now()) return false;
      const entry = entryOf(attempt.name);
      try {
        await auth(attempt.provider, { serverUrl: entry.config.url, authorizationCode: code });
      } catch (error) {
        settle(entry, { state: "needs_connect", reason: `authorization failed: ${(error as Error).message}` });
        return true;
      }
      await connect(entry);
      return true;
    },

    // Resolves once none of the named upstreams is waiting for a connect any more, or the wait elapses.
    waitFor(names: string[], ms: number): Promise<void> {
      const done = () => names.every((n) => ["connected", "unavailable"].includes(entryOf(n).status.state));
      if (done()) return Promise.resolve();
      return new Promise((resolve) => {
        const wake = () => {
          if (!done()) return;
          clearTimeout(timer);
          waiters.delete(wake);
          resolve();
        };
        const timer = setTimeout(() => {
          waiters.delete(wake);
          resolve();
        }, ms);
        waiters.add(wake);
      });
    },

    close: () => Promise.all([...entries.values()].map((e) => e.client?.close())).then(() => undefined),
  };
}
