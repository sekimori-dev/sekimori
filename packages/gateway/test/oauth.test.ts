import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { createActivityLog } from "../src/activity.ts";
import { createApprovalStore } from "../src/approvals.ts";
import { createCredentialStore } from "../src/credentials.ts";
import { approvalPorts, startDashboard } from "../src/dashboard.ts";
import { createGateway } from "../src/gateway.ts";
import { createPolicy } from "../src/policy.ts";
import { createRemotes } from "../src/upstream.ts";

const readBody = (req: IncomingMessage) =>
  new Promise<string>((resolve) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
  });

const random = () => randomBytes(9).toString("base64url");

// The remote MCP server and its authorization server are a network boundary, so one recorded fake plays both.
async function fakeTracker() {
  const access = new Set<string>();
  const refresh = new Set<string>();
  const codes = new Set<string>();
  let refreshes = 0;
  let base = "";
  const issue = () => {
    const tokens = { access_token: `at_${random()}`, refresh_token: `rt_${random()}`, token_type: "Bearer", expires_in: 3600 };
    access.add(tokens.access_token);
    refresh.add(tokens.refresh_token);
    return tokens;
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, base);
    const json = (status: number, value: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(value));
    };
    if (url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      return json(200, { resource: `${base}/mcp`, authorization_servers: [base] });
    }
    if (url.pathname.startsWith("/.well-known/oauth-authorization-server")) {
      return json(200, {
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        registration_endpoint: `${base}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
      });
    }
    if (url.pathname === "/register") return json(201, { ...JSON.parse(await readBody(req)), client_id: "sekimori-test-client" });
    if (url.pathname === "/authorize") {
      const code = random();
      codes.add(code);
      const back = new URL(url.searchParams.get("redirect_uri")!);
      back.searchParams.set("code", code);
      back.searchParams.set("state", url.searchParams.get("state")!);
      res.writeHead(302, { location: back.href });
      return res.end();
    }
    if (url.pathname === "/token") {
      const form = new URLSearchParams(await readBody(req));
      if (form.get("grant_type") === "authorization_code" && codes.delete(form.get("code")!)) return json(200, issue());
      if (form.get("grant_type") === "refresh_token" && refresh.delete(form.get("refresh_token")!)) {
        refreshes++;
        return json(200, issue());
      }
      return json(400, { error: "invalid_grant" });
    }
    if (url.pathname === "/mcp" && req.method === "POST") {
      const bearer = req.headers.authorization?.replace(/^Bearer /, "");
      if (!bearer || !access.has(bearer)) {
        return json(401, { error: "invalid_token" }, { "www-authenticate": `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"` });
      }
      const mcp = new McpServer({ name: "tracker", version: "0.0.0" });
      mcp.registerTool("search", { inputSchema: { query: z.string() } }, async ({ query }) => ({ content: [{ type: "text", text: `found ${query}` }] }));
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await mcp.connect(transport);
      return transport.handleRequest(req, res, JSON.parse(await readBody(req)));
    }
    json(405, {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    url: `${base}/mcp`,
    expireAccessTokens: () => access.clear(),
    refreshes: () => refreshes,
    liveRefreshTokens: refresh,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

const cleanups: Array<() => unknown> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function setup() {
  const fake = await fakeTracker();
  const dir = await mkdtemp(join(tmpdir(), "sekimori-oauth-"));
  const key = randomBytes(32);
  const store = createCredentialStore(dir, "tester", async () => key);
  const approvals = createApprovalStore(60_000);
  const basePort = 48_000 + Math.floor(Math.random() * 100) * 10;
  const classification = { trusted: ["search"], untrusted: [], sinks: [] };

  let page: Awaited<ReturnType<typeof startDashboard>>;
  const newRemotes = () =>
    createRemotes([{ name: "tracker", url: fake.url, classify: classification }], {
      store,
      redirectUris: approvalPorts(basePort).map((port) => `http://127.0.0.1:${port}/oauth/callback`),
      redirectUrl: () => `http://127.0.0.1:${page.port}/oauth/callback`,
      connectPage: (open) => page.connectPage(open),
      connectTimeoutMs: 5_000,
      audit: () => {},
      onChange: () => {},
    });
  const remotes = newRemotes();
  page = await startDashboard(approvals, {
    port: basePort,
    openBrowser: false,
    agent: "test-agent",
    user: "tester",
    sessionDir: dir,
    activity: createActivityLog(dir, "tester"),
    local: [],
    remotes,
    onNotified: () => {},
  });
  const origin = `http://127.0.0.1:${page.port}`;
  const cookie = (await fetch(page.indexUrl, { redirect: "manual" })).headers.get("set-cookie")!.split(";")[0]!;
  cleanups.push(() => rm(dir, { recursive: true, force: true }), fake.close, page.close, remotes.close);

  const gateway = createGateway({
    agent: "test-agent",
    upstreams: [],
    remotes,
    classification: { tracker: classification },
    policy: createPolicy(`permit(principal == Agent::"test-agent", action == Action::"call", resource);`),
    approvals,
    notifyApprover: (id) => id,
    audit: () => {},
    record: () => {},
    limits: { timeoutMs: 5_000, memoryBytes: 32 * 1024 * 1024 },
    approvalWaitMs: 3_000,
  });

  // Plays the human in the browser: the Connect button, the authorization server's redirect, then the callback.
  async function signIn(): Promise<Response> {
    const start = await fetch(`${origin}/connections/tracker`, { method: "POST", redirect: "manual", headers: { cookie, origin } });
    const authorize = await fetch(start.headers.get("location")!, { redirect: "manual" });
    return fetch(authorize.headers.get("location")!, { redirect: "manual" });
  }

  await remotes.start();
  return { fake, dir, store, remotes, newRemotes, gateway, origin, cookie, signIn };
}

const program = `return await tracker.search({ query: "disk" });`;

describe("per-user OAuth to remote MCP servers", () => {
  it("asks the user to connect, waits for the sign-in, hands back the new declarations, then runs", async () => {
    const { gateway, origin, cookie, signIn } = await setup();

    expect(gateway.describe()).toContain("Not connected yet: tracker");
    expect(await gateway.execute(program)).toMatchObject({ status: "connect_required", upstreams: ["tracker"], connectAt: `${origin}/connections` });

    const waiting = gateway.execute(program);
    expect((await signIn()).status).toBe(200);
    expect(await (await fetch(`${origin}/connections`, { headers: { cookie } })).text()).toContain("Every service is connected.");
    expect(await waiting).toMatchObject({ status: "connected", upstreams: ["tracker"], declarations: expect.stringContaining('"search"(') });

    expect(await gateway.execute(program)).toMatchObject({ status: "completed", value: "found disk" });
  });

  it("refreshes an expired token, persists the rotated one encrypted, and reconnects from storage after a restart", async () => {
    const { fake, dir, store, newRemotes, gateway, signIn } = await setup();
    await signIn();

    fake.expireAccessTokens();
    expect(await gateway.execute(program)).toMatchObject({ status: "completed", value: "found disk" });
    expect(fake.refreshes()).toBe(1);

    const { tokens } = await store.read("tracker");
    expect(fake.liveRefreshTokens.has(tokens!.refresh_token!)).toBe(true);
    const raw = await readFile(join(dir, "credentials", "tester", "tracker.json"), "utf8");
    expect(raw).not.toContain(tokens!.access_token);
    expect(raw).not.toContain(tokens!.refresh_token);

    const restarted = newRemotes();
    await restarted.start();
    expect(restarted.list()[0]).toMatchObject({ state: "connected" });
    await restarted.close();
  });

  it("rejects callbacks whose state the gateway never issued or already used", async () => {
    const { remotes, origin, signIn } = await setup();

    expect((await fetch(`${origin}/oauth/callback?state=forged&code=stolen`)).status).toBe(400);
    expect(remotes.list()[0]).toMatchObject({ state: "needs_connect" });

    const callback = await signIn();
    expect(callback.status).toBe(200);
    expect((await fetch(callback.url)).status).toBe(400);
  });
});
