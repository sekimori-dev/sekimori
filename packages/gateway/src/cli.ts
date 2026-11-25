#!/usr/bin/env node
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { approvalPorts, openInBrowser, startApprovalPage } from "./approval-page.ts";
import { createApprovalStore } from "./approvals.ts";
import { loadConfig, type RemoteUpstreamConfig, type StdioUpstreamConfig } from "./config.ts";
import { createCredentialStore, loadCredentialsKey } from "./credentials.ts";
import { createGateway } from "./gateway.ts";
import { createPolicy } from "./policy.ts";
import { connectUpstream, createRemotes } from "./upstream.ts";

const { values, positionals } = parseArgs({
  options: { config: { type: "string", default: "sekimori.config.json" } },
  allowPositionals: true,
});

// Running gateways leave a file with only their port and pid; the approver token never leaves gateway memory.
const sessionDir = join(homedir(), ".sekimori");
const approvalsCommand = `node ${import.meta.filename} approvals`;

if (positionals[0] === "approvals") {
  const files = (await readdir(sessionDir).catch(() => [])).filter((f) => f.startsWith("approver-"));
  if (files.length === 0) console.log("No running Sekimori gateway found.");
  for (const file of files) {
    const { port, pid } = JSON.parse(await readFile(join(sessionDir, file), "utf8"));
    try {
      process.kill(pid, "SIGUSR2");
      console.log(`Asked the gateway on port ${port} to open its approvals in your browser.`);
    } catch {
      await rm(join(sessionDir, file), { force: true });
      console.log(`Removed a stale entry for port ${port}.`);
    }
  }
  process.exit(0);
}

const { config, policyText } = await loadConfig(values.config);

const stdio = config.upstreams.filter((u): u is StdioUpstreamConfig => "command" in u);
const remote = config.upstreams.filter((u): u is RemoteUpstreamConfig => "url" in u);
const upstreams = await Promise.all(stdio.map(connectUpstream));
// stdout carries the MCP protocol, so audit events go to stderr as JSON lines.
const audit = (event: object) =>
  process.stderr.write(`${JSON.stringify({ at: new Date().toISOString(), user: config.user, ...event })}\n`);

let key: Promise<Buffer> | undefined;
const credentials = createCredentialStore(sessionDir, config.user, () => (key ??= loadCredentialsKey(sessionDir)));
let approvalPage: Awaited<ReturnType<typeof startApprovalPage>>;
const remotes = createRemotes(remote, {
  store: credentials,
  redirectUris: approvalPorts(config.approvals.port).map((port) => `http://127.0.0.1:${port}/oauth/callback`),
  redirectUrl: () => `http://127.0.0.1:${approvalPage.port}/oauth/callback`,
  connectPage: (open) => approvalPage.connectPage(open),
  connectTimeoutMs: 10_000,
  audit,
});

const approvals = createApprovalStore(config.approvals.ttlMinutes * 60_000);
approvalPage = await startApprovalPage(approvals, {
  ...config.approvals,
  remotes,
  onNotified: (approvalId, outcome) => audit({ type: "approver_notified", approvalId, outcome }),
});
const sessionFile = join(sessionDir, `approver-${approvalPage.port}.json`);
await mkdir(sessionDir, { recursive: true, mode: 0o700 });
await writeFile(sessionFile, JSON.stringify({ port: approvalPage.port, pid: process.pid }), { mode: 0o600 });
process.on("SIGUSR2", () => {
  openInBrowser(approvalPage.indexUrl).then((outcome) => audit({ type: "approver_notified", via: "signal", outcome }));
});
audit({ type: "approval_page", port: approvalPage.port });
await remotes.start();

const gateway = createGateway({
  agent: config.agent,
  upstreams,
  remotes,
  classification: Object.fromEntries(config.upstreams.map((u) => [u.name, u.classify])),
  policy: createPolicy(policyText),
  approvals,
  notifyApprover: approvalPage.announce,
  audit,
  limits: config.limits,
  approvalWaitMs: config.approvals.waitSeconds * 1000,
});

const server = new McpServer({ name: "sekimori", version: "0.0.0" });

server.registerTool(
  "describe_api",
  {
    description:
      "Returns TypeScript declarations for every tool reachable through Sekimori. Call this first, then write a program for `execute`.",
  },
  async () => ({ content: [{ type: "text", text: gateway.describe() }] }),
);

server.registerTool(
  "execute",
  {
    description:
      `Runs a TypeScript program in Sekimori's sandbox. The namespaces from \`describe_api\` are globals; use top-level await and \`return\` the value you need. Every tool call is checked against policy. If the result has status \`approval_required\`, tell the user that Sekimori opened the request in their browser and show the plan and reasons. If nothing opened, the user can run \`${approvalsCommand}\` in a terminal (in Claude Code: \`! ${approvalsCommand}\`). Then immediately call \`execute\` again with the identical code and the \`approvalId\`, without waiting for the user to reply: that call waits for their decision and runs the program once they approve. If it returns \`approval_pending\`, call it again the same way. If the result has status \`connect_required\`, tell the user that Sekimori opened a page to connect the named services with their own account, then immediately call \`execute\` again with the identical code (no \`approvalId\`): that call waits for the connection. On \`connected\`, write the program again against the returned declarations; on \`connect_pending\`, call again the same way.`,
    inputSchema: {
      code: z.string().describe("TypeScript program body"),
      approvalId: z.string().optional().describe("Approval ID from an earlier approval_required result"),
    },
  },
  async ({ code, approvalId }) => {
    const result = await gateway.execute(code, approvalId);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }], isError: result.status !== "completed" };
  },
);

await server.connect(new StdioServerTransport());

process.stdin.on("close", async () => {
  approvalPage.close();
  await rm(sessionFile, { force: true });
  await Promise.all([...upstreams.map((u) => u.close()), remotes.close()]);
  process.exit(0);
});
