#!/usr/bin/env node
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { openInBrowser, startApprovalPage } from "./approval-page.ts";
import { createApprovalStore } from "./approvals.ts";
import { loadConfig } from "./config.ts";
import { createGateway } from "./gateway.ts";
import { createPolicy } from "./policy.ts";
import { connectUpstream } from "./upstream.ts";

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

const upstreams = await Promise.all(config.upstreams.map(connectUpstream));
// stdout carries the MCP protocol, so audit events go to stderr as JSON lines.
const audit = (event: object) => process.stderr.write(`${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`);

const approvals = createApprovalStore(config.approvals.ttlMinutes * 60_000);
const approvalPage = await startApprovalPage(approvals, {
  ...config.approvals,
  onNotified: (approvalId, outcome) => audit({ type: "approver_notified", approvalId, outcome }),
});
const sessionFile = join(sessionDir, `approver-${approvalPage.port}.json`);
await mkdir(sessionDir, { recursive: true, mode: 0o700 });
await writeFile(sessionFile, JSON.stringify({ port: approvalPage.port, pid: process.pid }), { mode: 0o600 });
process.on("SIGUSR2", () => {
  openInBrowser(approvalPage.indexUrl).then((outcome) => audit({ type: "approver_notified", via: "signal", outcome }));
});
audit({ type: "approval_page", port: approvalPage.port });

const gateway = createGateway({
  agent: config.agent,
  upstreams,
  classification: Object.fromEntries(config.upstreams.map((u) => [u.name, u.classify])),
  policy: createPolicy(policyText),
  approvals,
  notifyApprover: approvalPage.announce,
  audit,
  limits: config.limits,
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
      `Runs a TypeScript program in Sekimori's sandbox. The namespaces from \`describe_api\` are globals; use top-level await and \`return\` the value you need. Every tool call is checked against policy. If the result has status \`approval_required\`, tell the user that Sekimori opened the request in their browser and show the plan and reasons. If nothing opened, the user can run \`${approvalsCommand}\` in a terminal (in Claude Code: \`! ${approvalsCommand}\`). Wait until they confirm they approved it, then call \`execute\` again with the identical code and the \`approvalId\`.`,
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
  await Promise.all(upstreams.map((u) => u.close()));
  process.exit(0);
});
