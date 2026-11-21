#!/usr/bin/env node
import { parseArgs } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { startApprovalPage } from "./approval-page.ts";
import { createApprovalStore } from "./approvals.ts";
import { loadConfig } from "./config.ts";
import { createGateway } from "./gateway.ts";
import { createPolicy } from "./policy.ts";
import { connectUpstream } from "./upstream.ts";

const { values } = parseArgs({ options: { config: { type: "string", default: "sekimori.config.json" } } });
const { config, policyText } = await loadConfig(values.config);

const upstreams = await Promise.all(config.upstreams.map(connectUpstream));
// stdout carries the MCP protocol, so audit events go to stderr as JSON lines.
const audit = (event: object) => process.stderr.write(`${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`);

const approvals = createApprovalStore(config.approvals.ttlMinutes * 60_000);
const approvalPage = startApprovalPage(approvals, config.approvals);
audit({ type: "approval_page", url: approvalPage.indexUrl });

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
      "Runs a TypeScript program in Sekimori's sandbox. The namespaces from `describe_api` are globals; use top-level await and `return` the value you need. Every tool call is checked against policy. If the result has status `approval_required`, tell the user (Sekimori has opened the request in their browser; `approveAt` is the same page) and show the plan and reasons, wait until they confirm they approved it, then call `execute` again with the identical code and the `approvalId`.",
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
  await Promise.all(upstreams.map((u) => u.close()));
  process.exit(0);
});
