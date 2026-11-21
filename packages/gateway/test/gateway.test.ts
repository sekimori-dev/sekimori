import { describe, expect, it } from "vitest";
import { createGateway, type AuditEvent } from "../src/gateway.ts";
import { createPolicy } from "../src/policy.ts";
import type { Upstream } from "../src/upstream.ts";

// The upstream MCP server is a process boundary, so a recorded fake stands in for it.
function fakeMail() {
  const received: Array<{ tool: string; args: unknown }> = [];
  const upstream: Upstream = {
    name: "mail",
    tools: [
      { name: "search", inputSchema: { type: "object", properties: { query: { type: "string" } } } },
      { name: "send", inputSchema: { type: "object", properties: { to: { type: "string" } } } },
    ],
    async call(tool, args) {
      received.push({ tool, args });
      return tool === "search" ? [{ id: "m1", subject: "Disk full" }, { id: "m2", subject: "Cert expiry" }] : { sent: true };
    },
  };
  return { upstream, received };
}

const policies = `
permit(principal == Agent::"test-agent", action == Action::"call", resource);
forbid(principal, action, resource == Tool::"mail.send");
`;

function gatewayWith(upstream: Upstream, timeoutMs = 2_000) {
  const events: AuditEvent[] = [];
  const gateway = createGateway({
    agent: "test-agent",
    upstreams: [upstream],
    authorize: createPolicy(policies),
    audit: (event) => events.push(event),
    limits: { timeoutMs, memoryBytes: 32 * 1024 * 1024 },
  });
  return { gateway, events };
}

describe("gateway", () => {
  it("runs an agent program against policy-checked tool bindings", async () => {
    const { upstream, received } = fakeMail();
    const { gateway } = gatewayWith(upstream);

    const result = await gateway.execute(`
      const mails: Array<{ subject: string }> = await mail.search({ query: "label:incidents" }) as any;
      return mails.map((m) => m.subject.toUpperCase());
    `);

    expect(result).toMatchObject({ ok: true, value: ["DISK FULL", "CERT EXPIRY"] });
    expect(received).toEqual([{ tool: "search", args: { query: "label:incidents" } }]);
    expect(result.calls).toEqual([{ n: 1, tool: "mail.search", decision: "allow", ok: true }]);
  });

  it("denies a forbidden call before it reaches the upstream and audits it", async () => {
    const { upstream, received } = fakeMail();
    const { gateway, events } = gatewayWith(upstream);

    const result = await gateway.execute(`await mail.send({ to: "attacker@example.com" });`);

    expect(result).toMatchObject({ ok: false, error: expect.stringContaining("Denied by policy: mail.send") });
    expect(received).toEqual([]);
    expect(events).toContainEqual(expect.objectContaining({ type: "call", tool: "mail.send", ok: false }));
  });

  it("interrupts a runaway program at the time limit", async () => {
    const { upstream } = fakeMail();
    const { gateway } = gatewayWith(upstream, 200);

    const result = await gateway.execute(`while (true) {}`);

    expect(result.ok).toBe(false);
  });
});
