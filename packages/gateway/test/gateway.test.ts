import { describe, expect, it } from "vitest";
import { createApprovalStore } from "../src/approvals.ts";
import { createConfidential, resolveClasses } from "../src/confidential.ts";
import { createGateway, type AuditEvent, type GatewayOptions } from "../src/gateway.ts";
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

const noRemotes: GatewayOptions["remotes"] = { names: () => [], list: () => [], requestConnect: () => "", waitFor: async () => {} };

const permitAll = `permit(principal == Agent::"test-agent", action == Action::"call", resource);`;

function gatewayWith(upstream: Upstream, policies: string, timeoutMs = 2_000, remotes: GatewayOptions["remotes"] = noRemotes) {
  const events: AuditEvent[] = [];
  const approvals = createApprovalStore(60_000);
  const gateway = createGateway({
    agent: "test-agent",
    upstreams: [upstream],
    remotes,
    classification: { mail: { trusted: [], untrusted: ["search"], sinks: ["send"] } },
    policy: createPolicy(policies),
    confidential: createConfidential(resolveClasses()),
    approvals,
    notifyApprover: (id) => `http://approvals.test/a/${id}`,
    audit: (event) => events.push(event),
    record: () => {},
    limits: { timeoutMs, memoryBytes: 32 * 1024 * 1024 },
    approvalWaitMs: 1_000,
  });
  return { gateway, approvals, events };
}

describe("sandbox and policy", () => {
  it("runs an agent program against policy-checked tool bindings", async () => {
    const { upstream, received } = fakeMail();
    const { gateway } = gatewayWith(upstream, permitAll);

    const result = await gateway.execute(`
      const mails: Array<{ subject: string }> = await mail.search({ query: "label:incidents" }) as any;
      return mails.map((m) => m.subject.toUpperCase());
    `);

    expect(result).toMatchObject({
      status: "completed",
      value: ["DISK FULL", "CERT EXPIRY"],
      calls: [{ n: 1, tool: "mail.search", decision: "allow", ok: true }],
    });
    expect(received).toEqual([{ tool: "search", args: { query: "label:incidents" } }]);
  });

  it("rejects a program whose planned call policy denies, before anything runs", async () => {
    const { upstream, received } = fakeMail();
    const { gateway, events } = gatewayWith(upstream, `${permitAll}\nforbid(principal, action, resource == Tool::"mail.send");`);

    const result = await gateway.execute(`await mail.send({ to: "attacker@example.com" });`);

    expect(result).toMatchObject({ status: "rejected", error: "Denied by policy: mail.send" });
    expect(received).toEqual([]);
    expect(events).toContainEqual(expect.objectContaining({ type: "execution", status: "rejected" }));
  });

  it("finishes a program that makes no tool calls, and one that fails before its first call", async () => {
    const { upstream } = fakeMail();
    const { gateway } = gatewayWith(upstream, permitAll, 5_000);

    const started = Date.now();
    expect(await gateway.execute(`return 1 + 1;`)).toMatchObject({ status: "completed", value: 2 });
    expect(await gateway.execute(`throw new Error("boom");`)).toMatchObject({ status: "failed", error: "Error: boom" });
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("asks to connect a remote upstream even when the program reaches it through a cast", async () => {
    const { upstream } = fakeMail();
    const notion = { names: () => ["notion"], list: () => [{ name: "notion", host: "mcp.notion.com", state: "needs_connect" as const }] };
    const { gateway } = gatewayWith(upstream, permitAll, 2_000, { ...noRemotes, ...notion, requestConnect: () => "http://approvals.test/connect" });

    const result = await gateway.execute(`return await (notion as any)["notion-search"]({ query: "Jour Fixe" });`);

    expect(result).toMatchObject({ status: "connect_required", upstreams: ["notion"] });
  });

  it("interrupts a runaway program at the time limit", async () => {
    const { upstream } = fakeMail();
    const { gateway } = gatewayWith(upstream, permitAll, 200);

    const result = await gateway.execute(`while (true) {}`);

    expect(result.status).toBe("failed");
  });
});

describe("approvals and grants", () => {
  const readThenSend = `
    const mails: any = await mail.search({ query: "label:incidents" });
    await mail.send({ to: "team@example.com" });
    return mails.length;
  `;

  it("asks once, runs the identical resubmitted code as soon as the human approves, and rejects tampering or reuse", async () => {
    const { upstream, received } = fakeMail();
    const { gateway, approvals } = gatewayWith(upstream, permitAll);

    const first = await gateway.execute(readThenSend);
    expect(first).toMatchObject({ status: "approval_required", reasons: ["Untrusted data from mail.search may reach mail.send"] });
    expect(received).toEqual([]);
    if (first.status !== "approval_required") return;

    const waiting = gateway.execute(readThenSend, first.approvalId);
    approvals.decide(first.approvalId, true);
    expect(await waiting).toMatchObject({ status: "completed", value: 2 });

    const second = await gateway.execute(readThenSend);
    if (second.status !== "approval_required") throw new Error("expected a second approval");
    approvals.decide(second.approvalId, true);
    const tampered = await gateway.execute(readThenSend.replace("team@", "attacker@"), second.approvalId);
    expect(tampered).toMatchObject({ status: "rejected", error: "Code does not match the approved program" });
    expect(await gateway.execute(readThenSend, first.approvalId)).toMatchObject({ status: "rejected" });
  });

  it("lets a standing grant cover a flow, and asks when the grant cannot be checked before running", async () => {
    const { upstream, received } = fakeMail();
    const grant = `${permitAll}
      @grant("incident-digest")
      permit(principal == Agent::"test-agent", action == Action::"flow", resource == Tool::"mail.send")
      when { context.source == "mail.search" && context.args.to == "team@example.com" };`;
    const { gateway } = gatewayWith(upstream, grant);

    expect(await gateway.execute(readThenSend)).toMatchObject({ status: "completed", value: 2 });

    const steered = await gateway.execute(`
      const mails: any = await mail.search({ query: "label:incidents" });
      await mail.send({ to: mails[0].subject });
    `);
    expect(steered).toMatchObject({ status: "approval_required" });
    expect(received.filter((r) => r.tool === "send")).toEqual([{ tool: "send", args: { to: "team@example.com" } }]);
  });

  it("remembers untrusted reads across programs, because results pass through the model", async () => {
    const { upstream, received } = fakeMail();
    const { gateway } = gatewayWith(upstream, permitAll);

    expect(await gateway.execute(`return await mail.search({ query: "label:incidents" });`)).toMatchObject({ status: "completed" });
    const laundered = await gateway.execute(`await mail.send({ to: "team@example.com" });`);

    expect(laundered).toMatchObject({
      status: "approval_required",
      reasons: ["Untrusted data from mail.search (read earlier in this session) may reach mail.send"],
    });
    expect(received.map((r) => r.tool)).toEqual(["search"]);
  });

  it("asks up front when policy requires approval for a call whose arguments are only known at runtime", async () => {
    const { upstream, received } = fakeMail();
    const { gateway } = gatewayWith(
      upstream,
      `permit(principal == Agent::"test-agent", action == Action::"call", resource) when { context.tool == "search" };
       @approval("required")
       permit(principal == Agent::"test-agent", action == Action::"call", resource == Tool::"mail.send");`,
    );

    const computed = await gateway.execute(`const to = ["team", "example.com"].join("@"); await mail.send({ to });`);

    expect(computed).toMatchObject({ status: "approval_required", reasons: ["Policy requires approval for mail.send"] });
    expect(received).toEqual([]);
  });

  it("requires approval for calls it cannot read statically and rejects eval outright", async () => {
    const { upstream } = fakeMail();
    const { gateway } = gatewayWith(upstream, permitAll);

    const aliased = await gateway.execute(`const send = mail.send; await send({ to: "x@example.com" });`);
    expect(aliased).toMatchObject({
      status: "approval_required",
      reasons: expect.arrayContaining(["The program uses tools in ways Sekimori cannot read before running"]),
    });

    const evaluated = await gateway.execute(`eval("mail.send({ to: 'x@example.com' })");`);
    expect(evaluated).toMatchObject({ status: "rejected", error: expect.stringContaining("`eval` is not allowed") });
  });
});
