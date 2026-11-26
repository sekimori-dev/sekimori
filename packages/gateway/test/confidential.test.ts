import { describe, expect, it } from "vitest";
import { createApprovalStore } from "../src/approvals.ts";
import { createConfidential, resolveClasses, type ClassConfig } from "../src/confidential.ts";
import { createGateway } from "../src/gateway.ts";
import { createPolicy } from "../src/policy.ts";
import type { Upstream } from "../src/upstream.ts";

// Fictional example data. Upstream MCP servers are a system boundary, so recorded fakes stand in for them.
const IBAN_A = "AT61 1904 3002 3457 3201";
const IBAN_B = "DE89 3704 0044 0532 0130 00";
const EMPLOYEES = JSON.stringify([
  { id: "E-1", name: "Mara Example", iban: IBAN_A, salary: 52000 },
  { id: "E-2", name: "Jon Example", iban: IBAN_B, salary: 61000 },
]);

function fakes() {
  const received: Array<{ tool: string; args: unknown }> = [];
  const upstream = (name: string, tools: Record<string, (args: any) => unknown>): Upstream => ({
    name,
    tools: Object.keys(tools).map((tool) => ({ name: tool, inputSchema: { type: "object" } })),
    async call(tool, args) {
      received.push({ tool: `${name}.${tool}`, args });
      return tools[tool]!(args);
    },
  });
  return {
    received,
    upstreams: [
      upstream("payroll", { list_employees: () => EMPLOYEES, update_employee: (args) => `Saved IBAN ${args.iban}` }),
      upstream("archive", { read: () => "Archived: Jon Example earned 61000 last year" }),
      upstream("ledger", { accounts: () => '[{"account_number": 123456789012345}, {"account_number": 9007199254740993}, {"account_number": 9.007199254740995e15}]' }),
      upstream("slack", { post: () => "posted" }),
      upstream("files", { read_file: () => "Quarterly notes, nothing special" }),
      upstream("erp", { get_project: () => JSON.stringify({ code: "ZEUS", note: "Ref PRJ-123456", budget: 90000, salary: 50000 }) }),
    ],
  };
}

const permitCalls = `permit(principal == Agent::"assistant", action == Action::"call", resource);`;

function gatewayWith(policies = permitCalls, classes: Record<string, ClassConfig> = {}) {
  const { received, upstreams } = fakes();
  const approvals = createApprovalStore(60_000);
  const gateway = createGateway({
    agent: "assistant",
    upstreams,
    remotes: { names: () => [], list: () => [], requestConnect: () => "", waitFor: async () => {} },
    classification: {
      payroll: { trusted: ["*"], untrusted: [], sinks: ["update_*"] },
      archive: { trusted: ["*"], untrusted: [], sinks: [] },
      ledger: { trusted: ["*"], untrusted: [], sinks: [] },
      slack: { trusted: [], untrusted: [], sinks: ["post"] },
      files: { trusted: [], untrusted: ["read_file"], sinks: [] },
      erp: { trusted: ["*"], untrusted: [], sinks: [] },
    },
    policy: createPolicy(policies),
    confidential: createConfidential(resolveClasses(classes)),
    approvals,
    notifyApprover: (id) => id,
    audit: () => {},
    record: () => {},
    limits: { timeoutMs: 5_000, memoryBytes: 32 * 1024 * 1024 },
    approvalWaitMs: 1_000,
  });
  return { gateway, approvals, received };
}

const read = `const rows = JSON.parse(await payroll.list_employees({}));`;
const value = async (gateway: ReturnType<typeof gatewayWith>["gateway"], code: string) => {
  const result = await gateway.execute(code);
  if (result.status === "completed") return result.value;
  if (result.status === "failed") return result.error;
  throw new Error(`unexpected ${result.status}`);
};

describe("confidential data", () => {
  it("keeps raw values from the model however the program returns them, and lets computed results through", async () => {
    const { gateway } = gatewayWith();

    const raw = JSON.stringify(await value(gateway, `return await payroll.list_employees({});`));
    const renamed = await value(gateway, `${read} return rows.map((r) => ({ s: r.salary }));`);
    const asKey = await value(gateway, `${read} return { [rows[0].salary]: 1 };`);
    const formatted = await value(gateway, `${read} return "Pay " + String(rows[0].salary).replace(/(\\d{2})(\\d{3})/, "$1,$2");`);
    const sentence = await value(gateway, `${read} return "Transfer to " + rows[0].iban;`);
    const average = await value(gateway, `${read} return { average_salary: rows.reduce((s, r) => s + r.salary, 0) / rows.length };`);
    const thrown = await value(gateway, `${read} throw new Error("salary " + rows[1].salary);`);
    const elsewhere = await value(gateway, `return await archive.read({});`);

    for (const output of [raw, JSON.stringify(renamed), JSON.stringify(asKey), formatted, sentence, thrown, elsewhere]) {
      expect(output).not.toMatch(/52000|61000|52,000|1904 3002|3704 0044/);
    }
    expect(raw).toMatch(/⟦withheld:payroll⟧[\s\S]*⟦bank·[0-9a-f]{6}⟧/);
    expect(JSON.parse(JSON.parse(raw))).toEqual([
      expect.objectContaining({ salary: "⟦withheld:payroll⟧", iban: expect.stringMatching(/^⟦bank·[0-9a-f]{6}⟧$/) }),
      expect.objectContaining({ salary: "⟦withheld:payroll⟧" }),
    ]);
    expect(renamed).toEqual([{ s: "⟦withheld:payroll⟧" }, { s: "⟦withheld:payroll⟧" }]);
    expect(sentence).toMatch(/^Transfer to ⟦bank·[0-9a-f]{6}⟧$/);
    expect(average).toEqual({ average_salary: 56500 });
    const accounts = await value(gateway, `const a = JSON.parse(await ledger.accounts({})); return { x: a[0].account_number, y: a[1].account_number, z: a[2].account_number };`);
    expect(JSON.stringify(accounts)).not.toMatch(/123456789012345|900719925474099|9\.007/);
    const numericCard = await value(gateway, `return '{"card": 4111111111111111, "tax_ref": 12345678903, "ref": 4.11111111111111111e18}';`);
    expect(JSON.parse(numericCard as string)).toEqual({
      card: expect.stringMatching(/^⟦bank·[0-9a-f]{6}⟧$/),
      tax_ref: expect.stringMatching(/^⟦national_id·[0-9a-f]{6}⟧$/),
      ref: expect.stringMatching(/^⟦bank·[0-9a-f]{6}⟧$/),
    });
  });

  it("puts placeholders back only where they may go, and blocks raw values forwarded elsewhere", async () => {
    const { gateway, received } = gatewayWith();
    const placeholder = (await value(gateway, `${read} return rows[0].iban;`)) as string;

    expect(await value(gateway, `return await payroll.update_employee({ iban: "${placeholder}" });`)).toBe(`Saved IBAN ${placeholder}`);
    expect(received.at(-1)).toEqual({ tool: "payroll.update_employee", args: { iban: IBAN_A } });

    expect(await gateway.execute(`await slack.post({ text: "${placeholder}" });`)).toMatchObject({
      status: "approval_required",
      reasons: ["Confidential bank value would be sent to slack.post"],
    });
    expect(await gateway.execute(`${read} await slack.post({ text: rows.map((r) => r.iban).join() });`)).toMatchObject({
      status: "failed",
      error: expect.stringContaining("Confidential bank value may not be sent to slack.post"),
    });
    expect(received.filter((r) => r.tool === "slack.post")).toEqual([]);

    const granted = gatewayWith(`${permitCalls}
      @grant("iban-to-slack")
      permit(principal == Agent::"assistant", action == Action::"reveal", resource == Tool::"slack.post") when { context.class == "bank" };`);
    expect(await granted.gateway.execute(`${read} await slack.post({ text: rows[0].iban }); return "ok";`)).toMatchObject({ status: "completed" });
    expect(granted.received.at(-1)).toEqual({ tool: "slack.post", args: { text: IBAN_A } });
  });

  it("applies the configured classes, and holds a confidential result after untrusted input until a human releases it", async () => {
    const configured = gatewayWith(permitCalls, {
      payroll: { enabled: false },
      project: { fields: ["budget"], patterns: ["PRJ-\\d{6}"], sources: ["erp.*"] },
    });
    expect(await value(configured.gateway, `return JSON.parse(await erp.get_project({}));`)).toEqual({
      code: "⟦withheld:project⟧",
      note: "Ref ⟦withheld:project⟧",
      budget: "⟦withheld:project⟧",
      salary: "⟦withheld:project⟧",
    });

    const { gateway, approvals, received } = gatewayWith();
    await value(gateway, `return await files.read_file({});`);
    const average = `${read} return rows.reduce((s, r) => s + r.salary, 0) / rows.length;`;
    const held = await gateway.execute(average);
    expect(held).toMatchObject({ status: "approval_required", reasons: ["Result computed from confidential data after untrusted input"] });
    if (held.status !== "approval_required") return;

    const reads = received.filter((r) => r.tool === "payroll.list_employees").length;
    approvals.decide(held.approvalId, true);
    expect(await gateway.execute(average, held.approvalId)).toMatchObject({ status: "completed", value: 56500 });
    expect(received.filter((r) => r.tool === "payroll.list_employees")).toHaveLength(reads);
  });

  it("catches reformatted values going out, asks when a reveal grant requires approval, and holds results the approver was not told about", async () => {
    const { gateway, received } = gatewayWith();
    const compact = await gateway.execute(`${read} await slack.post({ text: rows[0].iban.replace(/ /g, "").toLowerCase() });`);
    const inText = await gateway.execute(`${read} await slack.post({ text: "Mara earns " + String(rows[0].salary).replace(/(\\d{2})(\\d{3})/, "$1.$2") });`);
    expect(compact).toMatchObject({ status: "failed", error: expect.stringContaining("Confidential bank value may not be sent to slack.post") });
    expect(inText).toMatchObject({ status: "failed", error: expect.stringContaining("Confidential payroll value may not be sent to slack.post") });
    expect(received.filter((r) => r.tool === "slack.post")).toEqual([]);

    const annotated = gatewayWith(`${permitCalls}
      @approval("required")
      permit(principal == Agent::"assistant", action == Action::"reveal", resource == Tool::"slack.post");`);
    const placeholder = (await value(annotated.gateway, `${read} return rows[0].iban;`)) as string;
    expect(await annotated.gateway.execute(`await slack.post({ text: "${placeholder}" });`)).toMatchObject({ status: "approval_required" });

    const flow = gatewayWith(`${permitCalls}`);
    await value(flow.gateway, `return await files.read_file({});`);
    const mixed = `${read} await slack.post({ text: "summary" }); return rows.length;`;
    const first = await flow.gateway.execute(mixed);
    if (first.status !== "approval_required") throw new Error("expected a flow approval");
    flow.approvals.decide(first.approvalId, true);
    expect(await flow.gateway.execute(mixed, first.approvalId)).toMatchObject({
      status: "approval_required",
      reasons: ["Result computed from confidential data after untrusted input"],
    });
  });
});
