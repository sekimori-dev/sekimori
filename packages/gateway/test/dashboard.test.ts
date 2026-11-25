import { appendFile, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createActivityLog, foldRequests, type Session } from "../src/activity.ts";
import { createApprovalStore } from "../src/approvals.ts";
import { startDashboard } from "../src/dashboard.ts";
import { createConfidential, resolveClasses } from "../src/confidential.ts";
import { createGateway } from "../src/gateway.ts";
import { createPolicy } from "../src/policy.ts";

const cleanups: Array<() => unknown> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});

async function tempDir() {
  const dir = await mkdtemp(join(tmpdir(), "sekimori-dashboard-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

const sessionA: Session = { port: 4747, pid: 101, agent: "claude-code", user: "tester" };
const sessionB: Session = { port: 4748, pid: 202, agent: "claude-code", user: "tester" };
const step = { tool: "fs.write_file", args: ['path: "notes.md"'], runtimeArgs: false, repeated: false, untrusted: false, sink: true };

async function startOne(dir: string, signal: (pid: number) => void = () => {}) {
  const activity = createActivityLog(dir, "tester");
  const approvals = createApprovalStore(60_000);
  const dashboard = await startDashboard(approvals, {
    port: 48_000 + Math.floor(Math.random() * 100) * 10,
    openBrowser: false,
    agent: "claude-code",
    user: "tester",
    sessionDir: dir,
    activity,
    local: [],
    remotes: { list: () => [], beginConnect: async () => "/", finishConnect: async () => false },
    onNotified: () => {},
    signal,
  });
  cleanups.push(dashboard.close);
  const origin = `http://127.0.0.1:${dashboard.port}`;
  const cookie = (await fetch(dashboard.indexUrl, { redirect: "manual" })).headers.get("set-cookie")!.split(";")[0]!;
  await writeFile(join(dir, `approver-${dashboard.port}.json`), JSON.stringify({ port: dashboard.port, pid: process.pid, user: "tester" }));
  return { dashboard, activity, approvals, origin, cookie };
}

describe("dashboard", () => {
  it("folds both sessions' records into one row per request and expires what a dead session left waiting", async () => {
    const dir = await tempDir();
    const log = createActivityLog(dir, "tester");
    const at = new Date("2026-11-25T10:00:00Z");
    const later = (s: number) => new Date(at.getTime() + s * 1000);
    await log.append(sessionA, { kind: "request", executionId: "e1", status: "running", hash: "h1", steps: [step] }, at);
    await log.append(sessionA, { kind: "request", executionId: "e1", status: "approval_required", hash: "h1", approvalId: "ap_1", expiresAt: later(900).getTime() }, later(1));
    await log.append(sessionA, { kind: "decision", approvalId: "ap_1", decision: "approved" }, later(5));
    await log.append(sessionA, { kind: "request", executionId: "e2", status: "waiting", hash: "h1", approvalId: "ap_1" }, later(6));
    await log.append(sessionA, { kind: "request", executionId: "e2", status: "completed", hash: "h1", approvalId: "ap_1", calls: 1 }, later(7));
    await log.append(sessionB, { kind: "request", executionId: "e3", status: "approval_required", hash: "h3", steps: [step], approvalId: "ap_3", expiresAt: later(900).getTime() }, later(8));
    await log.append(sessionB, { kind: "decision", approvalId: "ap_3", decision: "denied" }, later(9));
    await log.append(sessionB, { kind: "request", executionId: "e4", status: "approval_required", hash: "h4", steps: [step], approvalId: "ap_4", expiresAt: later(900).getTime() }, later(10));
    await appendFile(join(dir, "activity", "tester", "2026-11-25.jsonl"), "{not json\n");

    const rows = foldRequests(await log.readAll(), (s) => s.pid === sessionA.pid, later(20).getTime());

    expect(rows.map((r) => [r.session.port, r.state, r.decision?.decision ?? null, r.ran])).toEqual([
      [4748, "expired", "expired", false],
      [4748, "denied", "denied", false],
      [4747, "completed", "approved", true],
    ]);
    expect(rows[0]!.decision!.sessionEnded).toBe(true);
    expect(log.skipped()).toBe(1);
  });

  it("pushes a request another session appends to every open dashboard", async () => {
    const dir = await tempDir();
    const { origin, cookie } = await startOne(dir);
    const stream = await fetch(`${origin}/events`, { headers: { cookie } });
    const reader = stream.body!.pipeThrough(new TextDecoderStream()).getReader();
    cleanups.push(() => reader.cancel());
    await reader.read();

    await createActivityLog(dir, "tester").append({ ...sessionB, pid: process.pid }, { kind: "request", executionId: "e9", status: "approval_required", hash: "h9", steps: [step], approvalId: "ap_9" });

    let received = "";
    while (!received.includes("ap_9") && !received.includes("notes.md")) received += (await reader.read()).value;
    const update = JSON.parse(received.split("data: ").at(-1)!);
    expect(update.rows).toEqual([expect.objectContaining({ list: "waiting", html: expect.stringContaining("fs.write_file") })]);
    expect(update.waiting).toBe(1);
  });

  it("signals another session only when it is listed, alive, and confirms its pid", async () => {
    const dir = await tempDir();
    const signalled: number[] = [];
    const a = await startOne(dir, (pid) => signalled.push(pid));
    const b = await startOne(dir);
    const open = (port: number, headers: Record<string, string> = { cookie: a.cookie, origin: a.origin }) =>
      fetch(`${a.origin}/sessions/${port}/open`, { method: "POST", redirect: "manual", headers });

    expect((await open(b.dashboard.port)).status).toBe(303);
    expect(signalled).toEqual([process.pid]);

    expect((await open(b.dashboard.port, { cookie: a.cookie })).status).toBe(403);
    expect((await open(1)).status).toBe(404);
    await writeFile(join(dir, `approver-${b.dashboard.port}.json`), JSON.stringify({ port: b.dashboard.port, pid: 2 ** 22 + 7, user: "tester" }));
    expect((await open(b.dashboard.port)).status).toBe(404);
    await writeFile(join(dir, `approver-${b.dashboard.port}.json`), JSON.stringify({ port: b.dashboard.port, pid: process.ppid, user: "tester" }));
    expect((await open(b.dashboard.port)).status).toBe(404);
    expect(signalled).toEqual([process.pid]);
  });

  it("never renders markup from an agent-supplied approval ID or a forged log line, and pins its scripts", async () => {
    const dir = await tempDir();
    const { dashboard, approvals, origin, cookie } = await startOne(dir);
    const gateway = createGateway({
      agent: "claude-code",
      upstreams: [{ name: "fs", tools: [{ name: "write_file", inputSchema: { type: "object" } }], call: async () => "ok" }],
      remotes: { names: () => [], list: () => [], requestConnect: () => "", waitFor: async () => {} },
      classification: { fs: { trusted: [], untrusted: [], sinks: ["write_file"] } },
      policy: createPolicy(`permit(principal, action, resource);`),
      confidential: createConfidential(resolveClasses()),
      approvals,
      notifyApprover: dashboard.announce,
      audit: () => {},
      record: (request) => dashboard.append({ kind: "request", ...request }),
      limits: { timeoutMs: 2_000, memoryBytes: 32 * 1024 * 1024 },
      approvalWaitMs: 100,
    });
    const injected = `ap_x"><img src=x onerror=alert(1)>`;

    await gateway.execute(`await fs.write_file({ path: "notes.md" });`, injected);
    await appendFile(
      join(dir, "activity", "tester", `${new Date().toISOString().slice(0, 10)}.jsonl`),
      `${JSON.stringify({ v: 1, at: new Date().toISOString(), session: { port: `1"><img src=y onerror=alert(2)>`, pid: process.pid, agent: "x", user: "tester" }, kind: "request", executionId: `e"><b>`, status: "approval_required", approvalId: injected })}\n`,
    );
    await new Promise((resolve) => setTimeout(resolve, 2_500));
    const home = await fetch(`${origin}/`, { headers: { cookie } });
    const html = await home.text();

    expect(html).toContain("fs.write_file");
    expect(html).not.toMatch(/<img src=[xy]|<b>/);
    expect(home.headers.get("content-security-policy")).toMatch(/script-src 'sha256-[^']+' 'sha256-[^']+';/);
  });
});
