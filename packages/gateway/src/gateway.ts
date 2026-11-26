import { randomUUID } from "node:crypto";
import type { RequestFields } from "./activity.ts";
import type { ApprovalStore } from "./approvals.ts";
import type { Classification, Limits } from "./config.ts";
import type { Confidential, Counts, Reveal } from "./confidential.ts";
import { renderDeclarations } from "./declarations.ts";
import { classify, extractPlan, formatStep, planSteps, type Flow, type Plan, type ToolClass } from "./plan.ts";
import type { Decision, Policy } from "./policy.ts";
import { runProgram, type Bindings } from "./sandbox.ts";
import type { Remotes, Upstream } from "./upstream.ts";

export interface CallRecord {
  n: number;
  tool: string;
  decision: "allow" | "deny" | "blocked";
  ok: boolean;
}

export type ExecuteResult = { executionId: string } & (
  | { status: "completed"; value: unknown; calls: CallRecord[]; confidential?: Counts }
  | { status: "failed"; error: string; calls: CallRecord[]; confidential?: Counts }
  | { status: "rejected"; error: string }
  | { status: "approval_required"; approvalId: string; approveAt: string; plan: string[]; reasons: string[]; confidential?: Counts }
  | { status: "approval_pending"; approvalId: string }
  | { status: "connect_required"; upstreams: string[]; connectAt: string }
  | { status: "connect_pending"; upstreams: string[] }
  | { status: "connected"; upstreams: string[]; declarations: string }
);

export type AuditEvent = { executionId: string; agent: string } & (
  | { type: "plan"; hash: string; calls: number; open: boolean; reasons: string[] }
  | { type: "approval_requested"; approvalId: string }
  | { type: "approval_used"; approvalId: string }
  | { type: "call"; n: number; tool: string; decision: Decision; ok: boolean }
  | { type: "grant_applied"; tool: string; source: string; reasons: string[] }
  | { type: "blocked"; tool: string; reason: string }
  | { type: "execution"; status: ExecuteResult["status"]; error?: string; calls: number }
  | { type: "confidential_kept"; counts: Counts }
  | { type: "confidential_revealed"; tool: string; class: string; placeholder?: string }
);

export interface GatewayOptions {
  agent: string;
  upstreams: Upstream[];
  remotes: Pick<Remotes, "names" | "list" | "requestConnect" | "waitFor">;
  classification: Record<string, Classification>;
  policy: Policy;
  confidential: Confidential;
  approvals: ApprovalStore;
  notifyApprover: (approvalId: string) => string;
  audit: (event: AuditEvent) => void;
  record: (request: RequestFields) => void;
  limits: Limits;
  approvalWaitMs: number;
}

// Program errors can carry tool output, so only messages the gateway itself wrote go into the activity log.
const GATEWAY_ERROR = /^(\w+: )?((Denied by policy|Policy requires approval|Call outside the plan|Not covered by a grant or approval): [\w.-]+|Confidential [\w-]+ value may not be sent to [\w.-]+|Program exceeded the \d+ ms limit)$/;
function loggableError(result: ExecuteResult): string | undefined {
  if (result.status === "rejected") return result.error;
  if (result.status !== "failed") return undefined;
  return GATEWAY_ERROR.test(result.error) ? result.error : `Program failed (${/^(\w+):/.exec(result.error)?.[1] ?? "Error"})`;
}

function splitTool(qualified: string): { upstream: string; tool: string } {
  const dot = qualified.indexOf(".");
  return { upstream: qualified.slice(0, dot), tool: qualified.slice(dot + 1) };
}

export function createGateway(options: GatewayOptions) {
  const { agent, upstreams, remotes, policy, confidential, approvals, audit, limits } = options;
  const namespaces = new Set([...upstreams.map((u) => u.name), ...remotes.names()]);
  // Code hash -> remote upstreams that program was told to connect; its resubmit waits for them.
  const pendingConnects = new Map<string, string[]>();
  const connected = () => [...upstreams, ...remotes.list().flatMap((r) => (r.upstream ? [r.upstream] : []))];
  // Results reach the model, so an untrusted read taints every later program in this agent session.
  const sessionUntrusted = new Set<string>();

  const classOf = (qualified: string): ToolClass => {
    const { upstream, tool } = splitTool(qualified);
    return classify(options.classification[upstream] ?? { trusted: [], untrusted: [], sinks: [] }, tool);
  };

  // A confidential value may go back to the upstream it came from; anything else needs a reveal grant,
  // and a grant marked @approval("required") still needs the human.
  const revealDecision = (reveal: Reveal, tool: string): "allow" | "approval" | "deny" => {
    if (reveal.source !== undefined && splitTool(reveal.source).upstream === splitTool(tool).upstream) return "allow";
    const decision = policy.authorizeReveal({ agent, tool, class: reveal.class, source: reveal.source });
    return !decision.allowed ? "deny" : decision.approvalRequired ? "approval" : "allow";
  };

  // Returns why a human must look at this program before it runs; empty means it may run as is.
  function approvalReasons(plan: Plan): { reasons: string[]; flows: Flow[]; reveals: Array<Reveal & { tool: string }>; denied?: string } {
    const reasons: string[] = [];
    const flows: Flow[] = [];
    const reveals: Array<Reveal & { tool: string }> = [];
    for (const call of plan.calls) {
      // With runtime arguments only the static ones are known, so a deny here is not final; Cedar decides again at runtime.
      const decision = policy.authorizeCall({ agent, ...splitTool(call.tool), args: call.args });
      if (!decision.allowed && !call.runtimeArgs) return { reasons, flows, reveals, denied: `Denied by policy: ${call.tool}` };
      if (decision.approvalRequired) reasons.push(`Policy requires approval for ${call.tool}`);
      for (const reveal of confidential.placeholdersIn(JSON.stringify(call.args))) {
        if (revealDecision(reveal, call.tool) === "allow") continue;
        reveals.push({ ...reveal, tool: call.tool });
        reasons.push(`Confidential ${reveal.class} value would be sent to ${call.tool}`);
      }
    }
    // A model that read untrusted data may have been told to encode confidential values; see the confidential data spec, section 7.
    const confidentialSource = plan.calls.find((c) => confidential.isSource(c.tool));
    if (sessionUntrusted.size > 0 && confidentialSource) reasons.push(`Reads confidential data from ${confidentialSource.tool} after untrusted input`);
    const planned = plan.calls.map((c) => c.tool).filter((t) => classOf(t).source === "untrusted");
    const sources = [...new Set([...planned, ...sessionUntrusted])];
    for (const sink of plan.calls.filter((c) => classOf(c.tool).sink)) {
      for (const source of sources) {
        if (!policy.authorizeFlow({ agent, source, sink: sink.tool, args: sink.args }).allowed) {
          const earlier = !planned.includes(source);
          if (!flows.some((f) => f.source === source && f.sink === sink.tool)) flows.push({ source, sink: sink.tool, earlier });
          reasons.push(`Untrusted data from ${source}${earlier ? " (read earlier in this session)" : ""} may reach ${sink.tool}`);
        }
      }
    }
    if (plan.open) reasons.push("The program uses tools in ways Sekimori cannot read before running");
    return { reasons: [...new Set(reasons)], flows, reveals };
  }

  return {
    describe(): string {
      const notes = remotes.list().flatMap((r) =>
        r.state === "connected"
          ? []
          : r.state === "unavailable"
            ? [`// Unavailable: ${r.name} (${r.reason}). Programs that use \`${r.name}\` are rejected.`]
            : [`// Not connected yet: ${r.name}. A program that uses \`${r.name}\` asks the user to connect it.`],
      );
      return [renderDeclarations(connected()), ...notes, confidential.describe()].filter(Boolean).join("\n\n");
    },

    async execute(code: string, approvalId?: string): Promise<ExecuteResult> {
      const executionId = randomUUID();
      let planned: Pick<RequestFields, "hash" | "steps" | "open"> = {};
      const finish = (result: ExecuteResult): ExecuteResult => {
        // The agent supplies approvalId, so only an ID this gateway issued reaches the dashboard.
        const id = approvals.get(("approvalId" in result ? result.approvalId : approvalId) ?? "")?.id;
        options.record({
          executionId,
          status: result.status,
          ...planned,
          reasons: "reasons" in result ? result.reasons : undefined,
          approvalId: id,
          expiresAt: id ? approvals.get(id)?.expiresAt : undefined,
          upstreams: "upstreams" in result ? result.upstreams : undefined,
          calls: "calls" in result ? result.calls.length : 0,
          error: loggableError(result),
          confidential: "confidential" in result ? result.confidential : undefined,
        });
        if ("confidential" in result && result.confidential) audit({ type: "confidential_kept", executionId, agent, counts: result.confidential });
        audit({
          type: "execution",
          executionId,
          agent,
          status: result.status,
          error: "error" in result ? result.error : undefined,
          calls: "calls" in result ? result.calls.length : 0,
        });
        return result;
      };

      let plan: Plan;
      try {
        plan = extractPlan(code, namespaces);
      } catch (error) {
        return finish({ executionId, status: "rejected", error: (error as Error).message });
      }
      planned = { hash: plan.hash, steps: planSteps(plan, classOf), open: plan.open };
      const issued = approvalId ? approvals.get(approvalId) : undefined;
      options.record({
        executionId,
        status: approvalId || pendingConnects.has(plan.hash) ? "waiting" : "running",
        ...planned,
        approvalId: issued?.id,
        expiresAt: issued?.expiresAt,
      });

      const waitingFor = pendingConnects.get(plan.hash);
      if (waitingFor) {
        await remotes.waitFor(waitingFor, options.approvalWaitMs);
        const waited = remotes.list().filter((r) => waitingFor.includes(r.name));
        const failed = waited.find((r) => r.state === "unavailable");
        if (failed) {
          pendingConnects.delete(plan.hash);
          return finish({ executionId, status: "rejected", error: `Upstream ${failed.name} is unavailable: ${failed.reason}` });
        }
        const ready = waited.filter((r) => r.upstream);
        if (ready.length < waitingFor.length) return finish({ executionId, status: "connect_pending", upstreams: waitingFor });
        pendingConnects.delete(plan.hash);
        return finish({ executionId, status: "connected", upstreams: waitingFor, declarations: renderDeclarations(ready.map((r) => r.upstream!)) });
      }
      const missing = remotes.list().filter((r) => plan.namespaces.includes(r.name) && r.state !== "connected");
      const unavailable = missing.find((r) => r.state === "unavailable");
      if (unavailable) return finish({ executionId, status: "rejected", error: `Upstream ${unavailable.name} is unavailable: ${unavailable.reason}` });
      if (missing.length > 0) {
        const names = missing.map((r) => r.name);
        pendingConnects.set(plan.hash, names);
        return finish({ executionId, status: "connect_required", upstreams: names, connectAt: remotes.requestConnect(names) });
      }

      const { reasons, flows, reveals, denied } = approvalReasons(plan);
      audit({ type: "plan", executionId, agent, hash: plan.hash, calls: plan.calls.length, open: plan.open, reasons });
      if (denied) return finish({ executionId, status: "rejected", error: denied });

      let approved = false;
      let approvedReveals = new Set<string>();
      // Only an approval whose reasons named the confidential checkpoint lets a result skip the hold.
      let confidentialApproved = false;
      if (approvalId) {
        if (approvals.get(approvalId)?.plan.hash === plan.hash) {
          await approvals.waitForDecision(approvalId, options.approvalWaitMs);
          if (approvals.get(approvalId)?.status === "pending") return finish({ executionId, status: "approval_pending", approvalId });
        }
        const consumed = approvals.consume(approvalId, plan.hash);
        if (!consumed.ok) return finish({ executionId, status: "rejected", error: consumed.error });
        approved = true;
        audit({ type: "approval_used", executionId, agent, approvalId });
        const { held } = consumed.request;
        if (held) return finish({ executionId, ...held });
        approvedReveals = new Set((consumed.request.reveals ?? []).map((r) => `${r.tool} ${r.placeholder}`));
        confidentialApproved = consumed.request.reasons.some((r) => r.startsWith("Reads confidential data from"));
      } else if (reasons.length > 0) {
        const steps = planned.steps!;
        const request = approvals.request({ agent, code, plan, steps, flows, reasons, reveals });
        audit({ type: "approval_requested", executionId, agent, approvalId: request.id });
        return finish({
          executionId,
          status: "approval_required",
          approvalId: request.id,
          approveAt: options.notifyApprover(request.id),
          plan: [...steps.map(formatStep), ...(plan.open ? ["plus calls Sekimori cannot read before running"] : [])],
          reasons,
        });
      }

      const plannedTools = new Set(plan.calls.map((c) => c.tool));
      const untrustedBefore = sessionUntrusted.size > 0;
      const untrustedSeen = new Set<string>(sessionUntrusted);
      const calls: CallRecord[] = [];
      const counts: Counts = {};
      let touchedConfidential = false;

      const guard = (qualified: string, args: unknown): string | undefined => {
        if (!plannedTools.has(qualified) && !(approved && plan.open)) return "Call outside the plan";
        if (!classOf(qualified).sink || untrustedSeen.size === 0 || approved) return undefined;
        for (const source of untrustedSeen) {
          const flow = policy.authorizeFlow({ agent, source, sink: qualified, args });
          if (!flow.allowed) return "Not covered by a grant or approval";
          audit({ type: "grant_applied", executionId, agent, tool: qualified, source, reasons: flow.reasons });
        }
        return undefined;
      };

      const bindings: Bindings = Object.fromEntries(
        connected().map((upstream) => [
          upstream.name,
          Object.fromEntries(
            upstream.tools.map((tool) => [
              tool.name,
              async (args: unknown) => {
                const n = calls.length + 1;
                const qualified = `${upstream.name}.${tool.name}`;
                const blocked = guard(qualified, args);
                if (blocked) {
                  calls.push({ n, tool: qualified, decision: "blocked", ok: false });
                  audit({ type: "blocked", executionId, agent, tool: qualified, reason: blocked });
                  throw new Error(`${blocked}: ${qualified}`);
                }
                const decision = policy.authorizeCall({ agent, upstream: upstream.name, tool: tool.name, args });
                const record: CallRecord = { n, tool: qualified, decision: decision.allowed ? "allow" : "deny", ok: false };
                calls.push(record);
                try {
                  if (!decision.allowed) throw new Error(`Denied by policy: ${qualified}`);
                  if (decision.approvalRequired && !approved) throw new Error(`Policy requires approval: ${qualified}`);
                  if (classOf(qualified).source === "untrusted") {
                    untrustedSeen.add(qualified);
                    sessionUntrusted.add(qualified);
                  }
                  const outbound = confidential.outbound(args);
                  for (const reveal of outbound.reveals) {
                    if (revealDecision(reveal, qualified) !== "allow" && !approvedReveals.has(`${qualified} ${reveal.placeholder}`)) {
                      record.decision = "blocked";
                      const reason = `Confidential ${reveal.class} value may not be sent to ${qualified}`;
                      audit({ type: "blocked", executionId, agent, tool: qualified, reason });
                      throw new Error(reason);
                    }
                    confidential.count(counts, reveal.class, "revealed");
                    audit({ type: "confidential_revealed", executionId, agent, tool: qualified, class: reveal.class, placeholder: reveal.placeholder });
                  }
                  let result: unknown;
                  try {
                    result = await upstream.call(tool.name, outbound.args);
                  } catch (error) {
                    if (confidential.inspect(qualified, (error as Error).message) > 0) touchedConfidential = true;
                    throw error;
                  }
                  if (confidential.inspect(qualified, result) > 0) touchedConfidential = true;
                  record.ok = true;
                  return result;
                } finally {
                  audit({ type: "call", executionId, agent, n, tool: qualified, decision, ok: record.ok });
                }
              },
            ]),
          ),
        ]),
      );

      const run = await runProgram(code, bindings, limits);
      const outcome = run.ok
        ? { status: "completed" as const, value: confidential.scrub(run.value, counts), calls }
        : { status: "failed" as const, error: confidential.scrubText(run.error, counts), calls };
      const kept = Object.keys(counts).length > 0 ? { confidential: counts } : {};
      if (untrustedBefore && touchedConfidential && !confidentialApproved) {
        const reason = "Result computed from confidential data after untrusted input";
        const request = approvals.request({ agent, code, plan, steps: planned.steps!, flows: [], reasons: [reason], held: { ...outcome, ...kept } });
        audit({ type: "approval_requested", executionId, agent, approvalId: request.id });
        return finish({
          executionId,
          status: "approval_required",
          approvalId: request.id,
          approveAt: options.notifyApprover(request.id),
          plan: planned.steps!.map(formatStep),
          reasons: [reason],
          ...kept,
        });
      }
      return finish({ executionId, ...outcome, ...kept });
    },
  };
}
