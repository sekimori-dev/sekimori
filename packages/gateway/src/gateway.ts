import { randomUUID } from "node:crypto";
import type { ApprovalStore } from "./approvals.ts";
import type { Classification, Limits } from "./config.ts";
import { renderDeclarations } from "./declarations.ts";
import { classify, describePlan, extractPlan, type Plan, type ToolClass } from "./plan.ts";
import type { Decision, Policy } from "./policy.ts";
import { runProgram, type Bindings } from "./sandbox.ts";
import type { Upstream } from "./upstream.ts";

export interface CallRecord {
  n: number;
  tool: string;
  decision: "allow" | "deny" | "blocked";
  ok: boolean;
}

export type ExecuteResult = { executionId: string } & (
  | { status: "completed"; value: unknown; calls: CallRecord[] }
  | { status: "failed"; error: string; calls: CallRecord[] }
  | { status: "rejected"; error: string }
  | { status: "approval_required"; approvalId: string; approveAt: string; plan: string[]; reasons: string[] }
);

export type AuditEvent = { executionId: string; agent: string } & (
  | { type: "plan"; hash: string; calls: number; open: boolean; reasons: string[] }
  | { type: "approval_requested"; approvalId: string }
  | { type: "approval_used"; approvalId: string }
  | { type: "call"; n: number; tool: string; decision: Decision; ok: boolean }
  | { type: "grant_applied"; tool: string; source: string; reasons: string[] }
  | { type: "blocked"; tool: string; reason: string }
  | { type: "execution"; status: ExecuteResult["status"]; error?: string; calls: number }
);

export interface GatewayOptions {
  agent: string;
  upstreams: Upstream[];
  classification: Record<string, Classification>;
  policy: Policy;
  approvals: ApprovalStore;
  notifyApprover: (approvalId: string) => string;
  audit: (event: AuditEvent) => void;
  limits: Limits;
}

function splitTool(qualified: string): { upstream: string; tool: string } {
  const dot = qualified.indexOf(".");
  return { upstream: qualified.slice(0, dot), tool: qualified.slice(dot + 1) };
}

export function createGateway(options: GatewayOptions) {
  const { agent, upstreams, policy, approvals, audit, limits } = options;
  const declarations = renderDeclarations(upstreams);
  const namespaces = new Set(upstreams.map((u) => u.name));

  const classOf = (qualified: string): ToolClass => {
    const { upstream, tool } = splitTool(qualified);
    return classify(options.classification[upstream] ?? { trusted: [], untrusted: [], sinks: [] }, tool);
  };

  // Returns why a human must look at this program before it runs; empty means it may run as is.
  function approvalReasons(plan: Plan): { reasons: string[]; denied?: string } {
    const reasons: string[] = [];
    for (const call of plan.calls.filter((c) => !c.runtimeArgs)) {
      const decision = policy.authorizeCall({ agent, ...splitTool(call.tool), args: call.args });
      if (!decision.allowed) return { reasons, denied: `Denied by policy: ${call.tool}` };
      if (decision.approvalRequired) reasons.push(`Policy requires approval for ${call.tool}`);
    }
    const sources = [...new Set(plan.calls.map((c) => c.tool).filter((t) => classOf(t).source === "untrusted"))];
    for (const sink of plan.calls.filter((c) => classOf(c.tool).sink)) {
      for (const source of sources) {
        if (!policy.authorizeFlow({ agent, source, sink: sink.tool, args: sink.args }).allowed) {
          reasons.push(`Untrusted data from ${source} may reach ${sink.tool}`);
        }
      }
    }
    if (plan.open) reasons.push("The program uses tools in ways Sekimori cannot read before running");
    return { reasons: [...new Set(reasons)] };
  }

  return {
    describe: () => declarations,

    async execute(code: string, approvalId?: string): Promise<ExecuteResult> {
      const executionId = randomUUID();
      const finish = (result: ExecuteResult): ExecuteResult => {
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
      const { reasons, denied } = approvalReasons(plan);
      audit({ type: "plan", executionId, agent, hash: plan.hash, calls: plan.calls.length, open: plan.open, reasons });
      if (denied) return finish({ executionId, status: "rejected", error: denied });

      let approved = false;
      if (approvalId) {
        const consumed = approvals.consume(approvalId, plan.hash);
        if (!consumed.ok) return finish({ executionId, status: "rejected", error: consumed.error });
        approved = true;
        audit({ type: "approval_used", executionId, agent, approvalId });
      } else if (reasons.length > 0) {
        const request = approvals.request({ agent, code, plan, summary: describePlan(plan, classOf), reasons });
        audit({ type: "approval_requested", executionId, agent, approvalId: request.id });
        return finish({
          executionId,
          status: "approval_required",
          approvalId: request.id,
          approveAt: options.notifyApprover(request.id),
          plan: request.summary,
          reasons,
        });
      }

      const plannedTools = new Set(plan.calls.map((c) => c.tool));
      const untrustedSeen = new Set<string>();
      const calls: CallRecord[] = [];

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
        upstreams.map((upstream) => [
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
                  if (classOf(qualified).source === "untrusted") untrustedSeen.add(qualified);
                  const result = await upstream.call(tool.name, args);
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

      const result = await runProgram(code, bindings, limits);
      return finish(
        result.ok
          ? { executionId, status: "completed", value: result.value, calls }
          : { executionId, status: "failed", error: result.error, calls },
      );
    },
  };
}
