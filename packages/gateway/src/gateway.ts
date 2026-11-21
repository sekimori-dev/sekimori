import { randomUUID } from "node:crypto";
import type { Limits } from "./config.ts";
import { renderDeclarations } from "./declarations.ts";
import type { CallRequest, Decision } from "./policy.ts";
import { runProgram, type Bindings } from "./sandbox.ts";
import type { Upstream } from "./upstream.ts";

export interface CallRecord {
  n: number;
  tool: string;
  decision: "allow" | "deny";
  ok: boolean;
}

export type ExecuteResult = { executionId: string; calls: CallRecord[] } & (
  | { ok: true; value: unknown }
  | { ok: false; error: string }
);

export type AuditEvent =
  | { type: "call"; executionId: string; agent: string; n: number; tool: string; decision: Decision; ok: boolean }
  | { type: "execution"; executionId: string; agent: string; ok: boolean; error?: string; calls: number };

export interface GatewayOptions {
  agent: string;
  upstreams: Upstream[];
  authorize: (request: CallRequest) => Decision;
  audit: (event: AuditEvent) => void;
  limits: Limits;
}

export function createGateway({ agent, upstreams, authorize, audit, limits }: GatewayOptions) {
  const declarations = renderDeclarations(upstreams);

  return {
    describe: () => declarations,

    async execute(code: string): Promise<ExecuteResult> {
      const executionId = randomUUID();
      const calls: CallRecord[] = [];

      const bindings: Bindings = Object.fromEntries(
        upstreams.map((upstream) => [
          upstream.name,
          Object.fromEntries(
            upstream.tools.map((tool) => [
              tool.name,
              async (args: unknown) => {
                const n = calls.length + 1;
                const qualified = `${upstream.name}.${tool.name}`;
                const decision = authorize({ agent, upstream: upstream.name, tool: tool.name, args });
                const record: CallRecord = { n, tool: qualified, decision: decision.allowed ? "allow" : "deny", ok: false };
                calls.push(record);
                try {
                  if (!decision.allowed) throw new Error(`Denied by policy: ${qualified}`);
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
      audit({
        type: "execution",
        executionId,
        agent,
        ok: result.ok,
        error: result.ok ? undefined : result.error,
        calls: calls.length,
      });
      return { executionId, calls, ...result };
    },
  };
}
