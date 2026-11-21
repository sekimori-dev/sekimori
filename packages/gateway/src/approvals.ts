import { randomBytes } from "node:crypto";
import type { Plan } from "./plan.ts";

export interface ApprovalRequest {
  id: string;
  agent: string;
  code: string;
  plan: Plan;
  summary: string[];
  reasons: string[];
  status: "pending" | "approved" | "denied" | "used";
  expiresAt: number;
}

export type ApprovalStore = ReturnType<typeof createApprovalStore>;

export function createApprovalStore(ttlMs: number, now: () => number = Date.now) {
  const requests = new Map<string, ApprovalRequest>();
  const waiters = new Map<string, Set<() => void>>();

  return {
    request(fields: Pick<ApprovalRequest, "agent" | "code" | "plan" | "summary" | "reasons">): ApprovalRequest {
      const request: ApprovalRequest = {
        ...fields,
        id: `ap_${randomBytes(9).toString("base64url")}`,
        status: "pending",
        expiresAt: now() + ttlMs,
      };
      requests.set(request.id, request);
      return request;
    },

    get: (id: string) => requests.get(id),

    pending: () => [...requests.values()].filter((r) => r.status === "pending" && r.expiresAt > now()),

    decide(id: string, approve: boolean): ApprovalRequest | undefined {
      const request = requests.get(id);
      if (!request || request.status !== "pending" || request.expiresAt <= now()) return undefined;
      request.status = approve ? "approved" : "denied";
      for (const wake of waiters.get(id) ?? []) wake();
      waiters.delete(id);
      return request;
    },

    // Resolves once the human decides or the wait elapses, whichever comes first.
    waitForDecision(id: string, ms: number): Promise<void> {
      if (requests.get(id)?.status !== "pending") return Promise.resolve();
      return new Promise((resolve) => {
        const wake = () => {
          clearTimeout(timer);
          waiters.get(id)?.delete(wake);
          resolve();
        };
        const timer = setTimeout(wake, ms);
        waiters.set(id, (waiters.get(id) ?? new Set()).add(wake));
      });
    },

    consume(id: string, codeHash: string): { ok: true; request: ApprovalRequest } | { ok: false; error: string } {
      const request = requests.get(id);
      if (!request) return { ok: false, error: `Unknown approval ${id}` };
      if (request.expiresAt <= now()) return { ok: false, error: `Approval ${id} has expired` };
      if (request.plan.hash !== codeHash) return { ok: false, error: "Code does not match the approved program" };
      if (request.status === "pending") return { ok: false, error: `Approval ${id} is still waiting for a decision` };
      if (request.status === "denied") return { ok: false, error: `Approval ${id} was denied` };
      if (request.status === "used") return { ok: false, error: `Approval ${id} was already used` };
      request.status = "used";
      return { ok: true, request };
    },
  };
}
