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
      return request;
    },

    consume(id: string, codeHash: string): { ok: true; request: ApprovalRequest } | { ok: false; error: string } {
      const request = requests.get(id);
      if (!request) return { ok: false, error: `Unknown approval ${id}` };
      if (request.expiresAt <= now()) return { ok: false, error: `Approval ${id} has expired` };
      if (request.status === "pending") return { ok: false, error: `Approval ${id} is still waiting for a decision` };
      if (request.status === "denied") return { ok: false, error: `Approval ${id} was denied` };
      if (request.status === "used") return { ok: false, error: `Approval ${id} was already used` };
      if (request.plan.hash !== codeHash) return { ok: false, error: "Code does not match the approved program" };
      request.status = "used";
      return { ok: true, request };
    },
  };
}
