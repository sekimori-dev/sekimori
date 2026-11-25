import { randomBytes } from "node:crypto";
import type { Counts, Reveal } from "./confidential.ts";
import type { CallRecord } from "./gateway.ts";
import type { Flow, Plan, PlanStep } from "./plan.ts";

// A result held at the checkpoint: already scrubbed, returned on approval without running the program again.
export type HeldResult =
  | { status: "completed"; value: unknown; calls: CallRecord[]; confidential?: Counts }
  | { status: "failed"; error: string; calls: CallRecord[]; confidential?: Counts };

export interface ApprovalRequest {
  id: string;
  agent: string;
  code: string;
  plan: Plan;
  steps: PlanStep[];
  flows: Flow[];
  reasons: string[];
  reveals?: Array<Reveal & { tool: string }>;
  held?: HeldResult;
  status: "pending" | "approved" | "denied" | "used" | "expired";
  expiresAt: number;
}

export type ApprovalStore = ReturnType<typeof createApprovalStore>;

export type ApprovalChange = { type: "requested" | "approved" | "denied" | "used" | "expired"; request: ApprovalRequest };

export function createApprovalStore(ttlMs: number, now: () => number = Date.now) {
  const requests = new Map<string, ApprovalRequest>();
  const waiters = new Map<string, Set<() => void>>();
  const listeners = new Set<(change: ApprovalChange) => void>();
  const emit = (change: ApprovalChange) => {
    for (const listener of listeners) listener(change);
  };

  return {
    request(fields: Pick<ApprovalRequest, "agent" | "code" | "plan" | "steps" | "flows" | "reasons" | "reveals" | "held">): ApprovalRequest {
      const request: ApprovalRequest = {
        ...fields,
        id: `ap_${randomBytes(9).toString("base64url")}`,
        status: "pending",
        expiresAt: now() + ttlMs,
      };
      requests.set(request.id, request);
      emit({ type: "requested", request });
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
      emit({ type: request.status, request });
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
      emit({ type: "used", request });
      return { ok: true, request };
    },

    onChange(listener: (change: ApprovalChange) => void): void {
      listeners.add(listener);
    },

    // Marks approvals that ran out undecided, or approved but never used, as expired.
    sweep(): void {
      for (const request of requests.values()) {
        if ((request.status === "pending" || request.status === "approved") && request.expiresAt <= now()) {
          request.status = "expired";
          emit({ type: "expired", request });
        }
      }
    },
  };
}
