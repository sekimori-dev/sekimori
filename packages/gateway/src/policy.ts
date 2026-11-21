import {
  checkParsePolicySet,
  isAuthorized,
  policySetTextToParts,
  policyToJson,
  type CedarValueJson,
} from "@cedar-policy/cedar-wasm/nodejs";

export interface CallRequest {
  agent: string;
  upstream: string;
  tool: string;
  args: unknown;
}

export interface FlowRequest {
  agent: string;
  source: string;
  sink: string;
  args: unknown;
}

export interface Decision {
  allowed: boolean;
  approvalRequired: boolean;
  reasons: string[];
  errors: string[];
}

export interface Policy {
  authorizeCall(request: CallRequest): Decision;
  authorizeFlow(request: FlowRequest): Decision;
}

// Agent-written arguments must not smuggle Cedar escapes (`__entity`, `__extn`) or values Cedar rejects.
function toCedar(value: unknown): CedarValueJson | undefined {
  if (value === null || value === undefined) return undefined;
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isSafeInteger(value) ? value : String(value);
  if (Array.isArray(value)) return value.map(toCedar).filter((v) => v !== undefined) as CedarValueJson[];
  if (typeof value === "object") {
    if (Object.keys(value).some((k) => k.startsWith("__"))) return JSON.stringify(value);
    const record: Record<string, CedarValueJson> = {};
    for (const [key, v] of Object.entries(value)) {
      const converted = toCedar(v);
      if (converted !== undefined) record[key] = converted;
    }
    return record;
  }
  return String(value);
}

function annotationsById(policyText: string): Map<string, Record<string, string>> {
  const parts = policySetTextToParts(policyText);
  if (parts.type === "failure") throw new Error(`Invalid Cedar policies: ${parts.errors.map((e) => e.message).join("; ")}`);
  return new Map(
    parts.policies.map((text, i) => {
      const json = policyToJson(text);
      const annotations = json.type === "success" ? ((json.json.annotations ?? {}) as Record<string, string>) : {};
      return [`policy${i}`, annotations];
    }),
  );
}

export function createPolicy(policyText: string): Policy {
  const parsed = checkParsePolicySet({ staticPolicies: policyText });
  if (parsed.type === "failure") {
    throw new Error(`Invalid Cedar policies: ${parsed.errors.map((e) => e.message).join("; ")}`);
  }
  const annotations = annotationsById(policyText);

  const decide = (agent: string, action: "call" | "flow", resource: string, context: Record<string, CedarValueJson>): Decision => {
    const answer = isAuthorized({
      principal: { type: "Agent", id: agent },
      action: { type: "Action", id: action },
      resource: { type: "Tool", id: resource },
      context,
      policies: { staticPolicies: policyText },
      entities: [],
    });
    if (answer.type === "failure") {
      return { allowed: false, approvalRequired: false, reasons: [], errors: answer.errors.map((e) => e.message) };
    }
    const { decision, diagnostics } = answer.response;
    return {
      allowed: decision === "allow",
      approvalRequired: decision === "allow" && diagnostics.reason.some((id) => annotations.get(id)?.approval === "required"),
      reasons: diagnostics.reason,
      errors: diagnostics.errors.map((e) => e.error.message),
    };
  };

  return {
    authorizeCall: ({ agent, upstream, tool, args }) =>
      decide(agent, "call", `${upstream}.${tool}`, { upstream, tool, args: toCedar(args) ?? {} }),
    authorizeFlow: ({ agent, source, sink, args }) =>
      decide(agent, "flow", sink, { source, sink, args: toCedar(args) ?? {} }),
  };
}
