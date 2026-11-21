import { checkParsePolicySet, isAuthorized, type CedarValueJson } from "@cedar-policy/cedar-wasm/nodejs";

export interface CallRequest {
  agent: string;
  upstream: string;
  tool: string;
  args: unknown;
}

export interface Decision {
  allowed: boolean;
  reasons: string[];
  errors: string[];
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

export function createPolicy(policyText: string): (request: CallRequest) => Decision {
  const parsed = checkParsePolicySet({ staticPolicies: policyText });
  if (parsed.type === "failure") {
    throw new Error(`Invalid Cedar policies: ${parsed.errors.map((e) => e.message).join("; ")}`);
  }

  return ({ agent, upstream, tool, args }) => {
    const answer = isAuthorized({
      principal: { type: "Agent", id: agent },
      action: { type: "Action", id: "call" },
      resource: { type: "Tool", id: `${upstream}.${tool}` },
      context: { upstream, tool, args: toCedar(args) ?? {} },
      policies: { staticPolicies: policyText },
      entities: [],
    });
    if (answer.type === "failure") {
      return { allowed: false, reasons: [], errors: answer.errors.map((e) => e.message) };
    }
    const { decision, diagnostics } = answer.response;
    return {
      allowed: decision === "allow",
      reasons: diagnostics.reason,
      errors: diagnostics.errors.map((e) => e.error.message),
    };
  };
}
