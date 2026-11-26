import { readFile } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, resolve } from "node:path";
import { z } from "zod";

const identifier = z.string().regex(/^[a-z][a-zA-Z0-9_]*$/, "must be a lower-camel identifier");

const classify = z
  .object({
    trusted: z.array(z.string()).default([]),
    untrusted: z.array(z.string()).default([]),
    sinks: z.array(z.string()).default([]),
  })
  .prefault({});

const stdioUpstream = z.object({
  name: identifier,
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({}),
  classify,
});

const remoteUpstream = z.object({
  name: identifier,
  url: z.url({ protocol: /^https?$/ }),
  oauth: z.object({ clientId: z.string().min(1), clientSecret: z.string().optional(), scope: z.string().optional() }).optional(),
  classify,
});

const confidentialClass = z.object({
  enabled: z.boolean().optional(),
  mode: z.enum(["withhold", "pseudonymise"]).optional(),
  fields: z.array(z.string().min(1)).optional(),
  patterns: z.array(z.string().min(1)).optional(),
  sources: z.array(z.string().min(1)).optional(),
});

const configSchema = z.object({
  agent: z.string().min(1),
  // Names a directory under ~/.sekimori/credentials, so it stays a plain path segment.
  user: z
    .string()
    .regex(/^[\w.-]+$/)
    .default(() => userInfo().username),
  policies: z.string().min(1),
  upstreams: z.array(z.union([stdioUpstream, remoteUpstream])).min(1),
  confidential: z.object({ classes: z.record(z.string().regex(/^[a-z][\w-]*$/), confidentialClass).default({}) }).prefault({}),
  limits: z
    .object({
      timeoutMs: z.number().int().positive().default(30_000),
      memoryBytes: z.number().int().positive().default(64 * 1024 * 1024),
    })
    .prefault({}),
  approvals: z
    .object({
      port: z.number().int().min(1).max(65535).default(4747),
      ttlMinutes: z.number().positive().default(15),
      openBrowser: z.boolean().default(true),
      waitSeconds: z.number().int().min(0).max(300).default(45),
    })
    .prefault({}),
});

export type GatewayConfig = z.infer<typeof configSchema>;
export type StdioUpstreamConfig = z.infer<typeof stdioUpstream>;
export type RemoteUpstreamConfig = z.infer<typeof remoteUpstream>;
export type Limits = GatewayConfig["limits"];
export type Classification = StdioUpstreamConfig["classify"];

export async function loadConfig(path: string): Promise<{ config: GatewayConfig; policyText: string }> {
  const config = configSchema.parse(JSON.parse(await readFile(path, "utf8")));
  const policyText = await readFile(resolve(dirname(path), config.policies), "utf8");
  return { config, policyText };
}
