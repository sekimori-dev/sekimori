import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { z } from "zod";

const identifier = z.string().regex(/^[a-z][a-zA-Z0-9_]*$/, "must be a lower-camel identifier");

const configSchema = z.object({
  agent: z.string().min(1),
  policies: z.string().min(1),
  upstreams: z
    .array(
      z.object({
        name: identifier,
        command: z.string().min(1),
        args: z.array(z.string()).default([]),
        env: z.record(z.string(), z.string()).default({}),
        classify: z
          .object({
            trusted: z.array(z.string()).default([]),
            untrusted: z.array(z.string()).default([]),
            sinks: z.array(z.string()).default([]),
          })
          .prefault({}),
      }),
    )
    .min(1),
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
    })
    .prefault({}),
});

export type GatewayConfig = z.infer<typeof configSchema>;
export type UpstreamConfig = GatewayConfig["upstreams"][number];
export type Limits = GatewayConfig["limits"];
export type Classification = UpstreamConfig["classify"];

export async function loadConfig(path: string): Promise<{ config: GatewayConfig; policyText: string }> {
  const config = configSchema.parse(JSON.parse(await readFile(path, "utf8")));
  const policyText = await readFile(resolve(dirname(path), config.policies), "utf8");
  return { config, policyText };
}
