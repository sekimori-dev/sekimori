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
      }),
    )
    .min(1),
  limits: z
    .object({
      timeoutMs: z.number().int().positive().default(30_000),
      memoryBytes: z.number().int().positive().default(64 * 1024 * 1024),
    })
    .prefault({}),
});

export type GatewayConfig = z.infer<typeof configSchema>;
export type UpstreamConfig = GatewayConfig["upstreams"][number];
export type Limits = GatewayConfig["limits"];

export async function loadConfig(path: string): Promise<{ config: GatewayConfig; policyText: string }> {
  const config = configSchema.parse(JSON.parse(await readFile(path, "utf8")));
  const policyText = await readFile(resolve(dirname(path), config.policies), "utf8");
  return { config, policyText };
}
