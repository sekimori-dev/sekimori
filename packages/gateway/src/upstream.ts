import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import type { UpstreamConfig } from "./config.ts";

export type JsonSchema = {
  type?: string | string[];
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: unknown[];
  description?: string;
};

export interface Tool {
  name: string;
  description?: string;
  inputSchema: JsonSchema;
  outputSchema?: JsonSchema;
}

export interface Upstream {
  name: string;
  tools: Tool[];
  call(tool: string, args: unknown): Promise<unknown>;
}

export async function connectUpstream(config: UpstreamConfig): Promise<Upstream & { close(): Promise<void> }> {
  const client = new Client({ name: "sekimori-gateway", version: "0.0.0" });
  await client.connect(
    new StdioClientTransport({
      command: config.command,
      args: config.args,
      env: { ...(process.env as Record<string, string>), ...config.env },
      stderr: "inherit",
    }),
  );
  const { tools } = await client.listTools();

  return {
    name: config.name,
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema as JsonSchema,
      outputSchema: t.outputSchema as JsonSchema | undefined,
    })),
    async call(tool, args) {
      const result = await client.callTool({ name: tool, arguments: (args ?? {}) as Record<string, unknown> });
      const text = Array.isArray(result.content)
        ? result.content.flatMap((c) => (c.type === "text" ? [c.text] : [])).join("\n")
        : "";
      if (result.isError) throw new Error(text || `${config.name}.${tool} failed`);
      return result.structuredContent ?? text;
    },
    close: () => client.close(),
  };
}
