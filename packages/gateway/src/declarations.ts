import type { JsonSchema, Upstream } from "./upstream.ts";

function toTs(schema: JsonSchema | undefined): string {
  if (!schema) return "unknown";
  if (schema.enum) return schema.enum.map((v) => JSON.stringify(v)).join(" | ");
  const type = Array.isArray(schema.type) ? schema.type[0] : schema.type;
  switch (type) {
    case "string":
      return "string";
    case "number":
    case "integer":
      return "number";
    case "boolean":
      return "boolean";
    case "null":
      return "null";
    case "array":
      return `Array<${toTs(schema.items)}>`;
    case "object": {
      const required = new Set(schema.required ?? []);
      const fields = Object.entries(schema.properties ?? {}).map(
        ([key, value]) => `${JSON.stringify(key)}${required.has(key) ? "" : "?"}: ${toTs(value)}`,
      );
      return fields.length ? `{ ${fields.join("; ")} }` : "Record<string, unknown>";
    }
    default:
      return "unknown";
  }
}

export function renderDeclarations(upstreams: Upstream[]): string {
  return upstreams
    .map((upstream) => {
      const methods = upstream.tools.map((tool) => {
        const doc = tool.description ? `  /** ${tool.description.replace(/\*\//g, "* /").replace(/\s+/g, " ")} */\n` : "";
        return `${doc}  ${JSON.stringify(tool.name)}(args: ${toTs(tool.inputSchema)}): Promise<${toTs(tool.outputSchema)}>;`;
      });
      return `declare const ${upstream.name}: {\n${methods.join("\n")}\n};`;
    })
    .join("\n\n");
}
