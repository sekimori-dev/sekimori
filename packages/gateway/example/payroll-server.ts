#!/usr/bin/env node
// Example payroll MCP server with fictional data, for trying Sekimori's confidential-data rules.
// It returns JSON as text, the way most MCP servers do.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const employees = [
  { id: "E-101", name: "Mara Beispiel", department: "Sales", iban: "AT61 1904 3002 3457 3201", salary: 52000 },
  { id: "E-102", name: "Jon Example", department: "Sales", iban: "DE89 3704 0044 0532 0130 00", salary: 61000 },
  { id: "E-103", name: "Lea Muster", department: "Engineering", iban: "AT48 3200 0000 1234 5864", salary: 68500 },
];

const server = new McpServer({ name: "example-payroll", version: "0.0.0" });
const text = (value: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(value) }] });

server.registerTool(
  "list_employees",
  { description: "Lists employees with department, IBAN and yearly salary (fictional example data).", inputSchema: { department: z.string().optional() } },
  async ({ department }) => text(employees.filter((e) => !department || e.department === department)),
);

server.registerTool(
  "update_bank_details",
  { description: "Sets an employee's IBAN.", inputSchema: { id: z.string(), iban: z.string() } },
  async ({ id, iban }) => {
    const employee = employees.find((e) => e.id === id);
    if (!employee) return { content: [{ type: "text", text: `No employee ${id}` }], isError: true };
    employee.iban = iban;
    return text({ updated: id, iban });
  },
);

await server.connect(new StdioServerTransport());
