import { createHash } from "node:crypto";
import ts from "typescript";
import type { Classification } from "./config.ts";

export type Literal = string | number | boolean;

export interface ToolClass {
  source: "trusted" | "untrusted" | null;
  sink: boolean;
}

export interface PlannedCall {
  tool: string;
  args: Record<string, Literal>;
  runtimeArgs: boolean;
  repeated: boolean;
}

export interface Plan {
  hash: string;
  calls: PlannedCall[];
  open: boolean;
  // Every upstream the code mentions, including through casts or aliases that keep a call out of `calls`.
  namespaces: string[];
}

const BANNED_IDENTIFIERS = new Set(["eval", "Function", "globalThis"]);

const LOOPS_AND_CALLBACKS = new Set([
  ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.ArrowFunction,
  ts.SyntaxKind.FunctionExpression,
  ts.SyntaxKind.FunctionDeclaration,
  ts.SyntaxKind.MethodDeclaration,
]);

function matches(pattern: string, tool: string): boolean {
  const source = pattern.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
  return new RegExp(`^${source}$`).test(tool);
}

export function classify(classification: Classification, tool: string): ToolClass {
  const sink = classification.sinks.some((p) => matches(p, tool));
  const source = classification.untrusted.some((p) => matches(p, tool))
    ? "untrusted"
    : classification.trusted.some((p) => matches(p, tool))
      ? "trusted"
      : null;
  if (!sink && !source) return { source: "untrusted", sink: true };
  return { source, sink };
}

function literal(node: ts.Expression): Literal | undefined {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(node.operand)) {
    return -Number(node.operand.text);
  }
  return undefined;
}

function readArgs(call: ts.CallExpression): Pick<PlannedCall, "args" | "runtimeArgs"> {
  const [first, ...rest] = call.arguments;
  if (!first) return { args: {}, runtimeArgs: false };
  if (!ts.isObjectLiteralExpression(first)) return { args: {}, runtimeArgs: true };
  const args: Record<string, Literal> = {};
  let runtimeArgs = rest.length > 0;
  for (const property of first.properties) {
    const name = property.name && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) ? property.name.text : undefined;
    const value = ts.isPropertyAssignment(property) ? literal(property.initializer) : undefined;
    if (name === undefined || value === undefined) runtimeArgs = true;
    else args[name] = value;
  }
  return { args, runtimeArgs };
}

function isPropertyName(node: ts.Identifier): boolean {
  const parent = node.parent;
  return (
    (ts.isPropertyAccessExpression(parent) && parent.name === node) ||
    (ts.isPropertyAssignment(parent) && parent.name === node) ||
    (ts.isMethodDeclaration(parent) && parent.name === node)
  );
}

export function extractPlan(code: string, namespaces: Set<string>): Plan {
  const file = ts.createSourceFile("program.ts", code, ts.ScriptTarget.ES2022, true);
  const calls: PlannedCall[] = [];
  const consumed = new Set<ts.Node>();
  const referenced = new Set<string>();
  let open = false;

  const visit = (node: ts.Node, repeated: boolean): void => {
    if (node.kind === ts.SyntaxKind.WithStatement) throw new Error("`with` is not allowed in Sekimori programs");
    if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      throw new Error("Dynamic import() is not allowed in Sekimori programs");
    }

    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      const target =
        ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)
          ? { ns: callee.expression, tool: callee.name.text }
          : ts.isElementAccessExpression(callee) && ts.isIdentifier(callee.expression) && ts.isStringLiteral(callee.argumentExpression)
            ? { ns: callee.expression, tool: callee.argumentExpression.text }
            : undefined;
      if (target && namespaces.has(target.ns.text)) {
        consumed.add(target.ns);
        calls.push({ tool: `${target.ns.text}.${target.tool}`, repeated, ...readArgs(node) });
      }
    }

    if (ts.isIdentifier(node) && !isPropertyName(node)) {
      if (BANNED_IDENTIFIERS.has(node.text)) throw new Error(`\`${node.text}\` is not allowed in Sekimori programs`);
      if (namespaces.has(node.text)) referenced.add(node.text);
      if (namespaces.has(node.text) && !consumed.has(node)) open = true;
    }

    const nested = repeated || LOOPS_AND_CALLBACKS.has(node.kind);
    ts.forEachChild(node, (child) => visit(child, nested));
  };

  visit(file, false);
  return { hash: `sha256:${createHash("sha256").update(code).digest("hex")}`, calls, open, namespaces: [...referenced] };
}

export interface PlanStep {
  tool: string;
  repeated: boolean;
  untrusted: boolean;
  sink: boolean;
  args: string[];
  runtimeArgs: boolean;
}

export interface Flow {
  source: string;
  sink: string;
  earlier: boolean;
}

export function planSteps(plan: Plan, classOf: (tool: string) => ToolClass): PlanStep[] {
  const byTool = new Map<string, PlannedCall[]>();
  for (const call of plan.calls) byTool.set(call.tool, [...(byTool.get(call.tool) ?? []), call]);
  return [...byTool].map(([tool, calls]) => {
    const kind = classOf(tool);
    return {
      tool,
      repeated: calls.length > 1 || calls.some((c) => c.repeated),
      untrusted: kind.source === "untrusted",
      sink: kind.sink,
      args: calls.flatMap((c) => Object.entries(c.args).map(([k, v]) => `${k}: ${JSON.stringify(v)}`)),
      runtimeArgs: calls.some((c) => c.runtimeArgs),
    };
  });
}

export function formatStep(step: PlanStep): string {
  const label = [step.untrusted ? "untrusted" : "", step.sink ? "sensitive" : ""].filter(Boolean).join(", ");
  const args = [...step.args, ...(step.runtimeArgs ? ["arguments decided at runtime"] : [])].join(", ");
  return [step.tool, step.repeated ? "×n" : "×1", label, args].filter(Boolean).join("  ");
}
