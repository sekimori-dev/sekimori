import { getQuickJS, shouldInterruptAfterDeadline, type QuickJSContext, type QuickJSDeferredPromise, type QuickJSHandle } from "quickjs-emscripten";
import ts from "typescript";
import type { Limits } from "./config.ts";

export type HostFunction = (args: unknown) => Promise<unknown>;
export type Bindings = Record<string, Record<string, HostFunction>>;
export type RunResult = { ok: true; value: unknown } | { ok: false; error: string };

function transpile(code: string): string {
  return ts.transpileModule(`(async () => {\n${code}\n})()`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText;
}

function errorMessage(context: QuickJSContext, handle: QuickJSHandle): string {
  const dumped = context.dump(handle);
  if (dumped && typeof dumped === "object" && "message" in dumped) {
    return `${dumped.name ?? "Error"}: ${dumped.message}`;
  }
  return String(dumped);
}

export async function runProgram(code: string, bindings: Bindings, limits: Limits): Promise<RunResult> {
  const QuickJS = await getQuickJS();
  const runtime = QuickJS.newRuntime();
  runtime.setMemoryLimit(limits.memoryBytes);
  runtime.setMaxStackSize(1024 * 1024);
  runtime.setInterruptHandler(shouldInterruptAfterDeadline(Date.now() + limits.timeoutMs));
  const context = runtime.newContext();
  const pending = new Set<QuickJSDeferredPromise>();
  let closed = false;
  let timer: NodeJS.Timeout | undefined;

  const toHandle = (value: unknown): QuickJSHandle =>
    value === undefined ? context.undefined : context.unwrapResult(context.evalCode(`(${JSON.stringify(value)})`));

  for (const [namespace, functions] of Object.entries(bindings)) {
    const object = context.newObject();
    for (const [name, host] of Object.entries(functions)) {
      const fn = context.newFunction(name, (argsHandle) => {
        const deferred = context.newPromise();
        pending.add(deferred);
        host(argsHandle ? context.dump(argsHandle) : undefined).then(
          (value) => {
            if (closed) return;
            const handle = toHandle(value);
            deferred.resolve(handle);
            handle.dispose();
          },
          (error: unknown) => {
            if (closed) return;
            const handle = context.newError(error instanceof Error ? error.message : String(error));
            deferred.reject(handle);
            handle.dispose();
          },
        );
        deferred.settled.then(() => {
          pending.delete(deferred);
          if (!closed) runtime.executePendingJobs();
        });
        return deferred.handle;
      });
      context.setProp(object, name, fn);
      fn.dispose();
    }
    context.setProp(context.global, namespace, object);
    object.dispose();
  }

  try {
    const evaluated = context.evalCode(transpile(code));
    if (evaluated.error) {
      const message = errorMessage(context, evaluated.error);
      evaluated.error.dispose();
      return { ok: false, error: message };
    }
    const promise = evaluated.value;
    const timeout = new Promise<"timeout">((resolve) => {
      timer = setTimeout(() => resolve("timeout"), limits.timeoutMs);
    });
    const resolved = context.resolvePromise(promise);
    // Without this, a program that settles before its first host call never resolves; host calls drain the queue later.
    runtime.executePendingJobs();
    const settled = await Promise.race([resolved, timeout]);
    promise.dispose();
    if (settled === "timeout") return { ok: false, error: `Program exceeded the ${limits.timeoutMs} ms limit` };
    if (settled.error) {
      const message = errorMessage(context, settled.error);
      settled.error.dispose();
      return { ok: false, error: message };
    }
    const value = context.dump(settled.value);
    settled.value.dispose();
    return { ok: true, value };
  } finally {
    clearTimeout(timer);
    closed = true;
    for (const deferred of pending) deferred.dispose();
    context.dispose();
    runtime.dispose();
  }
}
