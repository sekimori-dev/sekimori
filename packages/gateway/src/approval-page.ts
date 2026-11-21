import { randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import type { ApprovalRequest, ApprovalStore } from "./approvals.ts";

const escape = (value: string) =>
  value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const ASSETS: Record<string, { type: string; body: Buffer }> = Object.fromEntries(
  [
    ["jost.woff2", "font/woff2"],
    ["zen-old-mincho-400.woff2", "font/woff2"],
    ["seal.svg", "image/svg+xml"],
  ].map(([name, type]) => [name, { type: type!, body: readFileSync(new URL(`../assets/${name}`, import.meta.url)) }]),
);

const STYLE = `
@font-face { font-family: "Jost"; src: url("/assets/jost.woff2") format("woff2"); font-weight: 100 900; font-display: swap; }
@font-face { font-family: "Zen Old Mincho"; src: url("/assets/zen-old-mincho-400.woff2") format("woff2"); font-weight: 400; font-display: block; }
:root {
  --paper: #fff; --ink: #141414; --ink-2: #555; --ink-3: #707070; --hair: #e4e4e4; --hair-strong: #c9c9c9;
  --beni: #e8606a; --beni-ink: #c03a46; --beni-wash: #fcebec;
  --sans: "Jost", "Helvetica Neue", sans-serif; --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --mincho: "Zen Old Mincho", "Hiragino Mincho ProN", serif; --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --gutter: clamp(1.25rem, 5vw, 4.5rem);
  color-scheme: light; accent-color: var(--beni); scrollbar-color: var(--hair-strong) var(--paper); scrollbar-width: thin;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); font: 300 1rem/1.6 var(--sans); font-variant-numeric: tabular-nums; -webkit-font-smoothing: antialiased; }
::selection { background: var(--beni-wash); color: var(--beni-ink); }
a { color: inherit; text-decoration-thickness: 1px; text-underline-offset: 0.28em; }
:focus-visible { outline: 1px solid var(--beni); outline-offset: 4px; }
h1, h2, h3 { margin: 0; font-weight: 200; letter-spacing: -0.02em; line-height: 1.1; text-wrap: balance; }
p { margin: 0; text-wrap: pretty; }

.bar { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; padding: 1.25rem var(--gutter); border-bottom: 1px solid var(--hair); }
.mark { display: flex; align-items: baseline; gap: 0.5em; font-size: 1.25rem; font-weight: 300; letter-spacing: -0.02em; text-decoration: none; }
.mark [lang="ja"] { font-family: var(--mincho); font-weight: 400; font-size: 0.8em; letter-spacing: 0.08em; color: var(--beni); }
.bar-link { font-size: 0.875rem; color: var(--ink-2); }

.layout { display: grid; grid-template-columns: minmax(18rem, 24rem) minmax(0, 1fr); gap: clamp(2rem, 5vw, 5rem); padding: clamp(2rem, 5vw, 3.5rem) var(--gutter) 5rem; max-width: 90rem; margin: 0 auto; }
.decision { position: sticky; top: 2rem; align-self: start; display: grid; gap: 1.75rem; }
.decision h1 { font-size: clamp(2.2rem, 3.4vw, 3rem); }
.expiry { font-size: 0.9375rem; color: var(--ink-2); }
.expiry strong { font-weight: 400; color: var(--ink); }

.reasons { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--ink); }
.reasons li { padding: 0.9rem 0; border-bottom: 1px solid var(--hair); display: grid; gap: 0.2rem; }
.flow { display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem 0.6rem; font-size: 0.9375rem; }
.flow svg { width: 2.2rem; height: 0.6rem; flex: none; }
.flow svg path { fill: none; stroke: var(--beni); stroke-width: 1.2; }
.flow .sink { color: var(--beni-ink); }
.caption { font-size: 0.8125rem; color: var(--ink-3); }

.actions { display: flex; flex-wrap: wrap; gap: 0.75rem; }
.actions form { margin: 0; }
button { display: inline-flex; align-items: center; gap: 0.7rem; padding: 0.85rem 1.35rem; border: 1px solid var(--ink); border-radius: 0; background: var(--ink); color: var(--paper); font: inherit; font-weight: 400; font-size: 1rem; cursor: pointer; transition: background-color 0.4s var(--ease-out), color 0.4s var(--ease-out); }
button:hover { background: var(--paper); color: var(--ink); }
button img { width: 1.5rem; height: 1.5rem; }
button.deny { background: var(--paper); color: var(--ink); }
button.deny:hover { border-color: var(--beni); color: var(--beni-ink); }
.fine { font-size: 0.8125rem; color: var(--ink-3); max-width: 24rem; display: grid; gap: 0.15rem; }
.fine code { font-family: var(--sans); font-size: 0.8125rem; font-variant-numeric: tabular-nums; color: var(--ink-2); overflow-wrap: anywhere; }
.actions-late { display: none; border-top: 1px solid var(--ink); padding-top: 1.5rem; gap: 1rem; }

.outcome { display: grid; gap: 1rem; justify-items: start; }
.outcome img { width: 6rem; height: 6rem; transform: rotate(-4deg); animation: stamp 0.55s var(--ease-out) both; }
@keyframes stamp { from { opacity: 0; transform: scale(1.5) rotate(-4deg); } to { opacity: 1; transform: scale(1) rotate(-4deg); } }

.detail { display: grid; grid-template-columns: minmax(0, 1fr); gap: 3rem; min-width: 0; }
.panel { border-top: 1px solid var(--ink); }
.panel h2 { font-size: 1.375rem; font-weight: 300; padding: 1rem 0; }
.diagram { width: 100%; height: auto; display: block; margin: 0.25rem 0 1.25rem; }
.diagram.narrow { display: none; }
.diagram text { font-family: var(--sans); font-size: 13px; font-weight: 400; fill: var(--ink-3); }
.diagram .station text.earlier { fill: var(--beni-ink); }
.diagram .cp line { stroke: var(--beni); stroke-dasharray: 2 5; }
.diagram .station line { stroke: var(--hair-strong); }
.diagram .cp text { fill: var(--beni-ink); }
.diagram path { fill: none; stroke-width: 1.4; }
.diagram .in { stroke: var(--beni); }
.diagram .hold { stroke: var(--beni); stroke-dasharray: 3 4; }
.diagram .out { stroke: #f2b5ba; stroke-dasharray: 3 4; }
.diagram .slot { fill: var(--paper); stroke: var(--beni); stroke-dasharray: 3 3; }
.diagram.sealed .in, .diagram.sealed .hold, .diagram.sealed .out { stroke-dasharray: var(--len); stroke-dashoffset: 0; animation: draw 0.9s var(--ease-out) backwards; }
.diagram.sealed .in, .diagram.sealed .hold { stroke: var(--ink); }
.diagram.sealed .out { stroke: var(--beni); animation-delay: 0.45s; }
@keyframes draw { from { stroke-dashoffset: var(--len); } to { stroke-dashoffset: 0; } }

.steps { width: 100%; border-collapse: collapse; font-size: 0.9375rem; }
.steps tr { border-top: 1px solid var(--hair); }
.steps tr:last-child { border-bottom: 1px solid var(--hair); }
.steps td { padding: 0.75rem 1rem 0.75rem 0; vertical-align: baseline; }
.steps td:last-child { padding-right: 0; }
.steps .args { display: block; margin-top: 0.15rem; font-size: 0.8125rem; color: var(--ink-2); overflow-wrap: anywhere; }
.steps .count { color: var(--ink-3); white-space: nowrap; }
.steps .flag { font-size: 0.75rem; font-weight: 400; color: var(--beni-ink); white-space: nowrap; text-align: right; }

.code { margin: 0; padding: 1rem 0 0; font: 300 0.8125rem/1.8 var(--mono); counter-reset: line; }
.code > span { display: block; padding-left: 3.5rem; text-indent: -3.5rem; white-space: pre-wrap; overflow-wrap: anywhere; }
.code > span::before { counter-increment: line; content: counter(line); display: inline-block; width: 2.5rem; margin-right: 1rem; text-indent: 0; color: var(--ink-3); text-align: right; font-family: var(--sans); }
.code > span.sensitive { box-shadow: inset 1px 0 0 var(--beni); }
.code > span.sensitive::before { color: var(--beni-ink); }
.code i { font-style: normal; }
.code .k { color: var(--ink-3); }
.code .s { color: var(--beni-ink); }
.code .n { color: var(--ink-2); }

.queue { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--ink); }
.queue li { border-bottom: 1px solid var(--hair); }
.queue a { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 0.25rem 2rem; padding: 1.1rem 0; text-decoration: none; }
.queue a:hover .queue-title { text-decoration: underline; text-decoration-color: var(--beni); }
.queue-title { font-size: 1.0625rem; }
.queue .flow { flex-wrap: nowrap; white-space: nowrap; }
.queue .caption { grid-column: 1; }
.queue .when { grid-row: 1 / span 2; grid-column: 2; align-self: center; font-size: 0.875rem; color: var(--ink-2); }
.index { padding: clamp(2rem, 5vw, 3.5rem) var(--gutter) 5rem; display: grid; gap: 2rem; max-width: 90rem; margin: 0 auto; }
.index h1 { font-size: clamp(2.2rem, 3.4vw, 3rem); }
.empty { color: var(--ink-2); }

@media (max-width: 60rem) {
  .layout { grid-template-columns: minmax(0, 1fr); }
  .decision { position: static; }
  .decision .actions, .decision .fine { display: none; }
  .actions-late { display: grid; }
}
@media (max-width: 40rem) {
  .diagram.wide { display: none; }
  .diagram.narrow { display: block; }
  .queue a { grid-template-columns: minmax(0, 1fr); }
  .queue .when { grid-row: auto; grid-column: 1; }
  .queue .flow { white-space: normal; flex-wrap: wrap; }
}
@media (prefers-reduced-motion: reduce) {
  .outcome img { animation: none; }
  button { transition: none; }
  .diagram.sealed .in, .diagram.sealed .hold, .diagram.sealed .out { animation: none; stroke-dashoffset: 0; }
}
`;

function page(title: string, body: string, pendingCount?: number): string {
  const queue = pendingCount === undefined ? "" : `<a class="bar-link" href="/">${pendingCount === 1 ? "1 pending approval" : `${pendingCount} pending approvals`}</a>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escape(title)} · Sekimori</title><link rel="icon" href="/assets/seal.svg" type="image/svg+xml"><style>${STYLE}</style></head>
<body><header class="bar"><a class="mark" href="/">Sekimori <span lang="ja">関守</span></a>${queue}</header>${body}</body></html>`;
}

const ARROW = `<svg viewBox="0 0 36 10" aria-hidden="true"><path d="M0 5h32M28 1l4 4-4 4"/></svg>`;

function minutesLeft(request: ApprovalRequest): number {
  return Math.max(0, Math.ceil((request.expiresAt - Date.now()) / 60_000));
}

type DiagramState = "pending" | "sealed" | "stopped";

// The sealed draw-in animates stroke-dashoffset over each segment's real length.
function segment(cls: string, x1: number, y1: number, x2: number, y2: number): string {
  const len = Math.ceil(Math.hypot(x2 - x1, y2 - y1));
  return `<path class="${cls}" style="--len:${len}" d="M${x1} ${y1} L${x2} ${y2}"/>`;
}

// Reads left to right: source rails feed one junction on the checkpoint, where the seal sits; the train continues to the sensitive action.
function diagram(request: ApprovalRequest, state: DiagramState, width: number, variant: "wide" | "narrow"): string {
  const sources = [...new Map(request.flows.map((f) => [f.source, f.earlier])).entries()];
  const sinks = [...new Set(request.flows.map((f) => f.sink))];
  if (sources.length === 0) return "";
  const row = 52;
  const yOf = (r: number) => 34 + r * row;
  const narrow = variant === "narrow";
  const junction = { x: Math.round(width * (narrow ? 0.7 : 0.5)), y: (yOf(sources.length - 1) + yOf(sources.length)) / 2 };
  const depart = Math.round(width * (narrow ? 0.56 : 0.28));
  const arrive = Math.round(width * (narrow ? 0.84 : 0.72));
  const height = yOf(sources.length + sinks.length - 1) + 30;

  const rails = [
    ...sources.map(([tool, earlier], i) => {
      const y = yOf(i);
      return `<g class="station"><line x1="0" y1="${y}" x2="${depart}" y2="${y}"/><text x="0" y="${y - 9}"${earlier ? ' class="earlier"' : ""}>${escape(earlier && !narrow ? `${tool} · read earlier` : tool)}</text></g>`;
    }),
    ...sinks.map((tool, j) => {
      const y = yOf(sources.length + j);
      return `<g class="station"><line x1="${arrive}" y1="${y}" x2="${width}" y2="${y}"/><text x="${width}" y="${y + 19}" text-anchor="end">${escape(tool)}</text></g>`;
    }),
  ].join("");
  const checkpoint = `<g class="cp"><line x1="${junction.x}" y1="8" x2="${junction.x}" y2="${height - 4}"/><text x="${junction.x + (narrow ? -10 : 10)}" y="18"${narrow ? ' text-anchor="end"' : ""}>関 checkpoint</text></g>`;

  const inbound = sources.map((_, i) => segment("in", depart, yOf(i), junction.x - 18, junction.y));
  const hold = state === "stopped" ? "" : segment("hold", junction.x - 18, junction.y, junction.x + 18, junction.y);
  const outbound = state === "stopped" ? [] : sinks.map((_, j) => segment("out", junction.x + 18, junction.y, arrive, yOf(sources.length + j)));
  const seal =
    state === "sealed"
      ? `<image href="/assets/seal.svg" x="${junction.x - 18}" y="${junction.y - 18}" width="36" height="36" transform="rotate(-4 ${junction.x} ${junction.y})"/>`
      : state === "pending"
        ? `<rect class="slot" x="${junction.x - 18}" y="${junction.y - 18}" width="36" height="36"/>`
        : "";
  return `<svg class="diagram ${variant}${state === "sealed" ? " sealed" : ""}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Untrusted sources on the left run through the checkpoint to sensitive actions on the right">${checkpoint}${rails}${inbound.join("")}${hold}${outbound.join("")}${seal}</svg>`;
}

const KEYWORDS = /^(const|let|var|await|async|return|for|of|in|if|else|new|function|while|try|catch|throw)$/;

function highlight(line: string): string {
  return line.replace(/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|\b(\d+(?:\.\d+)?)\b|\b([A-Za-z_]\w*)\b|([^"'`\w]+|.)/g, (_, str, num, word, rest) => {
    if (str) return `<i class="s">${escape(str)}</i>`;
    if (num) return `<i class="n">${num}</i>`;
    if (word) return KEYWORDS.test(word) ? `<i class="k">${word}</i>` : escape(word);
    return escape(rest);
  });
}

function codeLines(request: ApprovalRequest): string {
  const sinkCalls = request.steps.filter((s) => s.sink).map((s) => s.tool.slice(s.tool.indexOf(".") + 1));
  return request.code
    .split("\n")
    .map((line) => {
      const sensitive = sinkCalls.some((tool) => line.includes(`.${tool}(`) || line.includes(`["${tool}"]`));
      return `<span${sensitive ? ' class="sensitive"' : ""}>${highlight(line) || " "}</span>`;
    })
    .join("");
}

function reasons(request: ApprovalRequest): string {
  const rows = request.flows.map(
    (f) => `<li><span class="flow">${escape(f.source)} ${ARROW} <span class="sink">${escape(f.sink)}</span></span></li>`,
  );
  const others = request.reasons.filter((r) => !r.startsWith("Untrusted data from")).map((r) => `<li><span>${escape(r)}</span></li>`);
  const earlier = request.flows.filter((f) => f.earlier).length;
  const caption =
    request.flows.length === 0
      ? ""
      : earlier === request.flows.length
        ? "These sources were read earlier in this session. Anything they contained may now reach these actions."
        : earlier === 0
          ? "This program reads untrusted data that may reach these actions."
          : "Untrusted data, some of it read earlier in this session, may reach these actions.";
  return `<ul class="reasons">${[...rows, ...others].join("")}</ul>${caption ? `<p class="caption">${caption}</p>` : ""}`;
}

function actions(request: ApprovalRequest): string {
  return `<div class="actions">
      <form method="post" action="/a/${request.id}/approve"><button><img src="/assets/seal.svg" alt="">Approve</button></form>
      <form method="post" action="/a/${request.id}/deny"><button class="deny">Deny</button></form>
    </div>`;
}

function fine(request: ApprovalRequest, note: string): string {
  return `<p class="fine"><span>${note}</span><span>Approval ${escape(request.id)} · agent ${escape(request.agent)}</span>
    <code title="${escape(request.plan.hash)}">${escape(request.plan.hash.slice(0, 23))}…</code></p>`;
}

function requestPage(request: ApprovalRequest, pendingCount: number): string {
  const expired = request.status === "pending" && request.expiresAt <= Date.now();
  const sealed = request.status === "approved" || request.status === "used";
  const pending = request.status === "pending" && !expired;
  const state: DiagramState = sealed ? "sealed" : pending ? "pending" : "stopped";

  const decision = pending
    ? `<h1>Seal this program?</h1>
       <p class="expiry">Expires in <strong>${minutesLeft(request)} min</strong>. Approving runs exactly this code once.</p>
       ${reasons(request)}${actions(request)}${fine(request, "If the agent changes the code, it needs a new seal.")}`
    : sealed
      ? `<div class="outcome"><img src="/assets/seal.svg" alt="Sealed"><h1>Sealed.</h1>
         <p class="expiry">The agent continues on its own.${request.status === "used" ? " The program has run." : ""}</p></div>
         ${fine(request, "Sealed for exactly this code.")}`
      : expired
        ? `<h1>This request expired.</h1><p class="expiry">The agent has to ask again with a new program run.</p>${fine(request, "Nothing ran.")}`
        : `<h1>Denied.</h1><p class="expiry">The agent was told and will not run this program.</p>${fine(request, "Nothing ran.")}`;

  const steps = request.steps
    .map((s) => {
      const args = [...s.args, ...(s.runtimeArgs ? ["arguments decided at runtime"] : [])].join(", ");
      return `<tr><td>${escape(s.tool)}${args ? `<span class="args">${escape(args)}</span>` : ""}</td><td class="count">${s.repeated ? "×n" : "×1"}</td>
        <td class="flag">${[s.untrusted ? "untrusted" : "", s.sink ? "sensitive" : ""].filter(Boolean).join(" · ")}</td></tr>`;
    })
    .join("");

  return page(
    `Approval ${request.id}`,
    `<main class="layout">
      <section class="decision" aria-label="Decision">${decision}</section>
      <div class="detail">
        <section class="panel"><h2>Plan</h2>${diagram(request, state, 760, "wide")}${diagram(request, state, 360, "narrow")}
          <table class="steps"><tbody>${steps}</tbody></table>
          ${request.plan.open ? '<p class="caption">The program also uses tools in ways Sekimori cannot read before running.</p>' : ""}</section>
        <section class="panel"><h2>Program</h2><pre class="code">${codeLines(request)}</pre></section>
        ${pending ? `<section class="actions-late" aria-label="Decision after review">${actions(request)}${fine(request, "If the agent changes the code, it needs a new seal.")}</section>` : ""}
      </div>
    </main>`,
    pendingCount,
  );
}

function indexPage(store: ApprovalStore): string {
  const pending = store.pending();
  const items = pending
    .map(
      (r) => `<li><a href="/a/${r.id}"><span class="queue-title flow">${r.flows[0] ? `${escape(r.flows[0].source)} ${ARROW} <span class="sink">${escape(r.flows[0].sink)}</span>` : escape(r.reasons[0] ?? r.id)}</span>
        <span class="caption">${escape(r.agent)} · ${escape(r.id)}${r.reasons.length > 1 ? ` · ${r.reasons.length} reasons` : ""}</span>
        <span class="when">expires in ${minutesLeft(r)} min</span></a></li>`,
    )
    .join("");
  return page(
    "Pending approvals",
    `<main class="index"><h1>${pending.length ? "Waiting for your seal." : "Nothing is waiting for your seal."}</h1>
      ${pending.length ? `<ul class="queue">${items}</ul>` : '<p class="empty">When an agent asks for approval, the request opens here.</p>'}</main>`,
    pending.length,
  );
}

const FORBIDDEN = page(
  "Approver session needed",
  `<main class="index"><h1>This browser is not signed in as the approver.</h1>
   <p class="empty">Sekimori opens approval requests in your browser when an agent asks for one. If nothing opened, run <code>pnpm approvals</code> in the Sekimori repository.</p></main>`,
);

function cookieToken(req: IncomingMessage): string | null {
  const match = (req.headers.cookie ?? "").match(/(?:^|;\s*)sekimori_approver=([\w-]+)/);
  return match?.[1] ?? null;
}

export function openInBrowser(url: string): Promise<string> {
  const [command, args] =
    process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  return new Promise((resolve) => {
    const child = spawn(command, args as string[], { stdio: "ignore" });
    child.on("error", (error) => resolve(`failed: ${error.message}`));
    child.on("exit", (code) => resolve(code === 0 ? "opened" : `failed: ${command} exited with ${code}`));
  });
}

// The approver credential never appears in anything the agent receives; it reaches the browser
// through the opened URL and lives on as an HttpOnly cookie. See docs/superpowers/specs/2026-11-21-slice-2-approvals-design.md section 6.
export async function startApprovalPage(
  store: ApprovalStore,
  options: { port: number; openBrowser: boolean; onNotified: (approvalId: string, outcome: string) => void },
) {
  let origin = `http://127.0.0.1:${options.port}`;
  const token = randomBytes(18).toString("base64url");
  const valid = (candidate: string | null) =>
    candidate !== null && candidate.length === token.length && timingSafeEqual(Buffer.from(candidate), Buffer.from(token));

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", origin);
    const send = (status: number, html: string) => {
      res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(html);
    };

    const asset = req.method === "GET" && url.pathname.startsWith("/assets/") ? ASSETS[url.pathname.slice(8)] : undefined;
    if (asset) {
      res.writeHead(200, { "content-type": asset.type, "cache-control": "max-age=3600" });
      return res.end(asset.body);
    }

    if (req.method === "GET" && valid(url.searchParams.get("t"))) {
      res.writeHead(303, {
        location: url.pathname,
        "set-cookie": `sekimori_approver=${token}; HttpOnly; SameSite=Strict; Path=/`,
        "cache-control": "no-store",
      });
      return res.end();
    }
    if (!valid(cookieToken(req))) return send(403, FORBIDDEN);

    const decision = req.method === "POST" ? url.pathname.match(/^\/a\/(ap_[\w-]+)\/(approve|deny)$/) : null;
    if (decision) {
      if (req.headers.origin !== origin) return send(403, FORBIDDEN);
      const decided = store.decide(decision[1]!, decision[2] === "approve");
      if (!decided) return send(409, page("Not pending", '<main class="index"><h1>This approval is no longer pending.</h1></main>'));
      res.writeHead(303, { location: `/a/${decided.id}` });
      return res.end();
    }
    if (req.method !== "GET") return send(405, page("Not allowed", '<main class="index"><h1>Method not allowed.</h1></main>'));

    const view = url.pathname.match(/^\/a\/(ap_[\w-]+)$/);
    if (view) {
      const request = store.get(view[1]!);
      return request
        ? send(200, requestPage(request, store.pending().length))
        : send(404, page("Not found", '<main class="index"><h1>Unknown approval.</h1></main>'));
    }
    return send(200, indexPage(store));
  });

  // Another gateway (e.g. a second Claude Code session) may hold the configured port; fall back to a free one.
  const port = await new Promise<number>((resolve, reject) => {
    const listen = (candidate: number) => server.listen(candidate, "127.0.0.1");
    server.once("listening", () => resolve((server.address() as AddressInfo).port));
    server.on("error", (error: NodeJS.ErrnoException) => (error.code === "EADDRINUSE" && server.listening === false ? listen(0) : reject(error)));
    listen(options.port);
  });
  origin = `http://127.0.0.1:${port}`;

  return {
    port,
    indexUrl: `${origin}/?t=${token}`,
    // Opens the request for the human and returns the token-free link the agent may show.
    announce(approvalId: string): string {
      if (options.openBrowser) {
        openInBrowser(`${origin}/a/${approvalId}?t=${token}`).then((outcome) => options.onNotified(approvalId, outcome));
      }
      return `${origin}/a/${approvalId}`;
    },
    close: () => server.close(),
  };
}
