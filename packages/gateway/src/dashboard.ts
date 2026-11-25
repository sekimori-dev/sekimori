import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { foldRequests, isWaiting, type ActivityEntry, type ActivityLog, type ActivityRecord, type RequestRow, type RowState, type Session } from "./activity.ts";
import type { ApprovalRequest, ApprovalStore } from "./approvals.ts";
import type { Counts } from "./confidential.ts";
import type { Remotes, RemoteStatus } from "./upstream.ts";

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
  --paper: #151515; --ink: #ecebe8; --ink-2: #bdbbb6; --ink-3: #8f8d88; --hair: #2b2b2a; --hair-strong: #3d3c3a;
  --beni: #e8606a; --beni-ink: #f0868e; --beni-wash: #3a1d20; --beni-dim: #6e3a3f;
  --sans: "Jost", "Helvetica Neue", sans-serif; --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --mincho: "Zen Old Mincho", "Hiragino Mincho ProN", serif; --ease-out: cubic-bezier(0.16, 1, 0.3, 1);
  --gutter: clamp(1.25rem, 5vw, 4.5rem);
  color-scheme: dark; accent-color: var(--beni); scrollbar-color: var(--hair-strong) var(--paper); scrollbar-width: thin;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); font: 300 1rem/1.6 var(--sans); font-variant-numeric: tabular-nums; -webkit-font-smoothing: antialiased; }
::selection { background: var(--beni-wash); color: var(--beni-ink); }
a { color: inherit; text-decoration-thickness: 1px; text-underline-offset: 0.28em; }
:focus-visible { outline: 1px solid var(--beni); outline-offset: 4px; }
h1, h2, h3 { margin: 0; font-weight: 200; letter-spacing: -0.02em; line-height: 1.1; text-wrap: balance; }
p { margin: 0; text-wrap: pretty; }

.bar { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.75rem 2.5rem; padding: 1.25rem var(--gutter); border-bottom: 1px solid var(--hair); }
.mark { display: flex; align-items: baseline; gap: 0.5em; font-size: 1.25rem; font-weight: 300; letter-spacing: -0.02em; text-decoration: none; }
.mark [lang="ja"] { font-family: var(--mincho); font-weight: 400; font-size: 0.8em; letter-spacing: 0.08em; color: var(--beni); }
.nav { display: flex; gap: 1.75rem; font-size: 0.9375rem; }
.nav a { color: var(--ink-2); text-decoration: none; padding-bottom: 0.2rem; border-bottom: 1px solid transparent; transition: color 0.3s var(--ease-out); }
.nav a:hover { color: var(--ink); }
.nav a[aria-current] { color: var(--ink); border-bottom-color: var(--beni); }
.live { margin-left: auto; font-size: 0.8125rem; color: var(--ink-3); }
.live::before { content: ""; display: inline-block; width: 0.4rem; height: 0.4rem; margin-right: 0.55rem; background: var(--ink-2); vertical-align: 0.08rem; }

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
button, a.button { display: inline-flex; text-decoration: none; white-space: nowrap; align-items: center; gap: 0.7rem; padding: 0.85rem 1.35rem; border: 1px solid var(--ink); border-radius: 0; background: var(--ink); color: var(--paper); font: inherit; font-weight: 400; font-size: 1rem; cursor: pointer; transition: background-color 0.4s var(--ease-out), color 0.4s var(--ease-out); }
button:hover, a.button:hover { background: var(--paper); color: var(--ink); }
button.ghost, a.button.ghost { background: transparent; color: var(--ink); }
button.ghost:hover, a.button.ghost:hover { background: var(--ink); color: var(--paper); }
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
.diagram .out { stroke: var(--beni-dim); stroke-dasharray: 3 4; }
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

.index { padding: clamp(2rem, 5vw, 3.5rem) var(--gutter) 5rem; display: grid; gap: 2rem; max-width: 90rem; margin: 0 auto; }
.index h1 { font-size: clamp(2.2rem, 3.4vw, 3rem); }
.empty { color: var(--ink-2); }
.index .lede { max-width: 38rem; font-size: 1.0625rem; color: var(--ink-2); }

.links { list-style: none; margin: 0; padding: 0; border-top: 1px solid var(--ink); }
.links li { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 0.25rem 2rem; padding: 1.1rem 0; border-bottom: 1px solid var(--hair); }
.links form { margin: 0; grid-row: 1 / span 2; grid-column: 2; }
.links .name { font-size: 1.0625rem; }
.links .caption { overflow-wrap: anywhere; }
.links .failed { color: var(--ink); }
.links .state { grid-row: 1 / span 2; grid-column: 2; font-size: 0.875rem; color: var(--ink-2); }
button.secondary { background: var(--paper); color: var(--ink); }
button.secondary:hover { background: var(--ink); color: var(--paper); }

.home { display: grid; grid-template-columns: minmax(0, 1fr) 19rem; gap: clamp(2rem, 5vw, 4.5rem); padding: clamp(2rem, 5vw, 3.5rem) var(--gutter) 5rem; max-width: 90rem; margin: 0 auto; }
.requests h1 { font-size: clamp(2.2rem, 3.4vw, 3rem); margin-bottom: 1.75rem; }
.waiting, .feed, .conns { list-style: none; margin: 0; padding: 0; }
.waiting { margin-bottom: 2.5rem; }
.waiting:empty { display: none; }
.waiting li { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 0.35rem 2rem; padding: 1.1rem 0 1.2rem; border-top: 1px solid var(--beni); }
.waiting li:last-child { border-bottom: 1px solid var(--hair); }
.waiting .what { font-size: 1.0625rem; overflow-wrap: anywhere; }
.waiting .why { font-size: 0.875rem; color: var(--ink-2); }
.waiting .acts { grid-row: 1 / span 2; grid-column: 2; }
.waiting form { margin: 0; }
.feed { border-top: 1px solid var(--ink); }
.feed:empty { border-top: 0; }
.feed li { display: grid; grid-template-columns: 4rem minmax(0, 1fr) minmax(8rem, auto); gap: 1.25rem; align-items: baseline; padding: 0.85rem 0; border-bottom: 1px solid var(--hair); }
.feed .t { font-size: 0.875rem; color: var(--ink-3); }
.feed .p { overflow-wrap: anywhere; }
.feed .s { text-align: right; font-size: 0.875rem; color: var(--ink-2); }
.feed .s.bad { color: var(--ink); }
.p span, .what span { color: var(--ink-3); }
.p .flag, .what .flag { margin-left: 0.5rem; font-size: 0.75rem; font-weight: 400; color: var(--beni-ink); }
.p .meta { display: block; margin-top: 0.15rem; font-size: 0.8125rem; color: var(--ink-3); }
.none { display: none; color: var(--ink-2); }
.waiting:empty + .feed:empty + .none { display: block; }
.rail { display: grid; gap: 2.5rem; align-content: start; }
.rail section { border-top: 1px solid var(--ink); padding-top: 1rem; display: grid; gap: 0.75rem; }
.rail h2 { font-size: 1rem; font-weight: 300; letter-spacing: 0; }
.conns li { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 0 1rem; padding: 0.55rem 0; border-bottom: 1px solid var(--hair); }
.conns .caption { grid-column: 1; overflow-wrap: anywhere; }
.conns .state { grid-row: 1 / span 2; grid-column: 2; align-self: center; font-size: 0.8125rem; color: var(--ink-2); }
.tally { display: grid; grid-template-columns: repeat(3, 1fr); }
.tally div { font-size: 0.8125rem; color: var(--ink-3); }
.tally strong { display: block; font-size: 2rem; font-weight: 200; line-height: 1.2; color: var(--ink); }
.tally .den strong { color: var(--beni-ink); }
a.quiet { justify-self: start; font-size: 0.875rem; color: var(--ink-2); text-decoration-color: var(--hair-strong); }
a.quiet:hover { color: var(--ink); text-decoration-color: var(--beni); }
.filters { display: flex; gap: 1.5rem; font-size: 0.9375rem; }
.filters a { color: var(--ink-2); text-decoration: none; border-bottom: 1px solid transparent; padding-bottom: 0.2rem; }
.filters a[aria-current] { color: var(--ink); border-bottom-color: var(--beni); }
.day { display: grid; gap: 0.75rem; }
.day h2 { font-size: 1.0625rem; font-weight: 300; }

@media (max-width: 60rem) {
  .layout, .home { grid-template-columns: minmax(0, 1fr); }
  .decision { position: static; }
  .decision .actions, .decision .fine { display: none; }
  .actions-late { display: grid; }
}
@media (max-width: 40rem) {
  .diagram.wide { display: none; }
  .diagram.narrow { display: block; }
  .links li, .waiting li { grid-template-columns: minmax(0, 1fr); }
  .links form, .links .state, .waiting .acts { grid-row: auto; grid-column: 1; margin-top: 0.6rem; }
  .feed li { grid-template-columns: 3.25rem minmax(0, 1fr); row-gap: 0.35rem; }
  .feed .s { grid-column: 2; text-align: left; }
  .live { margin-left: 0; flex-basis: 100%; }
}
@media (prefers-reduced-motion: reduce) {
  .outcome img { animation: none; }
  button, .nav a { transition: none; }
  .diagram.sealed .in, .diagram.sealed .hold, .diagram.sealed .out { animation: none; stroke-dashoffset: 0; }
}
`;

// Pages without chrome (callback and error pages) get the bare mark and no live channel.
function page(title: string, body: string, chrome?: Chrome): string {
  const link = (nav: Chrome["nav"], href: string, label: string) => `<a href="${href}"${chrome?.nav === nav ? ' aria-current="page"' : ""}>${label}</a>`;
  const header = chrome
    ? `<nav class="nav" aria-label="Dashboard">${link("requests", "/", "Requests")}${link("connections", "/connections", "Connections")}${link("history", "/history", "History")}</nav>
       <span id="live" class="live">Live · ${chrome.sessions} ${chrome.sessions === 1 ? "session" : "sessions"}</span>`
    : "";
  const count = chrome?.waiting ? `(${chrome.waiting}) ` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${count}${escape(title)} · Sekimori</title><link rel="icon" href="/assets/seal.svg" type="image/svg+xml"><style>${STYLE}</style></head>
<body><header class="bar"><a class="mark" href="/">Sekimori <span lang="ja">関守</span></a>${header}</header>${body}${chrome ? `<script>${LIVE_JS}</script>` : ""}</body></html>`;
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

// Counts only: the dashboard never shows a confidential value.
function keptLine(counts?: Counts): string {
  if (!counts) return "";
  const kept = Object.entries(counts).flatMap(([name, c]) => (c.withheld + c.pseudonymised ? [`${c.withheld + c.pseudonymised} ${name}`] : []));
  const passed = Object.entries(counts).flatMap(([name, c]) => (c.revealed ? [`${c.revealed} ${name}`] : []));
  return [kept.length ? `kept back: ${kept.join(" · ")}` : "", passed.length ? `passed on: ${passed.join(" · ")}` : ""].filter(Boolean).join(" · ");
}

function requestPage(request: ApprovalRequest, chrome: Chrome): string {
  const expired = request.status === "expired" || (request.status === "pending" && request.expiresAt <= Date.now());
  const sealed = request.status === "approved" || request.status === "used";
  const pending = request.status === "pending" && !expired;
  const state: DiagramState = sealed ? "sealed" : pending ? "pending" : "stopped";

  const held = request.held;
  const decision = pending
    ? `<h1>${held ? "Release this result?" : "Seal this program?"}</h1>
       <p class="expiry">Expires in <strong>${minutesLeft(request)} min</strong>. ${held ? "Approving hands this result to the agent; the program does not run again." : "Approving runs exactly this code once."}</p>
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
        ${held ? `<section class="panel"><h2>Result the agent would receive</h2><p class="caption">${escape(keptLine(held.confidential) || "Nothing was kept back.")} The model sees exactly this, placeholders included.</p><pre class="code">${escape(held.status === "completed" ? JSON.stringify(held.value, null, 2) ?? "undefined" : held.error)
          .split("\n")
          .map((line) => `<span>${line || " "}</span>`)
          .join("")}</pre></section>` : ""}
        <section class="panel"><h2>Program</h2><pre class="code">${codeLines(request)}</pre></section>
        ${pending ? `<section class="actions-late" aria-label="Decision after review">${actions(request)}${fine(request, "If the agent changes the code, it needs a new seal.")}</section>` : ""}
      </div>
    </main>`,
    chrome,
  );
}

type Chrome = { nav?: "requests" | "connections" | "history"; waiting: number; sessions: number };

const STATE_LABEL: Record<RowState, string> = {
  running: "Running",
  waiting_approval: "Waits for you",
  waiting_connect: "Waits for a connect",
  approved: "Approved · not run yet",
  denied: "Denied",
  expired: "Expired",
  completed: "Completed",
  failed: "Failed",
  rejected: "Rejected",
  connected: "Connected · agent rewrites it",
  ended: "Session ended",
};

const clock = (iso: string) => new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });

function planLine(row: RequestRow): string {
  if (row.steps.length === 0) return row.open ? "Calls Sekimori cannot read before running" : "No tool calls";
  // Rows keep the end of long values, where paths and recipients differ; the approval page shows them in full.
  const short = (arg: string) => (arg.length > 48 ? `${arg.slice(0, arg.indexOf(": ") + 2)}…${arg.slice(-34)}` : arg);
  const parts = row.steps.slice(0, 3).map((step) => {
    const args = step.args.join(", ");
    return `${escape(step.tool)}${args ? ` <span title="${escape(args)}">${escape(step.args.map(short).join(", "))}</span>` : ""}`;
  });
  const more = row.steps.length > 3 ? ` <span>+${row.steps.length - 3} more</span>` : "";
  const flags = [row.steps.some((s) => s.untrusted) ? "untrusted" : "", row.steps.some((s) => s.sink) ? "sensitive" : ""].filter(Boolean);
  return `${parts.join(" · ")}${more}${flags.map((f) => `<span class="flag">${f}</span>`).join("")}`;
}

type Viewer = { port: number; foreign: Set<number> };

function waitingAction(row: RequestRow, viewer: Viewer): string {
  const own = row.session.port === viewer.port && row.session.pid === process.pid;
  const path = row.state === "waiting_approval" && row.approvalId ? `/a/${row.approvalId}` : "/connections";
  const label = row.state === "waiting_approval" ? "Review" : "Connect";
  if (own) return `<a class="button" href="${escape(path)}">${label}</a>`;
  if (viewer.foreign.has(row.session.port)) return `<a class="button ghost" href="http://127.0.0.1:${row.session.port}${escape(path)}">${label} in :${row.session.port}</a>`;
  return `<form method="post" action="/sessions/${row.session.port}/open"><button class="ghost">Open in its session</button></form>`;
}

function requestRow(row: RequestRow, viewer: Viewer): string {
  const meta = [`${escape(row.session.agent)} :${row.session.port}`, row.calls ? `${row.calls} call${row.calls === 1 ? "" : "s"}` : "", row.error ? escape(row.error) : "", escape(keptLine(row.confidential))];
  if (isWaiting(row)) {
    const why = row.state === "waiting_connect" ? `Needs ${escape(row.upstreams.join(", ") || "a connection")}` : escape(row.reasons[0] ?? "Needs your approval");
    const left = row.expiresAt ? ` · expires in ${Math.max(0, Math.ceil((row.expiresAt - Date.now()) / 60_000))} min` : "";
    return `<li id="${escape(row.id)}" class="wait"><span class="what">${planLine(row)}</span><span class="why">${why} · ${meta[0]}${left}</span><span class="acts">${waitingAction(row, viewer)}</span></li>`;
  }
  const label = row.state === "expired" && row.decision?.sessionEnded ? "Expired · session ended" : STATE_LABEL[row.state];
  const tone = row.state === "denied" || row.state === "failed" || row.state === "rejected" ? " bad" : "";
  return `<li id="${escape(row.id)}"><span class="t">${clock(row.startedAt)}</span><span class="p">${planLine(row)}<span class="meta">${meta.filter(Boolean).join(" · ")}</span></span><span class="s${tone}">${label}</span></li>`;
}

type LocalUpstream = { name: string; tools: unknown[] };

function connectionItem(item: { name: string; caption: string; state: string; action?: string; failed?: boolean }, prefix: string): string {
  return `<li id="${prefix}-${escape(item.name)}"><span class="name">${escape(item.name)}</span><span class="caption${item.failed ? " failed" : ""}">${item.caption}</span>${item.action ?? `<span class="state">${item.state}</span>`}</li>`;
}

function connectionItems(local: LocalUpstream[], remotes: RemoteStatus[], withActions: boolean) {
  const action = (remote: RemoteStatus, label: string, cls = "") =>
    withActions ? `<form method="post" action="/connections/${remote.name}"><button${cls ? ` class="${cls}"` : ""}>${label}</button></form>` : undefined;
  return [
    ...local.map((u) => ({ name: u.name, caption: `local · ${u.tools.length} tools`, state: "Connected" })),
    ...remotes.map((r) =>
      r.state === "connected"
        ? { name: r.name, caption: `${escape(r.host)} · ${r.upstream!.tools.length} tools`, state: "Connected" }
        : r.state === "connecting"
          ? { name: r.name, caption: `${escape(r.host)} · waiting for you to finish signing in`, state: "Signing in", action: action(r, "Start again", "secondary") }
          : r.state === "unavailable"
            ? { name: r.name, caption: escape(r.reason ?? "unreachable"), state: "Unavailable", action: action(r, "Retry", "secondary"), failed: true }
            : { name: r.name, caption: `${escape(r.host)} · not connected`, state: "Not connected", action: action(r, "Connect") },
    ),
  ];
}

function tally(rows: RequestRow[]): string {
  const today = new Date().toDateString();
  const count = (d: string) => rows.filter((r) => r.decision?.decision === d && new Date(r.decision.at).toDateString() === today).length;
  return `<div id="tally" class="tally"><div><strong>${count("approved")}</strong>approved</div><div class="den"><strong>${count("denied")}</strong>denied</div><div><strong>${count("expired")}</strong>expired</div></div>`;
}

const FEED_SIZE = 100;

function homePage(rows: RequestRow[], local: LocalUpstream[], remotes: RemoteStatus[], viewer: Viewer, chrome: Chrome, skipped: number): string {
  const waiting = rows.filter(isWaiting);
  const feed = rows.filter((r) => !isWaiting(r)).slice(0, FEED_SIZE);
  return page(
    "Requests",
    `<main class="home">
      <section class="requests" aria-label="Requests"><h1>Requests</h1>
        <ul id="waiting" class="waiting">${waiting.map((r) => requestRow(r, viewer)).join("")}</ul>
        <ul id="feed" class="feed">${feed.map((r) => requestRow(r, viewer)).join("")}</ul>
        <p class="none">No requests yet. Programs from every agent session show up here as they arrive.</p>
        ${skipped ? `<p class="caption">${skipped} unreadable line${skipped === 1 ? "" : "s"} in the activity log were skipped.</p>` : ""}
      </section>
      <aside class="rail">
        <section><h2>Connections</h2><ul class="conns">${connectionItems(local, remotes, false).map((c) => connectionItem(c, "rc")).join("")}</ul>
          <a class="quiet" href="/connections">Manage connections</a></section>
        <section><h2>Today</h2>${tally(rows)}<a class="quiet" href="/history">All decisions</a></section>
      </aside>
    </main>`,
    { ...chrome, nav: "requests" },
  );
}

function connectionsPage(local: LocalUpstream[], remotes: RemoteStatus[], chrome: Chrome): string {
  const open = remotes.filter((r) => r.state !== "connected").length;
  return page(
    "Connections",
    `<main class="index"><h1>${open === 0 ? "Every service is connected." : "Connect the services your agent works with."}</h1>
      <p class="lede">These are the MCP servers this session reaches. Remote ones act as you, with your own accounts; Sekimori keeps the sign-in encrypted on this machine and never hands it to the agent.</p>
      <ul class="links">${connectionItems(local, remotes, true).map((c) => connectionItem(c, "c")).join("")}</ul></main>`,
    { ...chrome, nav: "connections" },
  );
}

function historyPage(rows: RequestRow[], filter: string | null, chrome: Chrome): string {
  const at = (row: RequestRow) => row.decision?.at ?? row.updatedAt;
  const decided = filter === "kept" ? rows.filter((r) => keptLine(r.confidential)) : rows.filter((r) => r.decision && (!filter || r.decision.decision === filter));
  const days = new Map<string, RequestRow[]>();
  for (const row of decided.sort((a, b) => (at(a) < at(b) ? 1 : -1))) {
    const day = new Date(at(row)).toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long" });
    days.set(day, [...(days.get(day) ?? []), row]);
  }
  const outcome = (row: RequestRow) =>
    !row.decision
      ? STATE_LABEL[row.state]
      : row.decision.decision === "approved" ? (row.ran ? `Approved · ${row.state === "failed" ? "failed when it ran" : "ran"}` : "Approved · never ran") : row.decision.sessionEnded ? "Expired · session ended" : row.decision.decision === "denied" ? "Denied" : "Expired";
  const filters = [["", "All"], ["approved", "Approved"], ["denied", "Denied"], ["expired", "Expired"], ["kept", "Kept back"]]
    .map(([value, label]) => `<a href="/history${value ? `?decision=${value}` : ""}"${(filter ?? "") === value ? ' aria-current="page"' : ""}>${label}</a>`)
    .join("");
  return page(
    "History",
    `<main class="index"><h1>Decisions</h1><nav class="filters" aria-label="Filter by decision">${filters}</nav>
      ${days.size === 0 ? `<p class="empty">${filter === "kept" ? "Nothing was kept back from the model in the last 30 days." : "No decisions in the last 30 days."}</p>` : ""}
      ${[...days]
        .map(
          ([day, list]) => `<section class="day"><h2>${day}</h2><ul class="feed">${list
            .map(
              (r) => `<li><span class="t">${clock(at(r))}</span><span class="p">${planLine(r)}<span class="meta">${[`${escape(r.session.agent)} :${r.session.port}`, r.reasons[0] ? escape(r.reasons[0]) : "", escape(keptLine(r.confidential))].filter(Boolean).join(" · ")}</span></span><span class="s${r.decision?.decision === "denied" ? " bad" : ""}">${outcome(r)}</span></li>`,
            )
            .join("")}</ul></section>`,
        )
        .join("")}</main>`,
    { ...chrome, nav: "history" },
  );
}

// The callback request carried no cookie; navigating from this same-site page sends it again.
const CALLBACK_JS = `location.replace("/connections")`;
const CALLBACK_DONE = page(
  "Connected",
  `<main class="index"><h1>Connected.</h1><p class="empty">Taking you back to your connections. <a href="/connections">Continue</a></p></main>
   <script>${CALLBACK_JS}</script>`,
);

const CALLBACK_INVALID = page(
  "Sign-in link not valid",
  `<main class="index"><h1>This sign-in link is not valid.</h1>
   <p class="empty">It was used already, expired after 10 minutes, or did not start from this gateway. Nothing was connected. <a href="/connections">Start again from your connections</a>.</p></main>`,
);

const FORBIDDEN = page(
  "Approver session needed",
  `<main class="index"><h1>This browser is not signed in to this gateway.</h1>
   <p class="empty">Sekimori opens its dashboard in your browser when an agent needs you. If nothing opened, run pnpm approvals in the Sekimori repository.</p></main>`,
);

// Browsers share cookies across ports, so each gateway's cookie carries its port in the name.
const COOKIE = /(?:^|;\s*)sekimori_approver_(\d+)=([\w-]+)/g;
function cookies(req: IncomingMessage): Map<number, string> {
  return new Map([...(req.headers.cookie ?? "").matchAll(COOKIE)].map((m) => [Number(m[1]), m[2]!]));
}

// Every OAuth client is registered with the redirect URIs of this whole range; see the slice 3 spec, section 6.
export const approvalPorts = (base: number) => Array.from({ length: 10 }, (_, i) => base + i);

export function openInBrowser(url: string): Promise<string> {
  const [command, args] =
    process.platform === "darwin" ? ["open", [url]] : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]] : ["xdg-open", [url]];
  return new Promise((resolve) => {
    const child = spawn(command, args as string[], { stdio: "ignore" });
    child.on("error", (error) => resolve(`failed: ${error.message}`));
    child.on("exit", (code) => resolve(code === 0 ? "opened" : `failed: ${command} exited with ${code}`));
  });
}

const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

async function listedGateway(sessionDir: string, port: number): Promise<{ port: number; pid: number; user?: string } | undefined> {
  const raw = await readFile(join(sessionDir, `approver-${port}.json`), "utf8").catch(() => undefined);
  return raw ? JSON.parse(raw) : undefined;
}

// A listed pid can belong to another process after pid reuse, and SIGUSR2 kills processes that don't handle it.
export async function verifiedGateway(sessionDir: string, port: number, user?: string): Promise<{ pid: number } | undefined> {
  const listed = await listedGateway(sessionDir, port);
  if (!listed || (user !== undefined && listed.user !== user) || !alive(listed.pid)) return undefined;
  const health = await fetch(`http://127.0.0.1:${port}/health`, { signal: AbortSignal.timeout(1_000) })
    .then((r) => r.json() as Promise<{ service?: string; pid?: number }>)
    .catch(() => undefined);
  return health?.service === "sekimori" && health.pid === listed.pid ? { pid: listed.pid } : undefined;
}

async function liveSessions(sessionDir: string, user: string): Promise<number> {
  const files = (await readdir(sessionDir).catch(() => [] as string[])).filter((f) => /^approver-\d+\.json$/.test(f));
  const listed = await Promise.all(files.map((f) => listedGateway(sessionDir, Number(f.slice(9, -5)))));
  return listed.filter((g) => g && g.user === user && alive(g.pid)).length;
}

const LIVE_JS = `
(() => {
  const live = document.getElementById("live");
  const base = document.title.replace(/^\\(\\d+\\) /, "");
  const events = new EventSource("/events");
  events.onmessage = (message) => {
    const update = JSON.parse(message.data);
    for (const row of update.rows) {
      const list = document.getElementById(row.list);
      const current = document.getElementById(row.id);
      if (current && current.parentElement === list) { current.outerHTML = row.html; continue; }
      if (current) current.remove();
      if (list) list.insertAdjacentHTML("afterbegin", row.html);
    }
    for (const id of update.removed) document.getElementById(id)?.remove();
    for (const part of update.fragments) { const el = document.getElementById(part.id); if (el) el.outerHTML = part.html; }
    document.title = (update.waiting ? "(" + update.waiting + ") " : "") + base;
    live.textContent = "Live · " + update.sessions + (update.sessions === 1 ? " session" : " sessions");
  };
  events.onerror = () => { live.textContent = "Reconnecting…"; };
})();
`;

// See docs/superpowers/specs/2026-11-25-dashboard-design.md; the approver credential rules are in the slice 2 spec, section 6.
export async function startDashboard(
  store: ApprovalStore,
  options: {
    port: number;
    openBrowser: boolean;
    agent: string;
    user: string;
    sessionDir: string;
    activity: ActivityLog;
    local: LocalUpstream[];
    remotes: Pick<Remotes, "list" | "beginConnect" | "finishConnect">;
    onNotified: (approvalId: string, outcome: string) => void;
    signal?: (pid: number) => void;
  },
) {
  let origin = `http://127.0.0.1:${options.port}`;
  let port = options.port;
  // Only the dashboard's own two scripts may run, so markup that slips into a row cannot act as the approver.
  const scriptHash = (js: string) => `'sha256-${createHash("sha256").update(js).digest("base64")}'`;
  const CSP = `default-src 'none'; script-src ${scriptHash(LIVE_JS)} ${scriptHash(CALLBACK_JS)}; style-src 'unsafe-inline'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'`;
  const token = randomBytes(18).toString("base64url");
  const valid = (candidate: string | undefined) =>
    candidate !== undefined && candidate.length === token.length && timingSafeEqual(Buffer.from(candidate), Buffer.from(token));
  const signal = options.signal ?? ((pid: number) => process.kill(pid, "SIGUSR2"));

  const records: ActivityRecord[] = await options.activity.readAll();
  const rows = () => foldRequests(records, (session: Session) => alive(session.pid));
  let sessions = 1;
  const chrome = (): Chrome => ({ waiting: rows().filter(isWaiting).length, sessions });

  type Client = { res: ServerResponse; viewer: Viewer; sent: Map<string, string> };
  const clients = new Set<Client>();

  function push(client: Client, current: RequestRow[]) {
    const visible = [...current.filter(isWaiting), ...current.filter((r) => !isWaiting(r)).slice(0, FEED_SIZE)];
    const changed = [];
    for (const row of [...visible].reverse()) {
      const html = requestRow(row, client.viewer);
      const list = isWaiting(row) ? "waiting" : "feed";
      if (client.sent.get(row.id) === list + html) continue;
      client.sent.set(row.id, list + html);
      changed.push({ id: row.id, list, html });
    }
    const ids = new Set(visible.map((r) => r.id));
    const removed = [...client.sent.keys()].filter((id) => !ids.has(id));
    for (const id of removed) client.sent.delete(id);
    const remotes = options.remotes.list();
    const fragments = [
      ...connectionItems(options.local, remotes, false).map((c) => ({ id: `rc-${c.name}`, html: connectionItem(c, "rc") })),
      ...connectionItems(options.local, remotes, true).map((c) => ({ id: `c-${c.name}`, html: connectionItem(c, "c") })),
      { id: "tally", html: tally(current) },
    ];
    const update = { rows: changed, removed, fragments, waiting: current.filter(isWaiting).length, sessions };
    client.res.write(`data: ${JSON.stringify(update)}\n\n`);
  }

  async function broadcast() {
    sessions = await liveSessions(options.sessionDir, options.user);
    const current = rows();
    for (const client of clients) push(client, current);
  }

  const session = (): Session => ({ port, pid: process.pid, agent: options.agent, user: options.user });
  const append = (entry: ActivityEntry) => options.activity.append(session(), entry).catch(() => {});

  store.onChange(({ type, request }) => {
    if (type === "approved" || type === "denied" || type === "expired") append({ kind: "decision", approvalId: request.id, decision: type });
  });

  const server = createServer((req, res) => {
    handle(req, res).catch((error: Error) => {
      if (!res.headersSent) res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      res.end(`Sekimori error: ${error.message}`);
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? "/", origin);
    const send = (status: number, html: string) => {
      res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "content-security-policy": CSP });
      res.end(html);
    };
    const redirect = (location: string) => {
      res.writeHead(303, { location });
      res.end();
    };

    const asset = req.method === "GET" && url.pathname.startsWith("/assets/") ? ASSETS[url.pathname.slice(8)] : undefined;
    if (asset) {
      res.writeHead(200, { "content-type": asset.type, "cache-control": "max-age=3600" });
      return res.end(asset.body);
    }
    // Lets another gateway confirm who listens here before it signals the listed pid; reveals nothing else.
    if (req.method === "GET" && url.pathname === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ service: "sekimori", pid: process.pid }));
    }

    if (req.method === "GET" && valid(url.searchParams.get("t") ?? undefined)) {
      res.writeHead(303, {
        location: url.pathname,
        "set-cookie": `sekimori_approver_${port}=${token}; HttpOnly; SameSite=Strict; Path=/`,
        "cache-control": "no-store",
      });
      return res.end();
    }
    // Arrives cross-site from the authorization server, so no Strict cookie: the single-use state is the credential.
    if (req.method === "GET" && url.pathname === "/oauth/callback") {
      const state = url.searchParams.get("state");
      const code = url.searchParams.get("code");
      const finished = state && code ? await options.remotes.finishConnect(state, code) : false;
      return finished ? send(200, CALLBACK_DONE) : send(400, CALLBACK_INVALID);
    }
    const jar = cookies(req);
    if (!valid(jar.get(port))) return send(403, FORBIDDEN);
    jar.delete(port);
    const viewer: Viewer = { port, foreign: new Set(jar.keys()) };

    if (req.method === "POST") {
      if (req.headers.origin !== origin) return send(403, FORBIDDEN);
      const connect = url.pathname.match(/^\/connections\/([a-z][a-zA-Z0-9_]*)$/);
      if (connect) {
        if (!options.remotes.list().some((r) => r.name === connect[1])) return send(404, page("Not found", '<main class="index"><h1>Unknown upstream.</h1></main>'));
        return redirect(await options.remotes.beginConnect(connect[1]!));
      }
      const decision = url.pathname.match(/^\/a\/(ap_[\w-]+)\/(approve|deny)$/);
      if (decision) {
        const decided = store.decide(decision[1]!, decision[2] === "approve");
        if (!decided) return send(409, page("Not pending", '<main class="index"><h1>This approval is no longer pending.</h1></main>'));
        return redirect(`/a/${decided.id}`);
      }
      const other = url.pathname.match(/^\/sessions\/(\d+)\/open$/);
      if (other) {
        const target = Number(other[1]) === port ? undefined : await verifiedGateway(options.sessionDir, Number(other[1]), options.user);
        if (!target) return send(404, page("Session not found", '<main class="index"><h1>That session is no longer running.</h1><p class="empty"><a href="/">Back to requests</a></p></main>'));
        signal(target.pid);
        return redirect("/");
      }
      return send(404, page("Not found", '<main class="index"><h1>Not found.</h1></main>'));
    }
    if (req.method !== "GET") return send(405, page("Not allowed", '<main class="index"><h1>Method not allowed.</h1></main>'));

    if (url.pathname === "/events") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store", connection: "keep-alive" });
      const client: Client = { res, viewer, sent: new Map() };
      clients.add(client);
      req.on("close", () => clients.delete(client));
      return push(client, rows());
    }
    if (url.pathname === "/connections") return send(200, connectionsPage(options.local, options.remotes.list(), chrome()));
    if (url.pathname === "/history") return send(200, historyPage(rows(), url.searchParams.get("decision"), chrome()));
    const view = url.pathname.match(/^\/a\/(ap_[\w-]+)$/);
    if (view) {
      const request = store.get(view[1]!);
      return request ? send(200, requestPage(request, chrome())) : send(404, page("Not found", '<main class="index"><h1>Unknown approval.</h1></main>'));
    }
    if (url.pathname === "/") return send(200, homePage(rows(), options.local, options.remotes.list(), viewer, chrome(), options.activity.skipped()));
    return send(404, page("Not found", '<main class="index"><h1>Not found.</h1></main>'));
  }

  // Another gateway (e.g. a second Claude Code session) may hold the configured port; try the next ones in the range.
  const candidates = approvalPorts(options.port);
  port = await new Promise<number>((resolve, reject) => {
    const listen = () => server.listen(candidates.shift(), "127.0.0.1");
    server.once("listening", () => resolve((server.address() as AddressInfo).port));
    server.on("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "EADDRINUSE" || server.listening) return reject(error);
      if (candidates.length === 0) return reject(new Error(`Ports ${options.port}–${options.port + 9} are all taken by other Sekimori gateways`));
      listen();
    });
    listen();
  });
  origin = `http://127.0.0.1:${port}`;

  const stopWatching = options.activity.watch((fresh) => {
    records.push(...fresh);
    void broadcast();
  });
  // Expiry and dead sessions change rows without any new record.
  const ticker = setInterval(() => {
    store.sweep();
    void broadcast();
  }, 30_000);

  // With a dashboard open, new requests arrive there instead of in a new tab.
  const open = (path: string, subject: string) => {
    if (options.openBrowser && clients.size === 0) openInBrowser(`${origin}${path}?t=${token}`).then((outcome) => options.onNotified(subject, outcome));
  };

  return {
    port,
    indexUrl: `${origin}/?t=${token}`,
    session,
    append,
    // Opens the request for the human and returns the token-free link the agent may show.
    announce(approvalId: string): string {
      open(`/a/${approvalId}`, approvalId);
      return `${origin}/a/${approvalId}`;
    },
    connectPage(show: boolean): string {
      if (show) open("/connections", "connect");
      return `${origin}/connections`;
    },
    close() {
      stopWatching();
      clearInterval(ticker);
      for (const client of clients) client.res.end();
      server.close();
    },
  };
}
