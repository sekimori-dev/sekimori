import { randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer, type IncomingMessage } from "node:http";
import type { ApprovalRequest, ApprovalStore } from "./approvals.ts";

const escape = (value: string) =>
  value.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const STYLE = `
  body { margin: 0; padding: 3rem clamp(1rem, 5vw, 4rem); font: 300 1rem/1.6 "Helvetica Neue", sans-serif; color: #141414; background: #fff; }
  h1 { font-weight: 200; font-size: 2.2rem; letter-spacing: -0.02em; margin: 0 0 0.25rem; }
  h1 span { color: #e8606a; font-weight: 400; margin-left: 0.4em; }
  .meta { color: #707070; font-size: 0.875rem; margin-bottom: 2.5rem; }
  section { border-top: 1px solid #141414; padding: 1rem 0 2rem; max-width: 60rem; }
  h2 { font-weight: 300; font-size: 1.1rem; margin: 0 0 0.75rem; }
  ul { margin: 0; padding: 0; list-style: none; }
  li { padding: 0.45rem 0; border-bottom: 1px solid #e4e4e4; }
  .reasons li { color: #c03a46; }
  pre { margin: 0; padding: 1rem 0; overflow-x: auto; font: 0.8125rem/1.7 ui-monospace, Menlo, monospace; }
  form { display: inline; }
  button { font: inherit; font-weight: 400; padding: 0.75rem 1.3rem; border: 1px solid #141414; background: #141414; color: #fff; cursor: pointer; margin-right: 1rem; }
  button.deny { background: #fff; color: #141414; }
  .seal { display: inline-grid; place-items: center; width: 3rem; height: 3rem; background: #e8606a; color: #fff; font-size: 1.6rem; transform: rotate(-4deg); }
  a { color: inherit; }
`;

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escape(title)}</title><style>${STYLE}</style></head><body><h1>Sekimori<span lang="ja">関守</span></h1>${body}</body></html>`;
}

function requestPage(request: ApprovalRequest): string {
  const list = (items: string[]) => `<ul>${items.map((i) => `<li>${escape(i)}</li>`).join("")}</ul>`;
  const decided =
    request.status === "pending"
      ? `<form method="post" action="/a/${request.id}/approve"><button>Approve</button></form>
         <form method="post" action="/a/${request.id}/deny"><button class="deny">Deny</button></form>`
      : request.status === "denied"
        ? "<p>Denied.</p>"
        : `<p><span class="seal" lang="ja" aria-label="Approved">関</span> Approved. The agent can now resubmit this program.</p>`;
  return page(
    `Approval ${request.id}`,
    `<p class="meta">Approval ${escape(request.id)} · agent ${escape(request.agent)} · ${escape(request.plan.hash.slice(0, 19))}…</p>
     <section class="reasons"><h2>Why this needs your seal</h2>${list(request.reasons)}</section>
     <section><h2>Plan</h2>${list(request.summary)}</section>
     <section><h2>Program</h2><pre>${escape(request.code)}</pre></section>
     <section>${decided}</section>`,
  );
}

const FORBIDDEN = page(
  "Approver session needed",
  `<section><h2>This browser is not signed in as the approver.</h2>
   <p>Sekimori opens approval requests in your browser when an agent asks for one. You can also open the index link the gateway printed to its log (stderr).</p></section>`,
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
export function startApprovalPage(
  store: ApprovalStore,
  options: { port: number; openBrowser: boolean; onNotified: (approvalId: string, outcome: string) => void },
) {
  const { port } = options;
  const origin = `http://127.0.0.1:${port}`;
  const token = randomBytes(18).toString("base64url");
  const valid = (candidate: string | null) =>
    candidate !== null && candidate.length === token.length && timingSafeEqual(Buffer.from(candidate), Buffer.from(token));

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", origin);
    const send = (status: number, html: string) => {
      res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(html);
    };

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
      if (!decided) return send(409, page("Not pending", "<p>This approval is no longer pending.</p>"));
      res.writeHead(303, { location: `/a/${decided.id}` });
      return res.end();
    }
    if (req.method !== "GET") return send(405, page("Not allowed", "<p>Method not allowed.</p>"));

    const view = url.pathname.match(/^\/a\/(ap_[\w-]+)$/);
    if (view) {
      const request = store.get(view[1]!);
      return request ? send(200, requestPage(request)) : send(404, page("Not found", "<p>Unknown approval.</p>"));
    }
    const pending = store.pending();
    return send(
      200,
      page(
        "Pending approvals",
        `<section><h2>Pending approvals</h2>${
          pending.length
            ? `<ul>${pending.map((r) => `<li><a href="/a/${r.id}">${escape(r.id)}</a> · ${escape(r.agent)} · ${escape(r.reasons[0] ?? "")}</li>`).join("")}</ul>`
            : "<p>Nothing is waiting for a seal.</p>"
        }</section>`,
      ),
    );
  });

  server.listen(port, "127.0.0.1");
  return {
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
