# Sekimori 関守

The checkpoint between AI agents and the tools they use.

Sekimori is an MCP gateway for code-mode agents such as Claude Code. The agent doesn't call tools one by one: it writes a short TypeScript program against a typed API generated from your MCP servers. Sekimori runs that program in a sandbox and keeps two promises.

**What an agent may do.** Before the program runs, Sekimori:
1. reads it and extracts a plan;
2. checks every planned call against Cedar policies;
3. asks a human once for the whole program whenever untrusted data could reach a sensitive action.

Standing grants (a **tegata**, the pass a traveller showed at an Edo-period checkpoint) let routine programs through without asking.

**What the model may read.** Programs may work with confidential data (payroll, bank details, national IDs, health data, credentials) inside the sandbox. Before anything goes back to the model, Sekimori replaces the raw values:
- computed results, such as an average, go back;
- payroll and health values are withheld;
- IBANs and IDs become placeholders that the agent can still pass on to tools that may receive them.

For companies that don't want such data sent to a cloud model's data centre, the dashboard shows for every request what was kept back.

**Status: pre-release.**
- What works: the standalone gateway with both promises, dogfooded by its author with Claude Code against a filesystem server, Notion and an example payroll server.
- Not published: no npm package, no container image, no stable configuration format.
- Not built yet: Sekimori Cloud (policy distribution, approvals in the web and Slack, audit history), which is the next milestone.

Site: https://sekimori-dev.github.io

## Goal

- **Acting.** Agents should be able to act on real systems (mail, chat, issue trackers, files) without a human approving every call. A prompt injection in something the agent read should still be unable to reach a sensitive action unnoticed. "Approve programs, not calls" keeps the human in the loop without approval fatigue.
- **Reading.** Agents should be able to work with data a company won't hand to a cloud model, and the company should be able to check that it wasn't handed over.

## How it works

- **Code mode.** The gateway is an MCP server with two tools:
  - `describe_api` returns TypeScript declarations for every upstream tool;
  - `execute` runs the agent's program in a QuickJS sandbox. Credentials never enter the sandbox.
- **Plans.** Before running a program, the gateway parses it and lists every tool call with its static arguments. Code it cannot read statically (aliases, computed access) marks the plan as open, and an open plan always needs approval.
- **Classification.** Every tool is a source (trusted or untrusted output), a sink (a sensitive action), both or neither. A tool nobody classified counts as both an untrusted source and a sink, so the default fails closed.
- **Data flow.** Once an untrusted source has been read in an agent session, a sink needs a grant or a human approval. The tracking is coarse in v1: it works per program and session, not per value.
- **Policies.** Every call is checked by [Cedar](https://www.cedarpolicy.com/), at plan time and again at runtime with the real arguments.
  - An approval never overrides a deny.
  - `@approval("required")` on a policy forces a human look.
  - `Action::"flow"` policies are the standing grants.
- **Approvals.** The gateway serves a local dashboard on `127.0.0.1:4747` and opens it in your browser when a program needs you. An approval is bound to the exact code (by hash), single-use and expires.
- **Confidential data.** Agents may work with data a cloud model should not read: payroll, bank details, national IDs, health data, credentials. Programs read it inside the sandbox and pass it from tool to tool. What goes back to the model is checked first:
  - computed results (an average, a count) pass;
  - raw values are withheld (`⟦withheld:payroll⟧`) or replaced by placeholders (`⟦bank·7f3a2c⟧`). Sekimori puts the real value back when a placeholder is passed to a tool that may receive it;
  - the check catches raw values even when a program renames them, uses them as keys, writes them into sentences or formats them differently. It also covers error messages and values read back from other tools later.
  - **Where values may go.** A confidential value may go back to the server it came from. Anything else needs a Cedar `Action::"reveal"` grant or an approval, and that includes raw values a program forwards to another tool.
  - **The checkpoint.** A program that deliberately encodes a value (for example the digits reversed) gets past rules like these. Such a program normally only appears after the agent read something untrusted. So once a session has read untrusted data, a program that reads confidential data has its result held for your approval before the model sees it.
  - **The proof.** The dashboard and the activity log show for every request how many values of which class were kept back, never the values.
- **Remote MCP servers.** The gateway connects to them as you, with OAuth 2.1. Tokens are stored encrypted on your machine, with the key in the macOS Keychain, and are refreshed by the gateway. They never reach the agent.
- **Dashboard.** Requests from every running session appear live, together with your connections and a 30-day history of decisions.

## Technologies

| Area | Used |
|---|---|
| Language | TypeScript, run directly on Node 26 (type stripping, no build step) |
| MCP | `@modelcontextprotocol/sdk` (server, stdio and streamable HTTP clients, OAuth) |
| Sandbox | QuickJS via `quickjs-emscripten` |
| Policies | Cedar via `@cedar-policy/cedar-wasm` |
| Validation | zod |
| Tests | vitest |
| Package manager | pnpm (workspace) |

## Setup

You need Node 26 and pnpm 11.

```bash
git clone https://github.com/sekimori-dev/sekimori.git
cd sekimori
pnpm install
```

## Running it with Claude Code

The `dogfood/` folder is a locked-down Claude Code profile. Started there, Claude Code can only act through Sekimori:

```bash
cd dogfood
claude
```

Approve the `sekimori` MCP server when asked, then give the agent a task. The gateway uses [`packages/gateway/example/sekimori.config.json`](packages/gateway/example/sekimori.config.json) and [`policies.cedar`](packages/gateway/example/policies.cedar) next to it:
- the filesystem server runs on the `dogfood/` folder;
- Notion is configured as a remote server; reads run freely, and every change asks first;
- an example payroll server with fictional data (`packages/gateway/example/payroll-server.ts`) shows the confidential-data rules at work.

The gateway loads its configuration and policies at startup, so run `/mcp` in Claude Code to reconnect after changing them.

To use Sekimori in your own project, add it to that project's `.mcp.json`:

```json
{
  "mcpServers": {
    "sekimori": {
      "command": "node",
      "args": ["/path/to/sekimori/packages/gateway/src/cli.ts", "--config", "/path/to/sekimori.config.json"]
    }
  }
}
```

### Configuration

| Field | Meaning |
|---|---|
| `agent` | The Cedar principal, `Agent::"<agent>"`. |
| `user` | Whose tokens and activity this gateway uses. Defaults to your OS user name. |
| `policies` | Path to the Cedar policy file, relative to the config file. |
| `upstreams[]` | MCP servers. Either `command` and `args` (stdio, started by the gateway), or `url` (remote, connected with OAuth). Each gets a `classify` block with glob patterns for `trusted`, `untrusted` and `sinks`. |
| `confidential` | `classes`: switch built-in classes (`credentials`, `bank`, `national_id`, `payroll`, `health` on; `contact`, `person` off) with `enabled` and `mode` (`withhold` or `pseudonymise`), or add your own with `fields`, `patterns` (regular expressions) and `sources` (tool globs such as `erp.*`). |
| `limits` | `timeoutMs` and `memoryBytes` for the sandbox. |
| `approvals` | `port` (default 4747; the next nine ports are the fallback), `ttlMinutes`, `openBrowser`, `waitSeconds`. |

If no browser tab opens when a program needs you, run `pnpm approvals`. It asks every running gateway to open its dashboard.

### What the gateway stores

Everything lives under `~/.sekimori/` on your machine:

- `credentials/<user>/`: OAuth tokens, encrypted with AES-256-GCM;
- `activity/<user>/`: one log file per day for the dashboard. It holds plans, statuses and decisions, but never code, tool results or tokens, and is kept for 30 days;
- `approver-<port>.json`: the port, pid and user of each running gateway.

On macOS the encryption key is a Keychain item (service `sekimori`); elsewhere it is `~/.sekimori/credentials.key`.

No environment variables are needed.

## Development

```bash
pnpm -C packages/gateway typecheck
pnpm -C packages/gateway test
```

- The tests fake only system boundaries: upstream MCP servers, the OAuth authorization server and process signals.
- New dependencies need the maintainer's approval.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/).

## Known limits

- **Same-user agents.** An agent with unrestricted shell access as the same OS user can still read the browser's cookie store or edit the policy file. Real separation needs an approval channel off the agent's machine; that is planned for Sekimori Cloud.
- **Confidential data is found by rules, not by meaning.** Field names, value patterns with checksums and configured sources find it. A salary mentioned in free text with no pattern around it is not found. Short values and booleans (`sick_leave: true`) are withheld under their field, but not recognised once copied elsewhere. An average over one person equals that person's value, and Sekimori withholds it for that reason.
- **One person per gateway.** Shared platforms that serve many users from one server (Open WebUI, LibreChat, Onyx) need a gateway per user for now. A shared team gateway is planned.
- **Upstream logs.** The stderr output of MCP servers the gateway starts is passed through as it is. Sekimori's own records never contain confidential values; the servers' own logs are outside its control.
- **Coarse data-flow tracking.** It works per program and session; per-value tracking comes later.
- **Linked account.** The dashboard cannot show which upstream account an OAuth connection belongs to.
- **Windows.** `pnpm approvals` and "Open in its session" rely on `SIGUSR2` and do not work on Windows yet.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) for the gateway in this repository.
