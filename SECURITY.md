# Security

Sekimori is a security layer, so we take reports about it seriously, including while it is pre-release.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. This creates a private advisory that only the maintainers can see.

Please do **not** open a public issue, pull request or discussion for a vulnerability.

We acknowledge reports within **5 working days** and keep you updated until the issue is fixed. Once a fix is available, we publish an advisory and credit you, unless you prefer not to be named.

A useful report contains:

- the affected commit or version;
- steps to reproduce, ideally with a gateway config, a policy and an agent program;
- what you expected and what happened;
- the impact you suspect, for example "an agent program can run a sink without approval".

### What we especially want to hear about

Anything that lets an agent get past the checkpoint:

- running a sensitive action without an approval or a matching grant;
- making the plan Sekimori shows differ from what the program does;
- escaping the QuickJS sandbox or reaching upstream credentials from it;
- approving its own program through the local dashboard;
- obtaining or replaying OAuth tokens or authorization codes.

### Known limits that are not vulnerabilities

The [README](README.md#known-limits) lists limits of the current design. The main one: an agent with unrestricted shell access as the same OS user can read the browser's cookie store or edit the policy file. Reports that show a new way around these limits are still welcome.

## Supported versions

Sekimori is pre-release. Only the current state of `main` receives security fixes. There are no released versions yet.

## Automated checks

| Check | Status |
|---|---|
| Secret scanning with push protection | on |
| Dependabot alerts | on |
| Code scanning (CodeQL, default setup) | on |

## Secrets

- Secrets never belong in code, commits, issues or pull requests. That includes gateway configs, logs and screenshots.
- A secret that reaches the repository counts as compromised: rotate it, don't just delete it.
- The gateway keeps upstream OAuth tokens encrypted under `~/.sekimori/credentials/` on the user's machine, never in the repository or the sandbox.
