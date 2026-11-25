import { execFile } from "node:child_process";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { OAuthClientProvider, OAuthDiscoveryState } from "@modelcontextprotocol/sdk/client/auth.js";
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";

// Tokens belong to the client registration that obtained them; see docs/superpowers/specs/2026-11-25-slice-3-oauth-design.md section 8.
export interface StoredCredentials {
  client?: OAuthClientInformationMixed;
  tokens?: OAuthTokens;
  discovery?: OAuthDiscoveryState;
}

export type CredentialStore = ReturnType<typeof createCredentialStore>;

const KEYCHAIN = ["-s", "sekimori", "-a", "credentials-key"];

function security(args: string[], input?: string): Promise<{ ok: boolean; stdout: string }> {
  return new Promise((resolve) => {
    const child = execFile("/usr/bin/security", args, (error, stdout) => resolve({ ok: !error, stdout: stdout.trim() }));
    child.stdin?.end(input);
  });
}

export async function loadCredentialsKey(dir: string): Promise<Buffer> {
  if (process.platform === "darwin") {
    const found = await security(["find-generic-password", ...KEYCHAIN, "-w"]);
    if (found.ok) return Buffer.from(found.stdout, "hex");
    const key = randomBytes(32).toString("hex");
    // `-w` last makes security read the secret from stdin, so the key never appears in argv.
    const added = await security(["add-generic-password", ...KEYCHAIN, "-w"], `${key}\n${key}\n`);
    if (!added.ok) throw new Error("Could not store the credentials key in the macOS Keychain");
    return Buffer.from(key, "hex");
  }
  const file = join(dir, "credentials.key");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(file, randomBytes(32).toString("hex"), { mode: 0o600, flag: "wx" }).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "EEXIST") throw error;
  });
  return Buffer.from((await readFile(file, "utf8")).trim(), "hex");
}

export function createCredentialStore(dir: string, user: string, key: () => Promise<Buffer>) {
  const fileOf = (upstream: string) => join(dir, "credentials", user, `${upstream}.json`);
  // Binds each file to its user and upstream, so a file copied to another name fails to decrypt.
  const aad = (upstream: string) => Buffer.from(`${user}/${upstream}`);

  return {
    async read(upstream: string): Promise<StoredCredentials> {
      const raw = await readFile(fileOf(upstream), "utf8").catch((error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return undefined;
        throw error;
      });
      if (!raw) return {};
      const { iv, tag, data } = JSON.parse(raw) as Record<string, string>;
      const decipher = createDecipheriv("aes-256-gcm", await key(), Buffer.from(iv!, "base64"));
      decipher.setAAD(aad(upstream));
      decipher.setAuthTag(Buffer.from(tag!, "base64"));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(data!, "base64")), decipher.final()]).toString("utf8"));
    },

    async write(upstream: string, credentials: StoredCredentials): Promise<void> {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", await key(), iv);
      cipher.setAAD(aad(upstream));
      const data = Buffer.concat([cipher.update(JSON.stringify(credentials), "utf8"), cipher.final()]);
      const file = fileOf(upstream);
      await mkdir(join(dir, "credentials", user), { recursive: true, mode: 0o700 });
      const temporary = `${file}.${process.pid}.tmp`;
      await writeFile(temporary, JSON.stringify({ iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") }), {
        mode: 0o600,
      });
      await rename(temporary, file);
    },

    remove: (upstream: string) => rm(fileOf(upstream), { force: true }),
  };
}

export interface ProviderOptions {
  store: CredentialStore;
  upstream: string;
  redirectUrl: string;
  redirectUris: string[];
  preregistered?: { clientId: string; clientSecret?: string; scope?: string };
  // Only a connect the human started carries a state; without one, authorization URLs are dropped.
  state?: string;
}

export function createOAuthProvider(options: ProviderOptions): OAuthClientProvider & { authorizationUrl?: URL } {
  const { store, upstream, preregistered } = options;
  let verifier: string | undefined;
  let authorizationUrl: URL | undefined;
  const update = async (change: (stored: StoredCredentials) => StoredCredentials) =>
    store.write(upstream, change(await store.read(upstream)));

  return {
    get authorizationUrl() {
      return authorizationUrl;
    },
    redirectUrl: options.redirectUrl,
    clientMetadata: {
      client_name: "Sekimori gateway",
      redirect_uris: options.redirectUris,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: preregistered?.clientSecret ? "client_secret_post" : "none",
      scope: preregistered?.scope,
    } satisfies OAuthClientMetadata,
    state: () => options.state ?? randomBytes(18).toString("base64url"),
    async clientInformation() {
      const stored = (await store.read(upstream)).client;
      return stored ?? (preregistered ? { client_id: preregistered.clientId, client_secret: preregistered.clientSecret } : undefined);
    },
    saveClientInformation: (client) =>
      update((stored) => (stored.client?.client_id === client.client_id ? { ...stored, client } : { discovery: stored.discovery, client })),
    tokens: async () => (await store.read(upstream)).tokens,
    saveTokens: (tokens) => update((stored) => ({ ...stored, tokens })),
    saveCodeVerifier(codeVerifier) {
      verifier = codeVerifier;
    },
    codeVerifier() {
      if (!verifier) throw new Error(`No authorization in progress for ${upstream}`);
      return verifier;
    },
    redirectToAuthorization(url) {
      if (options.state) authorizationUrl = url;
    },
    saveDiscoveryState: (discovery) => update((stored) => ({ ...stored, discovery })),
    discoveryState: async () => (await store.read(upstream)).discovery,
    async invalidateCredentials(scope) {
      if (scope === "verifier") verifier = undefined;
      else if (scope === "all") await store.remove(upstream);
      else if (scope === "tokens") await update(({ tokens: _, ...rest }) => rest);
      else if (scope === "client") await update(({ discovery }) => ({ discovery }));
      else await update(({ discovery: _, ...rest }) => rest);
    },
  };
}
