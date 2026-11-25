import { watch, type FSWatcher } from "node:fs";
import { appendFile, mkdir, open, readdir, rm } from "node:fs/promises";
import { join } from "node:path";
import type { PlanStep } from "./plan.ts";

// The shared, local activity log behind the dashboard; see docs/superpowers/specs/2026-11-25-dashboard-design.md section 6.

export interface Session {
  port: number;
  pid: number;
  agent: string;
  user: string;
}

export type RequestStatus =
  | "running"
  | "waiting"
  | "completed"
  | "failed"
  | "rejected"
  | "approval_required"
  | "approval_pending"
  | "connect_required"
  | "connect_pending"
  | "connected";

export type RequestFields = {
  executionId: string;
  status: RequestStatus;
  hash?: string;
  steps?: PlanStep[];
  open?: boolean;
  reasons?: string[];
  approvalId?: string;
  expiresAt?: number;
  upstreams?: string[];
  calls?: number;
  error?: string;
};

export type ActivityEntry =
  | ({ kind: "request" } & RequestFields)
  | { kind: "decision"; approvalId: string; decision: "approved" | "denied" | "expired" }
  | { kind: "connection"; upstream: string; state: string; reason?: string }
  | { kind: "session"; state: "started" | "stopped" };

export type ActivityRecord = { v: 1; at: string; session: Session } & ActivityEntry;

const RETENTION_DAYS = 30;
const MAX_STEPS = 40;

const dayFile = (date: Date) => `${date.toISOString().slice(0, 10)}.jsonl`;

export function createActivityLog(root: string, user: string) {
  const dir = join(root, "activity", user);
  const offsets = new Map<string, number>();
  let skipped = 0;

  async function readNew(file: string): Promise<ActivityRecord[]> {
    const handle = await open(join(dir, file), "r").catch(() => undefined);
    if (!handle) return [];
    try {
      const start = offsets.get(file) ?? 0;
      const { size } = await handle.stat();
      if (size <= start) return [];
      const buffer = Buffer.alloc(size - start);
      await handle.read(buffer, 0, buffer.length, start);
      // Only complete lines count; a line still being written is read on the next pass.
      const end = buffer.lastIndexOf(10);
      if (end < 0) return [];
      offsets.set(file, start + end + 1);
      return buffer
        .subarray(0, end)
        .toString("utf8")
        .split("\n")
        .flatMap((line) => {
          try {
            const record = JSON.parse(line) as ActivityRecord;
            if (record.v === 1 && record.session && record.kind) return [record];
          } catch {}
          skipped++;
          return [];
        });
    } finally {
      await handle.close();
    }
  }

  const days = async () => (await readdir(dir).catch(() => [] as string[])).filter((f) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort();

  return {
    skipped: () => skipped,

    async prune(now = new Date()): Promise<void> {
      const cutoff = dayFile(new Date(now.getTime() - RETENTION_DAYS * 86_400_000));
      for (const file of await days()) if (file < cutoff) await rm(join(dir, file), { force: true });
    },

    // Appends one record with a single write; O_APPEND keeps concurrent gateways from interleaving.
    async append(session: Session, entry: ActivityEntry, now = new Date()): Promise<void> {
      const capped = entry.kind === "request" && entry.steps && entry.steps.length > MAX_STEPS ? { ...entry, steps: entry.steps.slice(0, MAX_STEPS), open: true } : entry;
      await mkdir(dir, { recursive: true, mode: 0o700 });
      await appendFile(join(dir, dayFile(now)), `${JSON.stringify({ v: 1, at: now.toISOString(), session, ...capped })}\n`, { mode: 0o600 });
    },

    // Reads everything not read yet, oldest day first.
    async readAll(): Promise<ActivityRecord[]> {
      const records: ActivityRecord[] = [];
      for (const file of await days()) records.push(...(await readNew(file)));
      return records;
    },

    // Calls back with new records from any gateway; fs.watch can miss events, so a slow re-read backs it up.
    watch(onRecords: (records: ActivityRecord[]) => void): () => void {
      let running = Promise.resolve();
      const poll = () => {
        running = running.then(async () => {
          const records: ActivityRecord[] = [];
          for (const file of (await days()).slice(-2)) records.push(...(await readNew(file)));
          if (records.length > 0) onRecords(records);
        });
      };
      let watcher: FSWatcher | undefined;
      mkdir(dir, { recursive: true, mode: 0o700 }).then(() => {
        watcher = watch(dir, poll);
      });
      const timer = setInterval(poll, 2_000);
      return () => {
        clearInterval(timer);
        watcher?.close();
      };
    },
  };
}

export type ActivityLog = ReturnType<typeof createActivityLog>;

export type RowState =
  | "running"
  | "waiting_approval"
  | "waiting_connect"
  | "approved"
  | "denied"
  | "expired"
  | "completed"
  | "failed"
  | "rejected"
  | "connected"
  | "ended";

export interface RequestRow {
  id: string;
  session: Session;
  startedAt: string;
  updatedAt: string;
  state: RowState;
  steps: PlanStep[];
  open: boolean;
  reasons: string[];
  approvalId?: string;
  expiresAt?: number;
  upstreams: string[];
  calls: number;
  error?: string;
  decision?: { decision: "approved" | "denied" | "expired"; at: string; sessionEnded?: boolean };
  ran: boolean;
}

export const isWaiting = (row: RequestRow) => row.state === "waiting_approval" || row.state === "waiting_connect";

const sessionKey = (session: Session) => `${session.port}-${session.pid}`;

// Folds records into one row per request: a resubmit joins the row of its approval, or of its connect wait.
export function foldRequests(records: ActivityRecord[], isAlive: (session: Session) => boolean, now = Date.now()): RequestRow[] {
  const rows = new Map<string, RequestRow & { status: RequestStatus }>();
  const alias = new Map<string, string>();

  for (const record of records) {
    const s = sessionKey(record.session);
    if (record.kind === "decision") {
      const row = rows.get(alias.get(`${s}:ap:${record.approvalId}`) ?? "");
      if (row) {
        row.decision = { decision: record.decision, at: record.at };
        row.updatedAt = record.at;
      }
      continue;
    }
    if (record.kind !== "request") continue;

    const key =
      alias.get(`${s}:ex:${record.executionId}`) ??
      (record.approvalId ? alias.get(`${s}:ap:${record.approvalId}`) : undefined) ??
      (record.hash ? alias.get(`${s}:cn:${record.hash}`) : undefined) ??
      `${s}-${record.executionId}`;
    let row = rows.get(key);
    if (!row) {
      row = {
        id: `r-${key}`,
        session: record.session,
        startedAt: record.at,
        updatedAt: record.at,
        status: record.status,
        state: "running",
        steps: [],
        open: false,
        reasons: [],
        upstreams: [],
        calls: 0,
        ran: false,
      };
      rows.set(key, row);
    }
    alias.set(`${s}:ex:${record.executionId}`, key);
    if (record.approvalId) alias.set(`${s}:ap:${record.approvalId}`, key);
    if (record.hash && (record.status === "connect_required" || record.status === "connect_pending")) alias.set(`${s}:cn:${record.hash}`, key);
    if (record.hash && record.status === "connected") alias.delete(`${s}:cn:${record.hash}`);

    row.status = record.status;
    row.updatedAt = record.at;
    if (record.steps) row.steps = record.steps;
    if (record.open !== undefined) row.open = record.open;
    if (record.reasons?.length) row.reasons = record.reasons;
    if (record.approvalId) row.approvalId = record.approvalId;
    if (record.expiresAt) row.expiresAt = record.expiresAt;
    if (record.upstreams) row.upstreams = record.upstreams;
    if (record.calls !== undefined) row.calls = record.calls;
    row.error = record.error;
    if (record.status === "completed" || record.status === "failed") row.ran = true;
  }

  return [...rows.values()]
    .map(({ status, ...row }) => {
      const alive = isAlive(row.session);
      const pendingApproval = status === "approval_required" || status === "approval_pending" || (status === "waiting" && !!row.approvalId);
      const pendingConnect = status === "connect_required" || status === "connect_pending" || (status === "waiting" && !row.approvalId);
      let state: RowState;
      if (row.decision?.decision === "denied" || row.decision?.decision === "expired") state = row.decision.decision;
      else if (status === "completed" || status === "failed" || status === "rejected" || status === "connected") state = status;
      else if (row.decision?.decision === "approved") state = alive ? "approved" : "expired";
      else if (pendingApproval) state = "waiting_approval";
      else if (pendingConnect) state = "waiting_connect";
      else state = "running";

      const timedOut = row.expiresAt !== undefined && row.expiresAt <= now;
      if (state === "waiting_approval" && (timedOut || !alive)) {
        state = "expired";
        row.decision = { decision: "expired", at: row.updatedAt, sessionEnded: !alive && !timedOut };
      } else if ((state === "waiting_connect" || state === "running") && !alive) {
        state = "ended";
      }
      return { ...row, state };
    })
    .sort((a, b) => (a.startedAt < b.startedAt ? 1 : -1));
}
