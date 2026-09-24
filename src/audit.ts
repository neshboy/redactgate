import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

/**
 * One line of the audit log. Deliberately excludes the matched secret value
 * itself — only enough metadata to know *that* something was redacted,
 * *what kind* it looked like, and *where*, so a user can review what almost
 * leaked without the audit log itself becoming a new place secrets leak to.
 */
export interface AuditEntry {
  timestamp: string;
  requestId: string;
  direction: "request" | "response";
  method?: string;
  path: string;
  upstreamHost: string;
  type: string;
  line: number;
  column: number;
  length: number;
}

/**
 * Append entries to the audit log as newline-delimited JSON, creating the
 * parent directory and file if needed. Safe to call concurrently from a
 * single process (Node's fs.appendFile uses O_APPEND under the hood, so
 * writes from the same process interleave safely at this volume).
 */
export async function appendAuditEntries(logPath: string, entries: AuditEntry[]): Promise<void> {
  if (entries.length === 0) return;
  await mkdir(dirname(logPath), { recursive: true });
  const lines = entries.map((entry) => JSON.stringify(entry)).join("\n") + "\n";
  await appendFile(logPath, lines, "utf8");
}
