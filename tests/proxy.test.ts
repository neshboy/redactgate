import { afterEach, beforeEach, describe, expect, it } from "vitest";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createRedactGateServer } from "../src/server.js";
import { startTestUpstream, type TestUpstream } from "./helpers/testUpstream.js";

interface GateHandle {
  server: http.Server;
  port: number;
  baseUrl: string;
  close: () => Promise<void>;
}

async function startGate(upstreamBaseUrl: string, auditLogPath: string): Promise<GateHandle> {
  const server = createRedactGateServer({ upstream: upstreamBaseUrl, auditLogPath });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        server,
        port,
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise<void>((res) => server.close(() => res())),
      });
    });
  });
}

async function readAuditEntries(auditLogPath: string): Promise<any[]> {
  try {
    const content = await readFile(auditLogPath, "utf8");
    return content
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line));
  } catch (error: any) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

describe("Redact Gate proxy (end-to-end)", () => {
  let upstream: TestUpstream;
  let gate: GateHandle;
  let tmpDir: string;
  let auditLogPath: string;

  beforeEach(async () => {
    upstream = await startTestUpstream();
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "redactgate-test-"));
    auditLogPath = path.join(tmpDir, "audit.log");
    gate = await startGate(upstream.baseUrl, auditLogPath);
  });

  afterEach(async () => {
    await gate.close();
    await upstream.close();
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("redacts planted secrets before the upstream ever sees them", async () => {
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    const githubToken = "ghp_" + "B".repeat(36);
    const requestBody = JSON.stringify({
      model: "test-model",
      messages: [
        {
          role: "user",
          content: `Here is my AWS key ${awsKey} and my GitHub token ${githubToken}. Please help me set up CI.`,
        },
      ],
    });

    const response = await fetch(`${gate.baseUrl}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: requestBody,
    });
    expect(response.status).toBe(200);
    const responseJson = (await response.json()) as { echoedBody: string };

    // (a) the fake upstream actually received a body with secrets redacted.
    expect(upstream.received).toHaveLength(1);
    const receivedBodyText = upstream.received[0]!.body.toString("utf8");
    expect(receivedBodyText).not.toContain(awsKey);
    expect(receivedBodyText).not.toContain(githubToken);
    expect(receivedBodyText).toContain("[REDACTED:aws-access-key]");
    expect(receivedBodyText).toContain("[REDACTED:github-token]");
    expect(receivedBodyText).toContain("Please help me set up CI");

    // The response the caller gets back should reflect what upstream actually got (redacted).
    expect(responseJson.echoedBody).not.toContain(awsKey);
    expect(responseJson.echoedBody).not.toContain(githubToken);

    // (c) the audit log records type/location, never the raw secret value.
    const entries = await readAuditEntries(auditLogPath);
    expect(entries.length).toBeGreaterThanOrEqual(2);
    const types = entries.map((e) => e.type).sort();
    expect(types).toContain("aws-access-key");
    expect(types).toContain("github-token");
    for (const entry of entries) {
      expect(typeof entry.line).toBe("number");
      expect(typeof entry.column).toBe("number");
      expect(typeof entry.length).toBe("number");
      const serialized = JSON.stringify(entry);
      expect(serialized).not.toContain(awsKey);
      expect(serialized).not.toContain(githubToken);
    }
  });

  it("passes a request with no secrets through byte-for-byte unchanged", async () => {
    const requestBody = JSON.stringify({
      model: "test-model",
      messages: [{ role: "user", content: "Please summarize the attached quarterly report in three bullet points." }],
    });

    const response = await fetch(`${gate.baseUrl}/v1/messages`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: requestBody,
    });
    expect(response.status).toBe(200);

    expect(upstream.received).toHaveLength(1);
    const receivedBodyText = upstream.received[0]!.body.toString("utf8");
    expect(receivedBodyText).toBe(requestBody);

    // No findings means no audit log entries (and the file may not even exist yet).
    const entries = await readAuditEntries(auditLogPath);
    expect(entries).toHaveLength(0);
  });
});
