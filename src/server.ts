import http, { type IncomingMessage, type ServerResponse } from "node:http";
import https from "node:https";
import { randomUUID } from "node:crypto";
import { redactSecrets, type Finding } from "./detectors/redact.js";
import { appendAuditEntries, type AuditEntry } from "./audit.js";

export interface RedactGateEvent {
  kind: "redacted" | "error" | "forward-error";
  requestId: string;
  direction?: "request" | "response";
  count?: number;
  findings?: AuditEntry[];
  error?: unknown;
}

export interface RedactGateOptions {
  /** Upstream base URL requests get forwarded to, e.g. https://api.anthropic.com */
  upstream: string;
  /** Path to the newline-delimited-JSON audit log file. */
  auditLogPath: string;
  /**
   * Also buffer and inspect/redact response bodies from upstream. Off by
   * default because it disables true streaming (SSE) responses, which most
   * LLM APIs use for token-by-token output.
   */
  redactResponses?: boolean;
  /** Maximum request/response body size to buffer, in bytes. Defaults to 25MB. */
  maxBodyBytes?: number;
  onEvent?: (event: RedactGateEvent) => void;
}

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function readBody(req: IncomingMessage, maxBodyBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBodyBytes) {
        reject(new Error(`Request body exceeds maxBodyBytes (${maxBodyBytes})`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function joinPath(basePath: string, requestPath: string | undefined): string {
  const reqPath = requestPath ?? "/";
  if (basePath === "" || basePath === "/") return reqPath;
  const trimmedBase = basePath.endsWith("/") ? basePath.slice(0, -1) : basePath;
  return `${trimmedBase}${reqPath.startsWith("/") ? reqPath : `/${reqPath}`}`;
}

function filterOutboundHeaders(headers: IncomingMessage["headers"]): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lower)) continue;
    if (lower === "content-length" || lower === "host") continue;
    out[key] = value;
  }
  return out;
}

function findingsToAuditEntries(
  findings: Finding[],
  meta: { requestId: string; direction: "request" | "response"; method?: string; path: string; upstreamHost: string },
): AuditEntry[] {
  const timestamp = new Date().toISOString();
  return findings.map((f) => ({
    timestamp,
    requestId: meta.requestId,
    direction: meta.direction,
    method: meta.method,
    path: meta.path,
    upstreamHost: meta.upstreamHost,
    type: f.type,
    line: f.line,
    column: f.column,
    length: f.length,
  }));
}

/**
 * Build (but do not start) the Redact Gate proxy server. Call `.listen()`
 * on the returned server yourself, same as any `http.Server`.
 */
export function createRedactGateServer(options: RedactGateOptions): http.Server {
  const upstreamUrl = new URL(options.upstream);
  const isHttps = upstreamUrl.protocol === "https:";
  const maxBodyBytes = options.maxBodyBytes ?? 25 * 1024 * 1024;

  const server = http.createServer((req, res) => {
    handleRequest(req, res, upstreamUrl, isHttps, maxBodyBytes, options).catch((error) => {
      options.onEvent?.({ kind: "error", requestId: "unknown", error });
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "application/json" });
      }
      res.end(JSON.stringify({ error: "redactgate_proxy_error", message: error instanceof Error ? error.message : String(error) }));
    });
  });

  return server;
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  upstreamUrl: URL,
  isHttps: boolean,
  maxBodyBytes: number,
  options: RedactGateOptions,
): Promise<void> {
  const requestId = randomUUID();
  const requestBuffer = await readBody(req, maxBodyBytes);

  let outboundBody = requestBuffer;
  if (requestBuffer.length > 0) {
    const bodyText = requestBuffer.toString("utf8");
    const { redacted, findings } = redactSecrets(bodyText);
    if (findings.length > 0) {
      outboundBody = Buffer.from(redacted, "utf8");
      const entries = findingsToAuditEntries(findings, {
        requestId,
        direction: "request",
        method: req.method,
        path: req.url ?? "/",
        upstreamHost: upstreamUrl.host,
      });
      await appendAuditEntries(options.auditLogPath, entries);
      options.onEvent?.({ kind: "redacted", requestId, direction: "request", count: findings.length, findings: entries });
    }
  }

  const outboundHeaders = filterOutboundHeaders(req.headers);
  outboundHeaders["host"] = upstreamUrl.host;
  outboundHeaders["content-length"] = String(outboundBody.length);
  if (options.redactResponses) {
    // The response-redaction path below scans/rewrites the upstream body as
    // plain UTF-8 text. If we forwarded the client's Accept-Encoding as-is,
    // upstream could return a gzip/br/deflate-compressed body, which would
    // be scanned/rewritten as raw bytes - silently missing real secrets
    // and/or corrupting the response. Force an uncompressed response so the
    // buffered body is always the actual plaintext being scanned.
    outboundHeaders["accept-encoding"] = "identity";
  }

  const requestModule = isHttps ? https : http;

  await new Promise<void>((resolve, reject) => {
    const upstreamReq = requestModule.request(
      {
        protocol: upstreamUrl.protocol,
        hostname: upstreamUrl.hostname,
        port: upstreamUrl.port || (isHttps ? 443 : 80),
        path: joinPath(upstreamUrl.pathname, req.url),
        method: req.method,
        headers: outboundHeaders,
      },
      (upstreamRes) => {
        void handleUpstreamResponse(upstreamRes, res, requestId, req, upstreamUrl, options).then(resolve, reject);
      },
    );

    upstreamReq.on("error", (error) => {
      options.onEvent?.({ kind: "forward-error", requestId, error });
      if (!res.headersSent) {
        res.writeHead(502, { "content-type": "application/json" });
      }
      res.end(JSON.stringify({ error: "redactgate_upstream_error", message: error.message }));
      reject(error);
    });

    upstreamReq.end(outboundBody);
  });
}

async function handleUpstreamResponse(
  upstreamRes: IncomingMessage,
  res: ServerResponse,
  requestId: string,
  req: IncomingMessage,
  upstreamUrl: URL,
  options: RedactGateOptions,
): Promise<void> {
  const statusCode = upstreamRes.statusCode ?? 502;

  if (!options.redactResponses) {
    // Default path: stream straight through untouched, so Server-Sent
    // Events / chunked streaming responses from the LLM API keep working.
    const headers = filterOutboundHeaders(upstreamRes.headers);
    res.writeHead(statusCode, headers);
    await new Promise<void>((resolve, reject) => {
      upstreamRes.pipe(res);
      upstreamRes.on("end", resolve);
      upstreamRes.on("error", reject);
    });
    return;
  }

  // Optional path: buffer the full response, scan/redact it too, then send
  // it as a single non-streamed reply.
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    upstreamRes.on("data", (chunk: Buffer) => chunks.push(chunk));
    upstreamRes.on("end", () => resolve());
    upstreamRes.on("error", reject);
  });

  const bodyBuffer = Buffer.concat(chunks);
  let outboundBody = bodyBuffer;
  if (bodyBuffer.length > 0) {
    const { redacted, findings } = redactSecrets(bodyBuffer.toString("utf8"));
    if (findings.length > 0) {
      outboundBody = Buffer.from(redacted, "utf8");
      const entries = findingsToAuditEntries(findings, {
        requestId,
        direction: "response",
        method: req.method,
        path: req.url ?? "/",
        upstreamHost: upstreamUrl.host,
      });
      await appendAuditEntries(options.auditLogPath, entries);
      options.onEvent?.({ kind: "redacted", requestId, direction: "response", count: findings.length, findings: entries });
    }
  }

  const headers = filterOutboundHeaders(upstreamRes.headers);
  headers["content-length"] = String(outboundBody.length);
  res.writeHead(statusCode, headers);
  res.end(outboundBody);
}
