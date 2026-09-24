#!/usr/bin/env node
import path from "node:path";
import { Command } from "commander";
import { createRedactGateServer, type RedactGateEvent } from "./server.js";

const program = new Command();

program
  .name("redactgate")
  .description("Local proxy that redacts secrets and PII from outgoing LLM API requests before they leave your machine.")
  .version("0.1.0");

program
  .command("serve")
  .description("Start the Redact Gate proxy")
  .requiredOption("--upstream <url>", "Upstream API base URL to forward requests to, e.g. https://api.anthropic.com")
  .option("-p, --port <port>", "Port to listen on", "8787")
  .option("--host <host>", "Host to bind to", "127.0.0.1")
  .option("--audit-log <path>", "Path to the audit log file", path.join(process.cwd(), ".redactgate", "audit.log"))
  .option("--redact-responses", "Also inspect/redact response bodies from upstream (buffers responses, disables streaming)", false)
  .action((opts: { upstream: string; port: string; host: string; auditLog: string; redactResponses: boolean }) => {
    const port = Number(opts.port);
    if (!Number.isInteger(port) || port <= 0) {
      console.error(`Invalid --port: ${opts.port}`);
      process.exitCode = 1;
      return;
    }

    let upstream: URL;
    try {
      upstream = new URL(opts.upstream);
    } catch {
      console.error(`Invalid --upstream URL: ${opts.upstream}`);
      process.exitCode = 1;
      return;
    }

    const auditLogPath = path.resolve(opts.auditLog);

    const server = createRedactGateServer({
      upstream: upstream.toString(),
      auditLogPath,
      redactResponses: Boolean(opts.redactResponses),
      onEvent: (event: RedactGateEvent) => {
        if (event.kind === "redacted") {
          console.log(
            `[redactgate] redacted ${event.count} secret(s) in ${event.direction ?? "request"} ${event.requestId}`,
          );
        } else if (event.kind === "error" || event.kind === "forward-error") {
          console.error(`[redactgate] error handling request ${event.requestId}:`, event.error);
        }
      },
    });

    server.listen(port, opts.host, () => {
      console.log(`redactgate listening on http://${opts.host}:${port} -> ${upstream.toString()}`);
      console.log(`audit log: ${auditLogPath}`);
      console.log(
        opts.redactResponses
          ? "response inspection: ON (responses are buffered, not streamed)"
          : "response inspection: OFF (responses stream through untouched)",
      );
    });
  });

program.parse();
