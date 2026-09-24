import http, { type IncomingMessage } from "node:http";

export interface ReceivedRequest {
  method?: string;
  url?: string;
  headers: IncomingMessage["headers"];
  body: Buffer;
}

export interface TestUpstream {
  server: http.Server;
  port: number;
  baseUrl: string;
  received: ReceivedRequest[];
  close: () => Promise<void>;
}

/**
 * A minimal "upstream API" for tests: it records every request it receives
 * (headers + raw body) and echoes the body back as JSON, so tests can
 * assert on exactly what bytes made it past the proxy.
 */
export function startTestUpstream(): Promise<TestUpstream> {
  const received: ReceivedRequest[] = [];

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      received.push({ method: req.method, url: req.url, headers: req.headers, body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ echoedBody: body.toString("utf8") }));
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        server,
        port,
        baseUrl: `http://127.0.0.1:${port}`,
        received,
        close: () => new Promise<void>((res2) => server.close(() => res2())),
      });
    });
  });
}
