# Redact Gate

**A local HTTP(S) proxy that redacts secrets and credentials from your AI agent's requests before they ever reach a cloud LLM.** Point your agent's `OPENAI_BASE_URL` / `ANTHROPIC_BASE_URL` at Redact Gate instead of the real API, and it transparently forwards your traffic upstream - scanning every request body first, swapping any AWS keys, GitHub tokens, private keys, JWTs, `.env` secrets, or other high-entropy credentials it finds for a clear `[REDACTED:type]` placeholder, and logging what it caught (never the secret itself) so you can audit what almost leaked.

## Why this exists

Coding agents routinely read entire files, `.env` dumps, shell history, and config directories into their context so they can act on them - and that context gets shipped straight to a cloud LLM API on every turn. It's a widely reported, easy-to-hit failure mode: an agent asked to "help debug the deploy script" pastes the whole `.env` file, AWS credentials and all, into a prompt sent to a third-party API. There's no malice involved, no prompt injection required - it's just how these tools work by default. Redact Gate adds a safety net at the network boundary: even if a secret makes it into a request body, it doesn't have to make it off your machine.

## What it does

- Runs a real local HTTP proxy (`redactgate serve`) that forwards requests to a configurable upstream (e.g. `https://api.anthropic.com`, `https://api.openai.com`).
- Buffers and inspects the outgoing request body before forwarding it.
- Detects secrets using:
  - Specific regex patterns for known formats: AWS access keys (`AKIA…`/`ASIA…`), AWS secret keys (via env-style context), PEM private key blocks, GitHub tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), Slack tokens (`xoxb-`/etc.) and webhooks, JWTs, OpenAI-style keys (`sk-…`), Anthropic keys (`sk-ant-…`), Google API keys (`AIza…`), and Stripe keys.
  - `.env`-style `KEY=value` lines where the key name looks sensitive (`*_SECRET`, `*_TOKEN`, `*_PASSWORD`, etc.) and the value is high-entropy.
  - A generic **Shannon entropy** scan over any other long base64/hex/URL-safe-looking token, to catch secrets that don't match a known format at all.
- Replaces every match with `[REDACTED:<type>]` in the body that actually gets forwarded upstream.
- Streams the real upstream response back to the caller (SSE/chunked streaming stays intact by default).
- Appends one line per redaction to a local, newline-delimited-JSON audit log containing the secret's **type and location** (line/column/length) - **never the value**.

This is the same class of technique gitleaks and detect-secrets use for scanning git history, applied instead to live outbound traffic.

## Install / quick start

```bash
git clone <this-repo>
cd redactgate
npm install
npm run build
```

Start the proxy in front of, say, the Anthropic API:

```bash
node dist/cli.js serve --upstream https://api.anthropic.com --port 8787
# or, once linked/installed as a bin:
redactgate serve --upstream https://api.anthropic.com --port 8787
```

Then point your agent/SDK at Redact Gate instead of the real endpoint - most SDKs support this via a base-URL override:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
# or for OpenAI-compatible tooling:
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
```

Your agent keeps working exactly as before; Redact Gate sits in the middle, forwarding real traffic to the real upstream, minus whatever it redacted.

### CLI options

```
redactgate serve --upstream <url> [options]

  --upstream <url>       Required. Upstream API base URL, e.g. https://api.anthropic.com
  -p, --port <port>      Port to listen on (default: 8787)
  --host <host>          Host to bind to (default: 127.0.0.1)
  --audit-log <path>     Path to the audit log file (default: ./.redactgate/audit.log)
  --redact-responses     Also inspect/redact response bodies from upstream.
                          Off by default because it buffers the full response,
                          which disables true token-by-token streaming.
```

## Example: before / after

Say your agent pastes a `.env` file into a chat message so it can "write a Dockerfile that uses it". The **request body Redact Gate receives** looks like:

```json
{
  "model": "gpt-4o",
  "messages": [
    {
      "role": "user",
      "content": "Here is our .env for the deploy script, can you write a Dockerfile that uses it?\n\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nGITHUB_TOKEN=ghp_EXAMPLE_NOT_A_REAL_TOKEN"
    }
  ]
}
```

The **request body that actually reaches the upstream API**:

```json
{
  "model": "gpt-4o",
  "messages": [
    {
      "role": "user",
      "content": "Here is our .env for the deploy script, can you write a Dockerfile that uses it?\n\nAWS_ACCESS_KEY_ID=[REDACTED:aws-access-key]\nAWS_SECRET_ACCESS_KEY=[REDACTED:aws-secret-key]\nGITHUB_TOKEN=[REDACTED:github-token]"
    }
  ]
}
```

And the corresponding lines appended to the audit log (`.redactgate/audit.log`), one JSON object per redaction - type and location only, never the value:

```json
{"timestamp":"2026-09-24T07:20:00.000Z","requestId":"...","direction":"request","method":"POST","path":"/v1/chat/completions","upstreamHost":"api.openai.com","type":"aws-access-key","line":6,"column":121,"length":20}
{"timestamp":"2026-09-24T07:20:00.000Z","requestId":"...","direction":"request","method":"POST","path":"/v1/chat/completions","upstreamHost":"api.openai.com","type":"aws-secret-key","line":6,"column":165,"length":40}
{"timestamp":"2026-09-24T07:20:00.000Z","requestId":"...","direction":"request","method":"POST","path":"/v1/chat/completions","upstreamHost":"api.openai.com","type":"github-token","line":6,"column":220,"length":40}
```

The model still gets a perfectly coherent request (it can still help write the Dockerfile, referencing the redaction placeholders instead of real credentials); the credentials themselves never left your machine.

## How detection works

1. **Pattern matching** (`src/detectors/patterns.ts`): a list of regexes for known credential formats. These run first and produce specific, informative labels.
2. **Contextual `.env` scanning** (`src/detectors/redact.ts`): lines that look like `SOME_KEY=value` where the key name contains `KEY`/`SECRET`/`TOKEN`/`PASSWORD`/etc. get their value entropy-checked.
3. **Generic entropy fallback** (`src/detectors/entropy.ts`): any other long (20+ char) contiguous base64/hex/URL-safe-looking token gets scored with real Shannon entropy (`H = -Σ p(c)·log2(p(c))`) against thresholds tuned per character set (hex ≥3.0 bits/char, base64 ≥4.5, generic mixed ≥4.0 - the same ballpark detect-secrets and gitleaks use). High-entropy tokens are redacted as `[REDACTED:high-entropy-string]` even though we don't know exactly what they are.
4. Overlapping matches are resolved so more specific detectors win over the generic entropy fallback.

## Running the tests

```bash
npm test
```

The test suite spins up its own throwaway local HTTP "upstream" server (plain `http.createServer`, echoing back whatever body it receives) and drives real requests through Redact Gate's actual proxy server end-to-end. It asserts:

- a request containing planted fake secrets (AWS key, GitHub token, etc.) arrives at the fake upstream with those secrets redacted;
- a request with no secrets passes through **byte-for-byte unchanged**;
- the audit log records the redaction type/location and never contains the raw secret value.

There's also a unit test suite for the detectors themselves (pattern matches, entropy scoring, overlap resolution, line/column reporting).

## Limitations (read this before relying on it)

- **This only protects traffic that actually goes through the proxy.** If an agent talks to the LLM API directly (wrong base URL, a different process, a hardcoded endpoint), Redact Gate never sees that traffic and can't help.
- **Regex + entropy detection has false negatives.** It will miss secret formats it doesn't know about and generic tokens that happen to score below the entropy threshold (short secrets, low-entropy passwords, secrets that are mostly dictionary words). It is a strong safety net, not a guarantee.
- **It can also have false positives**, especially from the generic entropy scanner - long random-looking identifiers (session IDs, hashes, UUID-like strings) can get redacted even though they weren't secret. This is a deliberate tradeoff: for a tool like this, over-redacting is a much better failure mode than under-redacting.
- **Detectors intentionally don't require a strict boundary before a match** (see comments in `src/detectors/patterns.ts`) so that secrets pasted back-to-back inside a JSON string (where line breaks are escaped as literal `\n`, not real newlines) still get caught. That same choice slightly increases the odds of a token being flagged when it appears as a substring of a longer identifier.
- **Response bodies stream through untouched by default** (so SSE/streaming completions keep working). Pass `--redact-responses` to also scan responses, at the cost of buffering the whole response instead of streaming it.
- **The audit log lives on your local disk in plain, unencrypted newline-delimited JSON.** It never contains secret values, but treat its location/path metadata as sensitive data about what your agent has been sending.
- This is a young, single-purpose MVP: no web dashboard, no multi-upstream routing, no PII-specific detectors (names/emails/SSNs) yet, no config file - just a CLI flag set and an audit log, by design.

## License

MIT - see [LICENSE](./LICENSE).
