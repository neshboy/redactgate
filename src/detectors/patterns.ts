/**
 * Known secret/credential format detectors.
 *
 * Each entry is a regex for a *specific, well-known* credential format.
 * These run before the generic entropy scanner so that things we can
 * positively identify get a precise, informative label (e.g.
 * `[REDACTED:aws-access-key]`) instead of the generic
 * `[REDACTED:high-entropy-string]`.
 *
 * Sources for these formats: AWS docs, GitHub's documented PAT prefixes,
 * Slack's token format docs, RFC 7519 (JWT), and public vendor key formats
 * (OpenAI, Anthropic, Google, Stripe).
 */
export interface PatternDetector {
  /** Stable machine-readable label used in redaction placeholders and audit logs. */
  type: string;
  /** Regex describing the format. Must be global (`g` flag). */
  regex: RegExp;
  /**
   * If set, the actual secret lives in this capture group rather than the
   * whole match (e.g. matching `AWS_SECRET_ACCESS_KEY=<value>` but only
   * wanting to redact `<value>`, keeping the key name readable in logs).
   */
  captureGroup?: number;
}

// NOTE on `\b` usage below: we deliberately only anchor the *trailing* edge
// of most prefix-based tokens, not the leading edge. Real-world request
// bodies are usually JSON, so a block of pasted `.env` content shows up
// with literal `\n`/`\t` escape sequences (backslash followed by a letter)
// rather than actual newlines. A leading `\b` right before a token whose
// first character is alphanumeric fails to match immediately after such an
// escape (the escape's letter and the token's first letter are both "word"
// characters as far as regex is concerned, so there's no boundary between
// them) - which would silently miss exactly the multi-secret-dump scenario
// this tool exists to catch. Dropping the leading anchor trades a small
// amount of extra false-positive risk (matching inside a longer identifier)
// for not missing real secrets, which is the right tradeoff for a tool
// whose failure mode should be "redacts too much" rather than "leaks".
export const patternDetectors: PatternDetector[] = [
  {
    type: "private-key",
    // The middle wildcard is bounded (rather than an unbounded `[\s\S]*?`)
    // to avoid quadratic-time backtracking blowup on input containing
    // repeated/unterminated BEGIN markers, which could otherwise block the
    // single-threaded proxy's event loop for an extended period. 20000
    // characters is comfortably larger than any real PEM-encoded key block.
    regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,20000}?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    // Standard (AKIA) and temporary/STS (ASIA) AWS access key IDs.
    type: "aws-access-key",
    regex: /(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    // AWS secret access keys have no distinctive prefix, so we only trust
    // them in context: an env-style assignment to a recognizably-named key.
    type: "aws-secret-key",
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/g,
    captureGroup: 1,
  },
  {
    // ghp_ (personal access token), gho_ (oauth), ghu_ (user-to-server),
    // ghs_ (server-to-server), ghr_ (refresh token).
    type: "github-token",
    regex: /gh[pousr]_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    // Slack bot/app/user/refresh tokens: xoxb-, xoxa-, xoxp-, xoxr-, xoxs-.
    type: "slack-token",
    regex: /xox[baprs]-[A-Za-z0-9-]{10,72}\b/g,
  },
  {
    type: "slack-webhook",
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
  },
  {
    // Anthropic API keys, e.g. sk-ant-api03-<...>. Checked before the
    // generic OpenAI-style pattern below.
    type: "anthropic-api-key",
    regex: /sk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    // OpenAI-style secret keys (sk-..., sk-proj-...). Excludes sk-ant- so it
    // doesn't shadow the more specific Anthropic detector above.
    type: "openai-api-key",
    regex: /sk-(?!ant-)[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: "google-api-key",
    regex: /AIza[0-9A-Za-z_-]{35}\b/g,
  },
  {
    type: "stripe-key",
    regex: /[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  },
  {
    // Three dot-separated base64url segments, header segment starting with
    // the near-universal `eyJ` (base64 of `{"`).
    type: "jwt",
    regex: /eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
  },
];
