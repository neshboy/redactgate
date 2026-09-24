import { patternDetectors } from "./patterns.js";
import { isHighEntropy } from "./entropy.js";

export interface Finding {
  /** Detector label, e.g. "aws-access-key", "env-style-secret", "high-entropy-string". */
  type: string;
  /** 0-based character offset where the redacted span started in the original text. */
  start: number;
  /** 0-based character offset where the redacted span ended (exclusive). */
  end: number;
  /** 1-based line number of `start` in the original text. */
  line: number;
  /** 1-based column number of `start` in the original text. */
  column: number;
  /** Length in characters of the redacted span. Never the value itself. */
  length: number;
}

export interface RedactResult {
  redacted: string;
  findings: Finding[];
  /** True if `redacted` differs from the input at all. */
  changed: boolean;
}

interface Span {
  start: number;
  end: number;
  type: string;
}

/**
 * `.env`-style `KEY=value` lines where the key name suggests a secret.
 * Deliberately only matches `=` assignment (not `:`) so it doesn't swallow
 * unrelated `Header-Name: value` lines (e.g. an `Authorization:` header),
 * which are better left to the more specific token/JWT detectors above.
 */
const ENV_LINE_REGEX = /^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*(.+?)[ \t]*$/gm;
const SENSITIVE_KEY_NAME = /(KEY|SECRET|TOKEN|PASSWORD|PWD|PASS|CREDENTIAL|AUTH|API)/i;

/** Candidate tokens for the generic entropy scan: base64/hex/URL-safe-ish runs of 20+ chars. */
const CANDIDATE_TOKEN_REGEX = /[A-Za-z0-9+/_.=-]{20,}/g;

function overlapsAny(span: { start: number; end: number }, accepted: Span[]): boolean {
  return accepted.some((a) => span.start < a.end && span.end > a.start);
}

function stripMatchingQuotes(value: string, offset: number): { value: string; start: number } {
  if (value.length >= 2) {
    const first = value[0];
    const last = value[value.length - 1];
    if ((first === '"' || first === "'") && first === last) {
      return { value: value.slice(1, -1), start: offset + 1 };
    }
  }
  return { value, start: offset };
}

function findEnvStyleSecretSpans(text: string): Span[] {
  const spans: Span[] = [];
  let match: RegExpExecArray | null;
  ENV_LINE_REGEX.lastIndex = 0;
  while ((match = ENV_LINE_REGEX.exec(text))) {
    const [full, key, rawValue] = match;
    if (!SENSITIVE_KEY_NAME.test(key)) continue;
    if (rawValue.length === 0) continue;

    const valueOffsetInMatch = full.lastIndexOf(rawValue);
    if (valueOffsetInMatch === -1) continue;
    const rawStart = match.index + valueOffsetInMatch;

    const { value, start } = stripMatchingQuotes(rawValue, rawStart);
    if (value.length === 0) continue;

    // Contextual match (sensitive key name already gives us confidence), so
    // allow a shorter minimum length than the context-free generic scan.
    if (!isHighEntropy(value, { minLength: 8 })) continue;

    spans.push({ start, end: start + value.length, type: "env-style-secret" });
  }
  return spans;
}

function findHighEntropySpans(text: string, accepted: Span[]): Span[] {
  const spans: Span[] = [];
  let match: RegExpExecArray | null;
  CANDIDATE_TOKEN_REGEX.lastIndex = 0;
  while ((match = CANDIDATE_TOKEN_REGEX.exec(text))) {
    const token = match[0];
    const start = match.index;
    const end = start + token.length;
    const candidateSpan = { start, end };
    if (overlapsAny(candidateSpan, accepted)) continue;
    if (!isHighEntropy(token, { minLength: 20 })) continue;
    spans.push({ start, end, type: "high-entropy-string" });
  }
  return spans;
}

function lineColumnAt(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let lastNewline = -1;
  const limit = Math.min(index, text.length);
  for (let i = 0; i < limit; i++) {
    if (text[i] === "\n") {
      line++;
      lastNewline = i;
    }
  }
  return { line, column: index - lastNewline };
}

/**
 * Scan `text` for secrets/credentials and return a redacted copy plus a
 * list of findings suitable for audit logging. Findings never carry the
 * matched value, only its type and location.
 */
export function redactSecrets(text: string): RedactResult {
  if (text.length === 0) {
    return { redacted: text, findings: [], changed: false };
  }

  const candidates: Span[] = [];

  for (const detector of patternDetectors) {
    const regex = new RegExp(detector.regex.source, detector.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text))) {
      if (detector.captureGroup !== undefined && match[detector.captureGroup] !== undefined) {
        const group = match[detector.captureGroup];
        const groupStart = match.index + match[0].lastIndexOf(group);
        candidates.push({ start: groupStart, end: groupStart + group.length, type: detector.type });
      } else {
        candidates.push({ start: match.index, end: match.index + match[0].length, type: detector.type });
      }
      if (match[0].length === 0) regex.lastIndex++;
    }
  }

  candidates.push(...findEnvStyleSecretSpans(text));

  // Resolve overlaps: longer matches win, and among equal-length matches the
  // one discovered first (i.e. earlier/more specific detector) wins, since
  // Array#sort is stable in the engines we target.
  candidates.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));

  const accepted: Span[] = [];
  for (const span of candidates) {
    if (!overlapsAny(span, accepted)) accepted.push(span);
  }

  accepted.push(...findHighEntropySpans(text, accepted));
  accepted.sort((a, b) => a.start - b.start);

  const findings: Finding[] = [];
  let redacted = "";
  let cursor = 0;
  for (const span of accepted) {
    redacted += text.slice(cursor, span.start);
    redacted += `[REDACTED:${span.type}]`;
    const { line, column } = lineColumnAt(text, span.start);
    findings.push({
      type: span.type,
      start: span.start,
      end: span.end,
      line,
      column,
      length: span.end - span.start,
    });
    cursor = span.end;
  }
  redacted += text.slice(cursor);

  return { redacted, findings, changed: findings.length > 0 };
}
