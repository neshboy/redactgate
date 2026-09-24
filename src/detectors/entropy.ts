/**
 * Shannon entropy utilities.
 *
 * Specific regex patterns (AWS keys, GitHub tokens, JWTs, etc.) only catch
 * secret formats we already know about. Real secrets frequently show up as
 * opaque high-entropy strings that don't match any known format (a random
 * API key from some internal service, a rotated token, etc). To catch those
 * we fall back to a Shannon entropy measurement, the same technique tools
 * like gitleaks and detect-secrets use for their "generic high entropy
 * string" detectors.
 */

/** Character classes we recognize, each with its own realistic entropy ceiling. */
type CharsetKind = "hex" | "base64" | "generic";

const HEX_CHARSET = /^[0-9a-fA-F]+$/;
const BASE64_CHARSET = /^[A-Za-z0-9+/=]+$/;

/**
 * Shannon entropy of a string, in bits per character.
 *
 * H = -sum(p_i * log2(p_i)) over the observed character frequency
 * distribution. A string built from very few distinct, repeated
 * characters (e.g. "aaaaaaaa" or "12121212") has low entropy. A string
 * that looks like random bytes base64/hex encoded has high entropy.
 */
export function shannonEntropy(input: string): number {
  if (input.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of input) {
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const probability = count / input.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function classifyCharset(token: string): CharsetKind {
  if (HEX_CHARSET.test(token)) return "hex";
  if (BASE64_CHARSET.test(token)) return "base64";
  return "generic";
}

/**
 * Entropy thresholds, in bits/char, above which a token of a given charset
 * is treated as "probably random data" rather than natural language or
 * structured text. These mirror the thresholds used by detect-secrets
 * (HexHighEntropyString ~3.0, Base64HighEntropyString ~4.5); "generic"
 * covers base64url-ish tokens that also use `-`, `_`, `.` (JWT segments,
 * URL-safe API keys) and gets a slightly lower bar than pure base64 since
 * the wider alphabet already makes collisions less likely.
 */
const THRESHOLDS: Record<CharsetKind, number> = {
  hex: 3.0,
  base64: 4.5,
  generic: 4.0,
};

export interface EntropyCheckOptions {
  /** Minimum token length to even consider. Short tokens are too noisy to score reliably. */
  minLength?: number;
}

/**
 * Decide whether `token` looks like random/high-entropy data worth flagging
 * as a potential secret, based purely on its character distribution (no
 * knowledge of what the token *is*).
 */
export function isHighEntropy(token: string, options: EntropyCheckOptions = {}): boolean {
  const minLength = options.minLength ?? 20;
  if (token.length < minLength) return false;

  const charset = classifyCharset(token);
  const entropy = shannonEntropy(token);
  return entropy >= THRESHOLDS[charset];
}
