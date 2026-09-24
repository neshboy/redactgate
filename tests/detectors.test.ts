import { describe, expect, it } from "vitest";
import { redactSecrets } from "../src/detectors/redact.js";
import { shannonEntropy, isHighEntropy } from "../src/detectors/entropy.js";

describe("shannonEntropy", () => {
  it("gives low entropy to repetitive strings", () => {
    expect(shannonEntropy("aaaaaaaaaaaaaaaaaaaa")).toBeLessThan(1);
  });

  it("gives higher entropy to varied strings than repetitive ones", () => {
    const low = shannonEntropy("aaaabbbbccccdddd");
    const high = shannonEntropy("kQ9$mZ2vXpL8wR4t");
    expect(high).toBeGreaterThan(low);
  });

  it("returns 0 for the empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });
});

describe("isHighEntropy", () => {
  it("rejects tokens shorter than the minimum length", () => {
    expect(isHighEntropy("aB3$", { minLength: 20 })).toBe(false);
  });

  it("rejects plain repeated-word tokens", () => {
    expect(isHighEntropy("passwordpasswordpasswordpassword", { minLength: 20 })).toBe(false);
  });

  it("accepts a random-looking base64 token", () => {
    expect(isHighEntropy("kQ9mZ2vXpL8wR4tYzB7cN3jH6sD1fA5g", { minLength: 20 })).toBe(true);
  });
});

describe("redactSecrets - known patterns", () => {
  it("redacts an AWS access key id", () => {
    const { redacted, findings } = redactSecrets("my key is AKIAIOSFODNN7EXAMPLE and that's it");
    expect(redacted).toBe("my key is [REDACTED:aws-access-key] and that's it");
    expect(redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(findings).toHaveLength(1);
    expect(findings[0]?.type).toBe("aws-access-key");
  });

  it("redacts an AWS secret access key given in env-assignment context", () => {
    const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const { redacted, findings } = redactSecrets(`AWS_SECRET_ACCESS_KEY=${secret}`);
    expect(redacted).toBe("AWS_SECRET_ACCESS_KEY=[REDACTED:aws-secret-key]");
    expect(redacted).not.toContain(secret);
    expect(findings.some((f) => f.type === "aws-secret-key")).toBe(true);
  });

  it("redacts a PEM private key block", () => {
    const pem = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "EXAMPLE-NOT-A-REAL-KEY-EXAMPLE-NOT-A-REAL-KEY-EXAMPLE-NOT-A-REAL",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");
    const { redacted, findings } = redactSecrets(`here is the key:\n${pem}\nthanks`);
    expect(redacted).toContain("[REDACTED:private-key]");
    expect(redacted).not.toContain("EXAMPLE-NOT-A-REAL-KEY-EXAMPLE-NOT-A-REAL-KEY-EXAMPLE-NOT-A-REAL");
    expect(findings.some((f) => f.type === "private-key")).toBe(true);
  });

  it("redacts a GitHub personal access token", () => {
    const token = "ghp_" + "A".repeat(36);
    const { redacted } = redactSecrets(`token: ${token}`);
    expect(redacted).toBe("token: [REDACTED:github-token]");
    expect(redacted).not.toContain(token);
  });

  it("redacts a Slack bot token", () => {
    const token = "xoxb-EXAMPLE-NOT-A-REAL-SLACK-TOKEN-VALUE";
    const { redacted } = redactSecrets(`slack: ${token}`);
    expect(redacted).toContain("[REDACTED:slack-token]");
    expect(redacted).not.toContain(token);
  });

  it("redacts a JWT-looking three-part token", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYE9m1-4pnzI";
    const { redacted } = redactSecrets(`Authorization: Bearer ${jwt}`);
    expect(redacted).toContain("[REDACTED:jwt]");
    expect(redacted).not.toContain(jwt);
  });

  it("redacts an Anthropic-style API key distinctly from OpenAI-style ones", () => {
    const anthropicKey = "sk-ant-api03-EXAMPLE-NOT-A-REAL-KEY-" + "0".repeat(20);
    const { redacted, findings } = redactSecrets(`ANTHROPIC_API_KEY=${anthropicKey}`);
    expect(findings.some((f) => f.type === "anthropic-api-key" || f.type === "env-style-secret")).toBe(true);
    expect(redacted).not.toContain(anthropicKey);
  });

  it("redacts an OpenAI-style API key", () => {
    const openaiKey = "sk-" + "A1b2C3d4E5f6G7h8I9j0".repeat(2);
    const { redacted } = redactSecrets(`the key is ${openaiKey} ok`);
    expect(redacted).toContain("[REDACTED:openai-api-key]");
    expect(redacted).not.toContain(openaiKey);
  });

  it("redacts .env-style KEY=value lines with high-entropy values", () => {
    const envBlock = ["DB_HOST=localhost", "DB_PASSWORD=mQ8$xL3vN9wRp6TbK2yZ7cF", "DEBUG=true"].join("\n");
    const { redacted } = redactSecrets(envBlock);
    expect(redacted).toContain("DB_HOST=localhost");
    expect(redacted).toContain("DEBUG=true");
    expect(redacted).toContain("[REDACTED:env-style-secret]");
    expect(redacted).not.toContain("mQ8$xL3vN9wRp6TbK2yZ7cF");
  });

  it("catches an unrecognized high-entropy string via the generic entropy fallback", () => {
    // Not a known format, no sensitive key name context - only entropy gives it away.
    const randomLookingToken = "qX7vLp2ZmR9tNc4WdA8sJ6fY3bH1oE0k";
    const { redacted, findings } = redactSecrets(`internal reference id ${randomLookingToken} for this record`);
    expect(redacted).not.toContain(randomLookingToken);
    expect(findings.some((f) => f.type === "high-entropy-string")).toBe(true);
  });

  it("does not flag ordinary prose or short structured data", () => {
    const text = "Please summarize this document and list the top three action items for the team.";
    const { redacted, findings, changed } = redactSecrets(text);
    expect(redacted).toBe(text);
    expect(findings).toHaveLength(0);
    expect(changed).toBe(false);
  });

  it("does not include the raw secret value anywhere in finding metadata", () => {
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const { findings } = redactSecrets(`key=${secret}`);
    const serializedFindings = JSON.stringify(findings);
    expect(serializedFindings).not.toContain(secret);
  });

  it("reports plausible line/column locations for multi-line input", () => {
    const text = "line one\nline two AKIAIOSFODNN7EXAMPLE\nline three";
    const { findings } = redactSecrets(text);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(2);
    expect(findings[0]?.column).toBe(10);
  });
});
