import { createHmac, timingSafeEqual } from "node:crypto";

export interface SignOptions {
  /** Override the timestamp (unix ms). Defaults to `Date.now()`. */
  timestamp?: number;
}

export interface SignResult {
  /** Composite header value, format: `t=<unix-ms>,v1=<hex>` */
  header: string;
  timestamp: number;
  signature: string;
}

/**
 * Sign a payload with a shared secret using HMAC-SHA256, including a timestamp
 * in the signed content to defend against replay.
 *
 * The returned `header` is suitable for a `X-Signature` header.
 */
export function sign(payload: string | Buffer, secret: string, opts: SignOptions = {}): SignResult {
  if (!secret) throw new Error("secret must be non-empty");
  const timestamp = opts.timestamp ?? Date.now();
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
  const signedInput = Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), body]);
  const signature = createHmac("sha256", secret).update(signedInput).digest("hex");
  return {
    header: `t=${timestamp},v1=${signature}`,
    timestamp,
    signature,
  };
}

export interface VerifyOptions {
  /** Allowed clock skew window in milliseconds. Default: 5 minutes. */
  toleranceMs?: number;
  /** Injectable clock for testing. Default: `Date.now`. */
  now?: () => number;
}

export type VerifyResult =
  | { valid: true; timestamp: number }
  | { valid: false; reason: string };

function parseHeader(header: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const piece of header.split(",")) {
    const idx = piece.indexOf("=");
    if (idx <= 0) continue;
    const k = piece.slice(0, idx).trim();
    const v = piece.slice(idx + 1).trim();
    if (k) out.set(k, v);
  }
  return out;
}

/**
 * Verify a signature produced by `sign()`. Timing-safe comparison, replay protection
 * via timestamp tolerance.
 */
export function verify(
  payload: string | Buffer,
  header: string,
  secret: string,
  opts: VerifyOptions = {},
): VerifyResult {
  if (!secret) return { valid: false, reason: "secret must be non-empty" };
  const tolerance = opts.toleranceMs ?? 5 * 60_000;
  const now = (opts.now ?? Date.now)();
  const parts = parseHeader(header);
  const tsStr = parts.get("t");
  const sig = parts.get("v1");
  if (!tsStr || !sig) return { valid: false, reason: "missing timestamp or signature" };
  const timestamp = Number(tsStr);
  if (!Number.isFinite(timestamp)) return { valid: false, reason: "invalid timestamp" };
  if (Math.abs(now - timestamp) > tolerance) {
    return { valid: false, reason: "timestamp outside tolerance window" };
  }
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
  const signedInput = Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), body]);
  const expectedHex = createHmac("sha256", secret).update(signedInput).digest("hex");
  if (expectedHex.length !== sig.length) return { valid: false, reason: "signature mismatch" };
  let expectedBuf: Buffer;
  let actualBuf: Buffer;
  try {
    expectedBuf = Buffer.from(expectedHex, "hex");
    actualBuf = Buffer.from(sig, "hex");
  } catch {
    return { valid: false, reason: "signature mismatch" };
  }
  if (expectedBuf.length !== actualBuf.length || expectedBuf.length === 0) {
    return { valid: false, reason: "signature mismatch" };
  }
  if (!timingSafeEqual(expectedBuf, actualBuf)) {
    return { valid: false, reason: "signature mismatch" };
  }
  return { valid: true, timestamp };
}

/**
 * Sign a payload with `HMAC-SHA256` and return a GitHub-compatible
 * `sha256=<hex>` header value. No timestamp included.
 */
export function signSimple(payload: string | Buffer, secret: string): string {
  if (!secret) throw new Error("secret must be non-empty");
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
  const hex = createHmac("sha256", secret).update(body).digest("hex");
  return `sha256=${hex}`;
}

/**
 * Verify a GitHub-style `sha256=<hex>` signature. Timing-safe.
 */
export function verifySimple(payload: string | Buffer, secret: string, signature: string): boolean {
  if (!secret) return false;
  if (typeof signature !== "string") return false;
  const m = signature.match(/^sha256=([0-9a-f]+)$/i);
  if (!m) return false;
  const expected = signSimple(payload, secret).slice("sha256=".length);
  if (expected.length !== m[1]!.length) return false;
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(m[1]!, "hex");
  if (a.length !== b.length || a.length === 0) return false;
  return timingSafeEqual(a, b);
}
