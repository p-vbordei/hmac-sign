import { describe, it, expect } from "vitest";
import { sign, verify, signSimple, verifySimple } from "../src/index.js";

const SECRET = "topsecret-shhhh";
const BODY = JSON.stringify({ event: "user.created", id: 42 });

describe("sign + verify (timestamped)", () => {
  it("round-trip succeeds within tolerance", () => {
    const { header } = sign(BODY, SECRET);
    const r = verify(BODY, header, SECRET);
    expect(r.valid).toBe(true);
  });

  it("returns t= and v1= in the header", () => {
    const { header, timestamp, signature } = sign(BODY, SECRET);
    expect(header).toBe(`t=${timestamp},v1=${signature}`);
    expect(signature).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects when body is tampered with", () => {
    const { header } = sign(BODY, SECRET);
    const r = verify(BODY + "x", header, SECRET);
    expect(r.valid).toBe(false);
  });

  it("rejects when secret is wrong", () => {
    const { header } = sign(BODY, SECRET);
    const r = verify(BODY, header, "other-secret");
    expect(r.valid).toBe(false);
  });

  it("rejects when timestamp is outside tolerance", () => {
    const old = Date.now() - 10 * 60_000;
    const { header } = sign(BODY, SECRET, { timestamp: old });
    const r = verify(BODY, header, SECRET, { toleranceMs: 5 * 60_000 });
    expect(r.valid).toBe(false);
    if (!r.valid) expect(r.reason).toContain("tolerance");
  });

  it("accepts when timestamp is within custom tolerance", () => {
    const old = Date.now() - 10 * 60_000;
    const { header } = sign(BODY, SECRET, { timestamp: old });
    const r = verify(BODY, header, SECRET, { toleranceMs: 30 * 60_000 });
    expect(r.valid).toBe(true);
  });

  it("rejects malformed headers", () => {
    expect(verify(BODY, "", SECRET).valid).toBe(false);
    expect(verify(BODY, "v1=abc", SECRET).valid).toBe(false);
    expect(verify(BODY, "t=abc,v1=abc", SECRET).valid).toBe(false);
  });

  it("rejects empty secret", () => {
    expect(() => sign(BODY, "")).toThrow();
    expect(verify(BODY, "t=1,v1=abc", "").valid).toBe(false);
  });

  it("works on Buffer payloads", () => {
    const buf = Buffer.from(BODY, "utf8");
    const { header } = sign(buf, SECRET);
    expect(verify(buf, header, SECRET).valid).toBe(true);
    expect(verify(BODY, header, SECRET).valid).toBe(true);
  });
});

describe("signSimple + verifySimple (no timestamp)", () => {
  it("round-trip", () => {
    const h = signSimple(BODY, SECRET);
    expect(h).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(verifySimple(BODY, SECRET, h)).toBe(true);
  });

  it("rejects tampered body", () => {
    const h = signSimple(BODY, SECRET);
    expect(verifySimple(BODY + "x", SECRET, h)).toBe(false);
  });

  it("rejects malformed header", () => {
    expect(verifySimple(BODY, SECRET, "abcdef")).toBe(false);
    expect(verifySimple(BODY, SECRET, "sha256=")).toBe(false);
    expect(verifySimple(BODY, SECRET, "sha1=abc")).toBe(false);
  });
});
