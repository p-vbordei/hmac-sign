# hmac-sign

[![ci](https://github.com/p-vbordei/hmac-sign/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/hmac-sign/actions/workflows/ci.yml)

[![npm](https://img.shields.io/npm/v/%40p-vbordei%2Fhmac-sign.svg)](https://www.npmjs.com/package/@p-vbordei/hmac-sign)
[![downloads](https://img.shields.io/npm/dm/%40p-vbordei%2Fhmac-sign.svg)](https://www.npmjs.com/package/@p-vbordei/hmac-sign)
[![bundle](https://img.shields.io/bundlejs/size/%40p-vbordei%2Fhmac-sign)](https://bundlejs.com/?q=%40p-vbordei%2Fhmac-sign)

> HMAC-SHA256 signing and timing-safe verification for webhooks. Two flavors — with timestamp (Stripe-style, replay-protected) and bare (GitHub-style). Zero dependencies; uses Node's built-in `crypto`.

```ts
import { sign, verify, signSimple, verifySimple } from "@p-vbordei/hmac-sign";

// Stripe-style: timestamp inside the signed input
const { header } = sign(body, SECRET);
// → "t=1716120000000,v1=c0fee..."

const r = verify(body, header, SECRET);
if (!r.valid) throw new Error(r.reason);

// GitHub-style: bare signature
const sigHeader = signSimple(body, SECRET);
// → "sha256=c0fee..."

if (!verifySimple(body, SECRET, sigHeader)) throw new Error("bad signature");
```

## Install

```sh
npm install @p-vbordei/hmac-sign
```

Node 20+. Uses `node:crypto`.

## Why

Most webhook-signing snippets you find online skip critical details:

- They use `===` for signature comparison → leaks timing info, attacker can brute-force byte by byte.
- They forget to include a timestamp in the signed input → susceptible to replay attacks.
- They Buffer-handle incorrectly → comparison fails for legitimate signatures on certain inputs.

`hmac-sign` is the **minimum correct version**: timing-safe comparison, replay protection via timestamp tolerance, Buffer-handling done right.

## Recipes

### Signing an outgoing webhook (sender)

```ts
import { sign } from "@p-vbordei/hmac-sign";

async function sendWebhook(url: string, event: object) {
  const body = JSON.stringify(event);
  const { header } = sign(body, process.env.WEBHOOK_SECRET!);

  await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Signature": header,
    },
    body,
  });
}
```

### Verifying an incoming webhook (receiver)

```ts
import { verify } from "@p-vbordei/hmac-sign";

async function handleWebhook(req: Request) {
  const sig = req.headers.get("x-signature");
  const body = await req.text();

  if (!sig) return new Response("missing signature", { status: 400 });

  const r = verify(body, sig, process.env.WEBHOOK_SECRET!);
  if (!r.valid) {
    console.warn(`webhook rejected: ${r.reason}`);
    return new Response("invalid signature", { status: 401 });
  }

  const event = JSON.parse(body);
  await processEvent(event);
  return new Response("ok");
}
```

### GitHub-style verification (no timestamp)

```ts
import { verifySimple } from "@p-vbordei/hmac-sign";

const sig = req.headers.get("x-hub-signature-256");  // "sha256=<hex>"
if (!verifySimple(rawBody, GITHUB_SECRET, sig!)) {
  return new Response("forbidden", { status: 403 });
}
```

### Custom tolerance window for clock skew

```ts
import { verify } from "@p-vbordei/hmac-sign";

const r = verify(body, header, SECRET, {
  toleranceMs: 30_000,  // tighter window — 30 seconds (default is 5 min)
});
```

### Inject a clock for tests

```ts
import { verify } from "@p-vbordei/hmac-sign";

const fixedNow = 1716120000_000;
verify(body, header, SECRET, { now: () => fixedNow });
```

## API

### Timestamped (recommended for outbound webhooks)

```ts
sign(payload: string | Buffer, secret: string, opts?: { timestamp?: number })
  → { header: "t=<ms>,v1=<hex>", timestamp, signature }

verify(payload, header, secret, opts?: { toleranceMs?: number; now?: () => number })
  → { valid: true, timestamp } | { valid: false, reason }
```

- The signed input is `<unix-ms>.<payload>`, so altering the timestamp invalidates the signature.
- `verify` rejects anything outside `toleranceMs` (default 5 min) — replay protection.
- Comparison is **timing-safe** (`crypto.timingSafeEqual`).

### Bare (compatible with GitHub-style `sha256=…` headers)

```ts
signSimple(payload, secret) → "sha256=<hex>"
verifySimple(payload, secret, signature) → boolean
```

Use this when integrating with a service that already specifies its own signature format and no timestamp is desired.

## Caveats

- **Buffer vs string.** Both work, but the input must be byte-identical to what was signed. If your framework parses JSON automatically, you may need to re-serialize — or better, sign/verify against the **raw bytes** received over the wire. Use a body-parser that exposes the raw buffer.
- **HMAC-SHA256 only.** No SHA-1, no MD5. If you're integrating with a legacy service that uses these, you'll need a different library — they shouldn't be used for new signatures.

## License

Apache-2.0 © Vlad Bordei
