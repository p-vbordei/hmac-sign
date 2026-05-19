# hmac-sign

HMAC-SHA256 signing and timing-safe verification for webhooks. Two flavors — with timestamp (Stripe-style, replay-protected) and bare (GitHub-style). Zero dependencies; uses Node's built-in `crypto`.

```ts
import { sign, verify, signSimple, verifySimple } from "hmac-sign";

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
npm install hmac-sign
```

Node 18+. Uses `node:crypto` (`createHmac` + `timingSafeEqual`).

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

## Why

Most webhook signing samples on the internet skip timing-safe comparison, mishandle Buffers, or omit replay protection. This package is the minimum correct version — small enough to read in one sitting, comprehensive enough to ship.

## License

Apache-2.0 © Vlad Bordei
