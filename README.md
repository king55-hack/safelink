# SafeLink

Check if a link is safe before you click. Paste any link and SafeLink explains, in plain words, whether it looks safe.

Live: https://safelink.rajanrimal.com.np

## How it works

1. **In the browser** – the address and structure of the link are analysed locally (look-alike brands, raw IPs, `@` tricks, risky endings, shorteners, …).
2. **On a Cloudflare Worker** (`POST /api/check`) – a deeper check follows the redirect chain, looks up the domain's age (RDAP) and, if a key is configured, asks Google Safe Browsing. Only the link itself is sent, and it is not stored.

**QR codes** – "Scan a QR code" reads a QR code with the camera or from an uploaded photo and runs the link through the same checks (protects against "quishing"). Decoding happens entirely on the device with [jsQR](https://github.com/cozmo/jsQR) (Apache-2.0, vendored in `public/vendor/`); the image is never uploaded.

Languages: English, Nepali and Japanese are built in (offline); other languages use online machine translation.

## Develop

```sh
npm install
npm run dev        # http://127.0.0.1:8787
npm test           # unit tests for the SSRF guard / helpers
npm run typecheck
```

## Deploy (Cloudflare Workers)

```sh
npx wrangler login
npx wrangler secret put SAFE_BROWSING_KEY   # optional: Google Safe Browsing API key
npm run deploy
```

`/api/check` is rate limited per IP (see `ratelimits` in `wrangler.jsonc`). Never commit API keys; use `wrangler secret` (or `.dev.vars` locally, which is git-ignored).

## Project layout

| Path | What |
|---|---|
| `public/` | Static site (`index.html`, logo, `_headers` with CSP/security headers) |
| `src/index.ts` | Worker: `/api/check` |
| `src/lib.ts` | Pure helpers (URL parsing, SSRF guard, RDAP parsing) |
| `test/` | Unit tests (`node --test`) |

## Notes

SafeLink reads warning signs; no tool can guarantee a link is safe. The Google Safe Browsing API is free for non-commercial use only.
