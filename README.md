# SafeLink

Check if a link is safe before you click. Paste any link and SafeLink explains, in plain words, whether it looks safe.

Live: https://safelink.rajanrimal.com.np

## How it works

1. **In the browser** – the address and structure of the link are analysed locally (look-alike brands, raw IPs, `@` tricks, risky endings, shorteners, …).
2. **On a Cloudflare Worker** (`POST /api/check`) – a deeper check follows the redirect chain, looks up the domain's age (RDAP) and, if a key is configured, asks Google Safe Browsing. Only the link itself is sent, and it is not stored.

**QR codes** – "Scan a QR code" reads a QR code with the camera or from an uploaded photo and runs the link through the same checks (protects against "quishing"). Decoding happens entirely on the device with [jsQR](https://github.com/cozmo/jsQR) (Apache-2.0, vendored in `public/vendor/`); the image is never uploaded.

Languages: English, Nepali and Japanese are built in (offline); other languages use online machine translation.

## Lookalike / typosquatting detection

The analyzer compares the domain with ~130 well-known brands (global, Japan, Nepal):

- **Look-alike skeleton** – digits and look-alike letters are normalised (`paypa1`, `paypai`, `g00gle`, `arnazon`, `pay-pal` all match `paypal`).
- **Typos** – one swapped/missing/extra letter (`googel`, `netfilx`, `paypall`).
- **Bait names** – the brand glued to words like `login`/`verify` or placed in a subdomain (`appleid-verify.com`, `appleid.apple.com.evil.ru`).
- **Wrong ending** – the real brand name on a cheap TLD (`paypal.xyz`, `amazon.tk`).

Official domains that legitimately contain a brand (`rakuten-card.co.jp`, `amazonaws.com`, …) are in `BRAND_SAFE_DOMAINS` in `public/index.html`. `npm test` runs ~80 scam and ~150 real-site cases against it, so add a case whenever you add a brand or exception.

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
npx wrangler d1 create safelink-reports     # then put the printed id into wrangler.jsonc (d1_databases)
npx wrangler d1 migrations apply DB --remote
npx wrangler secret put SAFE_BROWSING_KEY   # optional: Google Safe Browsing API key
npx wrangler secret put VIRUSTOTAL_KEY      # optional: VirusTotal API key
npx wrangler secret put TURNSTILE_SECRET    # optional: Turnstile secret (and set TURNSTILE_SITE_KEY in public/index.html)
npm run deploy
```

## VirusTotal

With `VIRUSTOTAL_KEY` set, the Worker asks VirusTotal what its security engines say about the link's final URL (and the domain if the URL is unknown). 3+ engines flagging it = dangerous; 1–2 = "be careful" (it can be a false alarm). Answers are cached for an hour because the free API allows only ~4 requests/minute, and quota errors are skipped silently. The free VirusTotal API is for non-commercial use only.

## Report a scam

"Report a scam" (button in every result + footer link) sends `POST /api/report` and stores the report in Cloudflare D1:

- Only the link **without** query string / fragment / credentials, the category and an optional note are saved. IP addresses are never stored; a one-way salted hash (IP + month) makes one person count once per site.
- Spam protection: per-IP rate limit (5/min), hidden honeypot field and an optional Cloudflare Turnstile check.
- Checked links show "Reported by other users" when different people reported the same site (info for 1–2 reports, warning for 3+). It never makes a site "dangerous" by itself, so false reports cannot blacklist a legitimate site.
- Reports are not displayed anywhere publicly. Read them with `npx wrangler d1 execute DB --remote --command "SELECT * FROM reports ORDER BY id DESC LIMIT 50"`.

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
