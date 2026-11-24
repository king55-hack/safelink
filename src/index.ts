import puppeteer from "@cloudflare/puppeteer";
import { connect } from "cloudflare:sockets";
import { PREVIEW_SKIP_TYPES, allowPreviewRequest, blockedReason, csvRow, sanitizeContact, parseInput, parseRdap, pageParams, parseVtStats, registrableDomain, sanitizeReport, summarizeCerts, timingSafeEqualBytes, vtUrlId, type CertSummary, type RdapInfo, type VtStats } from "./lib.ts";

export interface Env {
  ASSETS: Fetcher;
  /** Optional: Google Safe Browsing v4 key (wrangler secret put SAFE_BROWSING_KEY) */
  SAFE_BROWSING_KEY?: string;
  /** Optional: VirusTotal API key (wrangler secret put VIRUSTOTAL_KEY) */
  VIRUSTOTAL_KEY?: string;
  /** Per-IP rate limiter (see "ratelimits" in wrangler.jsonc) */
  CHECK_LIMITER?: RateLimit;
  /** Per-IP limiter for /api/report */
  REPORT_LIMITER?: RateLimit;
  /** Per-IP limiter for /api/admin/* */
  ADMIN_LIMITER?: RateLimit;
  /** Per-IP limiter for /api/preview (each preview uses Cloudflare Browser Rendering minutes) */
  PREVIEW_LIMITER?: RateLimit;
  /** Cloudflare Browser Rendering binding (screenshot preview) */
  BROWSER?: Fetcher;
  /** Daily cap on NEW previews (cached ones are free). Default 40 (the free Browser Run plan has 10 browser-minutes/day). */
  PREVIEW_DAILY_MAX?: string;
  /** Secret token that unlocks /admin (>= 16 chars; wrangler secret put ADMIN_TOKEN) */
  ADMIN_TOKEN?: string;
  /** D1 database holding community reports */
  DB?: D1Database;
  /** Optional Cloudflare Turnstile secret (wrangler secret put TURNSTILE_SECRET) */
  TURNSTILE_SECRET?: string;
  /** Secret key (16+ chars) for the keyed one-way reporter code, HMAC-SHA256 (wrangler secret put REPORT_SALT). Rotate it any time; old codes then simply stop matching. */
  REPORT_SALT?: string;
}

const MAX_HOPS = 8;
const UA = "SafeLinkBot/1.0 (+link safety checker)";

interface Hop { url: string; status: number }

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });

/** Follow redirects manually so every hop is re-validated (SSRF) and recorded. */
async function followRedirects(start: URL): Promise<{ chain: Hop[]; error?: string; tooMany?: boolean; failed?: URL }> {
  const chain: Hop[] = [];
  const seen = new Set<string>();
  let cur = start;
  for (let i = 0; i <= MAX_HOPS; i++) {
    const why = blockedReason(cur);
    if (why) return { chain, error: i === 0 ? "blocked: " + why : "redirected to a blocked target (" + why + ")" };
    if (seen.has(cur.href)) return { chain, error: "redirect loop" };
    seen.add(cur.href);

    let res: Response;
    try {
      res = await fetch(cur.href, { method: "GET", redirect: "manual", headers: { "user-agent": UA }, signal: AbortSignal.timeout(5000) });
    } catch {
      return { chain, error: "could not reach the site", failed: cur };
    }
    res.body?.cancel().catch(() => {}); // never download the page body
    chain.push({ url: cur.href, status: res.status });

    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc) {
      if (i === MAX_HOPS) return { chain, tooMany: true };
      try { cur = new URL(loc, cur); } catch { return { chain, error: "invalid redirect" }; }
      continue;
    }
    return { chain };
  }
  return { chain, tooMany: true };
}

async function domainAge(host: string): Promise<(RdapInfo & { domain: string }) | null> {
  const domain = registrableDomain(host);
  try {
    const res = await fetch("https://rdap.org/domain/" + encodeURIComponent(domain), {
      headers: { accept: "application/rdap+json", "user-agent": UA },
      signal: AbortSignal.timeout(4000),
      cf: { cacheTtl: 86400, cacheEverything: true },
    });
    if (!res.ok) return null;
    const info = parseRdap(await res.json());
    return info ? { ...info, domain } : null;
  } catch {
    return null;
  }
}

async function safeBrowsing(urls: string[], key: string | undefined): Promise<{ checked: boolean; threats: string[] }> {
  if (!key) return { checked: false, threats: [] };
  try {
    const res = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + encodeURIComponent(key), {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(4000),
      body: JSON.stringify({
        client: { clientId: "safelink", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: urls.map((url) => ({ url })),
        },
      }),
    });
    if (!res.ok) return { checked: false, threats: [] };
    const data: any = await res.json();
    const threats = [...new Set<string>((data.matches ?? []).map((m: any) => String(m.threatType)))];
    return { checked: true, threats };
  } catch {
    return { checked: false, threats: [] };
  }
}

/** One VirusTotal GET, cached for an hour (the free API allows only ~4 requests/minute). null = quota/outage. */
async function vtGet(path: string, key: string): Promise<{ status: number; json: any } | null> {
  const cache = caches.default;
  const cacheKey = new Request("https://vt-cache.safelink.invalid/" + (await sha256Hex(path))); // hashed: the cache never holds the link itself
  const hit = await cache.match(cacheKey);
  if (hit) return { status: Number(hit.headers.get("x-vt-status")), json: await hit.json() };
  try {
    const res = await fetch("https://www.virustotal.com/api/v3" + path, { headers: { "x-apikey": key, accept: "application/json" }, signal: AbortSignal.timeout(4000) });
    if (res.status === 429 || res.status >= 500 || res.status === 401 || res.status === 403) return null; // quota / bad key: never cache
    const json = res.ok ? await res.json() : null;
    await cache.put(cacheKey, new Response(JSON.stringify(json), { headers: { "content-type": "application/json", "cache-control": "max-age=3600", "x-vt-status": String(res.status) } }));
    return { status: res.status, json };
  } catch {
    return null;
  }
}

/** Ask VirusTotal what its security engines say about the final URL (falls back to the domain if the URL is unknown). */
async function virusTotal(finalUrl: string, host: string, key: string | undefined): Promise<({ checked: true } & VtStats) | { checked: false }> {
  if (!key) return { checked: false };
  let r = await vtGet("/urls/" + vtUrlId(finalUrl), key);
  let stats = r?.status === 200 ? parseVtStats(r.json) : null;
  if (!stats && r?.status === 404) {
    r = await vtGet("/domains/" + encodeURIComponent(registrableDomain(host)), key);
    stats = r?.status === 200 ? parseVtStats(r.json) : null;
  }
  return stats ? { checked: true, ...stats } : { checked: false };
}

/** Open a TCP (optionally TLS) connection to host:443. true = the connection was established. */
async function tryConnect(host: string, secure: boolean): Promise<boolean> {
  try {
    const sock = connect({ hostname: host, port: 443 }, { secureTransport: secure ? "on" : "off", allowHalfOpen: false });
    await Promise.race([sock.opened, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 4000))]);
    sock.close().catch(() => {});
    return true;
  } catch {
    return false;
  }
}

/**
 * true = the server answers on 443 but its TLS certificate was rejected (expired, self-signed, wrong site...).
 * Only called when the HTTPS request already failed, to tell "bad certificate" from "site is down".
 * (Workers cannot open raw sockets to Cloudflare-proxied sites, so those are reported as "unknown", never as a problem.)
 */
async function tlsProblem(host: string): Promise<boolean> {
  const [tlsOk, tcpOk] = await Promise.all([tryConnect(host, true), tryConnect(host, false)]);
  return !tlsOk && tcpOk;
}

/** One CertSpotter lookup, cached 6 hours. null = error / rate limit (never cached). */
async function ctList(domain: string): Promise<unknown[] | null> {
  const cache = caches.default;
  const cacheKey = new Request("https://ct-cache.safelink.invalid/" + encodeURIComponent(domain));
  const hit = await cache.match(cacheKey);
  if (hit) return (await hit.json()) as unknown[];
  try {
    const res = await fetch("https://api.certspotter.com/v1/issuances?domain=" + encodeURIComponent(domain) + "&match_wildcard=true&expand=issuer", {
      headers: { accept: "application/json", "user-agent": UA }, signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const list = (await res.json()) as unknown[];
    await cache.put(cacheKey, new Response(JSON.stringify(list), { headers: { "content-type": "application/json", "cache-control": "max-age=21600" } }));
    return list;
  } catch {
    return null;
  }
}

/** Newest valid certificate for a host from public Certificate Transparency logs (CertSpotter). */
async function certInfo(host: string): Promise<CertSummary | null> {
  const first = await ctList(host);
  const s = summarizeCerts(first);
  if (s || first === null) return s;
  const apex = registrableDomain(host); // wildcard certificates (*.example.com) are listed under the apex domain
  return apex !== host ? summarizeCerts(await ctList(apex)) : null;
}

/** How many different people reported these hosts (each reporter counts once per site). */
async function reportCount(env: Env, hosts: string[]): Promise<number> {
  if (!env.DB || hosts.length === 0) return 0;
  try {
    const marks = hosts.map(() => "?").join(",");
    const row = await env.DB.prepare("SELECT COUNT(DISTINCT reporter) AS n FROM reports WHERE host IN (" + marks + ")").bind(...hosts).first<{ n: number }>();
    return row?.n ?? 0;
  } catch {
    return 0;
  }
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacHex(key: string, msg: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function verifyTurnstile(token: unknown, secret: string, ip: string): Promise<boolean> {
  if (typeof token !== "string" || token.length === 0 || token.length > 2048) return false;
  try {
    const form = new FormData();
    form.append("secret", secret);
    form.append("response", token);
    if (ip) form.append("remoteip", ip);
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form, signal: AbortSignal.timeout(5000) });
    const data: any = await res.json();
    return data?.success === true;
  } catch {
    return false;
  }
}

async function handleReport(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return json({ error: "use POST" }, 405);
  if (!env.DB) return json({ error: "reports unavailable" }, 503);
  const ip = request.headers.get("cf-connecting-ip") ?? "";

  if (env.REPORT_LIMITER) {
    const { success } = await env.REPORT_LIMITER.limit({ key: ip || "unknown" });
    if (!success) return new Response(JSON.stringify({ error: "rate limited" }), { status: 429, headers: { "content-type": "application/json; charset=utf-8", "retry-after": "60", "cache-control": "no-store" } });
  }
  if (Number(request.headers.get("content-length") ?? 0) > 4096) return json({ error: "request too large" }, 413);

  let body: any;
  try { body = await request.json(); } catch { return json({ error: "invalid json" }, 400); }

  // honeypot: real people never fill the hidden field; pretend success so bots learn nothing
  if (typeof body?.website === "string" && body.website.length > 0) return json({ ok: true });

  if (env.TURNSTILE_SECRET && !(await verifyTurnstile(body?.token, env.TURNSTILE_SECRET, ip))) {
    return json({ error: "verification failed" }, 403);
  }

  const parsed = sanitizeReport(body);
  if (!parsed.ok) return json({ error: parsed.error }, 400);
  const r = parsed.value;

  // keyed one-way code (HMAC-SHA256 with a secret) so a person counts once per site per month; the IP itself is never stored.
  // A plain hash of an IPv4 address could be reversed by trying all ~4 billion addresses, the secret key prevents that.
  // Without the secret there is no duplicate detection at all (a random code is stored), never a guessable one.
  const month = new Date().toISOString().slice(0, 7);
  const reporter = env.REPORT_SALT && env.REPORT_SALT.length >= 16
    ? await hmacHex(env.REPORT_SALT, ip + "|" + month)
    : crypto.randomUUID();

  try {
    const res = await env.DB.prepare(
      "INSERT OR IGNORE INTO reports (host, url, category, note, lang, reporter, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind(r.host, r.url, r.category, r.note || null, r.lang || null, reporter, Math.floor(Date.now() / 1000)).run();
    return json({ ok: true, duplicate: (res.meta?.changes ?? 0) === 0 });
  } catch {
    return json({ error: "could not save report" }, 500);
  }
}

async function handleCheck(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return json({ error: "use POST" }, 405);
  // Rate limit first: it is the cheapest check and protects every lookup below it.
  if (env.CHECK_LIMITER) {
    const key = request.headers.get("cf-connecting-ip") ?? "unknown";
    const { success } = await env.CHECK_LIMITER.limit({ key });
    if (!success) {
      return new Response(JSON.stringify({ error: "rate limited" }), {
        status: 429,
        headers: { "content-type": "application/json; charset=utf-8", "retry-after": "60", "cache-control": "no-store" },
      });
    }
  }
  const len = Number(request.headers.get("content-length") ?? 0);
  if (len > 4096) return json({ error: "request too large" }, 413);

  let body: any;
  try { body = await request.json(); } catch { return json({ error: "invalid json" }, 400); }
  if (typeof body?.url !== "string") return json({ error: "missing url" }, 400);

  const start = parseInput(body.url);
  if (!start) return json({ error: "invalid url" }, 400);
  start.search = ""; start.hash = ""; // personal tokens often live in the query string; the address and path are enough to check

  const redirects = await followRedirects(start);
  const last = redirects.chain.at(-1);
  const finalUrl = last ? last.url : start.href;
  const finalHost = new URL(finalUrl).hostname;
  const blocked = !!blockedReason(start);

  // independent lookups run in parallel; we judge the domain the link really lands on
  const lastHop = redirects.chain.at(-1);
  const tlsVerified = !!lastHop && lastHop.url.startsWith("https:"); // the Worker completed an HTTPS request, so the certificate was valid and trusted
  const failed = redirects.error === "could not reach the site" ? redirects.failed : undefined;
  const [age, sb, reported, vt, cert, badTls] = await Promise.all([
    blocked ? Promise.resolve(null) : domainAge(finalHost),
    blocked ? Promise.resolve({ checked: false, threats: [] as string[] }) : safeBrowsing([...new Set([start.href, finalUrl])], env.SAFE_BROWSING_KEY),
    reportCount(env, [...new Set([start.hostname.toLowerCase(), finalHost.toLowerCase()])]),
    blocked ? Promise.resolve({ checked: false as const }) : virusTotal(finalUrl, finalHost, env.VIRUSTOTAL_KEY),
    tlsVerified ? certInfo(finalHost) : Promise.resolve(null),
    failed && failed.protocol === "https:" && !blockedReason(failed) ? tlsProblem(failed.hostname) : Promise.resolve(false),
  ]);

  return json({
    chain: redirects.chain,
    finalUrl,
    finalHost,
    redirected: redirects.chain.length > 1,
    tooManyRedirects: !!redirects.tooMany,
    reachError: redirects.error ?? null,
    domain: age,
    safeBrowsing: sb,
    reports: { count: reported },
    virusTotal: vt,
    tls: { verified: tlsVerified, problem: badTls },
    cert,
  });
}

/* ---------------- screenshot preview ---------------- */

const PREVIEW_W = 1024, PREVIEW_H = 640;

async function handlePreview(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return json({ error: "use POST" }, 405);
  if (!env.BROWSER) return json({ error: "preview unavailable" }, 503);

  if (env.PREVIEW_LIMITER) {
    const { success } = await env.PREVIEW_LIMITER.limit({ key: request.headers.get("cf-connecting-ip") ?? "unknown" });
    if (!success) return new Response(JSON.stringify({ error: "rate limited" }), { status: 429, headers: { "content-type": "application/json; charset=utf-8", "retry-after": "60", "cache-control": "no-store" } });
  }
  if (Number(request.headers.get("content-length") ?? 0) > 4096) return json({ error: "request too large" }, 413);

  let body: any;
  try { body = await request.json(); } catch { return json({ error: "invalid json" }, 400); }
  if (typeof body?.url !== "string") return json({ error: "missing url" }, 400);
  const target = parseInput(body.url);
  if (!target || blockedReason(target)) return json({ error: "not previewable" }, 400);
  target.search = ""; target.hash = ""; // query strings and fragments often hold personal tokens: never needed for a preview

  // a screenshot we already took in the last hour is free
  const cache = caches.default;
  const cacheKey = new Request("https://preview-cache.safelink.invalid/" + (await sha256Hex(target.href)));
  const hit = await cache.match(cacheKey);
  if (hit) return json({ image: await hit.text(), cached: true });

  // whole-site pace: the free Browser Run plan starts at most ~3 browsers per minute for the entire account
  if (env.PREVIEW_LIMITER) {
    const { success } = await env.PREVIEW_LIMITER.limit({ key: "global" });
    if (!success) return json({ error: "busy" }, 429);
  }

  // cap on new previews per day: every one costs Browser Rendering time
  if (env.DB) {
    try {
      const max = Math.max(1, Number(env.PREVIEW_DAILY_MAX) || 40);
      const day = new Date().toISOString().slice(0, 10);
      const row = await env.DB.prepare("INSERT INTO preview_usage (day, n) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET n = n + 1 RETURNING n").bind(day).first<{ n: number }>();
      if ((row?.n ?? 0) > max) return json({ error: "daily limit" }, 429);
    } catch { /* if the counter is unavailable, fall through: the per-IP limit still applies */ }
  }

  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | undefined;
  try {
    try {
      browser = await puppeteer.launch(env.BROWSER);
    } catch {
      return json({ error: "preview unavailable" }, 503); // e.g. today's free browser minutes are used up
    }
    const page = await browser.newPage();
    await page.setViewport({ width: PREVIEW_W, height: PREVIEW_H });
    await page.setRequestInterception(true);
    page.on("request", (req) => {
      // every hop (redirects, images, scripts) must be a public http(s) address
      if (!allowPreviewRequest(req.url()) || (PREVIEW_SKIP_TYPES as readonly string[]).includes(req.resourceType())) req.abort().catch(() => {});
      else req.continue().catch(() => {});
    });
    page.on("dialog", (d) => { d.dismiss().catch(() => {}); });
    await page.goto(target.href, { waitUntil: "domcontentloaded", timeout: 12000 });
    await new Promise((r) => setTimeout(r, 1500)); // let the page paint
    const b64 = (await page.screenshot({ type: "jpeg", quality: 55, encoding: "base64" })) as string;
    const image = "data:image/jpeg;base64," + b64;
    await cache.put(cacheKey, new Response(image, { headers: { "content-type": "text/plain", "cache-control": "max-age=3600" } }));
    return json({ image });
  } catch {
    return json({ error: "preview failed" }, 502);
  } finally {
    await browser?.close().catch(() => {}); // always close, or the minutes keep running
  }
}

/* ---------------- contact form (removal requests, mistakes, questions) ---------------- */

async function handleContact(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") return json({ error: "use POST" }, 405);
  if (!env.DB) return json({ error: "unavailable" }, 503);
  const ip = request.headers.get("cf-connecting-ip") ?? "";
  if (env.REPORT_LIMITER) {
    const { success } = await env.REPORT_LIMITER.limit({ key: "contact:" + (ip || "unknown") });
    if (!success) return new Response(JSON.stringify({ error: "rate limited" }), { status: 429, headers: { "content-type": "application/json; charset=utf-8", "retry-after": "60", "cache-control": "no-store" } });
  }
  if (Number(request.headers.get("content-length") ?? 0) > 8192) return json({ error: "request too large" }, 413);
  let body: any;
  try { body = await request.json(); } catch { return json({ error: "invalid json" }, 400); }
  if (typeof body?.website === "string" && body.website.length > 0) return json({ ok: true }); // honeypot
  const p = sanitizeContact(body);
  if (!p.ok) return json({ error: p.error }, 400);
  try {
    // whole-site daily cap so a bot network cannot fill the database
    const since = Math.floor(Date.now() / 1000) - 86400;
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM contact_requests WHERE created_at >= ?").bind(since).first<{ n: number }>();
    if ((n?.n ?? 0) >= 200) return json({ error: "busy" }, 429);
    await env.DB.prepare("INSERT INTO contact_requests (kind, message, contact, lang, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(p.value.kind, p.value.message, p.value.contact || null, p.value.lang || null, Math.floor(Date.now() / 1000)).run();
    return json({ ok: true });
  } catch {
    return json({ error: "could not save" }, 500);
  }
}

/* ---------------- public "recently reported" list ---------------- */

/** Only sites reported by 3+ different people in the last 30 days, host and count only (no notes, no full links).
 *  The admin can delete a site's reports to remove it. Cached 10 minutes. */
async function handleRecent(env: Env): Promise<Response> {
  const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=600", "x-content-type-options": "nosniff" };
  if (!env.DB) return new Response(JSON.stringify({ items: [] }), { headers });
  try {
    const since = Math.floor(Date.now() / 1000) - 30 * 86400;
    const rows = await env.DB.prepare("SELECT host, COUNT(DISTINCT reporter) AS n, MAX(created_at) AS last FROM reports WHERE created_at >= ? GROUP BY host HAVING n >= 3 ORDER BY last DESC LIMIT 20").bind(since).all<{ host: string; n: number; last: number }>();
    return new Response(JSON.stringify({ items: rows.results }), { headers });
  } catch {
    return new Response(JSON.stringify({ items: [] }), { headers });
  }
}

/* ---------------- admin API (token protected) ---------------- */

async function sha256Bytes(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
}
const adminJson = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-robots-tag": "noindex, nofollow", "x-content-type-options": "nosniff" } });

async function handleAdmin(request: Request, env: Env, url: URL): Promise<Response> {
  if (!env.ADMIN_TOKEN || env.ADMIN_TOKEN.length < 16 || !env.DB) return adminJson({ error: "admin disabled" }, 503);
  if (env.ADMIN_LIMITER) {
    const { success } = await env.ADMIN_LIMITER.limit({ key: request.headers.get("cf-connecting-ip") ?? "unknown" });
    if (!success) return adminJson({ error: "rate limited" }, 429);
  }
  const m = /^Bearer (.{1,256})$/.exec(request.headers.get("authorization") ?? "");
  if (!m) return adminJson({ error: "unauthorized" }, 401);
  const [given, real] = await Promise.all([sha256Bytes(m[1]), sha256Bytes(env.ADMIN_TOKEN)]);
  if (!timingSafeEqualBytes(given, real)) return adminJson({ error: "unauthorized" }, 401);

  const path = url.pathname.replace(/^\/api\/admin/, "");
  try {
    if (request.method === "GET" && path === "/reports") {
      const { limit, offset } = pageParams(url.searchParams);
      const host = (url.searchParams.get("host") ?? "").toLowerCase().slice(0, 253);
      const like = "%" + host.replace(/[\\%_]/g, (c) => "\\" + c) + "%";
      const where = host ? "WHERE host LIKE ? ESCAPE '\\'" : "";
      const list = env.DB.prepare("SELECT id, host, url, category, note, lang, created_at FROM reports " + where + " ORDER BY id DESC LIMIT ? OFFSET ?");
      const count = env.DB.prepare("SELECT COUNT(*) AS n FROM reports " + where);
      const [items, total, top] = await Promise.all([
        (host ? list.bind(like, limit, offset) : list.bind(limit, offset)).all(),
        (host ? count.bind(like) : count).first<{ n: number }>(),
        env.DB.prepare("SELECT host, COUNT(DISTINCT reporter) AS n FROM reports GROUP BY host ORDER BY n DESC, host LIMIT 10").all(),
      ]);
      return adminJson({ total: total?.n ?? 0, items: items.results, topHosts: top.results });
    }
    if (request.method === "GET" && path === "/export.csv") {
      const rows = await env.DB.prepare("SELECT id, created_at, host, url, category, lang, note FROM reports ORDER BY id DESC LIMIT 20000").all<Record<string, unknown>>();
      const lines = [csvRow(["id", "created_utc", "host", "url", "category", "lang", "note"])];
      for (const r of rows.results) lines.push(csvRow([r.id, new Date(Number(r.created_at) * 1000).toISOString(), r.host, r.url, r.category, r.lang, r.note]));
      return new Response("﻿" + lines.join("\r\n") + "\r\n", { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": 'attachment; filename="safelink-reports.csv"', "cache-control": "no-store", "x-robots-tag": "noindex, nofollow", "x-content-type-options": "nosniff" } });
    }
    if (request.method === "GET" && path === "/contact") {
      const rows = await env.DB.prepare("SELECT id, kind, message, contact, lang, created_at FROM contact_requests ORDER BY id DESC LIMIT 100").all();
      return adminJson({ items: rows.results });
    }
    let mm = /^\/contact\/(\d{1,12})$/.exec(path);
    if (request.method === "DELETE" && mm) {
      const r = await env.DB.prepare("DELETE FROM contact_requests WHERE id = ?").bind(Number(mm[1])).run();
      return adminJson({ ok: true, deleted: r.meta?.changes ?? 0 });
    }
    mm = /^\/reports\/(\d{1,12})$/.exec(path);
    if (request.method === "DELETE" && mm) {
      const r = await env.DB.prepare("DELETE FROM reports WHERE id = ?").bind(Number(mm[1])).run();
      return adminJson({ ok: true, deleted: r.meta?.changes ?? 0 });
    }
    mm = /^\/hosts\/([^/]{1,253})$/.exec(path);
    if (request.method === "DELETE" && mm) {
      const r = await env.DB.prepare("DELETE FROM reports WHERE host = ?").bind(decodeURIComponent(mm[1]).toLowerCase()).run();
      return adminJson({ ok: true, deleted: r.meta?.changes ?? 0 });
    }
    return adminJson({ error: "not found" }, 404);
  } catch {
    return adminJson({ error: "database error" }, 500);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/api/check") return handleCheck(request, env);
    if (pathname === "/api/report") return handleReport(request, env);
    if (pathname === "/api/preview") return handlePreview(request, env);
    if (pathname === "/api/contact") return handleContact(request, env);
    if (pathname === "/api/recent" && request.method === "GET") return handleRecent(env);
    if (pathname.startsWith("/api/admin/")) return handleAdmin(request, env, new URL(request.url));
    if (pathname.startsWith("/api/")) return json({ error: "not found" }, 404);
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
