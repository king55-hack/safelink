import { blockedReason, parseInput, parseRdap, registrableDomain, sanitizeReport, type RdapInfo } from "./lib.ts";

export interface Env {
  ASSETS: Fetcher;
  /** Optional: Google Safe Browsing v4 key (wrangler secret put SAFE_BROWSING_KEY) */
  SAFE_BROWSING_KEY?: string;
  /** Per-IP rate limiter (see "ratelimits" in wrangler.jsonc) */
  CHECK_LIMITER?: RateLimit;
  /** Per-IP limiter for /api/report */
  REPORT_LIMITER?: RateLimit;
  /** D1 database holding community reports */
  DB?: D1Database;
  /** Optional Cloudflare Turnstile secret (wrangler secret put TURNSTILE_SECRET) */
  TURNSTILE_SECRET?: string;
  /** Optional salt for the one-way reporter hash (wrangler secret put REPORT_SALT) */
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
async function followRedirects(start: URL): Promise<{ chain: Hop[]; error?: string; tooMany?: boolean }> {
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
      return { chain, error: "could not reach the site" };
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

  // one-way hash so a person counts once per site per month; the IP itself is never stored
  const month = new Date().toISOString().slice(0, 7);
  const reporter = await sha256Hex(ip + "|" + (env.REPORT_SALT ?? "safelink") + "|" + month);

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

  const redirects = await followRedirects(start);
  const last = redirects.chain.at(-1);
  const finalUrl = last ? last.url : start.href;
  const finalHost = new URL(finalUrl).hostname;
  const blocked = !!blockedReason(start);

  // independent lookups run in parallel; we judge the domain the link really lands on
  const [age, sb, reported] = await Promise.all([
    blocked ? Promise.resolve(null) : domainAge(finalHost),
    blocked ? Promise.resolve({ checked: false, threats: [] as string[] }) : safeBrowsing([...new Set([start.href, finalUrl])], env.SAFE_BROWSING_KEY),
    reportCount(env, [...new Set([start.hostname.toLowerCase(), finalHost.toLowerCase()])]),
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
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/api/check") return handleCheck(request, env);
    if (pathname === "/api/report") return handleReport(request, env);
    if (pathname.startsWith("/api/")) return json({ error: "not found" }, 404);
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
