import { blockedReason, parseInput, parseRdap, registrableDomain, type RdapInfo } from "./lib.ts";

export interface Env {
  ASSETS: Fetcher;
  /** Optional: Google Safe Browsing v4 key (wrangler secret put SAFE_BROWSING_KEY) */
  SAFE_BROWSING_KEY?: string;
  /** Per-IP rate limiter (see "ratelimits" in wrangler.jsonc) */
  CHECK_LIMITER?: RateLimit;
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
  const [age, sb] = await Promise.all([
    blocked ? Promise.resolve(null) : domainAge(finalHost),
    blocked ? Promise.resolve({ checked: false, threats: [] as string[] }) : safeBrowsing([...new Set([start.href, finalUrl])], env.SAFE_BROWSING_KEY),
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
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/api/check") return handleCheck(request, env);
    if (pathname.startsWith("/api/")) return json({ error: "not found" }, 404);
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
