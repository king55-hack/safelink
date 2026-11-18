/** Pure helpers (no Workers APIs) so they can be unit-tested with `node --test`. */

const MULTI_TLDS = ["co.uk","org.uk","gov.uk","ac.uk","co.jp","or.jp","ne.jp","com.au","net.au","org.au","co.nz","com.br","com.mx","co.in","co.kr","com.tr","com.sg","com.hk","com.tw","com.np","org.np","edu.np","gov.np","net.np","com.pk","com.bd","com.lk","co.id","co.th","com.my","com.ph","com.vn","com.ar","com.cn","co.za","com.ng","co.ke"];

export function registrableDomain(host: string): string {
  const p = host.toLowerCase().split(".");
  if (p.length <= 2) return host.toLowerCase();
  const last2 = p.slice(-2).join(".");
  return MULTI_TLDS.includes(last2) ? p.slice(-3).join(".") : last2;
}

const isIPv4 = (h: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(h);
const isIPv6 = (h: string) => h.includes(":");

/** Turn user input into a URL, assuming https when no scheme was typed. */
export function parseInput(raw: string): URL | null {
  let s = raw.trim();
  if (!s || s.length > 2048) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
  try { return new URL(s); } catch { return null; }
}

/**
 * SSRF guard: only public-looking http(s) hostnames on standard ports may be fetched.
 * Returns a reason string if the target must NOT be fetched, otherwise null.
 */
export function blockedReason(u: URL): string | null {
  if (u.protocol !== "http:" && u.protocol !== "https:") return "unsupported scheme";
  if (u.username || u.password) return "credentials in url";
  if (u.port && u.port !== "80" && u.port !== "443") return "non-standard port";
  const h = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!h) return "empty host";
  if (isIPv4(h) || isIPv6(h)) return "ip address";
  if (!h.includes(".")) return "single-label host";
  if (/(^|\.)(localhost|local|internal|intranet|lan|home|corp|test|invalid|example)$/.test(h)) return "reserved name";
  return null;
}

export interface RdapInfo { registeredAt: string; ageDays: number }

/** Extract the registration date from an RDAP domain response. */
export function parseRdap(json: any, now = Date.now()): RdapInfo | null {
  const ev = Array.isArray(json?.events) ? json.events.find((e: any) => e?.eventAction === "registration") : null;
  const t = ev?.eventDate ? Date.parse(ev.eventDate) : NaN;
  if (!Number.isFinite(t)) return null;
  return { registeredAt: new Date(t).toISOString(), ageDays: Math.max(0, Math.floor((now - t) / 86_400_000)) };
}
