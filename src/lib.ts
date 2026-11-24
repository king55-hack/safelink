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

/* ---------------- community reports ---------------- */

export const REPORT_CATEGORIES = ["phishing", "malware", "shopping", "impersonation", "qr", "other"] as const;
export type ReportCategory = (typeof REPORT_CATEGORIES)[number];

export interface ReportInput { url: string; host: string; category: ReportCategory; note: string; lang: string }

/**
 * Validate and clean a user-submitted report.
 * The stored URL never contains credentials, port, query string or fragment (they often hold personal data).
 */
export function sanitizeReport(body: any): { ok: true; value: ReportInput } | { ok: false; error: string } {
  if (!body || typeof body !== "object") return { ok: false, error: "invalid body" };
  if (typeof body.url !== "string") return { ok: false, error: "invalid url" };
  const u = parseInput(body.url);
  if (!u || (u.protocol !== "http:" && u.protocol !== "https:")) return { ok: false, error: "invalid url" };

  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  const looksIp = isIPv4(host) || isIPv6(host);
  if (!host || host.length > 253) return { ok: false, error: "invalid url" };
  if (!looksIp && !host.includes(".")) return { ok: false, error: "invalid url" };
  if (/(^|\.)(localhost|local|internal|intranet|lan|home|corp|test|invalid|example)$/.test(host)) return { ok: false, error: "invalid url" };

  const category = REPORT_CATEGORIES.find((c) => c === body.category);
  if (!category) return { ok: false, error: "invalid category" };

  let note = typeof body.note === "string" ? body.note : "";
  note = note.replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, "").trim().slice(0, 500);

  const lang = typeof body.lang === "string" && /^[A-Za-z]{2,3}(-[A-Za-z]{2,4})?$/.test(body.lang) ? body.lang : "";

  const url = (u.protocol + "//" + u.host.replace(/:\d+$/, "") + u.pathname).slice(0, 300);
  return { ok: true, value: { url, host, category, note, lang } };
}

/* ---------------- VirusTotal ---------------- */

export interface VtStats { malicious: number; suspicious: number; harmless: number; undetected: number }

/** VirusTotal v3 identifies a URL by its unpadded base64url encoding. */
export function vtUrlId(url: string): string {
  return btoa(url).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Pull the engine verdict counts out of a VirusTotal v3 url/domain response. */
export function parseVtStats(json: any): VtStats | null {
  const s = json?.data?.attributes?.last_analysis_stats;
  if (!s || typeof s !== "object") return null;
  const n = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.floor(v) : 0);
  return { malicious: n(s.malicious), suspicious: n(s.suspicious), harmless: n(s.harmless), undetected: n(s.undetected) };
}

/* ---------------- certificates (Certificate Transparency data) ---------------- */

export interface CertSummary { issuer: string; notBefore: string; notAfter: string; daysLeft: number }

/**
 * Pick the newest currently-valid certificate from a CertSpotter "issuances" list.
 * A full page (100 entries) means we cannot see the newest one, so we say nothing rather than guess.
 */
export function summarizeCerts(list: any, now = Date.now()): CertSummary | null {
  if (!Array.isArray(list) || list.length === 0 || list.length >= 100) return null;
  let best: { nb: number; na: number; issuer: string } | null = null;
  for (const c of list) {
    const nb = Date.parse(c?.not_before), na = Date.parse(c?.not_after);
    if (!Number.isFinite(nb) || !Number.isFinite(na) || c?.revoked === true) continue;
    if (nb > now || na < now) continue;
    if (!best || nb > best.nb) {
      const raw = String(c?.issuer?.friendly_name ?? /O=([^,]+)/.exec(String(c?.issuer?.name ?? ""))?.[1] ?? "").replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, 60);
      best = { nb, na, issuer: raw || "an unknown issuer" };
    }
  }
  if (!best) return null;
  return {
    issuer: best.issuer,
    notBefore: new Date(best.nb).toISOString(),
    notAfter: new Date(best.na).toISOString(),
    daysLeft: Math.floor((best.na - now) / 86_400_000),
  };
}

/* ---------------- admin ---------------- */

/** Constant-time comparison of two byte arrays. */
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Parse ?limit=&offset= safely. */
export function pageParams(sp: URLSearchParams): { limit: number; offset: number } {
  const n = (v: string | null, d: number, max: number) => {
    const x = Number(v);
    return v !== null && Number.isInteger(x) && x >= 0 ? Math.min(x, max) : d;
  };
  return { limit: Math.max(1, n(sp.get("limit"), 100, 200)), offset: n(sp.get("offset"), 0, 1_000_000) };
}

/* ---------------- screenshot preview ---------------- */

/**
 * Every request the preview browser makes (the page, redirects, images, scripts...) is checked with this.
 * Only public http(s) hostnames on standard ports are allowed; data: images are fine.
 */
export function allowPreviewRequest(rawUrl: string): boolean {
  if (rawUrl.startsWith("data:")) return true;
  let u: URL;
  try { u = new URL(rawUrl); } catch { return false; }
  return blockedReason(u) === null;
}

/** Resource kinds the preview never needs (saves time and Cloudflare browser minutes). */
export const PREVIEW_SKIP_TYPES = ["media", "font", "websocket", "eventsource", "manifest", "other"] as const;

/* ---------------- CSV export ---------------- */

/** One CSV cell. Quotes when needed and neutralises spreadsheet formulas (=, +, -, @) so an opened export cannot run code. */
export function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
export function csvRow(cells: unknown[]): string {
  return cells.map(csvCell).join(",");
}

/* ---------------- contact form ---------------- */

export const CONTACT_KINDS = ["removal", "mistake", "question"] as const;
export type ContactKind = (typeof CONTACT_KINDS)[number];

/** Validate a contact-form message. The optional contact detail is stored only so the operator can answer. */
export function sanitizeContact(body: any): { ok: true; value: { kind: ContactKind; message: string; contact: string; lang: string } } | { ok: false; error: string } {
  if (!body || typeof body !== "object") return { ok: false, error: "invalid body" };
  const kind = CONTACT_KINDS.find((k) => k === body.kind);
  if (!kind) return { ok: false, error: "invalid kind" };
  const clean = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim().slice(0, max) : "");
  const message = clean(body.message, 2000);
  if (message.length < 5) return { ok: false, error: "message too short" };
  const contact = clean(body.contact, 200);
  const lang = /^[a-zA-Z-]{2,8}$/.test(String(body.lang ?? "")) ? String(body.lang).slice(0, 8) : "";
  return { ok: true, value: { kind, message, contact, lang } };
}
