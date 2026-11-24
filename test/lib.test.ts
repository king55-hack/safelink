import test from "node:test";
import assert from "node:assert/strict";
import { blockedReason, parseInput, parseRdap, registrableDomain } from "../src/lib.ts";

test("registrableDomain", () => {
  assert.equal(registrableDomain("a.b.example.com"), "example.com");
  assert.equal(registrableDomain("www.amazon.co.jp"), "amazon.co.jp");
  assert.equal(registrableDomain("example.com"), "example.com");
});

test("parseInput assumes https and rejects junk", () => {
  assert.equal(parseInput("example.com/x")?.protocol, "https:");
  assert.equal(parseInput("http://example.com")?.protocol, "http:");
  assert.equal(parseInput(""), null);
  assert.equal(parseInput("http://"), null);
  assert.equal(parseInput("a".repeat(3000)), null);
});

test("blockedReason (SSRF guard)", () => {
  const b = (s: string) => blockedReason(new URL(s));
  assert.equal(b("https://paypal.com/a"), null);
  assert.equal(b("https://www.amazon.co.jp"), null);
  for (const bad of [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://10.0.0.5/",
    "http://localhost/", "http://intranet/", "http://printer.local/", "https://paypal.com:8443/",
    "https://user:pw@paypal.com/", "ftp://paypal.com/", "http://2130706433/", "http://0x7f.0.0.1/",
  ]) assert.notEqual(b(bad), null, bad);
});

test("parseRdap", () => {
  const now = Date.parse("2026-01-11T00:00:00Z");
  const r = parseRdap({ events: [{ eventAction: "last changed", eventDate: "2026-01-01T00:00:00Z" }, { eventAction: "registration", eventDate: "2026-01-01T00:00:00Z" }] }, now);
  assert.equal(r?.ageDays, 10);
  assert.equal(parseRdap({}), null);
  assert.equal(parseRdap({ events: [{ eventAction: "registration", eventDate: "nope" }] }), null);
});

import { sanitizeReport } from "../src/lib.ts";

test("sanitizeReport strips private parts and validates", () => {
  const ok = sanitizeReport({ url: "https://Evil-PayPa1.xyz:8443/login?email=a@b.com&t=1#x", category: "phishing", note: "  hi\u0001 there  ", lang: "ja" });
  assert.ok(ok.ok);
  if (ok.ok) {
    assert.equal(ok.value.url, "https://evil-paypa1.xyz/login");
    assert.equal(ok.value.host, "evil-paypa1.xyz");
    assert.equal(ok.value.note, "hi there");
    assert.equal(ok.value.lang, "ja");
  }
  // credentials never survive
  const cred = sanitizeReport({ url: "https://user:pw@scam.top/a", category: "other" });
  assert.ok(cred.ok && !cred.value.url.includes("pw") && !cred.value.url.includes("user"));
  // bare domain is accepted
  assert.ok(sanitizeReport({ url: "scam-shop.top", category: "shopping" }).ok);
  // notes are capped, bad language dropped
  const long = sanitizeReport({ url: "https://a.top", category: "other", note: "x".repeat(900), lang: "<script>" });
  assert.ok(long.ok && long.value.note.length === 500 && long.value.lang === "");
});

test("sanitizeReport rejects junk", () => {
  for (const bad of [
    { url: "javascript:alert(1)", category: "other" }, { url: "ftp://a.com/x", category: "other" },
    { url: "http://localhost/x", category: "other" }, { url: "http://intranet/x", category: "other" },
    { url: "https://a.com", category: "hacking" }, { url: "https://a.com" }, { category: "other" },
    { url: 123, category: "other" }, null, "str",
  ]) assert.equal(sanitizeReport(bad as any).ok, false, JSON.stringify(bad));
});

import { parseVtStats, vtUrlId } from "../src/lib.ts";

test("vtUrlId is unpadded base64url", () => {
  assert.equal(vtUrlId("http://www.example.com/"), "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8");
  assert.ok(!/[+/=]/.test(vtUrlId("https://a.top/?>>>???")));
});

test("parseVtStats", () => {
  const ok = parseVtStats({ data: { attributes: { last_analysis_stats: { malicious: 5, suspicious: 1, harmless: 60, undetected: 20, timeout: 0 } } } });
  assert.deepEqual(ok, { malicious: 5, suspicious: 1, harmless: 60, undetected: 20 });
  assert.equal(parseVtStats({}), null);
  assert.equal(parseVtStats(null), null);
  assert.deepEqual(parseVtStats({ data: { attributes: { last_analysis_stats: { malicious: -3, suspicious: "x" } } } }), { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 });
});

import { pageParams, summarizeCerts, timingSafeEqualBytes } from "../src/lib.ts";

test("summarizeCerts picks the newest currently-valid certificate", () => {
  const now = Date.parse("2026-11-18T00:00:00Z");
  const list = [
    { not_before: "2026-09-24T14:37:37Z", not_after: "2026-12-23T14:37:36Z", issuer: { friendly_name: "Google Trust Services" } },
    { not_before: "2026-10-04T18:34:51Z", not_after: "2027-01-02T18:34:50Z", issuer: { friendly_name: "Let's Encrypt" } },
    { not_before: "2026-11-01T00:00:00Z", not_after: "2026-11-10T00:00:00Z", issuer: { friendly_name: "Expired CA" } }, // already expired
    { not_before: "2026-11-10T00:00:00Z", not_after: "2027-02-10T00:00:00Z", revoked: true, issuer: { friendly_name: "Revoked CA" } },
  ];
  const s = summarizeCerts(list, now);
  assert.equal(s?.issuer, "Let's Encrypt");
  assert.equal(s?.daysLeft, 45);
  assert.equal(s?.notAfter, "2027-01-02T18:34:50.000Z");
});

test("summarizeCerts stays quiet when it cannot know", () => {
  assert.equal(summarizeCerts([]), null);
  assert.equal(summarizeCerts(null), null);
  assert.equal(summarizeCerts({}), null);
  assert.equal(summarizeCerts(Array.from({ length: 100 }, () => ({ not_before: "2020-01-01T00:00:00Z", not_after: "2099-01-01T00:00:00Z" }))), null); // truncated page
  // issuer falls back to the O= field and is sanitised
  const s = summarizeCerts([{ not_before: "2020-01-01T00:00:00Z", not_after: "2099-01-01T00:00:00Z", issuer: { name: "C=US, O=Some CA\u0001, CN=X" } }]);
  assert.equal(s?.issuer, "Some CA");
});

test("timingSafeEqualBytes", () => {
  assert.equal(timingSafeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
  assert.equal(timingSafeEqualBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  assert.equal(timingSafeEqualBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
});

test("pageParams clamps input", () => {
  assert.deepEqual(pageParams(new URLSearchParams("")), { limit: 100, offset: 0 });
  assert.deepEqual(pageParams(new URLSearchParams("limit=5&offset=10")), { limit: 5, offset: 10 });
  assert.deepEqual(pageParams(new URLSearchParams("limit=99999&offset=-3")), { limit: 200, offset: 0 });
  assert.deepEqual(pageParams(new URLSearchParams("limit=abc&offset=1.5")), { limit: 100, offset: 0 });
  assert.deepEqual(pageParams(new URLSearchParams("limit=0")), { limit: 1, offset: 0 });
});

import { allowPreviewRequest, PREVIEW_SKIP_TYPES } from "../src/lib.ts";

test("allowPreviewRequest only lets public http(s) through", () => {
  for (const ok of ["https://example.org/", "http://paypa1.com/login", "https://cdn.site.com/a.js?x=1", "data:image/png;base64,AAAA"])
    assert.equal(allowPreviewRequest(ok), true, ok);
  for (const bad of [
    "http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "http://[::1]/", "http://10.0.0.5/admin", "http://localhost/",
    "http://intranet/", "https://site.com:8443/", "file:///etc/passwd", "ftp://a.com/x", "javascript:alert(1)", "chrome://settings", "not a url", "",
  ]) assert.equal(allowPreviewRequest(bad), false, bad);
});

test("preview skips heavy resource types", () => {
  assert.ok((PREVIEW_SKIP_TYPES as readonly string[]).includes("media"));
  assert.ok(!(PREVIEW_SKIP_TYPES as readonly string[]).includes("document"));
  assert.ok(!(PREVIEW_SKIP_TYPES as readonly string[]).includes("image"));
});
