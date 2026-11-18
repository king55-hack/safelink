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
