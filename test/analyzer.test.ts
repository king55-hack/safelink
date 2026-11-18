import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

/**
 * The link analyzer lives inside public/index.html (it runs in the browser).
 * Extract it here so the lookalike / typosquatting rules are regression-tested.
 */
const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
const s = html.indexOf("<script>");
const js = html.slice(s + 8, html.indexOf("</script>", s));
const code = js.slice(js.indexOf("const BRANDS"), js.indexOf("/* ---------- rendering"));
type Result = { error?: boolean; verdict: string; findings: { sev: string; title: string }[] };
const mod = new Function(code + "; return { analyze, extractLinks };")() as { analyze: (u: string) => Result; extractLinks: (t: string) => string[] };
const analyze = mod.analyze;
const extractLinks = mod.extractLinks;

const SCAMS = `
g00gle.com arnazon.com paypa1.com paypai.com micr0soft.com faceb00k.com amaz0n-login.com pay-pal.com
paypal-secure-login.com secure-paypa1.com appleid-verify.com paypall.com gooogle.com googel.com netfilx.com
linkedln.com rakuten-card-login.com paypal.xyz amazon.tk google.icu microsoft.top instagrarn.com whatsap.com
rakutan.co.jp paypay-login.com esewa-nepal-login.com khalti.xyz docomo-support.com sbi-bank-verify.com mizuh0.co.jp uniq1o.com
paypa1-support.net netflix-billing-update.com micros0ft-security.com appie.com.verify-id.ru icloud-unlock.xyz
yamato-redelivery.top sagawa-kyuubin.work mufg-bk-login.com smbc-card-secure.net kddi-au-login.com
esewa.top khalti-wallet.link nabilbank-login.com ncell-offer.xyz daraz-gift.top
cloudfl4re.com coinbasse.com binnance.com metamaskk.io dropb0x.com spotifyy.com tiktok-verify.com
amazon.co.jp.account-verify.ru support.apple.com.id-confirm.top login.microsoft.com.evil.work
`.split(/\s+/).filter(Boolean);

const LEGIT = `
google.com youtube.com facebook.com wikipedia.org amazon.com yahoo.com reddit.com instagram.com twitter.com x.com linkedin.com
netflix.com microsoft.com apple.com live.com office.com bing.com zoom.us twitch.tv discord.com github.com gitlab.com
stackoverflow.com cloudflare.com wordpress.com medium.com ebay.com paypal.com stripe.com shopify.com walmart.com target.com
etsy.com aliexpress.com alibaba.com temu.com booking.com airbnb.com uber.com spotify.com dropbox.com slack.com notion.so
figma.com canva.com adobe.com oracle.com ibm.com samsung.com sony.com nintendo.com steampowered.com bbc.co.uk cnn.com
rakuten.co.jp yahoo.co.jp mercari.com amazon.co.jp line.me docomo.ne.jp nttdocomo.co.jp softbank.jp paypay.ne.jp smbc.co.jp
smbc-card.com mufg.jp mizuhobank.co.jp jcb.co.jp aeon.co.jp uniqlo.com nintendo.co.jp jp.mercari.com japanpost.jp
kuronekoyamato.co.jp sagawa-exp.co.jp nikkei.com asahi.com nhk.or.jp
daraz.com.np esewa.com.np khalti.com nabilbank.com nicasiabank.com globalimebank.com ncell.axiata.com foodmandu.com
hamropatro.com onlinekhabar.com ekantipur.com setopati.com
mail.google.com docs.google.com accounts.google.com support.apple.com appleid.apple.com login.microsoftonline.com
outlook.live.com outlook.office.com teams.microsoft.com aws.amazon.com s3.amazonaws.com web.whatsapp.com business.facebook.com
store.steampowered.com
pipeline.com timeline.com groups.google.com lineage.com airline.com headline.com guideline.com deadline.com bookmarks.com
users.com targets.com phase.com strip.com apples.com bookings.com chaser.com wiser.com vista.com appleton.org pineapple.com
snapple.com grapple.com forget.com user.com github.io
`.split(/\s+/).filter(Boolean);

test("lookalike / typosquatting scams are flagged dangerous", () => {
  const missed = SCAMS.filter((d) => analyze("https://" + d).verdict !== "danger");
  assert.deepEqual(missed, []);
});

test("real sites are never flagged dangerous (false positives)", () => {
  const bad = LEGIT.filter((d) => analyze("https://" + d).verdict === "danger");
  assert.deepEqual(bad, []);
});

test("scheme / structure rules still work", () => {
  assert.equal(analyze("javascript:alert(1)").verdict, "danger");
  assert.equal(analyze("https://paypal.com@evil.ru").verdict, "danger");
  assert.equal(analyze("http://192.168.1.1/login").verdict, "danger");
  assert.equal(analyze("https://medium.com/@someone/post").verdict, "safe");
  assert.equal(analyze("http://").error, true);
});

test("extractLinks finds links inside a pasted message", () => {
  const sms = "【重要】お客様のアカウントが停止されました。こちらhttps://paypa1.com/login/verify?id=1から確認してください。 詳細: www.amazon-support.top/help.";
  assert.deepEqual(extractLinks(sms), ["https://paypa1.com/login/verify?id=1", "www.amazon-support.top/help"]);

  assert.deepEqual(extractLinks("Your parcel is held, pay at bit.ly/3abc or http://evil.xyz:8080/x, thanks!"), ["http://evil.xyz:8080/x", "bit.ly/3abc"]);
  assert.deepEqual(extractLinks("see (https://a.example.org/x)."), ["https://a.example.org/x"]);
  // duplicates (any case) collapse, order is kept
  assert.deepEqual(extractLinks("HTTPS://A.top/x https://a.top/x https://b.top"), ["HTTPS://A.top/x", "https://b.top"]);
  // dangerous pseudo-links are surfaced so they can be flagged
  assert.deepEqual(extractLinks("click javascript:alert(1) now"), ["javascript:alert(1)"]);
});

test("extractLinks ignores things that are not links", () => {
  assert.deepEqual(extractLinks("mail me at john.doe@gmail.com or see file.txt, e.g. i.e. version 1.2.3"), []);
  assert.deepEqual(extractLinks(""), []);
  assert.deepEqual(extractLinks("no links here at all"), []);
  assert.ok(extractLinks("a.com ".repeat(100)).length <= 20);   // capped (and de-duplicated)
});

test("every extracted link can be analysed", () => {
  for (const l of extractLinks("x https://paypa1.com/a y www.google.com z bit.ly/abc w javascript:alert(1)")) {
    const r = analyze(l);
    assert.ok(r.error || ["safe", "warn", "danger"].includes(r.verdict), l);
  }
});
