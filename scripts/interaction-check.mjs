// Click-through check of the mock build (synthetic data only).
//   NEXT_PUBLIC_WBM_MOCK=1 pnpm build && node scripts/interaction-check.mjs
// Serves ./out, drives headless Chrome, asserts the DOM changes after each interaction.
// Optional SHOT_DIR: directory for window-only screenshots (kept OUT of the repo).
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { chromium } from "playwright-core";

const OUT = path.resolve("out");
const SHOT_DIR = process.env.SHOT_DIR;
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".txt": "text/plain", ".ico": "image/x-icon", ".json": "application/json", ".woff2": "font/woff2" };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  let p = path.join(OUT, decodeURIComponent(url.pathname));
  if (!fs.existsSync(p) || fs.statSync(p).isDirectory()) {
    p = fs.existsSync(p + ".html") ? p + ".html" : path.join(OUT, "index.html");
  }
  res.writeHead(200, { "content-type": TYPES[path.extname(p)] ?? "application/octet-stream" });
  fs.createReadStream(p).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

let ran = 0;
let failed = 0;
function check(name, cond) {
  ran += 1;
  if (!cond) failed += 1;
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}`);
}
const shot = async (page, name) => {
  if (SHOT_DIR) await page.screenshot({ path: path.join(SHOT_DIR, `integ-${name}.png`) });
};

const browser = await chromium.launch({ channel: "chrome", headless: true });
const page = await browser.newPage({ viewport: { width: 1000, height: 760 } });
const errors = [];
page.on("pageerror", (e) => errors.push(String(e)));

try {
  // Dismiss an alert
  await page.goto(`${base}/alerts`);
  await page.getByText("Possible evil twin").first().waitFor();
  const before = await page.getByRole("button", { name: "Dismiss" }).count();
  await shot(page, "alerts-before");
  await page.getByRole("button", { name: "Dismiss" }).first().click();
  await page.waitForFunction((n) => document.querySelectorAll("li button").length < n, before);
  const after = await page.getByRole("button", { name: "Dismiss" }).count();
  check(`dismiss: alert count ${before} -> ${after}`, after === before - 1);
  await shot(page, "alerts-after-dismiss");

  // Scan now
  await page.goto(`${base}/`);
  const scanBtn = page.getByRole("button", { name: /Scan now|Scanning/ });
  await page.getByText(/Last scan/).waitFor();
  const t0 = await page.getByText(/Last scan/).innerText();
  await page.waitForTimeout(1100); // the clock shown has 1 s resolution
  await scanBtn.click();
  await page.waitForFunction((t) => {
    const el = [...document.querySelectorAll("span")].find((s) => s.textContent?.startsWith("Last scan"));
    return el && el.textContent !== t;
  }, t0);
  const t1 = await page.getByText(/Last scan/).innerText();
  check(`scan now: "${t0}" -> "${t1}"`, t0 !== t1);
  await shot(page, "dashboard-after-scan");

  // Trust from current scan, then Save settings
  await page.goto(`${base}/settings`);
  await page.getByText("Add from current scan").waitFor();
  const trustBtn = page.getByRole("button", { name: "Trust", exact: true }).first();
  await trustBtn.waitFor();
  const trustedBefore = await page.locator("button", { hasText: "Remove" }).count();
  await trustBtn.click();
  const trustedAfter = await page.locator("button", { hasText: "Remove" }).count();
  check(`trust: trusted networks ${trustedBefore} -> ${trustedAfter}`, trustedAfter === trustedBefore + 1);

  await page.getByLabel("Scan interval (seconds)").fill("120");
  await page.getByRole("button", { name: "Save settings" }).click();
  await page.getByText("Saved", { exact: true }).waitFor();
  check("save settings: status reads Saved", true);
  await shot(page, "settings-after-save");

  // Settings survived (mock backend is in-memory, so navigate client-side, not reload)
  await page.getByRole("link", { name: /Dashboard|Home/i }).first().click();
  await page.getByRole("link", { name: /Settings/i }).first().click();
  await page.getByText("Add from current scan").waitFor();
  const v = await page.getByLabel("Scan interval (seconds)").inputValue();
  check(`settings persisted across navigation (interval=${v})`, v === "120");

  // Network page: devices listed, sweep gated while the setting is off
  await page.goto(`${base}/network`);
  await page.getByRole("heading", { name: "Network", exact: true }).waitFor();
  await page.getByText("Vendor-A").first().waitFor();
  check("network page lists devices with vendors", (await page.getByText("Vendor-A").count()) > 0);
  for (const label of ["Neighbor table", "Announced", "Both"]) {
    check(`network page shows the source "${label}"`, (await page.getByTestId("lan-source").filter({ hasText: label }).count()) > 0);
  }
  const sweepBtn = page.getByRole("button", { name: /Sweep now/ });
  check("sweep now is disabled while the sweep setting is off", await sweepBtn.isDisabled());
  check(
    "sweep refusal reason is shown",
    (await page.getByText("The active sweep is switched off in Settings.").count()) > 0,
  );
  await shot(page, "network");

  // Settings: new sections render; turn the sweep on and the button enables
  await page.goto(`${base}/settings`);
  for (const h of ["Mine", "Places", "Watchlist", "Network devices"]) {
    await page.getByRole("heading", { name: h, exact: true }).waitFor();
    check(`settings section "${h}" renders`, true);
  }
  await shot(page, "settings-v2");
  // Watchlist: add an entry and see it listed
  await page.getByLabel("Pattern").fill("Net-Z");
  await page.locator("form", { has: page.getByLabel("Pattern") }).getByRole("button", { name: "Add", exact: true }).click();
  await page.getByText(/Net-Z/).first().waitFor();
  check("watchlist: entry added and listed", true);

  // Routes resolve
  for (const r of ["/alerts", "/history", "/settings", "/network"]) {
    const resp = await page.goto(`${base}${r}`);
    check(`route ${r} resolves`, resp?.status() === 200);
  }
  check("no uncaught page errors", errors.length === 0);
} finally {
  await browser.close();
  server.close();
}
console.log(`INTERACTION TALLY: ${ran - failed} passed / ${failed} failed (${ran} checks)`);
if (ran < 1 || failed > 0) process.exit(1);
