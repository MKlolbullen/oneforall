// Capture every page of the SPA against a running stack.
//
// Prereqs:
//   npm i -g playwright && npx playwright install chromium
//   reconforge up                              # API on :8000, Vite on :5173
//
// Usage:
//   node scripts/render-ui-screenshots.js [base_url] [out_dir]
//
// Writes PNGs into docs/screenshots/ui/ by default. The page-routing test
// in the SPA uses an X-Test-User header bypass; if RECONFORGE_TEST_AUTH_BYPASS
// is *not* set on the API, this script renders unauthenticated pages.
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

const BASE = process.argv[2] || 'http://127.0.0.1:5173';
const OUT  = process.argv[3] || path.resolve(__dirname, '..', 'docs', 'screenshots', 'ui');
fs.mkdirSync(OUT, { recursive: true });

const PAGES = [
  { id: 'dashboard', label: 'Dashboard', wait: '.metric' },
  { id: 'targets',   label: 'Targets',   wait: '.table' },
  { id: 'runs',      label: 'Runs',      wait: '.table' },
  { id: 'results',   label: 'Results',   wait: '.results-table' },
  { id: 'network',   label: 'Network Graph', wait: '.network-graph-pane' },
  { id: 'tools',     label: 'Tool Catalog', wait: '.table tr td' },
  { id: 'payloads',  label: 'Payloads',  wait: '.payload-shell' },
  { id: 'settings',  label: 'Settings Pack', wait: '.theme-grid' },
];

const wait = (ms) => new Promise(r => setTimeout(r, ms));

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    extraHTTPHeaders: { 'X-Test-User': 'admin' },
    deviceScaleFactor: 1,
  });
  const page = await ctx.newPage();

  for (const p of PAGES) {
    console.error(`-> ${p.id}`);
    await page.goto(BASE + '/', { waitUntil: 'networkidle' });
    await page.evaluate((label) => {
      const btn = Array.from(document.querySelectorAll('.sidebar button'))
        .find(b => b.textContent.trim().startsWith(label));
      if (btn) btn.click();
    }, p.label);
    // Wait for the page-specific signal, then give a longer beat for
    // async secondary loads (profile availability, tool checks, etc).
    try { await page.waitForSelector(p.wait, { timeout: 6000 }); }
    catch (_) { console.error(`   (no ${p.wait})`); }
    await wait(p.id === 'tools' || p.id === 'network' ? 2500 : 1100);
    await page.screenshot({ path: path.join(OUT, `ui-${p.id}.png`) });
  }

  // Cheatsheet via ?
  console.error('-> cheatsheet');
  await page.evaluate(() => Array.from(document.querySelectorAll('.sidebar button'))
    .find(b => b.textContent.includes('Dashboard'))?.click());
  await page.waitForSelector('.metric', { timeout: 5000 });
  await wait(600);
  await page.keyboard.press('Shift+Slash');
  await wait(300);
  await page.screenshot({ path: path.join(OUT, 'ui-cheatsheet.png') });
  await page.keyboard.press('Escape');

  // Payloads in base64
  console.error('-> payloads-base64');
  await page.evaluate(() => Array.from(document.querySelectorAll('.sidebar button'))
    .find(b => b.textContent.includes('Payloads'))?.click());
  await page.waitForSelector('.payload-shell', { timeout: 5000 });
  await wait(900);
  await page.evaluate(() => {
    const chip = Array.from(document.querySelectorAll('.encoding-chip'))
      .find(c => c.textContent.trim() === 'base64');
    if (chip) chip.click();
  });
  await wait(500);
  await page.screenshot({ path: path.join(OUT, 'ui-payloads-base64.png') });

  // Results with filter chips active
  console.error('-> results-filtered');
  await page.evaluate(() => Array.from(document.querySelectorAll('.sidebar button'))
    .find(b => b.textContent.includes('Results'))?.click());
  await page.waitForSelector('.results-table', { timeout: 5000 });
  await wait(800);
  await page.evaluate(() => {
    const sev = document.querySelectorAll('.results-filter-grid select')[1];
    if (sev) {
      sev.value = 'high';
      sev.dispatchEvent(new Event('change', { bubbles: true }));
    }
  });
  await wait(700);
  await page.screenshot({ path: path.join(OUT, 'ui-results-filtered.png') });

  // Targets — bulk import textarea filled in
  console.error('-> targets-bulk');
  await page.evaluate(() => Array.from(document.querySelectorAll('.sidebar button'))
    .find(b => b.textContent.includes('Targets'))?.click());
  await page.waitForSelector('.table', { timeout: 5000 });
  await wait(1500);
  await page.fill('textarea',
    "shop.acme-bank.com\nmobile.acme-bank.com\n# careers.acme-bank.com — out of scope\ndevops.acme-bank.com");
  await wait(400);
  await page.screenshot({ path: path.join(OUT, 'ui-targets-bulk.png') });

  await browser.close();
  console.error('done');
})();
