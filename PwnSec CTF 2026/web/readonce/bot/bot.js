const puppeteer = require("puppeteer");

const APP_URL = process.env.APP_URL || "http://127.0.0.1:3000";
const BOT_TOKEN = process.env.BOT_TOKEN || "dev-token";
const CHROMIUM_PATH = process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium";

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function review(report) {
  let browser;
  let context;

  try {
    browser = await puppeteer.launch({
      executablePath: CHROMIUM_PATH,
      headless: "new",
      args: [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        '--js-flags="--jitless"',
        "--disable-gpu",
      ],
    });

    context = await browser.createBrowserContext();

    const sessionPage = await context.newPage();
    await sessionPage.setExtraHTTPHeaders({ "X-Bot-Token": BOT_TOKEN });
    const sessionResponse = await sessionPage.goto(`${APP_URL}/reports/session`, {
      waitUntil: "domcontentloaded",
      timeout: 7000,
    });
    await sessionPage.close();

    if (!sessionResponse || !sessionResponse.ok()) {
      throw new Error(`reviewer session returned ${sessionResponse ? sessionResponse.status() : "no response"}`);
    }

    const page = await context.newPage();

    await page.goto(`${APP_URL}/reports/check?rid=${encodeURIComponent(report.id)}&state=${encodeURIComponent(report.nonce)}`, {
      waitUntil: "domcontentloaded",
      timeout: 7000,
    });

    await page.goto(`${APP_URL}/api/flag`, {
      waitUntil: "domcontentloaded",
      timeout: 7000,
    });

    const armResponse = await fetch(`${APP_URL}/reports/arm/${encodeURIComponent(report.id)}`, {
      method: "POST",
      headers: { "X-Bot-Token": BOT_TOKEN },
    });

    if (!armResponse.ok) {
      throw new Error(`report arm returned ${armResponse.status}`);
    }

    const url = new URL(report.url);
    url.searchParams.set("rid", report.id);

    await page.goto(url.href, {
      waitUntil: "domcontentloaded",
      timeout: 7000,
    });

    await sleep(10000);
    await page.close();
  } finally {
    if (context) {
      await context.close();
    }
    if (browser) {
      await browser.close();
    }
  }
}

module.exports = { review };
