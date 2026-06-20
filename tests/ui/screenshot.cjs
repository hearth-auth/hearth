const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  
  await page.setViewportSize({ width: 1440, height: 900 });
  
  await page.goto('http://127.0.0.1:8420/ui/login');
  await page.screenshot({ path: '/tmp/login-desktop.png', fullPage: true });
  console.log('login-desktop done');

  await page.goto('http://127.0.0.1:8420/ui/register');
  await page.screenshot({ path: '/tmp/register-desktop.png', fullPage: true });
  const csrfField = await page.$('input[name="_csrf"]');
  console.log('register has _csrf hidden field:', csrfField !== null);
  const hiddenFields = await page.$$eval('input[type="hidden"]', els => els.map(e => `${e.name}=${e.value.substring(0,20)}`));
  console.log('hidden fields:', JSON.stringify(hiddenFields));
  
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('http://127.0.0.1:8420/ui/login');
  await page.screenshot({ path: '/tmp/login-mobile.png', fullPage: true });
  await page.goto('http://127.0.0.1:8420/ui/register');
  await page.screenshot({ path: '/tmp/register-mobile.png', fullPage: true });
  
  await browser.close();
  console.log('all screenshots done');
})().catch(e => { console.error(e.message); process.exit(1); });
