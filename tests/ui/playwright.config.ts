import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  globalSetup: './globalSetup.ts',
  outputDir: 'reports/playwright-output',
  reporter: [
    ['html', { outputFolder: 'reports/html', open: 'never' }],
    ['list'],
  ],
  use: {
    baseURL: process.env.HEARTH_URL ?? 'http://127.0.0.1:8420',
    headless: true,
    screenshot: 'only-on-failure',
    video: 'off',
  },
  workers: 4,
  timeout: 30_000,
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
