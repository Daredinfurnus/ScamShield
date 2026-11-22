import { test, expect } from '@playwright/test';

test.describe('ScamShield Authentication Flow', () => {

  test.beforeEach(async ({ page }) => {
    await page.context().clearCookies();
  });

  test('TEST 1: Anonymous dashboard shows Authentication Required card', async ({ page }) => {
    await page.goto('http://localhost:5173/dashboard');
    await expect(page.locator('text=Authentication Required')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('text=Please sign in to access the Intelligence Desk')).toBeVisible();
  });

  test('TEST 2: Click ACCESS in card opens Register Organization modal', async ({ page }) => {
    await page.goto('http://localhost:5173/dashboard');
    await page.waitForSelector('text=Authentication Required', { timeout: 15000 });

    // Click ACCESS button inside the main content area (the card)
    await page.getByRole('main').getByRole('button', { name: 'ACCESS' }).click();

    // Modal should open with Register Organization (since register is now default)
    await expect(page.locator('text=Register Organization')).toBeVisible({ timeout: 15000 });

    // URL should remain /dashboard
    await expect(page).toHaveURL('http://localhost:5173/dashboard');
  });

  test('TEST 3: Can switch to Sign In inside modal', async ({ page }) => {
    await page.goto('http://localhost:5173/dashboard');
    await page.getByRole('main').getByRole('button', { name: 'ACCESS' }).click();

    // Should be in register mode initially
    await expect(page.locator('text=Register Organization')).toBeVisible();

    // Click Sign In button at bottom of modal
    await page.click('button:has-text("Sign In")');

    // Should switch to login mode
    await expect(page.locator('text=Investigator Sign In')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Register Organization')).toBeHidden();
  });

  test('TEST 4: Close modal returns to dashboard', async ({ page }) => {
    await page.goto('http://localhost:5173/dashboard');
    await page.getByRole('main').getByRole('button', { name: 'ACCESS' }).click();
    await expect(page.locator('text=Register Organization')).toBeVisible({ timeout: 15000 });

    // Click close button (X)
    await page.getByRole('button', { name: 'Close Modal' }).click();

    // Should be back on dashboard with auth card visible
    await expect(page.locator('text=Authentication Required')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL('http://localhost:5173/dashboard');
  });

  test('TEST 5: Navbar ACCESS opens same modal', async ({ page }) => {
    await page.goto('http://localhost:5173');

    // Click ACCESS in navbar (header/banner)
    await page.getByRole('banner').getByRole('button', { name: 'ACCESS' }).click();

    // Modal should open
    await expect(page.locator('text=Register Organization')).toBeVisible({ timeout: 15000 });

    // URL should remain /
    await expect(page).toHaveURL('http://localhost:5173/');
  });

  test('TEST 6: Successful registration loads dashboard telemetry', async ({ page }) => {
    const testEmail = `test-${Date.now()}@example.com`;

    await page.goto('http://localhost:5173/dashboard');
    await page.getByRole('main').getByRole('button', { name: 'ACCESS' }).click();
    await expect(page.locator('text=Register Organization')).toBeVisible({ timeout: 15000 });

    // Fill registration form
    await page.fill('input[placeholder="National Fraud Bureau"]', 'Test Organization');
    await page.fill('input[type="email"]', testEmail);
    await page.fill('input[type="password"]', 'password123');
    await page.getByRole('button', { name: 'Create Organization Unit' }).click();

    // Should see LOGOUT button (successful auth)
    await expect(page.getByRole('button', { name: 'LOGOUT' })).toBeVisible({ timeout: 15000 });

    // Should be on dashboard with telemetry
    await expect(page.locator('text=Case Telemetry & Operations')).toBeVisible({ timeout: 10000 });
  });

  test('TEST 7: Failed authentication keeps modal open', async ({ page }) => {
    await page.goto('http://localhost:5173/dashboard');
    await page.getByRole('main').getByRole('button', { name: 'ACCESS' }).click();
    await page.click('button:has-text("Sign In")');
    await expect(page.locator('text=Investigator Sign In')).toBeVisible();

    // Try login with wrong credentials
    await page.fill('input[type="email"]', 'wrong@example.com');
    await page.fill('input[type="password"]', 'wrongpassword');
    await page.getByRole('button', { name: 'Sign In to Workspace' }).click();

    // Modal should stay open with error
    await expect(page.locator('text=Investigator Sign In')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('text=Invalid email or password')).toBeVisible({ timeout: 5000 });
  });
});