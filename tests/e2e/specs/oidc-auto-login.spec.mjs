import { test, expect } from '@playwright/test';
import { installApi } from '../lib/api.mjs';

const unauthenticatedOidc = autoLogin => ({
    'GET /api/me': {
        status: 401,
        contentType: 'application/json',
        body: '{"error":"not authenticated"}'
    },
    'GET /api/auth/status': {
        oidc_enabled: true,
        oidc_auto_login: autoLogin,
        oidc_available: true,
        drive_configured: false
    }
});

test('auto-login redirects the home page to OIDC', async ({ page }) => {
    await installApi(page, { routes: unauthenticatedOidc(true) });
    await page.route('**/auth/login', route => route.fulfill({ status: 200, body: 'OIDC login started' }));

    await page.goto('/');
    await page.waitForURL(/\/auth\/login$/);
});

test('the manual login route skips auto-login and keeps the API-key form closed', async ({ page }) => {
    await installApi(page, { routes: unauthenticatedOidc(true) });

    await page.goto('/login');
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.locator('#sso-btn')).toBeVisible();
    await expect(page.locator('#api-key-toggle')).toBeVisible();
    await expect(page.locator('#login-form')).toBeHidden();

    await page.locator('#api-key-toggle').click();
    await expect(page.locator('#login-form')).toBeVisible();
});

test('an OIDC callback error prevents auto-login from starting again', async ({ page }) => {
    await installApi(page, { routes: unauthenticatedOidc(true) });
    await page.route('**/auth/login', route => route.fulfill({ status: 200, body: 'unexpected OIDC redirect' }));

    await page.goto('/?sso_error=failed');
    await expect(page.locator('#sso-error')).toHaveText('SSO login failed — please try again.');
    await expect(page).toHaveURL(/\/$/);
});

test('OIDC stays manual when auto-login is disabled', async ({ page }) => {
    await installApi(page, { routes: unauthenticatedOidc(false) });
    await page.route('**/auth/login', route => route.fulfill({ status: 200, body: 'unexpected OIDC redirect' }));

    await page.goto('/');
    await expect(page).toHaveURL(/\/$/);
    await expect(page.locator('#sso-btn')).toBeVisible();
});
