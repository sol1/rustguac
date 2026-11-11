// #295: "Connect to a host" is search.js's, beside the global search box on
// every page that has one, with the box's own rules plus the server's
// can_connect_adhoc: poweruser and above. On Connections it opens the ad-hoc
// editor in place; anywhere else it goes to /connections.html#adhoc.
import { test, expect } from '@playwright/test';
import { installApi, settle, ROLE_PERMS } from '../lib/api.mjs';

const GONE = { status: 401, contentType: 'application/json', body: '{"error":"not authenticated"}' };

for (const role of ['poweruser', 'admin']) {
    for (const path of ['/sessions.html', '/recordings.html', '/reports.html']) {
        test(`${role} on ${path}: the button sits beside the box and opens the ad-hoc editor`, async ({ page }) => {
            await installApi(page, { role });
            await page.goto(path);
            await settle(page);
            const btn = page.locator('.brand-row #rg-adhoc');
            await expect(btn).toBeVisible();
            await expect(page.locator('.brand-row #rg-search')).toBeVisible();
            // Beside the box, on its right, vertically centred with it.
            const [b, s] = await Promise.all([btn.boundingBox(), page.locator('#rg-search').boundingBox()]);
            expect(b.x).toBeGreaterThan(s.x + s.width);
            expect(Math.abs((b.y + b.height / 2) - (s.y + s.height / 2))).toBeLessThanOrEqual(2);
            await btn.click();
            await page.waitForURL(/\/connections\.html/);
            await settle(page);
            await expect(page.locator('#entry-modal')).toHaveClass(/adhoc/);
            await expect(page.locator('#entry-modal')).toHaveClass(/active/);
        });
    }
}

test('on Connections the button opens the editor in place', async ({ page }) => {
    await installApi(page, { role: 'poweruser' });
    await page.goto('/connections.html');
    await settle(page);
    const before = page.url();
    await page.locator('#rg-adhoc').click();
    await expect(page.locator('#entry-modal')).toHaveClass(/adhoc/);
    expect(page.url()).toBe(before);
    // The page itself has no button of its own: there is one.
    await expect(page.locator('#rg-adhoc')).toHaveCount(1);
    await expect(page.locator('#btn-adhoc')).toHaveCount(0);
});

for (const role of ['operator', 'viewer']) {
    test(`no button for ${role}`, async ({ page }) => {
        await installApi(page, { role });
        for (const path of ['/connections.html', '/recordings.html']) {
            await page.goto(path);
            await settle(page);
            await expect(page.locator('#rg-adhoc')).toHaveCount(0);
        }
    });
}

test('no button signed out, on the login page or on a page', async ({ page }) => {
    await installApi(page, { routes: { 'GET /api/me': GONE } });
    await page.goto('/');
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toHaveCount(0);
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toHaveCount(0);
});

test('without Vault a poweruser still gets the button', async ({ page }) => {
    await installApi(page, { role: 'poweruser', routes: {
        'GET /api/me': { name: 'pu@example.com', role: 'poweruser', permissions: ROLE_PERMS.poweruser, groups: [], vault_enabled: false, vault_configured: false },
        'GET /api/addressbook/search-index': { status: 404, contentType: 'application/json', body: '{"error":"vault not configured"}' }
    } });
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toBeVisible();
});

test('the button goes when the session expires, and after logout', async ({ page }) => {
    let expired = false;
    await installApi(page, { role: 'poweruser', routes: {
        'GET /api/addressbook/version': (req, url, state) => expired ? GONE : { version: state.version, changed_at: 0 }
    } });
    await page.clock.install();
    await page.goto('/sessions.html');
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toBeVisible();
    expired = true;
    await page.clock.runFor(31_000);
    await expect(page.locator('#rg-adhoc')).toHaveCount(0);
    await expect(page.locator('#rg-search')).toHaveCount(0);
});

test('logging out leaves no button on the login page', async ({ page }) => {
    let signedIn = true;
    await installApi(page, { routes: { 'GET /api/me': () => signedIn
        ? { name: 'pu@example.com', role: 'poweruser', permissions: ROLE_PERMS.poweruser, groups: [], vault_enabled: true, vault_configured: true }
        : GONE } });
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toBeVisible();
    signedIn = false;
    await page.locator('#logout-item').click();
    await page.waitForURL(/\/(index\.html)?$/);
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toHaveCount(0);
});

test('an API key is confirmed through /api/me before the button shows', async ({ page }) => {
    await page.addInitScript(() => { try { sessionStorage.setItem('rustguac_api_key', 'k'); } catch (e) {} });
    const api = await installApi(page, { role: 'admin' });
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toBeVisible();
    expect(api.calls.some(c => c.path === '/api/me')).toBe(true);
});
