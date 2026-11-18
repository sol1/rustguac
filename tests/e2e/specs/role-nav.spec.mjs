// Every page carries the same navigation, gated by permission (#294): the
// caller's permissions are on <html data-perms> and each gated link names the
// one it needs in data-perm. A link shows only to those who can use the page
// behind it, an admin sees all of them, and the link order is identical from
// page to page.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const PAGES = ['/connections.html', '/sessions.html', '/recordings.html', '/reports.html'];
const ALL = ['Connections', 'Sessions', 'Recordings', 'Reports', 'Docs', 'Tokens', 'Admin'];

async function visibleNav(page) {
    return page.locator('nav a:visible').evaluateAll(as => as.map(a => a.textContent.trim()).filter(t => /^[A-Z][a-z]+$/.test(t)));
}

for (const path of PAGES) {
    test(`admin sees the full nav on ${path}`, async ({ page }) => {
        await installApi(page, { role: 'admin' });
        await page.goto(path);
        await settle(page);
        await expect(page.locator('html')).toHaveAttribute('data-role-level', '4');
        const links = await visibleNav(page);
        for (const l of ALL) expect(links, `${l} must be in the nav`).toContain(l);
        // Same order on every page.
        expect(links.filter(l => ALL.includes(l))).toEqual(ALL);
    });
}

test('a viewer sees no gated links, Recordings and Credentials included', async ({ page }) => {
    await installApi(page, { role: 'viewer' });
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('html')).toHaveAttribute('data-role-level', '1');
    await expect(page.locator('html')).toHaveAttribute('data-perms', 'docs.view');
    const links = await visibleNav(page);
    // Recordings needs recordings.view (poweruser): the server never let a
    // viewer list them, but the link used to show.
    for (const gated of ['Sessions', 'Recordings', 'Reports', 'Tokens', 'Admin']) expect(links).not.toContain(gated);
    expect(links).toContain('Connections');
    expect(links).toContain('Docs');
    // Saving credentials needs credentials.self (operator).
    await expect(page.locator('#my-creds-nav')).toBeHidden();
});

test('an operator sees Credentials but not Tokens, Recordings, Sessions, Reports or Admin', async ({ page }) => {
    await installApi(page, { role: 'operator' });
    await page.goto('/docs.html');
    await settle(page);
    await expect(page.locator('html')).toHaveAttribute('data-role-level', '2');
    const links = await visibleNav(page);
    // Creating a token and listing recordings both need poweruser on the
    // server; the links used to show to operators anyway.
    for (const gated of ['Tokens', 'Recordings', 'Sessions', 'Reports', 'Admin']) expect(links).not.toContain(gated);
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('#my-creds-nav')).toBeVisible();
});

test('a poweruser sees everything but Admin', async ({ page }) => {
    await installApi(page, { role: 'poweruser' });
    await page.goto('/connections.html');
    await settle(page);
    const links = await visibleNav(page);
    for (const l of ['Sessions', 'Recordings', 'Reports', 'Tokens', 'Docs']) expect(links).toContain(l);
    expect(links).not.toContain('Admin');
});
