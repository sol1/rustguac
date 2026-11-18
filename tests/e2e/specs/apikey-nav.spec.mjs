// An API key in the browser used to be treated as an admin key, so a user
// token (rgu_...) showed Admin, Tokens and the rest, which the server then
// refused. The page now takes the key's own permissions from /api/me.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

async function visibleNav(page) {
    return page.locator('nav a:visible').evaluateAll(as => as.map(a => a.textContent.trim()).filter(t => /^[A-Z][a-z]+$/.test(t)));
}

for (const path of ['/connections.html', '/recordings.html', '/docs.html']) {
    test(`a user token capped at operator gets an operator's nav on ${path}`, async ({ page }) => {
        await page.addInitScript(() => { try { sessionStorage.setItem('rustguac_api_key', 'rgu_test'); } catch (e) {} });
        await installApi(page, { role: 'operator' });
        await page.goto(path);
        await settle(page);
        await expect(page.locator('html')).toHaveAttribute('data-role-level', '2');
        const links = await visibleNav(page);
        for (const gated of ['Admin', 'Tokens', 'Recordings', 'Reports', 'Sessions']) expect(links, path).not.toContain(gated);
        expect(links).toContain('Connections');
    });
}

test('an admin key still gets everything', async ({ page }) => {
    await page.addInitScript(() => { try { sessionStorage.setItem('rustguac_api_key', 'admin-key'); } catch (e) {} });
    await installApi(page, { role: 'admin' });
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('html')).toHaveAttribute('data-role-level', '4');
    const links = await visibleNav(page);
    for (const l of ['Sessions', 'Recordings', 'Reports', 'Tokens', 'Admin']) expect(links).toContain(l);
});
