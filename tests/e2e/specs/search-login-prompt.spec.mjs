// #360: Login… on a search result for an entry with no stored credentials
// asks for them first, as the folder view does, instead of connecting
// without them.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const connects = api => api.calls.filter(c => c.method === 'POST' && c.path.endsWith('/entries/files/connect'));

test('Login… in search asks for credentials and connects with them', async ({ page }) => {
    const api = await installApi(page, { role: 'operator' });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('#rg-search').click();
    await page.keyboard.type('files');
    const row = page.locator('#search-results tbody tr').first();
    const login = row.locator('button.btn-connect', { hasText: 'Login' });
    await expect(login).toBeVisible();
    await login.click();

    await expect(page.locator('#cred-modal')).toHaveClass(/active/);
    await expect(page.locator('#cred-domain-row')).toBeVisible();
    expect(connects(api)).toHaveLength(0);

    await page.locator('#cred-username').fill('alice');
    await page.locator('#cred-password').fill('s3cret');
    await page.locator('#cred-connect').click();
    await expect.poll(() => connects(api).length).toBe(1);
    const body = connects(api)[0].body;
    expect(body.username).toBe('alice');
    expect(body.password).toBe('s3cret');
});

test('Login… in search on another page opens the entry folder in Connections', async ({ page }) => {
    const api = await installApi(page, { role: 'operator' });
    await page.goto('/recordings.html');
    await settle(page);
    await page.locator('#rg-search').click();
    await page.keyboard.type('files');
    await page.locator('#search-results tbody tr').first().locator('button.btn-connect', { hasText: 'Login' }).click();
    await page.waitForURL(/\/connections\.html#open=/);
    expect(connects(api)).toHaveLength(0);
});
