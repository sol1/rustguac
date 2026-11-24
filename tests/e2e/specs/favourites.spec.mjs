// #335: a star on each entry adds it to Favourites at the top of
// Connections, from any folder, and Connect there opens the entry from its
// own folder. Favourites are the user's own, kept on the server.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

test('starring an entry puts it in Favourites, and Connect there uses its folder', async ({ page }) => {
    const api = await installApi(page, { role: 'operator' });
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('#favourites')).toBeHidden();

    await page.locator('.folder-row').filter({ hasText: /beta/ }).first().click();
    const row = page.locator('.main .entries-table tbody tr').filter({ hasText: 'app01' });
    // Hovering the star lights it gold, with no button box behind it.
    await row.locator('.fav-star').hover();
    await expect.poll(() => row.locator('.fav-star').evaluate(el => {
        const cs = getComputedStyle(el);
        return [cs.backgroundColor, cs.color];
    })).toEqual(['rgba(0, 0, 0, 0)', 'rgb(245, 197, 24)']);
    await row.locator('.fav-star').click();
    await expect.poll(() => api.calls.find(c => c.method === 'PUT' && c.path === '/api/me/favourites')?.body?.entry).toBe('app01');

    const favs = page.locator('#favourites');
    await expect(favs).toBeVisible();
    await expect(favs.locator('tbody tr')).toHaveCount(1);
    await expect(favs).toContainText('app01');
    await expect(row.locator('.fav-star')).toHaveAttribute('aria-pressed', 'true');

    // Connect from Favourites, from another folder: the request names the entry's own folder.
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
    const put = api.calls.find(c => c.method === 'PUT' && c.path === '/api/me/favourites').body;
    await favs.locator('button.btn-connect', { hasText: /Connect|Login/ }).first().click();
    const want = `/api/addressbook/folders/${put.scope}/${encodeURIComponent(put.folder)}/entries/app01/connect`;
    await expect.poll(() => api.calls.filter(c => c.method === 'POST' && c.path.endsWith('/entries/app01/connect')).map(c => c.path)).toContain(want);

    // Unstar from Favourites: it goes.
    await favs.locator('.fav-star').click();
    await expect(favs).toBeHidden();
});

test('favourites the user can no longer open are not shown', async ({ page }) => {
    await installApi(page, { role: 'operator', favourites: [{ scope: 'shared', folder: 'gone', entry: 'old' }] });
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('#favourites')).toBeHidden();
});
