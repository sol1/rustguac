// One global connection search on every page: '/' opens a floating overlay
// listing every connection, typing narrows it, Escape or the backdrop
// closes it, and on the connections page the folder view underneath is
// left exactly as it was.
import { test, expect } from '@playwright/test';
import { installApi, settle, ROLE_PERMS } from '../lib/api.mjs';

const TOTAL_ENTRIES = 4 + 2 + 20;

for (const path of ['/sessions.html', '/recordings.html', '/reports.html']) {
    test(`'/' opens the search overlay on ${path} and Escape closes it`, async ({ page }) => {
        await installApi(page);
        await page.goto(path);
        await settle(page);
        const box = page.locator('#rg-search');
        await expect(box).toBeVisible();
        await page.locator('body').click({ position: { x: 5, y: 5 } });
        await page.keyboard.press('/');
        await expect(box).toBeFocused();
        const overlay = page.locator('#search-overlay');
        await expect(overlay).toHaveClass(/open/);
        await expect(page.locator('#search-results tbody tr')).toHaveCount(TOTAL_ENTRIES);
        await page.keyboard.type('dc01');
        await expect(page.locator('#search-results tbody tr')).toHaveCount(1);
        await expect(page.locator('#search-results tbody tr').first()).toContainText('dc01');
        await page.keyboard.press('Escape');
        await expect(overlay).not.toHaveClass(/open/);
    });
}

test('on connections the overlay floats over an untouched folder view', async ({ page }) => {
    await installApi(page);
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /beta/ }).first().click();
    await expect(page.locator('#entries-title')).toHaveText(/beta/);
    const rowsBefore = await page.locator('.main .entries-table tbody tr').count();

    await page.locator('#rg-search').click();
    const overlay = page.locator('#search-overlay');
    await expect(overlay).toHaveClass(/open/);
    await page.keyboard.type('tenant-05');
    await expect(page.locator('#search-results tbody tr')).toHaveCount(1);
    // The folder view beneath has not changed.
    await expect(page.locator('#entries-title')).toHaveText(/beta/);
    expect(await page.locator('.main .entries-table tbody tr').count()).toBe(rowsBefore);

    // A mousedown outside the box and the panel closes the overlay.
    await page.mouse.click(20, 500);
    await expect(overlay).not.toHaveClass(/open/);
    await expect(page.locator('#entries-title')).toHaveText(/beta/);
});

test('results show the folder display name and a Connect button; Connect posts to the entry', async ({ page }) => {
    const api = await installApi(page);
    await page.goto('/recordings.html');
    await settle(page);
    await page.locator('#rg-search').click();
    await page.keyboard.type('web01');
    const row = page.locator('#search-results tbody tr').first();
    await expect(row).toContainText("Dani & Fiori's Gourmet Pizzeria");
    await expect(row).toContainText('web01');
    await row.locator('[data-sc-connect]').first().click();
    await expect.poll(() => api.calls.some(c => c.method === 'POST' && c.path.endsWith('/entries/web01/connect'))).toBe(true);
});

// ── Nothing leaks to whoever is not signed in ──
//
// The index is the whole address book the caller may see. It must never be
// drawn, fetched, or served from the tab's cache on the login page, for an
// anonymous or viewer caller, or for a different login than the one that
// cached it.

const IDX_KEY = 'rustguac_search_index_v1', VER_KEY = 'rustguac_search_version_v1', WHO_KEY = 'rustguac_search_user_v1';

// A leftover index from an earlier login in this tab: one entry no fixture has.
async function seedStaleCache(page, who = 'someone-else@example.com|admin|everyone') {
    await page.addInitScript(([idx, ver, whoKey, whoVal]) => {
        // Once per tab: init scripts run again on every navigation, and a
        // page that bounces to the login page must not find it re-seeded.
        if (sessionStorage.getItem('e2e_seeded')) return;
        sessionStorage.setItem('e2e_seeded', '1');
        const stale = [{ scope: 'shared', folderPath: 'secret', folderName: null, label: 'stale-host', host: 'stale.internal',
                         entry: { name: 'stale-host', session_type: 'ssh', hostname: 'stale.internal' }, haystack: 'stale-host stale.internal ssh secret' }];
        sessionStorage.setItem(idx, JSON.stringify(stale));
        sessionStorage.setItem(ver, '1');
        sessionStorage.setItem(whoKey, whoVal);
    }, [IDX_KEY, VER_KEY, WHO_KEY, who]);
}

const cacheKeys = (page) => page.evaluate(([a, b, c]) => [a, b, c].filter(k => sessionStorage.getItem(k) != null), [IDX_KEY, VER_KEY, WHO_KEY]);

test('the login page carries no search box and never loads search.js', async ({ page }) => {
    const api = await installApi(page, { routes: { 'GET /api/me': { status: 401, contentType: 'application/json', body: '{"error":"not authenticated"}' } } });
    const scripts = [];
    page.on('request', r => { if (/search\.js/.test(r.url())) scripts.push(r.url()); });
    await page.goto('/index.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toHaveCount(0);
    await expect(page.locator('#search-overlay')).toHaveCount(0);
    expect(scripts).toEqual([]);
    expect(api.calls.some(c => c.path.startsWith('/api/addressbook'))).toBe(false);
});

for (const path of ['/sessions.html', '/recordings.html', '/docs.html']) {
    test(`an anonymous caller gets no search on ${path}, and a stale cached index is wiped`, async ({ page }) => {
        // Answer slowly enough that the page finishes parsing (and search.js
        // runs) before the page's own 401 handling bounces it to the login page.
        const api = await installApi(page, { routes: { 'GET /api/me': async () => {
            await new Promise(r => setTimeout(r, 400));
            return { status: 401, contentType: 'application/json', body: '{"error":"not authenticated"}' };
        } } });
        await seedStaleCache(page);
        // The static harness bakes no role on <html>; the real server writes 0
        // for an anonymous caller, which is the case under test.
        await page.addInitScript(() => {
            document.addEventListener('DOMContentLoaded', () => { document.documentElement.setAttribute('data-role-level', '0'); document.documentElement.setAttribute('data-perms', ''); });
        });
        await page.goto(path);
        // The page itself bounces to the login page on 401; the assertions hold either side of that.
        await page.waitForTimeout(800);
        await expect(page.locator('#rg-search')).toHaveCount(0);
        await expect(page.locator('#search-overlay')).toHaveCount(0);
        expect(api.calls.some(c => c.path.startsWith('/api/addressbook'))).toBe(false);
        expect(await cacheKeys(page).catch(() => [])).toEqual([]);
    });
}

test('a viewer gets no search box', async ({ page }) => {
    const api = await installApi(page, { role: 'viewer' });
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toHaveCount(0);
    expect(api.calls.some(c => c.path.startsWith('/api/addressbook/search-index'))).toBe(false);
});

test('a cached index left by a different login is dropped, not shown', async ({ page }) => {
    await installApi(page);
    await seedStaleCache(page);
    await page.goto('/recordings.html');
    await settle(page);
    await page.locator('#rg-search').click();
    await page.keyboard.type('stale');
    await expect(page.locator('#search-results tbody tr')).toHaveCount(0);
    await page.keyboard.press('Escape');
    await page.locator('#rg-search').fill('');
    await page.locator('#rg-search').click();
    await expect(page.locator('#search-results tbody tr')).toHaveCount(TOTAL_ENTRIES);
    expect(await page.evaluate(k => sessionStorage.getItem(k), WHO_KEY)).toBe('tester@example.com|admin|everyone');
});

test('the same login keeps its cached index across pages', async ({ page }) => {
    const api = await installApi(page);
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toBeEnabled();
    const fetches = () => api.calls.filter(c => c.path === '/api/addressbook/search-index').length;
    expect(fetches()).toBe(1);
    await page.goto('/sessions.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toBeEnabled();
    expect(fetches()).toBe(1);
});

test('logging out forgets the cached index before the login page shows', async ({ page }) => {
    let signedIn = true;
    await installApi(page, { routes: { 'GET /api/me': () => signedIn
        ? { name: 'tester@example.com', role: 'admin', permissions: ROLE_PERMS.admin, groups: ['everyone'], vault_enabled: true, vault_configured: true }
        : { status: 401, contentType: 'application/json', body: '{"error":"not authenticated"}' } } });
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toBeEnabled();
    expect(await cacheKeys(page)).toEqual([IDX_KEY, VER_KEY, WHO_KEY]);
    signedIn = false;
    await page.locator('#logout-item').click();
    await page.waitForURL(/\/(index\.html)?$/);
    await settle(page);
    expect(await cacheKeys(page)).toEqual([]);
    await expect(page.locator('#rg-search')).toHaveCount(0);
});

test('a session that expires removes the box and forgets the index', async ({ page }) => {
    let expired = false;
    const gone = { status: 401, contentType: 'application/json', body: '{"error":"not authenticated"}' };
    await installApi(page, { routes: {
        'GET /api/addressbook/version': (req, url, state) => expired ? gone : { version: state.version, changed_at: 0 }
    } });
    await page.clock.install();
    await page.goto('/reports.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toBeEnabled();
    expect(await cacheKeys(page)).toEqual([IDX_KEY, VER_KEY, WHO_KEY]);
    expired = true;
    // The 30s version poll is the first request to see the 401.
    await page.clock.runFor(31_000);
    await expect(page.locator('#rg-search')).toHaveCount(0);
    await expect(page.locator('#search-overlay')).toHaveCount(0);
    expect(await cacheKeys(page)).toEqual([]);
});

test('without a change counter on the server the index is reloaded on each page, not polled', async ({ page }) => {
    const api = await installApi(page, { routes: { 'GET /api/addressbook/version': { status: 404, contentType: 'application/json', body: '{}' } } });
    await page.clock.install();
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toBeEnabled();
    const fetches = () => api.calls.filter(c => c.path === '/api/addressbook/search-index').length;
    expect(fetches()).toBe(1);
    await page.clock.runFor(65_000);
    expect(fetches()).toBe(1);                 // no 30s poll without a counter to compare
    await page.goto('/sessions.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toBeEnabled();
    expect(fetches()).toBe(2);                 // but a fresh copy on the next page
});

// The version counter starts again at 0 when the server restarts, so the same
// number can name a different address book. The cached index is keyed to the
// server process (epoch) as well, and a restart re-fetches it.
test('a server restart at the same version re-fetches the cached index', async ({ page }) => {
    let epoch = 111;
    const api = await installApi(page, { routes: {
        'GET /api/addressbook/version': () => ({ version: 1, changed_at: 0, epoch, changes: [] })
    } });
    const fetches = () => api.calls.filter(c => c.path === '/api/addressbook/search-index').length;
    await page.goto('/recordings.html');
    await settle(page);
    await expect(page.locator('#rg-search')).toBeEnabled();
    expect(fetches()).toBe(1);
    // Same process: the cache is current, nothing is fetched.
    await page.goto('/sessions.html');
    await settle(page);
    expect(fetches()).toBe(1);
    // Restarted: same version number, new epoch.
    epoch = 222;
    await page.goto('/reports.html');
    await settle(page);
    await expect.poll(fetches).toBe(2);
});
