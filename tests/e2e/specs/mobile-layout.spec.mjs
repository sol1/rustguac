// #306: on a 390px phone every page must fit the screen. The nav folds
// behind a Menu button with a proper disclosure, the Connections folder tree
// folds into a panel above the entries, list tables scroll inside their own
// box instead of widening the page, and Connect is on screen and big enough
// to tap. Above the breakpoint none of this shows.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const PHONE = { viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true };
const NAV_PAGES = ['/connections.html', '/sessions.html', '/recordings.html', '/reports.html', '/tokens.html', '/admin.html', '/docs.html'];

async function noHorizontalOverflow(page) {
    const m = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth
    }));
    expect(m.scrollWidth, 'the page must not scroll sideways').toBeLessThanOrEqual(m.clientWidth);
}

async function insideViewport(page, locator, what) {
    const box = await locator.boundingBox();
    expect(box, `${what} must be laid out`).not.toBeNull();
    expect(box.x, `${what} left edge`).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width, `${what} right edge`).toBeLessThanOrEqual(page.viewportSize().width + 0.5);
    return box;
}

test.describe('phone', () => {
    test.use(PHONE);

    for (const path of NAV_PAGES) {
        test(`${path}: fits the screen, nav behind a Menu button`, async ({ page }) => {
            await installApi(page);
            await page.goto(path);
            await settle(page);
            await noHorizontalOverflow(page);

            const nav = page.locator('body > nav');
            const toggle = page.locator('.nav-toggle');
            await expect(toggle).toBeVisible();
            await expect(toggle).toHaveAttribute('aria-expanded', 'false');
            await expect(toggle).toHaveAttribute('aria-controls', await nav.getAttribute('id'));
            await expect(nav).toBeHidden();

            await toggle.click();
            await expect(toggle).toHaveAttribute('aria-expanded', 'true');
            await expect(nav.locator('a', { hasText: 'Recordings' })).toBeVisible();
            const link = await insideViewport(page, nav.locator('a', { hasText: 'Recordings' }), 'a nav link');
            expect(link.height, 'a nav link is a comfortable tap target').toBeGreaterThanOrEqual(44);
            await noHorizontalOverflow(page);

            await page.keyboard.press('Escape');
            await expect(nav).toBeHidden();
            await expect(toggle).toHaveAttribute('aria-expanded', 'false');
            await expect(toggle).toBeFocused();
        });
    }

    test('the open menu keeps the role gate', async ({ page }) => {
        await installApi(page, { role: 'viewer' });
        await page.goto('/recordings.html');
        await settle(page);
        await page.locator('.nav-toggle').click();
        const nav = page.locator('body > nav');
        await expect(nav.locator('a', { hasText: 'Connections' })).toBeVisible();
        for (const gated of ['Sessions', 'Reports', 'Tokens', 'Admin']) {
            await expect(nav.locator('a', { hasText: gated }), `${gated} stays hidden from a viewer`).toBeHidden();
        }
    });

    test('connections: folders fold above the entries, Connect is on screen', async ({ page }) => {
        await installApi(page);
        await page.goto('/connections.html');
        await settle(page);
        await noHorizontalOverflow(page);

        const toggle = page.locator('#folders-toggle');
        const list = page.locator('#folder-list');
        await expect(toggle).toBeVisible();
        await expect(toggle).toHaveAttribute('aria-expanded', 'false');
        await expect(list).toBeHidden();

        await toggle.click();
        await expect(toggle).toHaveAttribute('aria-expanded', 'true');
        await expect(list).toBeVisible();
        // The panel sits above the entries, not beside them.
        const panel = await page.locator('.layout > .sidebar').boundingBox();
        const main = await page.locator('.layout > .main').boundingBox();
        expect(main.y).toBeGreaterThanOrEqual(panel.y + panel.height - 0.5);

        // Picking a folder folds the panel and shows that folder's entries.
        await page.locator('.folder-row').filter({ hasText: /beta/ }).first().click();
        await expect(page.locator('#entries-title')).toHaveText(/beta/);
        await expect(list).toBeHidden();
        await expect(toggle).toHaveAttribute('aria-expanded', 'false');

        const connect = page.locator('.entries-table tbody tr').first().locator('.connect-cell .btn-connect').first();
        await connect.scrollIntoViewIfNeeded();
        const box = await insideViewport(page, connect, 'Connect');
        expect(box.height, 'Connect is a comfortable tap target').toBeGreaterThanOrEqual(44);
        await noHorizontalOverflow(page);
    });

    test('connections: the entry editor fits the screen', async ({ page }) => {
        await installApi(page);
        await page.goto('/connections.html');
        await settle(page);
        await page.locator('#btn-new-entry').click();
        const modal = page.locator('#entry-modal .modal');
        await expect(modal).toBeVisible();
        const box = await insideViewport(page, modal, 'the entry editor');
        expect(box.height).toBeLessThanOrEqual(page.viewportSize().height);
    });

    for (const [path, rows, table] of [
        ['/recordings.html', '#recording-list tbody tr', '#recording-list table'],
        ['/reports.html', '#history-body tr', '#history-table'],
        ['/sessions.html', '#session-list tr', '#sessions table']
    ]) {
        test(`${path}: the table scrolls inside its own box`, async ({ page }) => {
            await installApi(page);
            await page.goto(path);
            await settle(page);
            await expect(page.locator(rows).first()).toBeVisible();
            await insideViewport(page, page.locator(table), 'the table box');
            const m = await page.locator(table).evaluate(t => ({ sw: t.scrollWidth, cw: t.clientWidth, ox: getComputedStyle(t).overflowX }));
            expect(m.ox).toBe('auto');
            expect(m.sw, 'the rows are wider than the box and scroll').toBeGreaterThan(m.cw);
            await noHorizontalOverflow(page);
        });
    }
});

test('desktop: no Menu or Folders button, the nav and folder tree stay put', async ({ page }) => {
    await installApi(page);
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('.nav-toggle')).toBeHidden();
    await expect(page.locator('#folders-toggle')).toBeHidden();
    await expect(page.locator('body > nav a', { hasText: 'Recordings' })).toBeVisible();
    await expect(page.locator('#folder-list')).toBeVisible();
});
