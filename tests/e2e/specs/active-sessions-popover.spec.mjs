// #333: Active Sessions is a button with a count that opens a panel over
// the page, so the folders and entries beneath never move.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const mine = (id, name) => ({
    session_id: id, session_type: 'ssh', status: 'active', hostname: name, username: 'root',
    entry_display_name: name, active_connections: 1, created_by: 'tester@example.com',
    thumbnail_url: '', client_url: '/client/' + id,
    share_url: '/share/' + id, share_url_readonly: '/share/' + id + '?ro=1',
});
const sessions = [
    mine('11111111-1111-4111-8111-111111111111', 'web01'),
    mine('22222222-2222-4222-8222-222222222222', 'web02'),
];

test('the button shows the count and the panel opens over the page', async ({ page }) => {
    await installApi(page, { role: 'operator', sessions });
    await page.goto('/connections.html');
    await settle(page);
    const btn = page.locator('#btn-active-sessions');
    await expect(btn).toBeVisible();
    await expect(page.locator('#active-sessions-count')).toHaveText('2');
    const panel = page.locator('#active-sessions-panel');
    await expect(panel).toBeHidden();

    const layout = page.locator('.layout');
    const before = await layout.boundingBox();
    await btn.click();
    await expect(panel).toBeVisible();
    await expect(btn).toHaveAttribute('aria-expanded', 'true');
    await expect(panel.locator('.session-card')).toHaveCount(2);
    // Nothing beneath moves, and the panel opens below the button.
    expect(await layout.boundingBox()).toEqual(before);
    const b = await btn.boundingBox();
    const p = await panel.boundingBox();
    expect(p.y).toBeGreaterThanOrEqual(b.y + b.height);
});

test('close button, Escape and an outside click each close the panel', async ({ page }) => {
    await installApi(page, { role: 'operator', sessions });
    await page.goto('/connections.html');
    await settle(page);
    const btn = page.locator('#btn-active-sessions');
    const panel = page.locator('#active-sessions-panel');

    await btn.click();
    await page.locator('#active-sessions-close').click();
    await expect(panel).toBeHidden();
    await expect(btn).toBeFocused();

    await btn.click();
    await page.keyboard.press('Escape');
    await expect(panel).toBeHidden();

    await btn.click();
    await page.mouse.click(5, 700);
    await expect(panel).toBeHidden();
});

test('a confirmation from the panel keeps it open', async ({ page }) => {
    await installApi(page, { role: 'operator', sessions });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('#btn-active-sessions').click();
    const panel = page.locator('#active-sessions-panel');
    await panel.locator('[data-terminate]').first().click();
    const dialog = page.locator('#rg-dialog-overlay');
    await expect(dialog).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(panel).toBeVisible();

    await panel.locator('[data-share-url]').first().click();
    await expect(page.locator('#share-modal')).toHaveClass(/active/);
    await page.keyboard.press('Escape');
    await expect(panel).toBeVisible();
});

test('the refresh keeps the row where it was scrolled', async ({ page }) => {
    const many = Array.from({ length: 8 }, (_, i) =>
        mine(`${i}1111111-1111-4111-8111-111111111111`, 'host' + i));
    const api = await installApi(page, { role: 'operator', sessions: many });
    await page.setViewportSize({ width: 1000, height: 800 });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('#btn-active-sessions').click();
    const grid = page.locator('#active-sessions-grid');
    await grid.evaluate(g => { g.scrollLeft = 400; });
    const fetches = () => api.calls.filter(c => c.method === 'GET' && c.path === '/api/vdi/containers').length;
    const seen = fetches();
    // Mark a card: a redraw replaces every one.
    await grid.evaluate(g => { g.firstElementChild.dataset.old = '1'; });
    await page.evaluate(() => loadActiveSessions());
    await expect.poll(fetches).toBeGreaterThan(seen);
    await expect(grid.locator('[data-old]')).toHaveCount(0);
    expect(await grid.evaluate(g => g.scrollLeft)).toBe(400);
});
