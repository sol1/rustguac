// #334: Terminate all on Connections' Active Sessions ends every session in
// the list after one confirmation, and only those: the list is the caller's
// own sessions (GET /api/sessions without ?all).
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const mine = (id, name, status = 'active') => ({
    session_id: id, session_type: 'ssh', status, hostname: name, username: 'root',
    entry_display_name: name, active_connections: 1, created_by: 'tester@example.com',
    thumbnail_url: '', client_url: '/client/' + id,
});

test('Terminate all ends every listed session after one confirmation', async ({ page }) => {
    const api = await installApi(page, { role: 'operator', sessions: [
        mine('11111111-1111-4111-8111-111111111111', 'web01'),
        mine('22222222-2222-4222-8222-222222222222', 'web02', 'pending'),
        mine('33333333-3333-4333-8333-333333333333', 'old', 'completed'),
    ] });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('#btn-active-sessions').click();
    const btn = page.locator('#btn-terminate-all');
    await expect(btn).toBeVisible();

    await btn.click();
    await expect(page.locator('#rg-dialog-overlay')).toContainText('all 2 of your sessions');
    await page.locator('#rg-dialog-overlay').getByRole('button', { name: 'Terminate all' }).click();

    await expect.poll(() => api.calls.filter(c => c.method === 'DELETE').map(c => c.path).sort()).toEqual([
        '/api/sessions/11111111-1111-4111-8111-111111111111',
        '/api/sessions/22222222-2222-4222-8222-222222222222',
    ]);
});

test('Terminate all is hidden with fewer than two sessions', async ({ page }) => {
    await installApi(page, { role: 'operator', sessions: [mine('11111111-1111-4111-8111-111111111111', 'web01')] });
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('#active-sessions')).toBeVisible();
    await page.locator('#btn-active-sessions').click();
    await expect(page.locator('#active-sessions-grid .session-card')).toHaveCount(1);
    await expect(page.locator('#btn-terminate-all')).toBeHidden();
});
