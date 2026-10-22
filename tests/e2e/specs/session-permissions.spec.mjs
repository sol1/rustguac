import { test, expect } from '@playwright/test';
import { installApi } from '../lib/api.mjs';

function gate() {
    let release;
    const promise = new Promise(resolve => { release = resolve; });
    return { promise, release };
}

const me = { name: 'tester@example.com', role: 'admin', groups: ['everyone'], vault_enabled: true };
const session = (id, owner, status = 'active') => ({
    session_id: id.repeat(8), session_type: 'rdp', hostname: 'example.internal',
    username: 'rdu-example', status, created_by: owner, active_connections: status === 'active' ? 1 : 0,
    client_url: '/client.html?session=' + id
});
const own = session('a', me.name);
const other = session('b', 'other@example.com');
const completed = session('c', 'other@example.com', 'completed');

for (const role of ['admin', 'poweruser']) {
    for (const first of ['identity', 'sessions']) {
        test(`${role}: correct actions on first render when ${first} arrives first`, async ({ page }) => {
            // The regression must resolve without the five-second poll hiding it.
            await page.addInitScript(() => {
                const original = window.setInterval;
                window.setInterval = (fn, delay, ...args) => delay === 5000 ? 0 : original(fn, delay, ...args);
            });
            const identityGate = gate(), sessionsGate = gate();
            const sessions = role === 'admin' ? [own, other, completed] : [own];
            await installApi(page, { role, routes: {
                'GET /api/me': async () => { await identityGate.promise; return { ...me, role }; },
                'GET /api/sessions': async () => { await sessionsGate.promise; return sessions; }
            } });
            await page.goto('/sessions.html', { waitUntil: 'domcontentloaded' });
            if (first === 'identity') {
                identityGate.release();
                await page.waitForFunction(() => sessionIdentityReady);
                await expect(page.locator('#session-list tr')).toHaveCount(0);
                sessionsGate.release();
            } else {
                sessionsGate.release();
                await page.waitForFunction(() => lastSessionList !== null);
                await expect(page.locator('#session-list tr')).toHaveCount(0);
                identityGate.release();
            }
            await expect(page.locator('#session-list tr')).toHaveCount(sessions.length);
            await expect(page.locator('[data-shadow]')).toHaveCount(role === 'admin' ? 2 : 0);
            await expect(page.locator('[data-delete]')).toHaveCount(sessions.length);
            await expect(page.locator('#session-list tr').first().locator('td').nth(7).locator('a')).toHaveText('open');
            await expect(page.locator('#session-list tr').first().locator('.owner-self')).toHaveText(me.name);
        });
    }
}

test('API-key identity arriving late classifies own sessions before rendering', async ({ page }) => {
    await page.addInitScript(() => sessionStorage.setItem('rustguac_api_key', 'test-key'));
    const identityGate = gate();
    await installApi(page, { sessions: [own, other], routes: {
        'GET /api/me': async () => { await identityGate.promise; return me; }
    } });
    await page.goto('/sessions.html', { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => lastSessionList !== null);
    await expect(page.locator('#session-list tr')).toHaveCount(0);
    identityGate.release();
    await expect(page.locator('#session-list tr')).toHaveCount(2);
    await expect(page.locator('#session-list tr').first().locator('[data-shadow]')).toHaveCount(0);
    await expect(page.locator('#session-list tr').first().locator('.owner-self')).toHaveText(me.name);
    await expect(page.locator('[data-shadow]')).toHaveCount(2);
});

test('failed identity lookup does not paint guessed permissions', async ({ page }) => {
    await installApi(page, { sessions: [own, other], routes: {
        'GET /api/me': { status: 500, body: '{}' }
    } });
    await page.goto('/sessions.html');
    await expect(page.locator('#error')).toHaveText('Failed to load session permissions. Please reload the page.');
    await expect(page.locator('#session-list tr')).toHaveCount(0);
});

// Connections already loads its folders after identity. Keep that ordering
// covered too, including a slow credential lookup that re-renders the entries.
for (const role of ['admin', 'operator', 'viewer']) {
    test(`Connections preserves ${role} actions with delayed identity and credentials`, async ({ page }) => {
        const identityGate = gate(), credentialsGate = gate();
        const api = await installApi(page, { role, routes: {
            'GET /api/me': async () => { await identityGate.promise; return { ...me, role }; },
            'GET /api/me/credentials': async () => { await credentialsGate.promise; return { credentials: {} }; }
        } });
        await page.goto('/connections.html', { waitUntil: 'domcontentloaded' });
        await expect.poll(() => api.calls.some(c => c.path === '/api/me')).toBe(true);
        expect(api.calls.some(c => c.path === '/api/addressbook')).toBe(false);
        identityGate.release();
        await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
        const rows = page.locator('.entries-table tbody tr');
        await expect(rows).toHaveCount(4);
        const edit = page.locator('[data-edit-entry]');
        await expect(edit).toHaveCount(role === 'admin' ? 4 : 0);
        credentialsGate.release();
        await page.waitForFunction(() => setCredVars !== null);
        await expect(rows).toHaveCount(4);
        await expect(edit).toHaveCount(role === 'admin' ? 4 : 0);
    });
}
