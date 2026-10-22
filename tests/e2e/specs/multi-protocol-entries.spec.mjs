// #296: an entry can offer several protocols. The list shows one row per
// host with a badge for every protocol (wrapping, none hidden),
// Connect opens the primary and its split-button menu lists every protocol;
// the editor has a Host box and a tab per protocol, and an entry saved in
// the old single-protocol shape comes back as one protocol.
import { test, expect } from '@playwright/test';
import { installApi, settle, entry, folder } from '../lib/api.mjs';

/* As the server lists an entry to an admin: the primary's fields on top,
 * every protocol under `protocols`, each level's own fields under
 * `settings` (secrets only as has_* flags). */
function multi() {
    const rdp = entry('srv01', 'rdp', { username: 'Administrator', hostname: '10.0.0.10' });
    const ssh = entry('srv01', 'ssh', { username: 'admin', hostname: '10.0.0.10', port: 2222 });
    return {
        ...rdp,
        display_name: 'srv01 (DC1)',
        protocol: 'rdp',
        settings: { hostname: '10.0.0.10', display_name: 'srv01 (DC1)', username: 'Administrator', has_password: true },
        protocols: [
            { ...rdp, protocol: 'rdp', settings: { port: 3389 } },
            { ...ssh, protocol: 'ssh', settings: { port: 2222, username: 'admin' } }
        ]
    };
}

function legacy() {
    const e = entry('web01', 'ssh', { username: 'root', hostname: 'web01.acme.internal' });
    return {
        ...e,
        protocol: 'ssh',
        settings: { hostname: 'web01.acme.internal', banner: 'Authorised use only' },
        protocols: [{ ...e, protocol: 'ssh', settings: { port: 22, username: 'root', has_password: true } }]
    };
}

/* The worst case: one host with every type, two of them SSH. */
function everything() {
    const types = [
        ['ssh', 'ssh', { port: 22 }], ['ssh', 'ssh-2222', { port: 2222 }], ['rdp', 'rdp', { port: 3389 }],
        ['vnc', 'vnc', { port: 5900 }], ['spice', 'spice', { port: 5901 }],
        ['proxmox', 'proxmox', { fields: { proxmox_url: 'https://pve.example.com:8006', proxmox_vmid: 100 } }],
        ['web', 'web', { url: 'https://10.0.0.20:8443/' }], ['vdi', 'vdi', { fields: { container_image: 'example/desktop:latest' } }]
    ];
    const ps = types.map(([t, name, extra]) => ({
        ...entry('allinone', t, { hostname: '10.0.0.20', ...extra }), protocol: name, settings: {}
    }));
    return { ...ps[0], display_name: 'allinone (lab)', protocol: 'ssh', settings: { hostname: '10.0.0.20' }, protocols: ps };
}

function folders() {
    return [folder('acme', { entries: [multi(), legacy(), entry('portal', 'web'), everything()] })];
}

async function openAcme(page) {
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
    await expect(page.locator('#entries-title')).toHaveText('acme');
}

const row = (page, name) => page.locator('.entries-table tbody tr').filter({ hasText: name });

test('one row per host, a badge per protocol, the menu connects with the chosen one', async ({ page }) => {
    const api = await installApi(page, { folders: folders() });
    await openAcme(page);
    const r = row(page, 'srv01');
    await expect(r).toHaveCount(1);
    await expect(r.locator('.type-cell .type-badge')).toHaveText(['RDP', 'SSH']);
    await expect(r.locator('.type-cell .type-badge').first()).toHaveClass(/proto-primary/);

    // Connect: the primary.
    await r.locator('.split-main').click();
    const sent = () => api.calls.filter(c => c.method === 'POST' && /srv01\/connect$/.test(c.path)).map(c => c.body.protocol);
    await expect.poll(sent).toEqual(['rdp']);

    // The menu lists every protocol, the primary first and marked default,
    // with its port.
    await r.locator('[data-proto-toggle]').click();
    const items = r.locator('.proto-menu-list [role="menuitem"]');
    await expect(items).toHaveCount(2);
    await expect(items.nth(0)).toContainText('RDP');
    await expect(items.nth(0).locator('.pi-default')).toHaveText('default');
    await expect(items.nth(0).locator('.pi-port')).toHaveText(':3389');
    await expect(items.nth(1).locator('.pi-default')).toHaveCount(0);
    await expect(items.nth(1).locator('.pi-port')).toHaveText(':2222');
    await items.nth(1).click();
    await expect.poll(sent).toEqual(['rdp', 'ssh']);
    await expect(r.locator('.proto-menu-list')).toBeHidden();

    // A single-protocol entry has a plain Connect and no menu.
    const web = row(page, 'web01');
    await expect(web.locator('[data-proto-toggle]')).toHaveCount(0);
    await expect(web.locator('.split-btn')).toHaveCount(0);
});

test('Connect and the menu toggle are one split button, the new-window button after it', async ({ page }) => {
    await installApi(page, { folders: folders() });
    await openAcme(page);
    const r = row(page, 'srv01');
    const main = await r.locator('.split-main').boundingBox();
    const toggle = await r.locator('.split-toggle').boundingBox();
    const win = await r.locator('.btn-connect-win').boundingBox();
    expect(Math.abs(toggle.x - (main.x + main.width)), 'no gap between Connect and the toggle').toBeLessThanOrEqual(1);
    expect(Math.abs(toggle.height - main.height)).toBeLessThanOrEqual(1);
    expect(Math.abs(toggle.y - main.y)).toBeLessThanOrEqual(1);
    expect(win.x, 'the new-window button follows the split button').toBeGreaterThanOrEqual(toggle.x + toggle.width);
    const radii = await r.locator('.split-btn').evaluate(el => {
        const m = getComputedStyle(el.querySelector('.split-main'));
        const t = getComputedStyle(el.querySelector('.split-toggle'));
        return [m.borderTopRightRadius, m.borderBottomRightRadius, t.borderTopLeftRadius, t.borderBottomLeftRadius];
    });
    expect(radii).toEqual(['0px', '0px', '0px', '0px']);
});

test('the protocol menu works from the keyboard and closes on an outside click', async ({ page }) => {
    const api = await installApi(page, { folders: folders() });
    await openAcme(page);
    const r = row(page, 'srv01');
    const toggle = r.locator('[data-proto-toggle]');
    const menu = r.locator('.proto-menu-list');
    await toggle.focus();
    await page.keyboard.press('Enter');
    await expect(menu).toBeVisible();
    await expect(toggle).toHaveAttribute('aria-expanded', 'true');
    const items = menu.locator('[role="menuitem"]');
    await expect(items.nth(0)).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(items.nth(1)).toBeFocused();
    await page.keyboard.press('ArrowDown');
    await expect(items.nth(0)).toBeFocused(); // wraps
    await page.keyboard.press('Escape');
    await expect(menu).toBeHidden();
    await expect(toggle).toBeFocused();
    await expect(page.locator('#entry-modal')).not.toHaveClass(/active/);

    // Space opens it too, and Enter on an item connects with it.
    await page.keyboard.press(' ');
    await expect(menu).toBeVisible();
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await expect.poll(() => api.calls.filter(c => c.method === 'POST' && /srv01\/connect$/.test(c.path)).map(c => c.body.protocol))
        .toEqual(['ssh']);
    await expect(menu).toBeHidden();
    await expect(toggle).toBeFocused();

    // An outside click closes it.
    await toggle.click();
    await expect(menu).toBeVisible();
    await page.locator('#entries-title').click();
    await expect(menu).toBeHidden();
});

for (const [label, viewport] of [['wide', { width: 1710, height: 1112 }], ['1180px', { width: 1180, height: 820 }], ['phone', { width: 390, height: 844 }]]) {
    test(`eight protocols all show in the Type column (${label})`, async ({ page }) => {
        await page.setViewportSize(viewport);
        await installApi(page, { folders: folders() });
        await openAcme(page);
        const r = row(page, 'allinone');
        const cell = r.locator('.type-cell');
        const box = cell.locator('.proto-badges');
        // The primary first and marked, then every other protocol: none is
        // hidden behind a chip, the cell wraps onto more lines instead.
        await expect(box.locator('.type-badge').first()).toHaveText('SSH');
        await expect(box.locator('.type-badge').first()).toHaveClass(/proto-primary/);
        await expect(box.locator('.type-badge:visible')).toHaveCount(8);
        await expect(box.locator('.type-badge').nth(1)).toHaveText('ssh-2222');
        // Every badge sits inside the box, and the box inside the cell.
        const b = await box.boundingBox();
        const kids = await box.evaluate(el => Array.from(el.children)
            .map(c => { const k = c.getBoundingClientRect(); return [k.top, k.bottom, k.right]; }));
        const p = await box.evaluate(el => { const k = el.getBoundingClientRect(); return [k.top, k.bottom, k.right]; });
        for (const [t, bot, right] of kids) {
            expect(t).toBeGreaterThanOrEqual(p[0] - 0.5);
            expect(bot).toBeLessThanOrEqual(p[1] + 0.5);
            expect(right).toBeLessThanOrEqual(p[2] + 0.5);
        }
        // More than one line of badges: the row grows rather than hiding any.
        const tops = new Set(kids.map(([t]) => Math.round(t)));
        expect(tops.size, 'eight badges wrap').toBeGreaterThan(1);
        // Nothing spills into the Host column.
        const typeRight = (await cell.boundingBox());
        const host = await cell.locator('xpath=following-sibling::td[1]').boundingBox();
        expect(b.x + b.width).toBeLessThanOrEqual(host.x + 0.5);
        expect(typeRight.x + typeRight.width).toBeLessThanOrEqual(host.x + 0.5);
        // The menu lists all eight, inside the viewport.
        await r.locator('[data-proto-toggle]').click();
        const menu = r.locator('.proto-menu-list');
        await expect(menu.locator('[role="menuitem"]')).toHaveCount(8);
        await expect(menu.locator('[role="menuitem"]').nth(1)).toContainText('ssh-2222');
        const m = await menu.boundingBox();
        expect(m.x).toBeGreaterThanOrEqual(0);
        expect(m.y).toBeGreaterThanOrEqual(0);
        expect(m.x + m.width).toBeLessThanOrEqual(viewport.width + 0.5);
        expect(m.y + m.height).toBeLessThanOrEqual(viewport.height + 0.5);
    });
}

test('the menu stays inside the viewport near the bottom edge', async ({ page }) => {
    await page.setViewportSize({ width: 1180, height: 560 });
    await installApi(page, { folders: folders() });
    await openAcme(page);
    const r = row(page, 'allinone');
    await r.scrollIntoViewIfNeeded();
    await r.locator('[data-proto-toggle]').click();
    const m = await r.locator('.proto-menu-list').boundingBox();
    expect(m.y).toBeGreaterThanOrEqual(0);
    expect(m.y + m.height).toBeLessThanOrEqual(560.5);
    expect(m.x + m.width).toBeLessThanOrEqual(1180.5);
});

test('editing an old single-protocol entry saves it as one protocol, host fields on the host', async ({ page }) => {
    const api = await installApi(page, { folders: folders() });
    await openAcme(page);
    await page.locator('button[data-edit-entry="web01"]').click();
    await expect(page.locator('#entry-modal')).toHaveClass(/active/);
    await expect(page.locator('#em-host-hostname')).toHaveValue('web01.acme.internal');
    await expect(page.locator('#em-proto-tabs .em-proto-tab')).toHaveText(['★ ssh', '+ Add protocol']);
    // The protocol inherits the hostname; its own password stays stored.
    await expect(page.locator('#em-hostname')).toHaveValue('');
    await expect(page.locator('#em-hostname')).toHaveAttribute('placeholder', 'Host: web01.acme.internal');
    await expect(page.locator('#em-password')).toHaveAttribute('placeholder', '(stored, leave blank to keep)');
    await expect(page.locator('#em-username')).toHaveValue('root');
    await page.locator('#em-save').click();
    await expect.poll(() => api.calls.find(c => c.method === 'PUT' && /entries\/web01$/.test(c.path))).toBeTruthy();
    const body = api.calls.find(c => c.method === 'PUT' && /entries\/web01$/.test(c.path)).body;
    expect(body.hostname).toBe('web01.acme.internal');
    expect(body.banner).toBe('Authorised use only');
    expect(body.type).toBeUndefined();
    expect(body.protocols).toHaveLength(1);
    expect(body.protocols[0]).toMatchObject({ type: 'ssh', port: 22, username: 'root' });
    // No secret is sent back, and nothing the host holds is copied down.
    expect(body.protocols[0].password).toBeUndefined();
    expect(body.protocols[0].hostname).toBeUndefined();
    expect(body.protocols[0].banner).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('has_password');
});

test('adding a protocol and making it primary', async ({ page }) => {
    const api = await installApi(page, { folders: folders() });
    await openAcme(page);
    await page.locator('button[data-edit-entry="web01"]').click();
    await page.locator('#em-proto-add').click();
    await expect(page.locator('#em-type')).toHaveValue('rdp');
    await expect(page.locator('#em-type')).toBeEnabled();
    await page.locator('#em-rdp-port').fill('3390');
    await page.locator('#em-proto-primary').click();
    await expect(page.locator('#em-proto-tabs .em-proto-tab')).toHaveText(['★ rdp', 'ssh', '+ Add protocol']);
    await page.locator('#em-save').click();
    await expect.poll(() => api.calls.find(c => c.method === 'PUT' && /entries\/web01$/.test(c.path))).toBeTruthy();
    const body = api.calls.find(c => c.method === 'PUT' && /entries\/web01$/.test(c.path)).body;
    expect(body.protocols.map(p => p.type)).toEqual(['rdp', 'ssh']);
    expect(body.protocols[0]).toMatchObject({ type: 'rdp', port: 3390 });
});

test('the multi-protocol editor loads each protocol with the host as its defaults', async ({ page }) => {
    await installApi(page, { folders: folders() });
    await openAcme(page);
    await page.locator('button[data-edit-entry="srv01"]').click();
    await expect(page.locator('#em-host-username')).toHaveValue('Administrator');
    await expect(page.locator('#em-host-password')).toHaveAttribute('placeholder', '(stored, leave blank to keep)');
    await expect(page.locator('#em-rdp-username')).toHaveValue('');
    await expect(page.locator('#em-rdp-username')).toHaveAttribute('placeholder', 'Host: Administrator');
    await page.locator('#em-proto-tabs [data-proto-tab="1"]').click();
    await expect(page.locator('#em-type')).toHaveValue('ssh');
    await expect(page.locator('#em-username')).toHaveValue('admin');
    await expect(page.locator('#em-port')).toHaveValue('2222');
});

test('the Type filter matches any of an entry\'s protocols', async ({ page }) => {
    await installApi(page, { folders: folders() });
    await openAcme(page);
    const rows = page.locator('.entries-table tbody tr');
    await expect(rows).toHaveCount(4);
    await page.locator('#entries-filters button').filter({ hasText: 'Type' }).first().click();
    await page.locator('#entries-filters').getByText('rdp', { exact: true }).first().click();
    await expect(rows).toHaveCount(2);
    await expect(rows.filter({ hasText: 'srv01' })).toHaveCount(1);
});
