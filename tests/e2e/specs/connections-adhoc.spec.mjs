// #295: ad-hoc connections use the Connections entry editor. "Connect to a
// host" (search.js, beside the search box) opens it here with no name or
// folder and Connect in place of Save;
// it sends the entry to POST /api/addressbook/adhoc/connect, never to
// /api/sessions. Non-admins do not see the options only a saved entry may
// set; admins can save what they filled in as an entry.
import { test, expect } from '@playwright/test';
import { installApi, settle, ROLE_PERMS } from '../lib/api.mjs';

const MY_CREDS = {
    credentials: {
        my_ssh_key: { masked: '****', scope: 'local' },
        my_user: { masked: 'a***', scope: 'local' }
    },
    creds_split: false,
    default_scope: 'local'
};

function adhocCalls(api) {
    return api.calls.filter(c => c.method === 'POST' && c.path === '/api/addressbook/adhoc/connect');
}

async function openEditor(page) {
    await page.locator('#rg-adhoc').click();
    const modal = page.locator('#entry-modal');
    await expect(modal).toHaveClass(/active/);
    await expect(modal).toHaveClass(/adhoc/);
    return modal;
}

test('a poweruser connects to a host with one of their own credential variables', async ({ page }) => {
    const api = await installApi(page, { role: 'poweruser', routes: { 'GET /api/me/credentials': MY_CREDS } });
    await page.goto('/connections.html');
    await settle(page);

    await expect(page.locator('#rg-adhoc')).toBeVisible();
    const modal = await openEditor(page);
    await expect(page.locator('#entry-modal-title')).toHaveText('Connect to a host');

    // No name, display name or Save; Connect instead.
    await expect(page.locator('#em-name')).toBeHidden();
    await expect(page.locator('#em-display-name')).toBeHidden();
    await expect(page.locator('#em-save')).toBeHidden();
    await expect(page.locator('#em-connect')).toBeVisible();
    await expect(page.locator('#em-saveas')).toBeHidden();

    // Entry-only options are not offered to a poweruser.
    await expect(page.locator('#em-ssh-prompt-creds')).toBeHidden();
    await expect(page.locator('#em-allow-sharing')).toBeHidden();
    await expect(page.locator('#em-auto-open-singleton')).toBeHidden();
    await expect(page.locator('#em-wol-section')).toBeHidden();
    await page.locator('#em-recording-toggle').click();
    await page.locator('#em-override-recording').check();
    await expect(page.locator('#em-enable-recording')).toBeVisible();
    await expect(page.locator('#em-max-recordings')).toBeHidden();
    await expect(page.locator('#em-typescript-row')).toBeHidden();
    // What a caller may choose stays, including options the old form lacked.
    await expect(page.locator('#em-ssh-font-size')).toBeVisible();
    await expect(page.locator('#em-disable-copy')).toBeVisible();
    await expect(page.locator('#em-ssh-generate-keypair')).toBeVisible();
    await page.locator('#em-type').selectOption('vdi');
    await expect(page.locator('#em-vdi-cpu')).toBeVisible();
    await expect(page.locator('#em-vdi-container-username')).toBeHidden();
    await page.locator('#em-type').selectOption('spice');
    await expect(page.locator('#em-spice-hostname')).toBeVisible();
    await expect(page.locator('#em-spice-prompt-creds')).toBeHidden();
    await page.locator('#em-type').selectOption('ssh');

    // The caller's variable names are offered: a picker for the key, a
    // datalist for the username. Values never reach the page.
    await expect(page.locator('#em-cred-vars option')).toHaveCount(2);
    await expect(page.locator('#em-username')).toHaveAttribute('list', 'em-cred-vars');
    const keyPick = page.locator('select.var-pick[data-for="em-private-key"]');
    await expect(keyPick).toBeVisible();
    await keyPick.selectOption('my_ssh_key');
    await expect(page.locator('#em-private-key')).toHaveValue('$my_ssh_key');

    await page.locator('#em-hostname').fill('10.0.0.5');
    await page.locator('#em-username').fill('$my_user');
    await page.locator('#em-ssh-font-size').fill('16');

    const [popup] = await Promise.all([
        page.waitForEvent('popup'),
        page.locator('#em-connect').click()
    ]);
    await expect.poll(() => adhocCalls(api).length).toBe(1);
    const sent = adhocCalls(api)[0].body;
    expect(sent.entry).toMatchObject({
        type: 'ssh', hostname: '10.0.0.5', port: 22, username: '$my_user',
        private_key: '$my_ssh_key', ssh_font_size: 16
    });
    expect(sent.entry.name).toBeUndefined();
    expect(sent.width).toBe(page.viewportSize().width);
    expect(sent.dpi).toBeGreaterThan(0);
    expect(api.calls.some(c => c.method === 'POST' && c.path === '/api/sessions')).toBe(false);
    await expect.poll(() => popup.url()).toContain('/client.html?session=4444');
    await expect(modal).not.toHaveClass(/active/);
    await popup.close();
});

test('the ephemeral keypair replaces the password and key', async ({ page }) => {
    const api = await installApi(page, { role: 'poweruser' });
    await page.goto('/connections.html');
    await settle(page);
    await openEditor(page);
    await page.locator('#em-hostname').fill('10.0.0.6');
    await page.locator('#em-password').fill('typed');
    await page.locator('#em-ssh-generate-keypair').check();
    await expect(page.locator('#em-password')).toBeDisabled();
    await expect(page.locator('#em-private-key')).toBeDisabled();
    const [popup] = await Promise.all([
        page.waitForEvent('popup'),
        page.locator('#em-connect').click()
    ]);
    await expect.poll(() => adhocCalls(api).length).toBe(1);
    const sent = adhocCalls(api)[0].body;
    expect(sent.generate_keypair).toBe(true);
    expect(sent.entry.password).toBeUndefined();
    expect(sent.entry.private_key).toBeUndefined();
    await popup.close();
});

test('a missing credential variable is named and nothing opens', async ({ page }) => {
    await installApi(page, {
        role: 'poweruser',
        routes: {
            'POST /api/addressbook/adhoc/connect': {
                status: 412, contentType: 'application/json',
                body: JSON.stringify({ error: 'missing credential variables', missing_variables: ['nope'] })
            }
        }
    });
    await page.goto('/connections.html');
    await settle(page);
    await openEditor(page);
    await page.locator('#em-hostname').fill('10.0.0.7');
    await page.locator('#em-password').fill('$nope');
    await page.locator('#em-connect').click();
    await expect(page.locator('#em-error')).toContainText('$nope');
    await expect(page.locator('#entry-modal')).toHaveClass(/active/);
});

test('an admin sees every option and can save the connection as an entry', async ({ page }) => {
    const api = await installApi(page, { role: 'admin', routes: { 'GET /api/me/credentials': MY_CREDS } });
    await page.goto('/connections.html');
    await settle(page);
    await openEditor(page);
    await expect(page.locator('#em-ssh-prompt-creds')).toBeVisible();
    await expect(page.locator('#em-allow-sharing')).toBeVisible();
    await expect(page.locator('#em-wol-section')).toBeVisible();
    await expect(page.locator('#em-name')).toBeHidden();
    await expect(page.locator('#em-saveas')).toBeVisible();

    await page.locator('#em-hostname').fill('10.0.0.8');
    await page.locator('select.var-pick[data-for="em-private-key"]').selectOption('my_ssh_key');
    await page.locator('#em-saveas-folder').selectOption('shared|beta');
    await page.locator('#em-saveas-name').fill('bad name');
    await page.locator('#em-saveas').click();
    await expect(page.locator('#em-error')).toContainText('Name must be');

    await page.locator('#em-saveas-name').fill('db02');
    await page.locator('#em-saveas').click();
    const create = () => api.calls.find(c => c.method === 'POST' && c.path === '/api/addressbook/folders/shared/beta/entries');
    await expect.poll(create).toBeTruthy();
    // The reference is saved, not a value.
    expect(create().body).toMatchObject({ name: 'db02', type: 'ssh', hostname: '10.0.0.8', private_key: '$my_ssh_key' });
    await expect(page.locator('#entry-modal')).not.toHaveClass(/active/);
    expect(adhocCalls(api)).toHaveLength(0);
});

test('the normal entry editor is unchanged after an ad-hoc connection', async ({ page }) => {
    await installApi(page, { role: 'admin' });
    await page.goto('/connections.html');
    await settle(page);
    await openEditor(page);
    await page.locator('#em-cancel').click();
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
    await page.locator('#btn-new-entry').click();
    const modal = page.locator('#entry-modal');
    await expect(modal).toHaveClass(/active/);
    await expect(modal).not.toHaveClass(/adhoc/);
    await expect(page.locator('#em-name')).toBeVisible();
    await expect(page.locator('#em-save')).toBeVisible();
    await expect(page.locator('#em-connect')).toBeHidden();
    await expect(page.locator('#em-ssh-generate-keypair')).toBeHidden();
    await expect(page.locator('#em-username')).not.toHaveAttribute('list', /.+/);
});

test('without Vault the button and #adhoc still work', async ({ page }) => {
    const api = await installApi(page, {
        role: 'poweruser',
        routes: {
            'GET /api/me': { name: 'pu@example.com', role: 'poweruser', permissions: ROLE_PERMS.poweruser, groups: [], vault_enabled: false, vault_configured: false }
        }
    });
    await page.goto('/connections.html#adhoc');
    await settle(page);
    await expect(page.locator('#no-vault')).toBeVisible();
    await expect(page.locator('#rg-adhoc')).toBeVisible();
    await expect(page.locator('#entry-modal')).toHaveClass(/adhoc/);
    await expect(page.locator('#entry-modal')).toHaveClass(/active/);
    await expect(page.locator('#em-saveas')).toBeHidden();
    // No variables to suggest, so the pickers stay away.
    await expect(page.locator('select.var-pick[data-for="em-private-key"]')).toBeHidden();
    expect(api.calls.some(c => c.path === '/api/me/credentials')).toBe(false);
    expect(new URL(page.url()).hash).toBe('');
});

test('an operator gets no button and #adhoc opens nothing', async ({ page }) => {
    await installApi(page, { role: 'operator' });
    await page.goto('/connections.html#adhoc');
    await settle(page);
    await expect(page.locator('#rg-adhoc')).toBeHidden();
    await expect(page.locator('#entry-modal')).not.toHaveClass(/active/);
});

// A poweruser's ad-hoc request can't turn on a drive the site has off, and
// VDI limits above the site defaults are capped: the editor must not offer
// what the server will silently drop.
test('a poweruser is not offered file transfer when the site has it off', async ({ page }) => {
    const status = (drive_enabled) => ({
        oidc_enabled: false, drive_configured: true, drive_enabled, theme: 'dark'
    });
    await installApi(page, { role: 'poweruser', routes: { 'GET /api/auth/status': status(false) } });
    await page.goto('/connections.html');
    await settle(page);
    await openEditor(page);
    await page.locator('#em-type').selectOption('ssh');
    await expect(page.locator('#em-drive-section')).toBeHidden();
    await page.locator('#em-type').selectOption('vdi');
    await expect(page.getByText('above the site\'s defaults are capped')).toBeVisible();
});

test('file transfer is offered when the site has it on, and always to admins', async ({ page }) => {
    for (const [role, drive_enabled] of [['poweruser', true], ['admin', false]]) {
        await page.unrouteAll({ behavior: 'ignoreErrors' });
        await installApi(page, { role, routes: { 'GET /api/auth/status': {
            oidc_enabled: false, drive_configured: true, drive_enabled, theme: 'dark'
        } } });
        await page.goto('/connections.html');
        await settle(page);
        await openEditor(page);
        await page.locator('#em-type').selectOption('ssh');
        await expect(page.locator('#em-drive-section'), `${role}, drive_enabled=${drive_enabled}`).toBeVisible();
        if (role === 'admin') await expect(page.getByText('above the site\'s defaults are capped')).toBeHidden();
    }
});

// VNC display resize is off unless asked: a physical console can't resize,
// and the session stalls if it is asked to.
test('VNC asks the server to resize only when the box is ticked', async ({ page }) => {
    const api = await installApi(page, { role: 'poweruser' });
    await page.goto('/connections.html');
    await settle(page);
    for (const tick of [false, true]) {
        await openEditor(page);
        await page.locator('#em-type').selectOption('vnc');
        const box = page.locator('#em-vnc-resize');
        await expect(box).toBeVisible();
        await expect(box).not.toBeChecked();
        if (tick) await box.check();
        await page.locator('#em-vnc-hostname').fill('192.0.2.20');
        const before = adhocCalls(api).length;
        await Promise.all([page.waitForEvent('popup'), page.locator('#em-connect').click()]);
        await expect.poll(() => adhocCalls(api).length).toBe(before + 1);
        const sent = adhocCalls(api)[before].body.entry;
        expect(sent.type).toBe('vnc');
        if (tick) expect(sent.vnc_resize).toBe(true);
        else expect(sent.vnc_resize).toBeUndefined();
    }
});

// The VNC network preset is sent only when one is picked.
test('a VNC network preset is sent when chosen, and nothing for Auto', async ({ page }) => {
    const api = await installApi(page, { role: 'poweruser' });
    await page.goto('/connections.html');
    await settle(page);
    for (const preset of ['', 'slow']) {
        await openEditor(page);
        await page.locator('#em-type').selectOption('vnc');
        await expect(page.locator('#em-vnc-network')).toHaveValue('');
        if (preset) await page.locator('#em-vnc-network').selectOption(preset);
        await page.locator('#em-vnc-hostname').fill('192.0.2.21');
        const before = adhocCalls(api).length;
        await Promise.all([page.waitForEvent('popup'), page.locator('#em-connect').click()]);
        await expect.poll(() => adhocCalls(api).length).toBe(before + 1);
        const sent = adhocCalls(api)[before].body.entry;
        if (preset) expect(sent.vnc_network).toBe(preset);
        else expect(sent.vnc_network).toBeUndefined();
    }
});
