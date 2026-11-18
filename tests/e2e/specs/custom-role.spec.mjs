// #294: pages follow the caller's permissions, not a role ladder. A custom
// "connection editor" (connections.connect + connections.edit, no admin.*)
// gets the editing controls on Connections, but not the Admin link, and
// the folder form says who can open a folder is set by an administrator
// instead of offering the access fields.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

const EDITOR = ['connections.connect', 'connections.edit', 'credentials.self', 'docs.view'];

test('a connection editor can edit connections but not folder access or admin', async ({ page }) => {
    await installApi(page, { role: 'operator', routes: {
        'GET /api/me': { name: 'jon@example.com', role: 'connection-editor', roles: ['connection-editor'],
            permissions: EDITOR, groups: [], vault_enabled: true, vault_configured: true }
    } });
    await page.goto('/connections.html');
    await settle(page);
    await expect(page.locator('html')).toHaveAttribute('data-perms', EDITOR.join(' '));

    // Editing controls are there.
    await expect(page.locator('#btn-new-folder')).toBeVisible();
    // No admin.users: no Admin link. No connections.adhoc: no Sessions.
    await expect(page.locator('#admin-link')).toBeHidden();
    await expect(page.locator('#sessions-link')).toBeHidden();

    // The folder form hides the access fields and explains why.
    await page.locator('#btn-new-folder').click();
    await expect(page.locator('#fm-access-note')).toBeVisible();
    await expect(page.locator('#fm-access')).toBeHidden();
});

test('an admin gets the folder access fields', async ({ page }) => {
    await installApi(page, { role: 'admin' });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('#btn-new-folder').click();
    await expect(page.locator('#fm-access')).toBeVisible();
    await expect(page.locator('#fm-access-note')).toBeHidden();
});
