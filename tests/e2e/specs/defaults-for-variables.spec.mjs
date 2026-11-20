// #297: a folder's default credentials can also cover entries that use
// credential variables when the user has set none of them. The folder editor
// has a switch per type; an entry covered by it is marked [folder] and is not
// flagged "credentials needed".
import { test, expect } from '@playwright/test';
import { installApi, settle, entry, folder } from '../lib/api.mjs';

const varEntry = (fallback) => ({
    ...entry('srv01', 'rdp', { username: '$acme_username', has_credentials: true }),
    credential_variables: ['acme_username', 'acme_password'],
    ...(fallback ? { variables_fallback: true } : {})
});

test('an entry covered by folder defaults is connectable, one that is not needs credentials', async ({ page }) => {
    await installApi(page, { role: 'operator', folders: [
        folder('acme', { entries: [varEntry(true)] }),
        folder('beta', { entries: [{ ...varEntry(false), name: 'srv02' }] })
    ] });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
    const covered = page.locator('.main .entries-table tbody tr').filter({ hasText: 'srv01' });
    await expect(covered).toContainText('[folder]');
    await expect(covered).not.toContainText('credentials needed');
    await page.locator('.folder-row').filter({ hasText: /beta/ }).first().click();
    const needs = page.locator('.main .entries-table tbody tr').filter({ hasText: 'srv02' });
    await expect(needs).toContainText('credentials needed');
});

test('the folder editor shows and sends the switch per type', async ({ page }) => {
    const api = await installApi(page, {
        role: 'admin',
        routes: {
            'GET /api/addressbook/folders/shared/beta/defaults': { defaults: {
                rdp: { username: 'svc', domain: 'ACME', has_password: true, has_private_key: false, cover_variables: false }
            } },
            'PUT /api/addressbook/folders/shared/beta/defaults': { ok: true, defaults: {} }
        }
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /beta/ }).first().click();
    await page.locator('#btn-edit-folder').click();
    const cover = page.locator('#fm-defaults-rows tr[data-type="rdp"] .fmd-cover');
    await expect(cover).not.toBeChecked();
    await cover.check();
    await page.locator('#folder-modal button[type="submit"], #folder-modal .btn-primary, #fm-save').first().click();
    await expect.poll(() => api.calls.find(c => c.method === 'PUT' && /\/folders\/shared\/beta\/defaults$/.test(c.path))?.body)
        .toEqual({ rdp: { cover_variables: true } });
});
