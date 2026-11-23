// #372: a folder can be moved under another parent, to the top level, or to
// a new name. The dialog asks the server for a dry run on each choice and
// shows whether who can open the folder changes before anything moves.
import { test, expect } from '@playwright/test';
import { installApi, settle, entry, folder, ROLE_PERMS } from '../lib/api.mjs';

const folders = [
    folder('devops', { allowed_groups: ['devops'] }),
    folder('software', { allowed_groups: ['software'], entries: [entry('git01', 'ssh')] }),
];

const preview = {
    subfolders: 1,
    entries: 3,
    access_before: { groups: ['software'], users: [], from: ['software'] },
    access_after: { groups: ['devops', 'software'], users: [], from: ['devops/software', 'devops'] },
    access_changes: true,
    defaults_before: [],
    defaults_after: [],
    defaults_change: false,
};

test('moving a folder under a new parent shows the access change, then moves it', async ({ page }) => {
    const api = await installApi(page, {
        role: 'admin',
        folders,
        routes: {
            'GET /api/addressbook/folder-paths': {
                folders: [{ scope: 'shared', path: 'devops' }, { scope: 'shared', path: 'software' }],
                unavailable: [],
            },
            'POST /api/addressbook/folders/shared/software/move': (req) => {
                const b = req.postDataJSON();
                const to = { scope: 'shared', folder: b.target_parent ? b.target_parent + '/' + b.new_name : b.new_name };
                if (b.dry_run) {
                    return { ok: true, dry_run: true, to, preview };
                }
                return { ok: true, to, subfolders: 1, entries: 3, favourites_moved: 2 };
            },
        },
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /software/ }).first().click();
    await page.locator('#btn-move-folder').click();

    const list = page.locator('#fmove-list');
    await expect(list).toContainText('(top level)');
    await expect(list).toContainText('devops');
    // Not the folder itself.
    await expect(list.locator('label').filter({ hasText: /^software/ })).toHaveCount(0);
    // It starts at its current place: a hint, not an error, and no dry run.
    await expect(page.locator('#fmove-preview')).toContainText('Pick a new parent or change the name');
    await expect(page.locator('#fmove-error')).toBeEmpty();
    await expect(page.locator('#fmove-confirm')).toBeDisabled();
    expect(api.calls.filter(c => c.path.endsWith('/move'))).toHaveLength(0);

    await list.locator('label').filter({ hasText: 'devops' }).locator('input').check();
    await expect(page.locator('#fmove-preview')).toContainText('will move to devops/software');
    await expect(page.locator('#fmove-preview .bulk-warn')).toContainText('groups devops, software');
    await expect(page.locator('#fmove-confirm')).toBeEnabled();
    await page.locator('#fmove-confirm').click();

    await expect(page.locator('#fmove-modal')).not.toHaveClass(/active/);
    const moves = api.calls.filter(c => c.method === 'POST' && c.path.endsWith('/software/move'));
    expect(moves.at(-1).body).toEqual({
        target_scope: 'shared', target_parent: 'devops', new_name: 'software', dry_run: false,
    });
});

test('the move needs folders.manage_access as well as connections.edit', async ({ page }) => {
    await installApi(page, {
        role: 'admin',
        folders,
        routes: {
            'GET /api/me': {
                name: 'editor@example.com', role: 'custom',
                permissions: [...ROLE_PERMS.operator, 'connections.edit'],
                groups: [], vault_enabled: true, vault_configured: true,
            },
        },
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /software/ }).first().click();
    await expect(page.locator('#btn-edit-folder')).toBeVisible();
    await expect(page.locator('#btn-move-folder')).toBeHidden();
});
