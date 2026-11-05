import { test, expect } from '@playwright/test';
import { installApi, settle, folder, entry } from '../lib/api.mjs';

const policyId = '8892b479-76b9-4b76-ad38-d8d0c7da3115';
const folders = [
    folder('source', { entries: [entry('host', 'ssh')] }),
    folder(policyId, { display_name: 'Operations <Lab>' }),
    folder('legacy'),
    folder('child', { path: 'parent/child', scope: 'instance', display_name: 'Nested destination' })
];

test('entry move uses friendly labels while retaining scope and full folder paths', async ({ page }) => {
    await installApi(page, { folders });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: 'source' }).click();
    await page.locator('[data-edit-entry="host"]').click();
    const select = page.locator('#em-move-target');
    await expect(select.locator(`option[value="shared|${policyId}"]`)).toHaveText('Operations <Lab> (shared)');
    await expect(select.locator(`option[value="shared|${policyId}"]`)).toHaveAttribute('title', policyId);
    await expect(select.locator('option[value="shared|legacy"]')).toHaveText('legacy (shared)');
    await expect(select.locator('option[value="instance|parent/child"]')).toHaveText('Nested destination (instance)');
    await expect(select.locator('option[value="shared|source"]')).toHaveCount(0);
    await expect(select.locator('option[value=""]')).toHaveText('(keep in current folder)');
    await select.selectOption(`shared|${policyId}`);
    await expect(select).toHaveValue(`shared|${policyId}`);
    await expect(select.locator('b')).toHaveCount(0);
});

test('ad-hoc save-as uses friendly labels and falls back to the internal path', async ({ page }) => {
    await installApi(page, { folders });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('#rg-adhoc').click();
    const select = page.locator('#em-saveas-folder');
    await expect(select.locator(`option[value="shared|${policyId}"]`)).toHaveText('Operations <Lab> (shared)');
    await expect(select.locator('option[value="shared|legacy"]')).toHaveText('legacy (shared)');
    await expect(select.locator('option[value="instance|parent/child"]')).toHaveText('Nested destination (instance)');
    await select.selectOption('instance|parent/child');
    await expect(select).toHaveValue('instance|parent/child');
});
