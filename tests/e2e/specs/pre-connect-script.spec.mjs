// #329: an entry can name a script from the server's pre-connect scripts
// directory, run before connecting (to power a VM on, say). The editor lists
// the scripts, keeps one the directory no longer has, saves the choice, and
// offers none for a VDI desktop.
import { test, expect } from '@playwright/test';
import { installApi, settle, entry, folder } from '../lib/api.mjs';

const folders = () => [folder('lab', { entries: [
    entry('win11', 'rdp', { username: 'alice', fields: { pre_connect_script: 'retired.sh' } }),
    entry('desk', 'vdi', { fields: { container_image: 'example/desktop:latest' } })
] })];

test('the editor lists, keeps and saves the pre-connect script', async ({ page }) => {
    const api = await installApi(page, {
        folders: folders(),
        routes: { 'GET /api/pre-connect-scripts': { scripts: ['power-on.sh', 'wake-cloud.py'] } }
    });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /lab/ }).first().click();

    await page.locator('button[data-edit-entry="win11"]').click();
    const sel = page.locator('#em-pre-connect-script');
    await expect(sel).toBeVisible();
    // The stored one stays selected although the directory no longer lists it.
    await expect(sel).toHaveValue('retired.sh');
    await expect(sel.locator('option')).toHaveText(['Nothing', 'power-on.sh', 'wake-cloud.py', 'retired.sh']);
    await sel.selectOption('power-on.sh');
    await page.locator('#em-save').click();
    await expect.poll(() => api.calls.find(c => c.method === 'PUT' && /entries\/win11$/.test(c.path))).toBeTruthy();
    const body = api.calls.find(c => c.method === 'PUT' && /entries\/win11$/.test(c.path)).body;
    const sent = body.pre_connect_script ?? (body.protocols || []).map(p => p.pre_connect_script).find(Boolean);
    expect(sent).toBe('power-on.sh');

    await page.locator('button[data-edit-entry="desk"]').click();
    await expect(page.locator('#em-preconnect-section')).toBeHidden();
});
