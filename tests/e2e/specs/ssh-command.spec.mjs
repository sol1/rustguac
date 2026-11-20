// #345: an SSH entry can run a command instead of the login shell (a
// database client, say). The editor saves it, shows it again, and offers it
// for SSH only.
import { test, expect } from '@playwright/test';
import { installApi, settle, entry, folder } from '../lib/api.mjs';

const folders = () => [folder('acme', { entries: [
    entry('db01', 'ssh', { username: 'alice', hostname: 'bastion.acme.internal', fields: { ssh_command: 'psql -h db.internal -U alice appdb' } }),
    entry('dc01', 'rdp', { username: 'administrator' })
] })];

test('the SSH command is shown, saved and only offered for SSH', async ({ page }) => {
    const api = await installApi(page, { folders: folders() });
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();

    await page.locator('button[data-edit-entry="db01"]').click();
    const cmd = page.locator('#em-ssh-command');
    await expect(cmd).toBeVisible();
    await expect(cmd).toHaveValue('psql -h db.internal -U alice appdb');
    await cmd.fill('mysql -h db.internal -u alice app');
    await page.locator('#em-save').click();
    await expect.poll(() => api.calls.find(c => c.method === 'PUT' && /entries\/db01$/.test(c.path))).toBeTruthy();
    const body = api.calls.find(c => c.method === 'PUT' && /entries\/db01$/.test(c.path)).body;
    const sent = body.ssh_command ?? (body.protocols || []).map(p => p.ssh_command).find(Boolean);
    expect(sent).toBe('mysql -h db.internal -u alice app');

    // Not on an RDP entry.
    await page.locator('button[data-edit-entry="dc01"]').click();
    await expect(page.locator('#em-ssh-command-row')).toBeHidden();
});
