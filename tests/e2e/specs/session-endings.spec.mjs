import { test, expect } from '@playwright/test';
import { installApi } from '../lib/api.mjs';

function instruction(opcode, ...args) {
    return [opcode, ...args].map(value => `${String(value).length}.${value}`).join(',') + ';';
}

async function connect(page) {
    await installApi(page);
    let socket;
    await page.routeWebSocket('**/ws/**', ws => {
        socket = ws;
        ws.send('4.sync,1.0;');
    });
    await page.goto('/client.html?session=11111111-1111-4111-8111-111111111111');
    await expect.poll(() => !!socket).toBe(true);
    await expect(page.locator('#status')).toHaveText('Connected');
    return socket;
}

test('a clean guacd disconnect is a neutral session ending', async ({ page }) => {
    const socket = await connect(page);
    socket.send(instruction('disconnect'));
    await expect(page.locator('#disconnected-overlay')).toBeVisible();
    await expect(page.locator('#disconnected-title')).toHaveText('Session Ended');
    await expect(page.locator('#disconnected-message')).toHaveText('The remote connection has ended.');
});

for (const [code, message, title] of [
    [523, 'Logged off.', 'Session Ended'],
    [522, 'Idle session time limit exceeded.', 'Session Ended'],
    [769, 'Authentication failure (invalid credentials?)', 'Connection Error']
]) {
    test(`guacd reason survives tunnel closure: ${message}`, async ({ page }) => {
        const socket = await connect(page);
        socket.send(instruction('error', message, code) + instruction('disconnect'));
        await expect(page.locator('#disconnected-overlay')).toBeVisible();
        await expect(page.locator('#disconnected-title')).toHaveText(title);
        await expect(page.locator('#disconnected-message')).toHaveText(message);
    });
}

test('an abnormal WebSocket closure is still a connection error', async ({ page }) => {
    const socket = await connect(page);
    socket.close({ code: 1011 });
    await expect(page.locator('#disconnected-overlay')).toBeVisible();
    await expect(page.locator('#disconnected-title')).toHaveText('Connection Error');
    await expect(page.locator('#disconnected-message')).toHaveText('Connection lost');
});
