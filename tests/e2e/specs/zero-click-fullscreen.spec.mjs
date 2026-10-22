// #257: Connect on a fullscreen-on-connect entry fullscreens the current tab
// and loads the session in a same-origin iframe sized to the measured
// viewport. Headless Chromium refuses the fullscreen request, which is the
// documented fallback: the launcher connects at the tab's size at once, the
// frame still loads the embedded client, and Exit tears everything down.
import { test, expect } from '@playwright/test';
import { installApi, settle } from '../lib/api.mjs';

// HTTP fixtures do not provide a guacd WebSocket. Keep a simulated session
// alive so these launcher tests don't race genuine disconnect cleanup.
test.beforeEach(async ({ page }) => {
    await page.routeWebSocket('**/ws/**', socket => {
        socket.send('4.sync,1.0;');
    });
});

test('Connect on a fullscreen entry launches the embedded frame with the measured size', async ({ page }) => {
    const api = await installApi(page);
    await page.goto('/connections.html');
    await settle(page);
    const acme = page.locator('.folder-row').filter({ hasText: /acme/ }).first();
    await acme.click();
    const kiosk = page.locator('.entries-table tbody tr').filter({ hasText: 'kiosk' });
    await expect(kiosk).toHaveCount(1);
    await kiosk.locator('button', { hasText: /^Connect/ }).first().click();

    // The launcher overlay appears in this tab, no new tab or window.
    const overlay = page.locator('#rg-session-overlay');
    await expect(overlay).toBeVisible();
    await expect(page.locator('#rg-session-exit')).toBeVisible();

    // The connect request carries the viewport the frame will be shown at.
    await expect.poll(() => api.calls.find(c => c.method === 'POST' && c.path.endsWith('/entries/kiosk/connect'))).toBeTruthy();
    const connect = api.calls.find(c => c.method === 'POST' && c.path.endsWith('/entries/kiosk/connect'));
    const vp = page.viewportSize();
    expect(connect.body.width).toBe(vp.width);
    expect(connect.body.height).toBe(vp.height);
    expect(connect.body.screen_width, 'a framed session is sized from the viewport, not the screen').toBeUndefined();

    // The embedded client loads inside the frame, same origin.
    const frame = page.locator('#rg-session-frame');
    await expect(frame).toHaveAttribute('src', /client\.html\?.*embedded=1/);
    const src = await frame.getAttribute('src');
    expect(src.startsWith('/') || src.startsWith(page.url().split('/connections')[0])).toBe(true);

    // Exit tears it down and the page underneath is unchanged.
    await page.locator('#rg-session-exit').click();
    await expect(overlay).toHaveCount(0);
    await expect(page.locator('#entries-title')).toBeVisible();
});

test('a non-fullscreen entry connects the old way, with no frame', async ({ page }) => {
    const api = await installApi(page);
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
    const row = page.locator('.entries-table tbody tr').filter({ hasText: 'web01' });
    const [popup] = await Promise.all([
        page.waitForEvent('popup', { timeout: 5000 }).catch(() => null),
        row.locator('button', { hasText: /^Connect/ }).first().click()
    ]);
    await expect.poll(() => api.calls.some(c => c.method === 'POST' && c.path.endsWith('/entries/web01/connect'))).toBe(true);
    expect(await page.locator('#rg-session-overlay').count()).toBe(0);
    if (popup) await popup.close();
});

// Leaving fullscreen (Escape held, F11, the OS) must not end the session: the
// frame stays at the tab's size and a button takes it back to fullscreen.
// Headless Chromium refuses real fullscreen, so the browser's side is faked:
// fullscreenElement is set and cleared and fullscreenchange fired, exactly
// what the launcher listens to.
test('leaving fullscreen keeps the session and offers to go back', async ({ page }) => {
    await page.addInitScript(() => {
        let fs = null;
        Object.defineProperty(Document.prototype, 'fullscreenElement', { configurable: true, get: () => fs });
        // Like a real browser, the change event fires after the call returns.
        const change = (el) => new Promise((resolve) => setTimeout(() => {
            fs = el;
            document.dispatchEvent(new Event('fullscreenchange'));
            resolve();
        }, 50));
        Element.prototype.requestFullscreen = function () { return change(document.documentElement); };
        document.exitFullscreen = function () { return change(null); };
        window.__leaveFullscreen = () => document.exitFullscreen();
    });
    await installApi(page);
    await page.goto('/connections.html');
    await settle(page);
    await page.locator('.folder-row').filter({ hasText: /acme/ }).first().click();
    const kiosk = page.locator('.entries-table tbody tr').filter({ hasText: 'kiosk' });
    await kiosk.locator('button', { hasText: /^Connect/ }).first().click();

    const overlay = page.locator('#rg-session-overlay');
    const back = page.locator('#rg-session-fs');
    await expect(overlay).toBeVisible();
    await expect(back).toBeHidden();

    // The user leaves fullscreen: the session is still there.
    await page.evaluate(() => window.__leaveFullscreen());
    await expect(overlay).toBeVisible();
    await expect(page.locator('#rg-session-frame')).toHaveCount(1);
    await expect(back).toBeVisible();

    // The button goes back to fullscreen and hides itself.
    await back.click();
    await expect(back).toBeHidden();
    await expect(overlay).toBeVisible();

    // Exit still ends it.
    await page.locator('#rg-session-exit').click();
    await expect(overlay).toHaveCount(0);
});
