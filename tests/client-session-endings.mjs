#!/usr/bin/env node
// Exercise the actual client.html handlers with Guacamole's status codes and
// the same error -> CLOSED -> client DISCONNECTED ordering as Tunnel.js.
// Run: node tests/client-session-endings.mjs (also covered by CI's tests/*.mjs).
import { readFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const html = await readFile(join(root, 'static/client.html'), 'utf8');
const start = html.indexOf('var sessionEndStatus = null;');
const end = html.indexOf('// Disconnected overlay buttons', start);
assert.ok(start !== -1 && end > start, 'session-ending handlers must exist');
const handlers = html.slice(start, end);
const statusSource = await readFile(join(root, 'static/guac/Status.js'), 'utf8');

function setup(embedded = false) {
    const elements = new Map();
    let state = 3;
    const ctx = {
        embedded, statusEl: {}, _thumbInterval: 42, cleared: [], notifications: [], monitors: [],
        console: { log() {} },
        document: { getElementById(id) {
            if (!elements.has(id)) elements.set(id, {});
            return elements.get(id);
        } },
        rgDisarmFullscreenGesture() {}, rgHideConnectCover() {},
        rgFullscreenEl() { return false; },
        rgNotifyParent(event) { ctx.notifications.push(event); },
        teardownMonitorWindows(reason) { ctx.monitors.push(reason); },
        clearInterval(id) { ctx.cleared.push(id); },
        captureAndUploadThumbnail() {},
        client: { disconnect() {
            if (state === 4 || state === 5) return;
            state = 4;
            ctx.client.onstatechange(state);
            ctx.tunnel.onstatechange(ctx.Guacamole.Tunnel.State.CLOSED);
            state = 5;
            ctx.client.onstatechange(state);
        } },
        tunnel: {}
    };
    vm.createContext(ctx);
    vm.runInContext(statusSource, ctx);
    ctx.Guacamole.Client = { State: {
        CONNECTING: 1, WAITING: 2, CONNECTED: 3, DISCONNECTING: 4, DISCONNECTED: 5
    } };
    ctx.Guacamole.Tunnel = { State: { CLOSED: 2, UNSTABLE: 3 } };
    vm.runInContext(handlers, ctx);
    return {
        ctx, elements, codes: ctx.Guacamole.Status.Code,
        closed() { ctx.tunnel.onstatechange(ctx.Guacamole.Tunnel.State.CLOSED); },
        title() { return elements.get('disconnected-title')?.textContent; },
        message() { return elements.get('disconnected-message')?.textContent; },
        cleanup() {
            assert.equal(state, 5, 'client must leave CONNECTED');
            assert.equal(ctx._thumbInterval, null);
            assert.deepEqual(ctx.cleared, [42]);
            assert.deepEqual(ctx.monitors, ['disconnect']);
        }
    };
}

// Clean remote ending and explicit client disconnect are not connection errors.
// Neither proves Windows logoff: don't invent that distinction in the UI.
for (const localDisconnect of [false, true]) {
    const h = setup();
    if (localDisconnect) h.ctx.client.disconnect(); else h.closed();
    assert.equal(h.title(), 'Session Ended');
    assert.equal(h.message(), 'The remote connection has ended.');
    assert.doesNotMatch(h.message(), /log(?:ged)?[ -]?off|sign(?:ed)?[ -]?out/i);
    h.cleanup();
}

// Guacd's specific reason survives subsequent client/tunnel closure events.
for (const [codeName, message, title] of [
    ['SESSION_CLOSED', 'Logged off.', 'Session Ended'],
    ['SESSION_CLOSED', 'Forcibly disconnected.', 'Session Ended'],
    ['SESSION_TIMEOUT', 'Idle session time limit exceeded.', 'Session Ended'],
    ['SESSION_CONFLICT', 'Disconnected by other connection.', 'Session Ended'],
    ['CLIENT_UNAUTHORIZED', 'Authentication failure (invalid credentials?)', 'Connection Error'],
    ['UPSTREAM_NOT_FOUND', 'DNS lookup failed (incorrect hostname?)', 'Connection Error']
]) {
    const h = setup();
    h.ctx.client.onerror({ code: h.codes[codeName], message });
    h.closed();
    h.ctx.tunnel.onerror({ code: h.codes.SERVER_ERROR, message: 'Connection lost' });
    assert.equal(h.title(), title);
    assert.equal(h.message(), message);
    assert.ok(h.ctx.statusEl.textContent.endsWith(message));
    h.cleanup();
}

// Abnormal transport closure still reports an error and performs cleanup.
for (const message of [undefined, 'Server timeout.']) {
    const h = setup();
    h.ctx.tunnel.onerror({ code: h.codes.SERVER_TIMEOUT, message });
    h.closed();
    assert.equal(h.title(), 'Connection Error');
    assert.equal(h.message(), message || 'Connection lost');
    h.cleanup();
}

// Missing statuses are errors; explicit SUCCESS is not.
for (const success of [false, true]) {
    const h = setup();
    h.ctx.client.onerror(success ? { code: h.codes.SUCCESS } : undefined);
    assert.equal(h.title(), success ? 'Session Ended' : 'Connection Error');
    h.cleanup();
}

// Embedded launcher receives one end notification, including for errors.
for (const error of [false, true]) {
    const h = setup(true);
    if (error) h.ctx.tunnel.onerror({ code: h.codes.SERVER_ERROR, message: 'Connection lost' });
    h.closed();
    h.closed();
    assert.deepEqual(h.ctx.notifications, ['end']);
    assert.equal(h.title(), undefined, 'embedded sessions use their launcher');
    h.cleanup();
}

console.log('client-session-endings: ok');
