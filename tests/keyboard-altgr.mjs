#!/usr/bin/env node
/*
 * Pins how the client sends AltGr from a Windows browser (#358).
 *
 * Windows reports AltGr to the browser as two keys: a left Ctrl, then a
 * right Alt that Chromium-based browsers name "AltGraph". The client turns
 * those into Control_L and ISO_Level3_Shift (AltGr). Before a printable
 * character Guacamole.Keyboard releases Ctrl and Alt, so guacd can apply the
 * server's own AltGr for the character, but it left ISO_Level3_Shift held.
 * A Windows server treats AltGr as Ctrl + right Alt, so with the Ctrl gone
 * and the right Alt still down, AltGr+8 on a French layout typed the wrong
 * character, while Ctrl+Alt+8 (left Alt, all released) worked.
 *
 * Whatever came before, when the character is sent no Ctrl, Alt or AltGr
 * may still be held: guacd then presses AltGr itself if the layout needs it.
 *
 * Usage: node tests/keyboard-altgr.mjs
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const sources = await Promise.all(['static/guac/Namespace.js', 'static/guac/Keyboard.js']
    .map((f) => readFile(join(root, f), 'utf8')));

const MODIFIERS = new Set([0xFFE3, 0xFFE4, 0xFFE9, 0xFFEA, 0xFE03]);
const hex = (k) => '0x' + k.toString(16).toUpperCase();

function keyboard(platform) {
    const listeners = {};
    const element = { addEventListener: (name, fn) => { (listeners[name] ||= []).push(fn); } };
    const sandbox = {
        console: { log() {}, warn() {}, error() {} },
        navigator: { platform },
        document: {},
        // No timers: key auto-repeat must not fire in the middle of a test.
        window: { setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {} },
        setTimeout: () => 0,
        clearTimeout() {},
    };
    vm.createContext(sandbox);
    for (const src of sources) vm.runInContext(src, sandbox);
    vm.runInContext('var kb = new Guacamole.Keyboard(element);', Object.assign(sandbox, { element }));
    const sent = [];
    const held = new Set();
    sandbox.kb.onkeydown = (k) => { sent.push(['down', k, [...held].filter((h) => MODIFIERS.has(h))]); held.add(k); return true; };
    sandbox.kb.onkeyup = (k) => { sent.push(['up', k]); held.delete(k); };
    let t = 0;
    const fire = (type, init) => {
        const e = {
            type, timeStamp: ++t, location: 0, keyCode: 0, which: 0, charCode: 0,
            ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, repeat: false, isComposing: false,
            preventDefault() {}, stopPropagation() {},
            getModifierState: (s) => !!(init.altGraph && s === 'AltGraph'),
            ...init,
        };
        for (const fn of listeners[type] || []) fn(e);
    };
    return { fire, sent };
}

// Edge on Windows 11, French keyboard, AltGr+8 for a backslash.
{
    const { fire, sent } = keyboard('Win32');
    fire('keydown', { key: 'Control', code: 'ControlLeft', keyCode: 17, location: 1, ctrlKey: true });
    fire('keydown', { key: 'AltGraph', code: 'AltRight', keyCode: 18, location: 2, ctrlKey: true, altKey: true, altGraph: true });
    fire('keydown', { key: '\\', code: 'Digit8', keyCode: 56, ctrlKey: true, altKey: true, altGraph: true });
    fire('keypress', { key: '\\', code: 'Digit8', charCode: 92, which: 92, ctrlKey: true, altKey: true, altGraph: true });
    fire('keyup', { key: '\\', code: 'Digit8', keyCode: 56, ctrlKey: true, altKey: true, altGraph: true });
    fire('keyup', { key: 'AltGraph', code: 'AltRight', keyCode: 18, location: 2, ctrlKey: true });
    fire('keyup', { key: 'Control', code: 'ControlLeft', keyCode: 17, location: 1 });

    const press = sent.find(([dir, k]) => dir === 'down' && k === 0x5C);
    assert.ok(press, 'the backslash itself is sent: ' + JSON.stringify(sent.map(([d, k]) => d + ' ' + hex(k))));
    assert.deepEqual(press[2].map(hex), [], 'nothing of Ctrl/Alt/AltGr may still be held when the character is sent');
}

// The working case stays working: Ctrl + left Alt + 8.
{
    const { fire, sent } = keyboard('Win32');
    fire('keydown', { key: 'Control', code: 'ControlLeft', keyCode: 17, location: 1, ctrlKey: true });
    fire('keydown', { key: 'Alt', code: 'AltLeft', keyCode: 18, location: 1, ctrlKey: true, altKey: true });
    fire('keydown', { key: '\\', code: 'Digit8', keyCode: 56, ctrlKey: true, altKey: true });
    fire('keypress', { key: '\\', code: 'Digit8', charCode: 92, which: 92, ctrlKey: true, altKey: true });
    const press = sent.find(([dir, k]) => dir === 'down' && k === 0x5C);
    assert.ok(press);
    assert.deepEqual(press[2].map(hex), []);
}

// Ctrl+Alt with a letter is a shortcut, not AltGr: it keeps its modifiers.
{
    const { fire, sent } = keyboard('Win32');
    fire('keydown', { key: 'Control', code: 'ControlLeft', keyCode: 17, location: 1, ctrlKey: true });
    fire('keydown', { key: 'Alt', code: 'AltLeft', keyCode: 18, location: 1, ctrlKey: true, altKey: true });
    fire('keydown', { key: 't', code: 'KeyT', keyCode: 84, ctrlKey: true, altKey: true });
    // No keypress for a shortcut; the keyup settles what the key was.
    fire('keyup', { key: 't', code: 'KeyT', keyCode: 84, ctrlKey: true, altKey: true });
    const press = sent.find(([dir, k]) => dir === 'down' && k === 0x74);
    assert.ok(press);
    assert.deepEqual(press[2].map(hex).sort(), ['0xFFE3', '0xFFE9'].sort(), 'Ctrl+Alt+T keeps Ctrl and Alt');
}

console.log('keyboard-altgr: ok');
