#!/usr/bin/env node
/*
 * Exercises the browser handling for Guacamole RDP print PDF file streams.
 * Usage: node tests/client-print-file.mjs
 */

import { readFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const html = await readFile(join(root, 'static/client.html'), 'utf8');
const marker = 'client.onfile = function(stream, mimetype, filename) {';
const start = html.indexOf(marker);
assert.notEqual(start, -1, 'client.onfile handler must exist');

const end = html.indexOf('function tracing_log(msg) {', start);
assert.ok(end > start, 'client print helper must be present');

const downloads = [];
const statuses = [];
const elements = [];
const openedWindows = [];
const timers = [];
let iframePrintCalls = 0;
let iframeFocusCalls = 0;
let blobReaderCount = 0;
let reader;
const streamEvents = [];
const client = {};
const ctx = {
    client,
    Guacamole: {
        Client: { State: { CONNECTED: 3 } },
        BlobReader: class {
            constructor(stream, mimetype) {
                blobReaderCount++;
                this.stream = stream;
                this.mimetype = mimetype;
                reader = this;
                streamEvents.push('reader');
            }
            getBlob() { return { type: this.mimetype }; }
        }
    },
    document: {
        body: {
            appendChild(element) { element.parentNode = this; },
            removeChild(element) { element.parentNode = null; }
        },
        createElement(tagName) {
            const element = {
                tagName,
                style: {},
                attributes: {},
                children: [],
                listeners: {},
                setAttribute(name, value) { this.attributes[name] = value; },
                appendChild(child) { this.children.push(child); child.parentNode = this; },
                addEventListener(name, callback) { this.listeners[name] = callback; },
                focus() { iframeFocusCalls++; },
                contentWindow: {
                    print() { iframePrintCalls++; }
                },
                click() { downloads.push({ href: this.href, filename: this.download }); }
            };
            elements.push(element);
            return element;
        }
    },
    URL: { createObjectURL: () => 'blob:print-job', revokeObjectURL() {} },
    window: {
        open(url, target) {
            const popup = {
                listeners: {},
                addEventListener(name, callback) { this.listeners[name] = callback; },
                focus() { this.focused = true; },
                print() { this.printed = true; },
                location: { replace(value) { popup.url = value; } }
            };
            openedWindows.push({ url, target, popup });
            return popup;
        }
    },
    setTimeout(callback, delay) { timers.push({ callback, delay }); },
    clearTimeout() {},
    setFileStatus: message => statuses.push(message)
};
ctx.Guacamole.Status = { Code: { SUCCESS: 0 } };
client.getState = () => ctx.Guacamole.Client.State.CONNECTED;
vm.createContext(ctx);
vm.runInContext(html.slice(start, end), ctx);

const stream = {
    sendAck(message, code) {
        streamEvents.push({ message, code });
    }
};
client.onfile(stream, 'application/pdf', 'C:\\print\\invoice');
assert.equal(blobReaderCount, 1);
assert.deepEqual(streamEvents, [
    'reader',
    { message: 'OK', code: 0 }
], 'the stream must be accepted after the BlobReader is ready');
reader.onprogress();
assert.deepEqual(streamEvents.at(-1), { message: 'Received', code: 0 }, 'each received blob must be acknowledged');
reader.onend();
const printFrame = elements.find(element => element.tagName === 'iframe');
assert.ok(printFrame, 'a hidden iframe should receive the PDF');
assert.equal(printFrame.style.display, 'none');
assert.equal(printFrame.src, 'blob:print-job');
assert.equal(typeof printFrame.onload, 'function');
printFrame.onload();
const printTimer = timers.find(timer => timer.delay === 1);
assert.ok(printTimer, 'printing should be scheduled immediately after the PDF frame loads');
printTimer.callback();
assert.equal(iframeFocusCalls, 1);
assert.equal(iframePrintCalls, 1, 'the hidden PDF frame should invoke the local print dialog');
assert.equal(openedWindows.length, 0, 'printing should not open a PDF tab');
assert.equal(elements.some(element => element.attributes.role === 'status'), false, 'PDF should not be shown in a print prompt');

client.onfile({ sendAck() {} }, 'text/plain', 'notes.txt');
reader.onend();
assert.deepEqual(downloads.at(-1), { href: 'blob:print-job', filename: 'notes.txt' });
console.log('client-print-file: ok');
