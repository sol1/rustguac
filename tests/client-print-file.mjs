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
const timers = [];
const printLogs = [];
const streamAcks = [];
let iframePrintCalls = 0;
let iframeFocusCalls = 0;
let blobReaderCount = 0;
let reader;
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
                click() { downloads.push({ href: this.href, filename: this.download }); },
                remove() { this.parentNode = null; }
            };
            elements.push(element);
            return element;
        }
    },
    URL: { createObjectURL: () => 'blob:print-job', revokeObjectURL() {} },
    window: {},
    sessionId: 'session-id',
    printingMethod: 'trigger_print',
    shareToken: null,
    fetchHeaders: {},
    fetch(url, options) { printLogs.push({ url, options }); return Promise.resolve(); },
    setTimeout(callback, delay) { timers.push({ callback, delay }); },
    clearTimeout() {},
    setFileStatus: message => statuses.push(message)
};
ctx.Guacamole.Status = { Code: { SUCCESS: 0 } };
client.getState = () => ctx.Guacamole.Client.State.CONNECTED;
vm.createContext(ctx);
vm.runInContext(html.slice(start, end), ctx);

const printStream = {
    sendAck(message, status) { streamAcks.push({ message, status }); }
};
client.onfile(printStream, 'application/pdf', 'C:\\print\\invoice');
assert.equal(blobReaderCount, 1);
assert.deepEqual(streamAcks, [{ message: 'OK', status: 0 }]);
reader.onend();
const printFrame = elements.find(element => element.tagName === 'iframe');
assert.ok(printFrame, 'a hidden frame should receive the PDF without showing it');
assert.equal(printFrame.style.display, 'none');
assert.equal(printFrame.src, 'blob:print-job');
printFrame.onload();
timers.find(timer => timer.delay === 1).callback();
assert.equal(iframeFocusCalls, 1);
assert.equal(iframePrintCalls, 1, 'the hidden PDF frame should open the local print dialog');
assert.equal(downloads.length, 0, 'the print PDF should not be downloaded');
assert.equal(printLogs.length, 1);
assert.equal(printLogs[0].url, '/api/sessions/session-id/print-job');
assert.deepEqual(JSON.parse(printLogs[0].options.body), { filename: 'C:\\print\\invoice' });

ctx.printingMethod = 'download';
client.onfile(printStream, 'application/pdf', 'C:\\print\\report');
reader.onend();
assert.deepEqual(downloads.at(-1), { href: 'blob:print-job', filename: 'C:\\print\\report' }, 'download mode should save the print PDF');
assert.equal(iframePrintCalls, 1, 'download mode must not invoke the local print dialog');
assert.equal(printLogs.length, 2, 'print jobs should be logged in either delivery mode');

client.onfile(printStream, 'text/plain', 'notes.txt');
reader.onend();
assert.deepEqual(downloads.at(-1), { href: 'blob:print-job', filename: 'notes.txt' });
console.log('client-print-file: ok');
