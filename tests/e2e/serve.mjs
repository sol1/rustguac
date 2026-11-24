#!/usr/bin/env node
/*
 * Serves the real static tree (../../static) over HTTP for the end-to-end
 * tests. No API: each spec stubs /api/* in the browser with page.route(),
 * so the pages run exactly as shipped against data the test controls.
 *
 * Usage: node tests/e2e/serve.mjs [port]   (default 8098)
 */

import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { dirname, resolve, join, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../static');
const port = parseInt(process.argv[2] || '8098', 10);

const TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js'  : 'text/javascript; charset=utf-8',
    '.mjs' : 'text/javascript; charset=utf-8',
    '.css' : 'text/css; charset=utf-8',
    '.svg' : 'image/svg+xml',
    '.png' : 'image/png',
    '.ico' : 'image/x-icon',
    '.json': 'application/json',
    '.woff2': 'font/woff2',
    '.woff': 'font/woff'
};

createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    let path = url.pathname === '/' || url.pathname === '/login' ? '/index.html' : url.pathname;
    const file = join(root, normalize(path).replace(/^(\.\.[/\\])+/, ''));
    if (!file.startsWith(root)) { res.writeHead(403); res.end(); return; }
    try {
        const s = await stat(file);
        if (!s.isFile()) throw new Error('not a file');
    } catch {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('not found: ' + path);
        return;
    }
    res.writeHead(200, {
        'Content-Type': TYPES[extname(file)] || 'application/octet-stream',
        'Cache-Control': 'no-store'
    });
    createReadStream(file).pipe(res);
}).listen(port, '127.0.0.1', () => {
    console.log(`e2e static server: http://127.0.0.1:${port}/  (root ${root})`);
});
