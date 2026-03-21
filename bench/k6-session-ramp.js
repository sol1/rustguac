// k6 session ramp-up test for rustguac.
// Gradually increases concurrent RDP sessions from 0 to 100.
//
// Usage:
//   k6 run --env API_KEY=rgu_xxx \
//          --env BASE_URL=https://10.10.50.51:8089 \
//          --env XRDP_HOST=10.10.50.52 \
//          bench/k6-session-ramp.js
//
// Env vars:
//   API_KEY    - rustguac admin API key
//   BASE_URL   - rustguac base URL
//   XRDP_HOST  - xrdp target IP (single VM with multiple users)
//   MAX_VUS    - max concurrent sessions (default 100)
//   HOLD_SECS  - seconds to hold at max (default 300)

import http from 'k6/http';
import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const sessionCreateTime = new Trend('session_create_ms');
const wsConnectTime = new Trend('ws_connect_ms');
const sessionsCreated = new Counter('sessions_created');
const sessionsFailed = new Counter('sessions_failed');
const wsMessages = new Counter('ws_messages_received');
const wsBytesIn = new Counter('ws_bytes_received');

const MAX_VUS = parseInt(__ENV.MAX_VUS || '100');
const HOLD = parseInt(__ENV.HOLD_SECS || '300');

export let options = {
    scenarios: {
        ramp_sessions: {
            executor: 'ramping-vus',
            startVUs: 0,
            stages: [
                { duration: '1m', target: 10 },
                { duration: '2m', target: 25 },
                { duration: '2m', target: 50 },
                { duration: '2m', target: 75 },
                { duration: '2m', target: MAX_VUS },
                { duration: `${HOLD}s`, target: MAX_VUS },
                { duration: '1m', target: 0 },
            ],
        },
    },
    insecureSkipTLSVerify: true,
    thresholds: {
        'session_create_ms': ['p(95)<5000'],
        'ws_connect_ms': ['p(95)<2000'],
    },
};

const API_KEY = __ENV.API_KEY;
const BASE_URL = __ENV.BASE_URL || 'https://localhost:8089';
const XRDP_HOST = __ENV.XRDP_HOST || '127.0.0.1';

const params = {
    headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
    },
};

export default function () {
    // Use a unique bench user per VU to avoid xrdp session conflicts
    const userNum = ((__VU - 1) % 100) + 1;
    const username = `bench${String(userNum).padStart(2, '0')}`;

    // Create session
    const createStart = Date.now();
    const createRes = http.post(`${BASE_URL}/api/sessions`, JSON.stringify({
        session_type: 'rdp',
        hostname: XRDP_HOST,
        port: 3389,
        username: username,
        password: 'bench',
        width: 1024,
        height: 768,
        ignore_cert: true,
        security: 'any',
    }), params);

    sessionCreateTime.add(Date.now() - createStart);

    if (createRes.status !== 200 && createRes.status !== 201) {
        sessionsFailed.add(1);
        console.error(`VU ${__VU}: session create failed: ${createRes.status} ${createRes.body}`);
        sleep(5);
        return;
    }

    sessionsCreated.add(1);
    const session = JSON.parse(createRes.body);
    const sessionId = session.session_id;

    // Connect WebSocket
    const wsProto = BASE_URL.startsWith('https') ? 'wss' : 'ws';
    const host = BASE_URL.replace(/^https?:\/\//, '');
    const wsUrl = `${wsProto}://${host}/ws/${sessionId}`;

    const wsStart = Date.now();
    const res = ws.connect(wsUrl, {
        headers: { 'X-API-Key': API_KEY },
    }, function (socket) {
        wsConnectTime.add(Date.now() - wsStart);

        // Simulate mouse movement every 2s
        socket.setInterval(function () {
            const x = Math.floor(Math.random() * 1024);
            const y = Math.floor(Math.random() * 768);
            const xStr = String(x);
            const yStr = String(y);
            socket.send(`5.mouse,${xStr.length}.${xStr},${yStr.length}.${yStr},1.0;`);
        }, 2000);

        // Simulate typing every 10s
        socket.setInterval(function () {
            // Press and release 'a' (keysym 97)
            socket.send('3.key,2.97,1.1;');
            socket.send('3.key,2.97,1.0;');
        }, 10000);

        socket.on('message', function (msg) {
            wsMessages.add(1);
            wsBytesIn.add(msg.length);
        });

        // Hold for iteration duration, then close
        socket.setTimeout(function () {
            socket.close();
        }, 60000);
    });

    // Cleanup
    http.del(`${BASE_URL}/api/sessions/${sessionId}`, null, params);
    sleep(1);
}
