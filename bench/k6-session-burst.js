// k6 session creation throughput test.
// Measures how many sessions/sec rustguac can create.
//
// Usage:
//   k6 run --env API_KEY=rgu_xxx \
//          --env BASE_URL=https://10.10.50.51:8089 \
//          --env XRDP_HOST=10.10.50.52 \
//          bench/k6-session-burst.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter, Rate } from 'k6/metrics';

const createDuration = new Trend('session_create_ms');
const createSuccess = new Rate('session_create_success');
const sessionsCreated = new Counter('total_sessions_created');

export let options = {
    scenarios: {
        burst: {
            executor: 'constant-arrival-rate',
            rate: 5,          // 5 sessions/sec
            timeUnit: '1s',
            duration: '60s',
            preAllocatedVUs: 30,
            maxVUs: 60,
        },
    },
    insecureSkipTLSVerify: true,
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
    const userNum = ((__ITER % 100) + 1);
    const username = `bench${String(userNum).padStart(2, '0')}`;

    const start = Date.now();
    const res = http.post(`${BASE_URL}/api/sessions`, JSON.stringify({
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

    createDuration.add(Date.now() - start);
    const ok = res.status === 200 || res.status === 201;
    createSuccess.add(ok);

    if (ok) {
        sessionsCreated.add(1);
        const session = JSON.parse(res.body);
        // Immediately delete — we're measuring creation throughput, not holding sessions
        http.del(`${BASE_URL}/api/sessions/${session.session_id}`, null, params);
    } else {
        console.error(`Create failed: ${res.status} ${res.body}`);
    }
}
