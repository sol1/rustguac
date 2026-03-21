// k6 address book latency test.
// Measures GET /api/addressbook response time at various entry counts.
//
// Usage:
//   k6 run --env API_KEY=rgu_xxx \
//          --env BASE_URL=https://10.10.50.51:8089 \
//          bench/k6-addressbook.js
//
// Run after populating Vault with populate-vault.sh at different counts
// to measure how response time scales with entry count.

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Counter } from 'k6/metrics';

const abListDuration = new Trend('ab_list_all_ms');
const abEntryCount = new Counter('ab_total_entries');
const abFolderCount = new Counter('ab_total_folders');

export let options = {
    scenarios: {
        // Single user, repeated requests
        ab_serial: {
            executor: 'constant-vus',
            vus: 1,
            duration: '60s',
        },
    },
    insecureSkipTLSVerify: true,
};

const API_KEY = __ENV.API_KEY;
const BASE_URL = __ENV.BASE_URL || 'https://localhost:8089';

export default function () {
    const res = http.get(`${BASE_URL}/api/addressbook`, {
        headers: { 'X-API-Key': API_KEY },
        tags: { name: 'list_all' },
    });

    check(res, { 'status 200': (r) => r.status === 200 });
    abListDuration.add(res.timings.duration);

    if (res.status === 200) {
        try {
            const data = JSON.parse(res.body);
            const folders = data.folders || [];
            let totalEntries = 0;
            folders.forEach(function (f) {
                totalEntries += (f.entries || []).length;
            });
            abFolderCount.add(folders.length);
            abEntryCount.add(totalEntries);
        } catch (e) {}
    }

    sleep(1);
}

// Also run a concurrent-user variant
export function concurrent() {
    const res = http.get(`${BASE_URL}/api/addressbook`, {
        headers: { 'X-API-Key': API_KEY },
        tags: { name: 'list_all_concurrent' },
    });
    check(res, { 'status 200': (r) => r.status === 200 });
    abListDuration.add(res.timings.duration);
    sleep(0.5);
}
