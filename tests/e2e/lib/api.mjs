/*
 * Stubbed rustguac API for the end-to-end tests.
 *
 * installApi(page, options) routes every /api/* request the page makes to a
 * JSON answer built from a small fixture address book, so the real pages run
 * against data the test controls and nothing needs Vault, guacd or a browser
 * session. Every request is recorded in the returned `calls` array so a spec
 * can assert on what the page sent (method, path, JSON body).
 *
 * options.role       'admin' (default) | 'poweruser' | 'operator' | 'viewer'
 * options.folders    replace the fixture folders (see fixtureFolders())
 * options.sessions   /api/sessions list (default: two sessions)
 * options.recordings /api/recordings list
 * options.routes     { 'METHOD /api/path': body | (req, url) => body|Response-like }
 *                    exact-path overrides, checked before the defaults
 */

// What /api/me returns as `permissions` for each built-in role, as
// src/perms.rs defines them (#294).
const VIEWER = ['docs.view'];
const OPERATOR = ['connections.connect', 'credentials.self', ...VIEWER];
const POWERUSER = ['connections.adhoc', 'recordings.view', 'reports.view', 'tokens.self', ...OPERATOR];
export const ROLE_PERMS = {
    viewer: VIEWER,
    operator: OPERATOR,
    poweruser: POWERUSER,
    admin: [...POWERUSER, 'connections.edit', 'folders.manage_access', 'connections.unrestricted',
        'sessions.view_all', 'sessions.shadow', 'recordings.delete',
        'admin.users', 'admin.roles', 'admin.audit', 'admin.system'],
};

export function entry(name, session_type, extra = {}) {
    return {
        name,
        session_type,
        hostname: extra.hostname ?? (session_type === 'web' ? null : `${name}.acme.internal`),
        port: extra.port ?? (session_type === 'ssh' ? 22 : session_type === 'rdp' ? 3389 : null),
        username: extra.username ?? (session_type === 'web' ? null : 'root'),
        url: extra.url ?? (session_type === 'web' ? `https://${name}.example.com/` : null),
        display_name: extra.display_name ?? null,
        domain: null,
        security: null,
        ignore_cert: null,
        has_credentials: extra.has_credentials ?? true,
        inherited_credentials: extra.inherited_credentials ?? false,
        fullscreen_on_connect: extra.fullscreen_on_connect ?? false,
        ...extra.fields
    };
}

export function folder(name, opts = {}) {
    return {
        name,
        scope: opts.scope ?? 'shared',
        path: opts.path ?? name,
        description: opts.description ?? '',
        display_name: opts.display_name ?? '',
        allowed_groups: opts.allowed_groups ?? [],
        has_children: opts.has_children ?? false,
        entries: opts.entries ?? []
    };
}

/* Two named tenants plus twenty generic ones, so the sidebar is long enough
 * for the scrolling, filtering and keyboard tests to mean something. */
export function fixtureFolders() {
    const folders = [
        folder('acme', {
            display_name: "Dani & Fiori's Gourmet Pizzeria",
            description: 'Acme tenant (NetBox)',
            entries: [
                entry('web01', 'ssh'),
                entry('dc01', 'rdp', { username: 'administrator' }),
                entry('kiosk', 'rdp', { username: 'kiosk', fullscreen_on_connect: true }),
                entry('portal', 'web')
            ]
        }),
        folder('beta', {
            description: 'Beta Industries',
            entries: [entry('app01', 'ssh'), entry('files', 'rdp', { has_credentials: false })]
        })
    ];
    for (let i = 1; i <= 20; i++) {
        const n = `tenant-${String(i).padStart(2, '0')}`;
        folders.push(folder(n, { description: `Tenant ${i}`, entries: [entry(`${n}-ssh`, 'ssh')] }));
    }
    return folders;
}

export function fixtureSessions() {
    return [
        { session_id: '11111111-1111-4111-8111-111111111111', session_type: 'ssh', status: 'Connected',
          created_at: '2026-10-11T01:00:00Z', client_url: '/client.html?session=1111', ws_url: '/ws/1111',
          hostname: 'web01.acme.internal', username: 'root', active_connections: 1, created_by: 'alice@example.com' },
        { session_id: '22222222-2222-4222-8222-222222222222', session_type: 'rdp', status: 'Pending',
          created_at: '2026-10-11T01:05:00Z', client_url: '/client.html?session=2222', ws_url: '/ws/2222',
          hostname: 'dc01.acme.internal', username: 'administrator', active_connections: 0, created_by: 'bob@example.com' }
    ];
}

export function fixtureRecordings() {
    return [
        { name: 'ssh-web01-20261011-010000.guac', modified: '2026-10-11T01:30:00Z', size_bytes: 120_000,
          session_type: 'ssh', user: 'alice@example.com', folder: 'shared/acme', address_book_entry: 'web01',
          entry_display_name: 'web01 (Acme)' },
        { name: 'rdp-dc01-20261011-020000.guac', modified: '2026-10-11T02:30:00Z', size_bytes: 9_000_000,
          session_type: 'rdp', user: 'bob@example.com', folder: 'shared/acme', address_book_entry: 'dc01',
          entry_display_name: 'dc01 (Acme)' }
    ];
}

function json(body, status = 200) {
    return { status, contentType: 'application/json', body: JSON.stringify(body) };
}

export async function installApi(page, options = {}) {
    const role = options.role ?? 'admin';
    const folders = options.folders ?? fixtureFolders();
    const sessions = options.sessions ?? fixtureSessions();
    const recordings = options.recordings ?? fixtureRecordings();
    const state = { version: 1, folders, sessions, recordings, calls: [] };

    // The first visit to Connections opens the onboarding tour over the page;
    // mark it seen so it never sits over the elements a test clicks.
    if (!options.onboarding) {
        await page.addInitScript(() => {
            try { localStorage.setItem('rustguac_onboarding_dismissed', '1'); } catch (e) { /* no storage */ }
        });
    }

    const findFolder = (scope, path) => folders.find(f => f.scope === scope && (f.path ?? f.name) === path);
    const searchIndex = () => ({
        entries: folders.flatMap(f => f.entries.map(e => ({
            scope: f.scope, folder_path: f.path ?? f.name, folder_display_name: f.display_name || '', entry: e
        })))
    });

    await page.route('**/api/**', async (route) => {
        const req = route.request();
        const url = new URL(req.url());
        const path = url.pathname;
        const method = req.method();
        let body = null;
        try { body = req.postDataJSON(); } catch { body = req.postData(); }
        state.calls.push({ method, path, query: Object.fromEntries(url.searchParams), body });

        const key = `${method} ${path}`;
        if (options.routes && key in options.routes) {
            const v = options.routes[key];
            const out = typeof v === 'function' ? await v(req, url, state) : v;
            if (out && typeof out === 'object' && 'status' in out && 'body' in out) return route.fulfill(out);
            return route.fulfill(json(out));
        }

        // ── identity ──
        if (path === '/api/me') return route.fulfill(json({
            name: 'tester@example.com', role, permissions: ROLE_PERMS[role] || [],
            groups: ['everyone'], vault_enabled: true, vault_configured: true
        }));
        if (path === '/api/auth/status') return route.fulfill(json({
            oidc_enabled: false, drive_configured: false, theme: 'dark'
        }));
        if (path === '/api/me/credentials') return route.fulfill(json({ credentials: {} }));
        if (path === '/api/credential-variables' || path === '/api/login-scripts' || path === '/api/auth/known-groups')
            return route.fulfill(json([]));

        // ── address book ──
        if (path === '/api/addressbook') return route.fulfill(json({ folders, unavailable_scopes: [] }));
        // As the server answers: `changes` is null for the baseline poll
        // (no `since`) and lists nothing after it, so a stubbed poll is not
        // read as "refresh everything". Specs that need a change supply
        // their own route.
        if (path === '/api/addressbook/version') return route.fulfill(json({
            version: state.version, changed_at: 0, epoch: 1,
            changes: url.searchParams.has('since') ? [] : null
        }));
        if (path === '/api/addressbook/search-index') return route.fulfill(json(searchIndex()));
        if (path === '/api/addressbook/folder-paths') return route.fulfill(json({
            paths: folders.map(f => ({ scope: f.scope, path: f.path ?? f.name }))
        }));
        if (path === '/api/addressbook/folders' && method === 'GET') return route.fulfill(json({ folders }));
        let m = path.match(/^\/api\/addressbook\/folders\/([^/]+)\/(.+?)\/(entries|config|defaults|subfolders)$/);
        if (m) {
            const f = findFolder(decodeURIComponent(m[1]), decodeURIComponent(m[2]));
            if (!f) return route.fulfill(json({ error: 'no such folder' }, 404));
            if (m[3] === 'entries') return route.fulfill(json(f.entries));
            if (m[3] === 'subfolders') return route.fulfill(json([]));
            if (m[3] === 'config') return route.fulfill(json({
                allowed_groups: f.allowed_groups, allowed_users: [], description: f.description, display_name: f.display_name
            }));
            if (m[3] === 'defaults') return route.fulfill(json({ defaults: {} }));
        }
        m = path.match(/^\/api\/addressbook\/folders\/([^/]+)\/(.+?)\/entries\/([^/]+)\/connect$/);
        if (m && method === 'POST') {
            const id = '33333333-3333-4333-8333-333333333333';
            return route.fulfill(json({
                session_id: id, client_url: `/client.html?session=${id}`, ws_url: `/ws/${id}`, session_type: 'rdp'
            }));
        }
        if (path === '/api/addressbook/adhoc/connect' && method === 'POST') {
            const id = '44444444-4444-4444-8444-444444444444';
            return route.fulfill(json({
                session_id: id, client_url: `/client.html?session=${id}`, ws_url: `/ws/${id}`,
                session_type: body?.entry?.type ?? 'ssh'
            }, 201));
        }
        if (path.startsWith('/api/addressbook/') && method !== 'GET') {
            state.version += 1;
            return route.fulfill(json({ ok: true }));
        }

        // ── sessions / recordings / reports ──
        if (path === '/api/sessions' && method === 'GET') return route.fulfill(json(sessions));
        if (path.startsWith('/api/sessions/') && method === 'DELETE') return route.fulfill(json({ ok: true }));
        if (path === '/api/vdi/containers') return route.fulfill(json([]));
        if (path === '/api/recordings' && method === 'GET') return route.fulfill(json(recordings));
        if (path.startsWith('/api/recordings/') && method === 'DELETE') return route.fulfill(json({ ok: true }));
        if (path === '/api/typescripts') return route.fulfill(json({ items: [] }));
        if (path === '/api/reports/summary') return route.fulfill(json({
            total_sessions: 42, total_hours: 17.5, unique_users: 3, active_now: 1
        }));
        if (path === '/api/reports/sessions') return route.fulfill(json({
            total: 2, limit: 100, offset: 0,
            sessions: [
                { session_id: '1111', session_type: 'ssh', hostname: 'web01.acme.internal', username: 'root',
                  created_by: 'alice@example.com', status: 'Ended', started_at: '2026-10-11T01:00:00Z',
                  ended_at: '2026-10-11T01:30:00Z', duration_secs: 1800, entry_name: 'web01 (Acme)' },
                { session_id: '2222', session_type: 'rdp', hostname: 'dc01.acme.internal', username: 'administrator',
                  created_by: 'bob@example.com', status: 'Ended', started_at: '2026-10-11T02:00:00Z',
                  ended_at: '2026-10-11T02:30:00Z', duration_secs: 1800, entry_name: 'dc01 (Acme)' }
            ]
        }));
        if (path === '/api/reports/top-connections' || path === '/api/reports/top-users') return route.fulfill(json([]));

        return route.fulfill(json({}));
    });
    return state;
}

/* Wait until the page has finished its initial loads: no pending fetches for
 * a short while and no spinner-type skeletons left. */
export async function settle(page, ms = 250) {
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(ms);
}
