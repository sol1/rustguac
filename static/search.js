/*
 * Global connection search — a floating, dim overlay available on every page.
 *
 * Drop-in: a page only needs <script src="/search.js"></script>. It injects its
 * own styles, a search box into the brand row, and the results overlay into the
 * body, loads the address-book search index, and wires the "/" shortcut.
 *
 * On the connections page, opening a folder from a result selects it in the
 * sidebar in place (via window.rgSelectFolder) instead of navigating; the
 * loaded index is also exposed as window.rgSearchIndex for that page's
 * credentials banner. Depends on rgFilters (filters.js), loaded on demand.
 *
 * Only an authenticated operator or above gets the box: the server writes the
 * caller's role on <html data-role-level> (0 anonymous ... 4 admin), and an
 * API-key user, who is served the anonymous variant, is confirmed through
 * /api/me first. A poweruser or above also gets "Connect to a host" beside
 * it, for an ad-hoc connection: it opens the editor in place on the
 * connections page (window.rgOpenAdhoc) and /connections.html#adhoc
 * elsewhere. It needs no Vault, so it shows even when the box has nothing to
 * search, and it goes with the box when the identity is dropped. The cached index is keyed to that identity and dropped the
 * moment the server stops recognising it (logout, expiry, a different user in
 * the same tab), so nothing of one user's address book is ever shown to the
 * next, nor on the login page.
 */
(function () {
    'use strict';
    if (window.__rgGlobalSearch) return;
    window.__rgGlobalSearch = true;

    var searchIndex = null, searchEngaged = false, searchFilters = null;
    var confirmedLevel = null; // role level /api/me answered with

    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
        });
    }
    function attr(s) { return esc(s); }
    function highlight(text, tokens) {
        var safe = esc(text);
        if (!tokens || !tokens.length) return safe;
        var escaped = tokens.filter(function (t) { return t.length > 0; })
            .map(function (t) { return t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); });
        if (!escaped.length) return safe;
        return safe.replace(new RegExp('(' + escaped.join('|') + ')', 'gi'), '<mark>$1</mark>');
    }
    // "host (Tenant)" -> host over a quieter tenant sub-line
    function entryNameHtml(label, tokens) {
        var e = tokens ? function (t) { return highlight(t, tokens); } : esc;
        var m = /^(.*\S)\s+\(([^()]+)\)$/.exec(label || '');
        if (!m) return e(label || '');
        return '<span class="entry-name">' + e(m[1]) + '</span><span class="entry-sub">' + e(m[2]) + '</span>';
    }
    function apiKey() { try { return sessionStorage.getItem('rustguac_api_key'); } catch (e) { return null; } }
    function headers(extra) {
        var h = extra || {}; var k = apiKey();
        if (k) h['Authorization'] = 'Bearer ' + k;
        return h;
    }


    function injectUI() {
        var brand = document.querySelector('.brand-row');
        if (brand) {
            brand.style.position = 'relative';
            brand.style.zIndex = '300';
            var gs = document.createElement('div');
            gs.className = 'global-search'; gs.id = 'global-search';
            gs.innerHTML = '<span class="global-search-icon" aria-hidden="true">⚲</span>' +
                '<input type="search" id="rg-search" placeholder="Search connections…" autocomplete="off" spellcheck="false" aria-label="Search connections" disabled />' +
                '<kbd class="global-search-key" title="Press / to search">/</kbd>';
            brand.appendChild(gs);
        }
        var ov = document.createElement('div');
        ov.id = 'search-overlay'; ov.setAttribute('aria-hidden', 'true');
        ov.innerHTML = '<div id="search-overlay-panel" role="dialog" aria-label="Search results">' +
            '<div id="search-overlay-head"><div id="search-summary" class="search-summary"></div><div id="search-facets" class="list-tools"></div></div>' +
            '<div id="search-results"></div></div>';
        document.body.appendChild(ov);
    }

    // "Connect to a host": poweruser and above, the server's can_connect_adhoc.
    var ADHOC_LEVEL = 3;
    function injectAdhoc(level) {
        var brand = document.querySelector('.brand-row');
        if (!brand || level == null || level < ADHOC_LEVEL || document.getElementById('rg-adhoc')) return;
        var b = document.createElement('button');
        b.type = 'button'; b.id = 'rg-adhoc'; b.className = 'btn-add global-adhoc';
        b.title = 'Connect to a host that is not a saved entry, with every option an entry has. Nothing is saved.';
        b.innerHTML = '&#9889; Connect to a host';
        b.addEventListener('click', function () {
            if (typeof window.rgOpenAdhoc === 'function') window.rgOpenAdhoc();
            else window.location.href = '/connections.html#adhoc';
        });
        brand.appendChild(b);
    }
    function removeAdhoc() { var b = document.getElementById('rg-adhoc'); if (b) b.parentNode.removeChild(b); }

    function input() { return document.getElementById('rg-search'); }
    function overlay() { return document.getElementById('search-overlay'); }

    // The index is cached per session so moving between pages is instant and
    // doesn't re-index. It is only re-fetched when the address book's version
    // changes (polled), which the connections page bumps when anything is
    // edited. The connections page itself always loads a fresh copy.
    var IDX_KEY = 'rustguac_search_index_v1', VER_KEY = 'rustguac_search_version_v1',
        WHO_KEY = 'rustguac_search_user_v1';
    var knownVersion = null, pollTimer = null, versionChecked = false;

    function dropCache() {
        try {
            sessionStorage.removeItem(IDX_KEY);
            sessionStorage.removeItem(VER_KEY);
            sessionStorage.removeItem(WHO_KEY);
        } catch (e) {}
        searchIndex = null; knownVersion = null;
        window.rgSearchIndex = null;
    }
    // The server no longer recognises the caller (401/403): forget everything
    // and take the box away. The page itself sends them to the login page.
    function signedOut() {
        dropCache();
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        var gs = document.getElementById('global-search'); if (gs) gs.parentNode.removeChild(gs);
        var ov = overlay(); if (ov) ov.parentNode.removeChild(ov);
        removeAdhoc();
        document.body.classList.remove('search-engaged');
        searchEngaged = false;
    }
    function rejected(r) { return r.status === 401 || r.status === 403; }

    function buildIndex(rows) {
        return rows.map(function (r) {
            var e = r.entry;
            var label = e.display_name || e.name;
            var host = e.session_type === 'web' ? (e.url || '')
                : e.session_type === 'vdi' ? (e.container_image || '')
                : e.session_type === 'proxmox' ? ((e.proxmox_url || '') + (e.proxmox_vmid ? ' · VM ' + e.proxmox_vmid : ''))
                : (e.hostname || '');
            // Every protocol's type and name, so "ssh" finds an RDP host that
            // also offers SSH (#296).
            var protos = (e.protocols && e.protocols.length) ? e.protocols : [e];
            var protoWords = protos.map(function (p) { return p.session_type + ' ' + (p.protocol || ''); }).join(' ');
            var haystack = [e.name, e.display_name || '', host, e.username || '', e.proxmox_token_id || '', e.url || '', e.domain || '', e.session_type, protoWords, r.folder_path].join(' ').toLowerCase();
            return { scope: r.scope, folderPath: r.folder_path, folderName: r.folder_display_name || null, entry: e, label: label, host: host, haystack: haystack };
        });
    }
    function applyIndex(idx) {
        searchIndex = idx;
        window.rgSearchIndex = idx;
        try { document.dispatchEvent(new CustomEvent('rg-search-index-ready')); } catch (e) {}
        var inp = input(); if (!inp) return;
        inp.placeholder = 'Search ' + idx.length + ' connection' + (idx.length === 1 ? '' : 's') + '…';
        inp.disabled = false;
        if (searchEngaged) runSearch();
    }
    function fetchIndex(version) {
        var inp = input();
        fetch('/api/addressbook/search-index', { headers: headers(), credentials: 'same-origin' })
            .then(function (r) {
                if (rejected(r)) { signedOut(); return null; }
                if (!r.ok) throw new Error('index');
                return r.json();
            })
            .then(function (data) {
                if (!data) return;
                var idx = buildIndex((data && data.entries) || []);
                applyIndex(idx);
                try {
                    sessionStorage.setItem(IDX_KEY, JSON.stringify(idx));
                    if (version != null) sessionStorage.setItem(VER_KEY, String(version));
                } catch (e) {}
                knownVersion = version;
            })
            .catch(function () { if (!searchIndex && inp) inp.placeholder = 'Search unavailable'; });
    }
    // Compare the server's address-book version with ours; fetch only on change.
    function checkVersion(cachedOk) {
        fetch('/api/addressbook/version', { headers: headers(), credentials: 'same-origin' })
            .then(function (r) {
                if (rejected(r)) { signedOut(); return false; }
                if (r.status === 404) return 'none';
                return r.ok ? r.json() : null;
            })
            .then(function (data) {
                if (data === false) return; // signed out: nothing more to do
                if (data === 'none') {
                    // No change counter on this server: nothing can tell a
                    // cached index it is stale, so load it fresh on each page
                    // (the cached copy is already painted) and do not poll.
                    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
                    if (!cachedOk || !versionChecked) fetchIndex(null);
                    versionChecked = true;
                    return;
                }
                if (!data || typeof data.version !== 'number') { if (!cachedOk) fetchIndex(null); return; }
                // The counter starts again at 0 when the server restarts, so a
                // version alone could match an index cached before the
                // restart: key the cache to the server process (epoch) too.
                var v = (data.epoch != null ? data.epoch + ':' : '') + data.version;
                if (cachedOk && String(v) === String(knownVersion)) return; // up to date
                fetchIndex(v);
            })
            .catch(function () { if (!cachedOk && !searchIndex) fetchIndex(null); });
    }
    // `who` is the identity /api/me answered with; a cached index left by a
    // different login in this tab is thrown away rather than shown.
    function loadIndex(who) {
        var cached = null;
        try {
            if (sessionStorage.getItem(WHO_KEY) !== who) dropCache();
            sessionStorage.setItem(WHO_KEY, who);
            var raw = sessionStorage.getItem(IDX_KEY);
            if (raw) { cached = JSON.parse(raw); knownVersion = sessionStorage.getItem(VER_KEY); }
        } catch (e) { cached = null; }
        if (cached && cached.length != null) applyIndex(cached);   // instant, no re-index flash
        checkVersion(!!cached);                                    // refresh only if changed
        if (!pollTimer) pollTimer = setInterval(function () { if (!document.hidden) checkVersion(true); }, 30000);
    }

    // The connections page's live refresh knows the moment the address book
    // changes; it calls this so the index is checked now rather than at the
    // next 30 s poll.
    window.rgSearchRecheck = function () { if (searchIndex) checkVersion(true); };

    function setEngaged(on) {
        if (searchEngaged === on) return;
        searchEngaged = on;
        var ov = overlay();
        ov.classList.toggle('open', on);
        ov.setAttribute('aria-hidden', on ? 'false' : 'true');
        if (on) runSearch();
    }
    function close() {
        var inp = input();
        if (inp) { inp.value = ''; inp.blur(); }
        document.getElementById('global-search').classList.remove('has-value');
        setEngaged(false);
    }

    function runSearch() {
        var inp = input(); if (!inp) return;
        var q = (inp.value || '').trim().toLowerCase();
        document.getElementById('global-search').classList.toggle('has-value', !!inp.value);
        if (!searchEngaged) return;
        var res = document.getElementById('search-results');
        if (!searchIndex) { res.innerHTML = '<p class="empty-state">Indexing connections…</p>'; return; }
        if (!q) {
            var all = searchIndex.map(function (row) { return { row: row, score: 0 }; });
            all.sort(function (a, b) {
                if (a.row.folderPath !== b.row.folderPath) return a.row.folderPath.localeCompare(b.row.folderPath);
                return a.row.label.localeCompare(b.row.label);
            });
            renderResults(all, '', []); return;
        }
        var tokens = q.split(/\s+/).filter(Boolean);
        var matches = [];
        for (var i = 0; i < searchIndex.length; i++) {
            var row = searchIndex[i], ok = true;
            for (var t = 0; t < tokens.length; t++) { if (row.haystack.indexOf(tokens[t]) === -1) { ok = false; break; } }
            if (!ok) continue;
            var first = tokens[0], lcL = row.label.toLowerCase(), lcN = row.entry.name.toLowerCase(), score = 0;
            if (lcL.indexOf(first) === 0 || lcN.indexOf(first) === 0) score += 100;
            else if (lcL.indexOf(first) !== -1 || lcN.indexOf(first) !== -1) score += 50;
            if ((row.host || '').toLowerCase().indexOf(first) !== -1) score += 20;
            if (row.folderPath.toLowerCase().indexOf(first) !== -1) score += 10;
            matches.push({ row: row, score: score });
        }
        matches.sort(function (a, b) {
            if (b.score !== a.score) return b.score - a.score;
            if (a.row.folderPath !== b.row.folderPath) return a.row.folderPath.localeCompare(b.row.folderPath);
            return a.row.label.localeCompare(b.row.label);
        });
        renderResults(matches, q, tokens);
    }

    function renderResults(matches, query, tokens) {
        var content = document.getElementById('search-results');
        searchFilters.update(matches.map(function (m) { return m.row; }));
        var all = matches;
        matches = matches.filter(function (m) { return searchFilters.apply([m.row]).length > 0; });
        var summary = document.getElementById('search-summary');
        var total = searchIndex ? searchIndex.length : all.length;
        if (!query) {
            summary.innerHTML = searchFilters.active()
                ? '<strong>' + matches.length + '</strong> of ' + total + ' connections'
                : 'All <strong>' + total + '</strong> connections';
        } else {
            summary.innerHTML = '<strong>' + matches.length + '</strong>' +
                (searchFilters.active() && all.length !== matches.length ? ' of ' + all.length : '') +
                ' match' + (matches.length === 1 ? '' : 'es') + ' for <strong>' + esc(query) + '</strong>';
        }
        if (matches.length === 0) {
            content.innerHTML = '<div class="empty-state"><p style="color:var(--text-dim);margin:0">' +
                (query ? (all.length ? 'No matches for ' + esc(query) + ' with the current filters' : 'No matches for ' + esc(query)) : 'No connections match the current filters') +
                '</p></div>';
            return;
        }
        var max = 50, more = matches.length - max, shown = matches.slice(0, max);
        var html = '<table class="entries-table search-results"><colgroup><col class="c-name"><col class="c-type"><col class="c-host"><col class="c-user"><col class="c-folder"><col class="c-actions"></colgroup>' +
            '<thead><tr><th>Name</th><th>Type</th><th>Host</th><th>User</th><th>Folder</th><th></th></tr></thead><tbody>';
        shown.forEach(function (m) {
            var r = m.row, e = r.entry;
            var typeLabel = e.session_type.toUpperCase();
            var typeCls = 'type-' + attr(e.session_type);
            var needsPrompt = (e.prompt_credentials || !e.has_credentials) && e.session_type !== 'web' && e.session_type !== 'proxmox';
            var connectLabel = needsPrompt ? 'Login…' : 'Connect';
            var userCol = e.session_type === 'proxmox' ? highlight(e.proxmox_token_id || '', tokens) : (e.username ? highlight(e.username, tokens) : '');
            var scopeIcon = r.scope === 'shared' ? '⊕' : '▣';
            var fName = r.folderName || r.folderPath;
            html += '<tr>' +
                '<td title="' + attr(r.label) + '">' + entryNameHtml(r.label, tokens) + '</td>' +
                '<td><span class="type-badge ' + typeCls + '">' + esc(typeLabel) + '</span>' + extraProtos(r, e) + '</td>' +
                '<td class="host-cell" title="' + attr(r.host || '') + '">' + highlight(r.host || '', tokens) + '</td>' +
                '<td>' + userCol + '</td>' +
                '<td class="folder-cell" title="' + attr(r.scope + '/' + r.folderPath) + '"><span class="fname"><span class="folder-scope">' + scopeIcon + '</span>' + highlight(fName, tokens) + '</span>' +
                (fName !== r.folderPath ? '<span class="fkey">' + highlight(r.folderPath, tokens) + '</span>' : '') + '</td>' +
                '<td class="actions-cell"><button class="btn-connect" data-sc-connect="' + attr(e.name) + '" data-scope="' + attr(r.scope) + '" data-folder="' + attr(r.folderPath) + '">' + connectLabel + '</button>' +
                '<button class="btn-connect btn-connect-win" title="Open in a new window" data-sc-connect="' + attr(e.name) + '" data-scope="' + attr(r.scope) + '" data-folder="' + attr(r.folderPath) + '">⧉</button>' +
                '<a href="#" class="search-open-folder" data-open-scope="' + attr(r.scope) + '" data-open-folder="' + attr(r.folderPath) + '" title="Open this folder">folder ↗</a></td>' +
                '</tr>';
        });
        html += '</tbody></table>';
        if (more > 0) html += '<div class="search-more">+' + more + ' more — refine your search to narrow results</div>';
        content.innerHTML = html;
        content.scrollTop = 0;
    }

    // The protocols after the primary, each a small button that connects
    // with it (#296).
    function extraProtos(r, e) {
        var ps = (e.protocols && e.protocols.length) ? e.protocols : [e];
        return ps.slice(1).map(function (p) {
            var nm = p.protocol || p.session_type;
            return ' <button class="type-badge type-' + attr(p.session_type) + '" style="cursor:pointer;border:0;opacity:0.8" title="Connect with ' + attr(nm) + '" data-sc-connect="' + attr(e.name) + '" data-scope="' + attr(r.scope) + '" data-folder="' + attr(r.folderPath) + '" data-protocol="' + attr(nm) + '">' + esc(p.session_type.toUpperCase()) + '</button>';
        }).join('');
    }
    // An entry's info for one protocol (none: the entry, i.e. its primary).
    function protoInfo(e, name) {
        if (!e || !name || !e.protocols) return e;
        for (var i = 0; i < e.protocols.length; i++) if (e.protocols[i].protocol === name) return e.protocols[i];
        return e;
    }
    function btnProtocol(btn) { return (btn && btn.getAttribute && btn.getAttribute('data-protocol')) || null; }

    // "Open in a new window" (⧉): open a sized popup synchronously (inside the
    // click, so it is not blocked) on the splash page /launch.html, which
    // measures its own viewport once laid out and posts it back. The caller
    // creates the session at exactly that size, so nothing resizes after the
    // first paint. A popup's size cannot be read from here right after
    // window.open — it reports the opener's size until the window is laid out
    // (that was the RDP resize on ⧉). Resolves {width,height} either way:
    // defaults if the popup was blocked, or after 2.5s if it never answers.
    function rgOpenSessionWindow(name) {
        var win = window.open('/launch.html?name=' + encodeURIComponent(name), '_blank',
            'width=1280,height=800,menubar=no,toolbar=no,location=no,status=no');
        var size = new Promise(function (resolve) {
            var done = false;
            function fin(w, h) {
                if (done) return; done = true;
                window.removeEventListener('message', onMsg); clearTimeout(cap);
                resolve({ width: w > 0 ? w : 1280, height: h > 0 ? h : 800 });
            }
            function onMsg(e) {
                if (e.origin !== location.origin || !e.data || e.data.rgLaunch !== 'size' || e.source !== win) return;
                fin(e.data.width, e.data.height);
            }
            var cap = null;
            if (!win) { fin(0, 0); return; }
            window.addEventListener('message', onMsg);
            cap = setTimeout(function () {
                var w = 0, h = 0; try { w = win.innerWidth; h = win.innerHeight; } catch (e) {}
                fin(w, h);
            }, 2500);
        });
        return { win: win, size: size };
    }
    window.rgOpenSessionWindow = rgOpenSessionWindow;

    // Connect to an entry: open the client in a window opened within this click
    // (keeps activation for fullscreen). Missing credentials send the user to
    // the connections page to set them.
    function doConnect(scope, folder, name, btn, newWindow) {
        // The ⧉ button gets a sized popup (measured, see above), a plain Connect a tab.
        var pop = newWindow ? rgOpenSessionWindow(name) : null;
        var win = pop ? pop.win : window.open('', '_blank');
        if (btn) { btn.classList.add('loading'); btn.disabled = true; }
        var reset = function () { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } };
        var body = { width: window.innerWidth, height: window.innerHeight, dpi: Math.round((window.devicePixelRatio || 1) * 96) };
        if (btnProtocol(btn)) body.protocol = btnProtocol(btn);
        // screen_* only for the tab path (the server prefers it for a
        // fullscreen bitmap entry); a popup is sized by its measurement alone.
        if (!newWindow && window.screen && screen.width) { body.screen_width = screen.width; body.screen_height = screen.height; }
        (pop ? pop.size : Promise.resolve(null)).then(function (sz) {
            if (sz) { body.width = sz.width; body.height = sz.height; }
            return fetch('/api/addressbook/folders/' + encodeURIComponent(scope) + '/' + encodeURIComponent(folder) + '/entries/' + encodeURIComponent(name) + '/connect',
                { method: 'POST', headers: headers({ 'Content-Type': 'application/json' }), credentials: 'same-origin', body: JSON.stringify(body) });
        })
            .then(function (res) {
                if (!res.ok) {
                    if (win && !win.closed) win.close();
                    if (res.status === 412) { openFolder(scope, folder); return null; }
                    return res.text().then(function (t) { throw new Error(t); });
                }
                return res.json();
            })
            .then(function (data) {
                if (!data) return;
                var _row = null, _si = searchIndex || [];
                for (var _k = 0; _k < _si.length; _k++) { var _r = _si[_k]; if (_r.scope === scope && _r.folderPath === folder && _r.entry.name === name) { _row = _r; break; } }
                var _pi = _row && protoInfo(_row.entry, btnProtocol(btn));
                var _fs = _pi && _pi.fullscreen_on_connect;
                // A new window is explicitly windowed: fs=0 tells the client
                // not to fullscreen-on-connect even if the entry asks for it.
                var url = data.client_url + '?name=' + encodeURIComponent(name) + (newWindow ? '&fs=0' : (_fs ? '&fs=1' : ''));
                if (win && !win.closed) win.location.href = url; else window.open(url, '_blank');
            })
            .catch(function () { if (win && !win.closed) win.close(); })
            .then(reset, reset);
    }
    // Zero-click fullscreen: a browser only lets the tab that holds the Connect
    // gesture go fullscreen, so for a fullscreen-on-connect entry we fullscreen
    // THIS tab now and load the session in a full-viewport iframe (the embedded
    // client fills it). No new tab, no second click. If the browser refuses
    // fullscreen the session still loads in the overlay, filling the tab.
    function rgLaunchFullscreen(scope, folder, name, btn) {
        var el = document.documentElement;
        var req = el.requestFullscreen || el.webkitRequestFullscreen || el.mozRequestFullScreen || el.msRequestFullscreen;
        // The session must be created at the viewport's FINAL size — the one
        // the frame will paint into — or the first picture is a fit of some
        // other size that the post-connect resize then snaps. That size cannot
        // be predicted: screen.width/height overshoot on a notched Mac (the
        // strip beside the camera is never part of a fullscreen viewport) and
        // the transition is asynchronous. So: enter fullscreen first, wait for
        // the viewport to stop changing, measure it, then connect. Refused (or
        // no Fullscreen API): the overlay fills the tab as it is, so measure
        // that straight away. Costs the transition time (~half a second)
        // before the connect request goes out; buys zero resizes.
        var fsState = null, frameReady = false;   // null = pending, true = entered, false = refused
        var started = false, settleTimer = null, lastW = 0, lastH = 0;
        var w0 = window.innerWidth, h0 = window.innerHeight, fsAt = 0;   // pre-fullscreen size
        function pushViewport() {
            if (!frameReady || fsState === null) return;
            var fr = document.getElementById('rg-session-frame');
            try { if (fr && fr.contentWindow) fr.contentWindow.postMessage({ rgLauncher: 'viewport', fullscreen: fsState }, location.origin); } catch (e) {}
        }
        // Connect once the viewport has held the same size for 150ms.
        function armSettle() {
            lastW = window.innerWidth; lastH = window.innerHeight;
            clearTimeout(settleTimer);
            settleTimer = setTimeout(function () {
                if (window.innerWidth !== lastW || window.innerHeight !== lastH) { armSettle(); return; }
                // Entered fullscreen but the viewport still has its windowed
                // size: the resize has not landed yet (some browsers fire
                // fullscreenchange first). Keep waiting, up to 1.5s.
                if (fsState === true && window.innerWidth === w0 && window.innerHeight === h0 && Date.now() - fsAt < 1500) { armSettle(); return; }
                startConnect();
            }, 150);
        }
        function onResize() { if (!started) armSettle(); }
        function fsRefused() { if (fsState === null) { fsState = false; pushViewport(); startConnect(); } }
        window.addEventListener('resize', onResize);
        if (req) {
            try { var fp = req.call(el); if (fp && fp.catch) fp.catch(fsRefused); } catch (e) { fsRefused(); }
            // No fullscreenchange within 3s (a browser that returns no promise
            // and never enters): treat as refused.
            setTimeout(fsRefused, 3000);
        } else fsRefused();
        var ov = document.createElement('div'); ov.id = 'rg-session-overlay';
        ov.innerHTML = '<div id="rg-session-spinner"></div>' +
            '<button id="rg-session-fs" class="rg-session-btn" type="button" title="Back to fullscreen" hidden>⛶ Fullscreen</button>' +
            '<button id="rg-session-exit" class="rg-session-btn" type="button" title="Leave the session">× Exit</button>' +
            '<iframe id="rg-session-frame" allow="fullscreen; clipboard-read; clipboard-write" title="Session"></iframe>';
        document.body.appendChild(ov);
        if (btn) { btn.classList.add('loading'); btn.disabled = true; }
        var done = false, enteredFs = false;
        function teardown() {
            if (done) return; done = true;
            window.removeEventListener('message', onMsg);
            window.removeEventListener('resize', onResize);
            clearTimeout(settleTimer);
            document.removeEventListener('fullscreenchange', onFsChange);
            var o = document.getElementById('rg-session-overlay'); if (o) o.remove();
            if (btn) { btn.classList.remove('loading'); btn.disabled = false; }
            try { if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen(); } catch (e) {}
        }
        function onMsg(e) {
            if (e.origin !== location.origin || !e.data) return;
            if (e.data.rgSession === 'ready') { var sp = document.getElementById('rg-session-spinner'); if (sp) sp.style.display = 'none'; frameReady = true; pushViewport(); }
            else if (e.data.rgSession === 'end') teardown();
        }
        function onFsChange() {
            if (document.fullscreenElement) {
                enteredFs = true;
                if (fsState === null) { fsState = true; fsAt = Date.now(); pushViewport(); }
                // Entered: the viewport may already be final or still animating;
                // the settle check covers both.
                if (!started) armSettle();
            }
            // Leaving fullscreen (Escape held, F11, the OS) keeps the session:
            // it carries on at the tab's size and the button takes it back
            // to fullscreen. Only Exit, or the session ending, closes it.
            else if (enteredFs) { showFsButton(true); }
            if (document.fullscreenElement) showFsButton(false);
        }
        function showFsButton(on) {
            var b = document.getElementById('rg-session-fs'); if (b) b.hidden = !on;
            if (!on) { var f = document.getElementById('rg-session-frame'); try { if (f) f.focus(); } catch (e) {} }
        }
        window.addEventListener('message', onMsg);
        document.addEventListener('fullscreenchange', onFsChange);
        document.getElementById('rg-session-exit').addEventListener('click', teardown);
        document.getElementById('rg-session-fs').addEventListener('click', function () {
            // A click is a fresh gesture, so the browser allows fullscreen again.
            try { var p = req && req.call(el); if (p && p.catch) p.catch(function () {}); } catch (e) {}
        });
        // Create the session at the measured viewport size — the size the
        // frame paints into — so there is nothing to resize afterwards.
        function startConnect() {
            if (started || done) return;
            started = true;
            clearTimeout(settleTimer);
            window.removeEventListener('resize', onResize);
            // Window size only: the measured viewport IS the fullscreen size.
            // No screen_width/height — the server prefers those for a
            // fullscreen bitmap session, and the physical screen overshoots
            // the viewport on a notched Mac (that was the RDP resize).
            var body = { dpi: Math.round((window.devicePixelRatio || 1) * 96), width: window.innerWidth, height: window.innerHeight };
            if (btnProtocol(btn)) body.protocol = btnProtocol(btn);
            fetch('/api/addressbook/folders/' + encodeURIComponent(scope) + '/' + encodeURIComponent(folder) + '/entries/' + encodeURIComponent(name) + '/connect',
                { method: 'POST', headers: headers({ 'Content-Type': 'application/json' }), credentials: 'same-origin', body: JSON.stringify(body) })
                .then(function (res) {
                    if (!res.ok) { if (res.status === 412) { teardown(); openFolder(scope, folder); return null; } return res.text().then(function (t) { throw new Error(t); }); }
                    return res.json();
                })
                .then(function (data) {
                    if (!data) return;
                    var fr = document.getElementById('rg-session-frame');
                    if (!fr) return;
                    fr.src = data.client_url + '?name=' + encodeURIComponent(name) + '&embedded=1';
                    // Fallback: hide the spinner if 'ready' never arrives.
                    setTimeout(function () { var sp = document.getElementById('rg-session-spinner'); if (sp) sp.style.display = 'none'; }, 8000);
                })
                .catch(function (err) { teardown(); if (window.rgAlert) rgAlert('Connect failed: ' + err.message); });
        }
        // Whatever happens, never leave the user on a spinner: connect at the
        // current size if nothing has settled it within 2.5s.
        setTimeout(startConnect, 2500);
    }
    window.rgLaunchFullscreen = rgLaunchFullscreen;

    function openFolder(scope, path) {
        if (typeof window.rgSelectFolder === 'function') { close(); window.rgSelectFolder(scope, path); return; }
        location.href = '/connections.html#open=' + encodeURIComponent(scope + '/' + path);
    }

    function wire() {
        var inp = input();
        inp.addEventListener('input', runSearch);
        inp.addEventListener('focus', function () { setEngaged(true); });
        // The overlay closes on any mousedown that is not on the search box
        // or inside the results panel (so the backdrop, the nav, the logo,
        // anywhere else all close it), and interacting with the results or
        // the box keeps it open. Capture phase so it runs before result
        // clicks are handled.
        document.addEventListener('mousedown', function (e) {
            if (!searchEngaged) return;
            var gs = document.getElementById('global-search');
            var panel = document.getElementById('search-overlay-panel');
            if ((gs && gs.contains(e.target)) || (panel && panel.contains(e.target))) return;
            close();
        }, true);
        document.getElementById('search-results').addEventListener('click', function (e) {
            var t = e.target;
            var open = t.closest && t.closest('.search-open-folder');
            if (open) { e.preventDefault(); openFolder(open.getAttribute('data-open-scope'), open.getAttribute('data-open-folder')); return; }
            var conn = t.closest && t.closest('[data-sc-connect]');
            if (conn) {
                e.preventDefault();
                var sc = conn.getAttribute('data-scope'), fo = conn.getAttribute('data-folder'), nm = conn.getAttribute('data-sc-connect');
                var row = null, si = searchIndex || [];
                for (var k = 0; k < si.length; k++) { if (si[k].scope === sc && si[k].folderPath === fo && si[k].entry.name === nm) { row = si[k]; break; } }
                var fsoc = row && row.entry && protoInfo(row.entry, btnProtocol(conn)).fullscreen_on_connect;
                // The regular Connect goes zero-click fullscreen in this tab; the
                // ⧉ button is an explicit "open in a new window", so it keeps the
                // new-window path.
                if (fsoc && !conn.classList.contains('btn-connect-win')) { close(); rgLaunchFullscreen(sc, fo, nm, conn); }
                else doConnect(sc, fo, nm, conn, conn.classList.contains('btn-connect-win'));
            }
        });
        // Escape closes the overlay from anywhere (not only the search box);
        // capture phase so it runs before page-level handlers. If a facet menu
        // is open inside the overlay, let filters.js close just that first.
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape') return;
            if (!searchEngaged && !overlay().classList.contains('open')) return;
            if (document.querySelector('#search-overlay .rg-facet.open')) return; // let the facet menu close first
            e.preventDefault(); e.stopPropagation(); close();
        }, true);
        // "/" focuses the search unless typing in a field or a modal is open.
        document.addEventListener('keydown', function (e) {
            if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return;
            var t = document.activeElement;
            if (t) { var tag = t.tagName; if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || t.isContentEditable) return; }
            if (document.querySelector('.modal-overlay.active')) return;
            if (inp.disabled) return;
            e.preventDefault(); e.stopPropagation();
            setTimeout(function () { inp.focus(); inp.select(); }, 0);
        });
    }

    var ROLE_LEVEL = { admin: 4, poweruser: 3, operator: 2, viewer: 1 };
    var MIN_LEVEL = 2; // the search endpoints answer operator and above

    // Who the served page says it is for. Missing (a static copy with no
    // server behind it) is unknown, not anonymous.
    function servedLevel() {
        var v = document.documentElement.getAttribute('data-role-level');
        return v == null || v === '' ? null : (parseInt(v, 10) || 0);
    }

    // Ask the server who the caller is. Resolves to an identity string, or
    // null when the caller is not signed in or is below operator.
    function whoAmI() {
        return fetch('/api/me', { headers: headers(), credentials: 'same-origin' })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (me) {
                if (!me || !me.role || (ROLE_LEVEL[me.role] || 0) < MIN_LEVEL) return null;
                confirmedLevel = ROLE_LEVEL[me.role];
                return (me.name || '') + '|' + me.role + '|' + (me.groups || []).join(',');
            })
            .catch(function () { return null; });
    }

    function start() {
        // Logout from any page: forget the index before the login page shows.
        document.addEventListener('click', function (e) {
            var t = e.target && e.target.closest ? e.target.closest('#logout-item') : null;
            if (t) dropCache();
        }, true);

        var level = servedLevel();
        // The server wrote anonymous or viewer on the page and no API key is in
        // hand: nothing to search with, nothing to show. Also sweep any index
        // a previous login left in this tab.
        if (level != null && level < MIN_LEVEL && !apiKey()) { dropCache(); return; }
        if (!document.querySelector('.brand-row')) return;

        // Operator or above by the server's word: paint the box now so the
        // header is right on first paint, and confirm the identity in the
        // background. Anyone else (API key, or a page with no role written on
        // it) is confirmed first and gets the box only on a yes.
        if (level != null && level >= MIN_LEVEL) {
            injectUI();
            injectAdhoc(level);
            whoAmI().then(function (who) {
                if (!who) { signedOut(); return; }
                // The server's answer wins over the page's.
                if (confirmedLevel < ADHOC_LEVEL) removeAdhoc(); else injectAdhoc(confirmedLevel);
                boot(who);
            });
        } else {
            whoAmI().then(function (who) {
                if (!who) { dropCache(); return; }
                injectUI();
                injectAdhoc(confirmedLevel);
                boot(who);
            });
        }
    }

    function boot(who) {
        // injectUI only creates the box when a .brand-row exists; without it
        // there is nothing to wire, so stand down rather than throw.
        if (!input()) return;
        var mkFilters = function () {
            searchFilters = window.rgFilters.create({
                mount: document.getElementById('search-facets'),
                id: 'global-search',
                facets: [
                    { key: 'type', label: 'Type', value: function (x) {
                        var e = x.entry, ps = (e.protocols && e.protocols.length) ? e.protocols : [e], out = [];
                        ps.forEach(function (p) { if (out.indexOf(p.session_type) < 0) out.push(p.session_type); });
                        return out;
                    },
                      render: function (v) { return '<span class="type-badge type-' + attr(v) + '">' + esc(v) + '</span>'; } },
                    { key: 'folder', label: 'Folder', value: function (x) { return x.folderPath || null; } }
                ],
                onChange: function () { runSearch(); }
            });
            wire();
            loadIndex(who);
        };
        if (window.rgFilters) { mkFilters(); }
        else {
            var s = document.createElement('script'); s.src = '/filters.js';
            s.onload = mkFilters; document.head.appendChild(s);
        }
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
})();
