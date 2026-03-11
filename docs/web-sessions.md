# Web Browser Sessions

Web browser sessions give users a full Chromium browser running on the server, streamed to their own browser via the Guacamole protocol. Each session spawns a headless Xvnc display with Chromium in kiosk mode — the user sees and interacts with a real browser without installing anything locally.

This is useful for:

- **Controlled web access** — give operators access to specific internal web applications without exposing credentials or granting direct network access
- **Credential isolation** — passwords and session cookies stay server-side, never reaching the user's machine
- **Kiosk-style portals** — lock Chromium to a specific site with domain allowlisting
- **Automated login** — pre-fill credentials via native autofill or run a login script so the user lands on an authenticated page

## How it works

```
User's browser
    │
    │ WebSocket (Guacamole protocol)
    ▼
rustguac
    │
    │ Guacamole protocol (TCP/TLS)
    ▼
guacd
    │
    │ VNC to localhost
    ▼
Xvnc (virtual display :100–:199)
    │
    └── Chromium (kiosk mode, isolated profile)
            │
            └── https://target-app.example.com
```

1. rustguac allocates an X display number and spawns Xvnc
2. A unique Chromium profile directory is created (`/tmp/rustguac-chromium-{uuid}`)
3. Optionally, the autofill database is pre-populated with credentials
4. Chromium launches on the Xvnc display, navigating to the configured URL
5. guacd connects to the Xvnc display via VNC and streams it to the user
6. Optionally, a login script runs to automate complex login flows
7. When the session ends, Chromium and Xvnc are killed and the profile directory is deleted

## Quick start

### Address book entry

Create a web entry in the address book with at minimum:

| Field | Value |
|-------|-------|
| Type | `web` |
| URL | `https://your-app.example.com` |

Optionally add credentials for autofill or login scripts:

| Field | Value |
|-------|-------|
| Username | `operator@example.com` |
| Password | `secret` |

### API

```bash
curl -X POST https://rustguac.example.com/api/sessions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "web",
    "url": "https://your-app.example.com",
    "width": 1920,
    "height": 1080
  }'
```

### Network allowlist

By default, web sessions can only connect to localhost. To allow external URLs, add the target networks to `web_allowed_networks` in your config:

```toml
web_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12"]
```

This is a server-side CIDR check applied at session creation. The URL's hostname is resolved and every returned IP must match at least one allowed range. See [Domain allowlisting](#domain-allowlisting) for the separate client-side restriction.

## Native autofill

For simple login flows (a form with username and password fields), native autofill is the easiest approach. rustguac pre-populates Chromium's built-in password manager database before launch — no scripts, no external runtimes, no CDP.

When the user clicks on a login form, Chromium shows its familiar autofill dropdown with the pre-filled credentials.

### Configuring autofill

The `autofill` field on an address book entry is a JSON string containing an array of credential objects:

```json
[
  {
    "url": "https://your-app.example.com",
    "username": "$USERNAME",
    "password": "$PASSWORD"
  }
]
```

| Field | Description |
|-------|-------------|
| `url` | Origin URL that Chromium matches against the login form. Must include the scheme (`https://`). |
| `username` | Username to autofill. Use `$USERNAME` to substitute the entry's username field. |
| `password` | Password to autofill. Use `$PASSWORD` to substitute the entry's password field. |

The `$USERNAME` and `$PASSWORD` placeholders are resolved server-side from the entry's credentials before Chromium launches. You can also use literal values if the credentials differ from the entry's main username/password.

### Multiple autofill entries

For SSO redirect chains where the user is redirected from one site to an identity provider and back, add multiple entries:

```json
[
  {
    "url": "https://app.example.com",
    "username": "$USERNAME",
    "password": "$PASSWORD"
  },
  {
    "url": "https://idp.example.com",
    "username": "$USERNAME",
    "password": "$PASSWORD"
  }
]
```

Chromium will offer autofill on both domains.

### How it works internally

rustguac creates a Chromium profile directory before launch and writes to `Default/Login Data` (a SQLite database that Chromium uses for its password manager). Passwords are encrypted using Chromium's Linux `os_crypt` backend:

1. Derive a 16-byte AES key via PBKDF2 (password `"peanuts"`, salt `"saltysalt"`, 1 iteration, SHA-1)
2. Encrypt with AES-128-CBC, IV = 16 × `0x20` (space characters)
3. Store as `v10` prefix + ciphertext blob

This is Chromium's own obfuscation layer for the headless Linux case (no keyring). It is not a security boundary — the security boundary is that the profile directory is ephemeral (deleted on session end) and only accessible server-side.

### UI

In the address book entry editor, the **Autofill** section provides a visual builder. Click **"Add site"** to add credential rows. The URL field auto-populates with the entry's target URL. Save the entry and the UI serialises the rows to JSON.

## Domain allowlisting

Each address book entry can specify an `allowed_domains` list to restrict which websites the browser can reach. This is enforced inside Chromium via the `--host-rules` flag, which blocks DNS resolution for non-allowed domains.

### Configuring allowed domains

In the address book entry editor, expand the **Allowed Domains** section and add domain names:

```
example.com
cdn.example.com
```

Subdomains are automatically included — adding `example.com` also allows `*.example.com`. Localhost (`127.0.0.1`) is always allowed.

### Two-layer restriction

There are two separate mechanisms that control what a web session can access:

| Layer | Config | Applied | Scope |
|-------|--------|---------|-------|
| **`web_allowed_networks`** | `config.toml` (global) | Server-side, at session creation | CIDR ranges — controls which IPs rustguac will connect to |
| **`allowed_domains`** | Address book entry | Client-side, inside Chromium at runtime | Domain names — controls which sites the user can navigate to |

They don't conflict — both can be active simultaneously for defense in depth:

- `web_allowed_networks` prevents rustguac from initiating connections to disallowed networks (SSRF protection)
- `allowed_domains` prevents the user from navigating to sites outside the allowlist within an already-running session

**Example:** Your config allows `10.0.0.0/8` for web sessions (server-side). An address book entry for the internal wiki sets `allowed_domains: ["wiki.internal.example.com"]`. The session can only reach the wiki — even though the server-side allowlist permits the entire `10.0.0.0/8` range.

### API

```bash
curl -X POST https://rustguac.example.com/api/sessions \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "session_type": "web",
    "url": "https://wiki.internal.example.com",
    "allowed_domains": ["wiki.internal.example.com"]
  }'
```

## Login scripts

For complex login flows that native autofill can't handle (multi-step forms, CAPTCHAs, JavaScript-heavy SPAs, MFA prompts), login scripts provide full browser automation via the Chrome DevTools Protocol (CDP).

A login script is a server-side executable that connects to the already-running Chromium instance, performs login automation, then disconnects — leaving the user on an authenticated page.

### How it works

1. The address book entry specifies a `login_script` filename (e.g., `portal-login.js`)
2. When the session starts, Chromium is launched with `--remote-debugging-port={cdp_port}`
3. After Chromium is ready, rustguac spawns the script as a child process
4. The script connects to Chromium via CDP, performs automation, then exits
5. The user watches the automation live (it's all happening on the VNC display) and takes over the authenticated session

### Script interface

**Environment variables:**

| Variable | Description |
|----------|-------------|
| `DISPLAY` | X display number (e.g., `:100`) |
| `RUSTGUAC_CDP_PORT` | Chrome DevTools Protocol port (e.g., `9200`) |
| `RUSTGUAC_URL` | Target URL |
| `RUSTGUAC_USERNAME` | Username (empty string if not set) |
| `RUSTGUAC_PASSWORD` | Password (empty string if not set) |
| `RUSTGUAC_SESSION_ID` | Session UUID |

**Stdin (preferred for credentials):**

Credentials are also sent as JSON on stdin, which is more secure than environment variables (env vars are readable via `/proc/<pid>/environ` on Linux):

```json
{
  "username": "operator@example.com",
  "password": "secret",
  "url": "https://app.example.com",
  "cdp_port": 9200,
  "session_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Requirements:**

- The script must be in the `login_scripts_dir` directory (default: `/opt/rustguac/scripts`)
- The script must be executable (`chmod +x`)
- Path traversal is blocked — the filename is validated against the scripts directory
- Scripts have a timeout (default: 120 seconds, configurable via `login_script_timeout_secs`)
- Script failure is non-fatal — the session continues and the user can log in manually

### Example: Playwright login script

This example uses [Playwright](https://playwright.dev/) to automate a login flow. It reads credentials from stdin, connects to Chromium's CDP endpoint, fills a login form, and disconnects.

```javascript
#!/usr/bin/env node
// login-example.js — Playwright login script for rustguac
//
// Install: npm install playwright-core  (in /opt/rustguac/scripts or globally)
// The script uses playwright-core (no bundled browsers) since Chromium is
// already running — it connects via CDP rather than launching a new browser.

'use strict';

const { chromium } = require('playwright-core');

// ── Read credentials from stdin (secure) or env vars (fallback) ─────

async function getCredentials() {
    const stdinData = await readStdin();
    if (stdinData) {
        try {
            const creds = JSON.parse(stdinData);
            return {
                cdpPort:  creds.cdp_port,
                url:      creds.url,
                username: creds.username,
                password: creds.password,
            };
        } catch (e) {
            console.warn('[login] Failed to parse stdin, falling back to env vars');
        }
    }
    return {
        cdpPort:  parseInt(process.env.RUSTGUAC_CDP_PORT, 10),
        url:      process.env.RUSTGUAC_URL || '',
        username: process.env.RUSTGUAC_USERNAME || '',
        password: process.env.RUSTGUAC_PASSWORD || '',
    };
}

function readStdin() {
    return new Promise((resolve) => {
        const chunks = [];
        const timer = setTimeout(() => {
            process.stdin.destroy();
            resolve(chunks.join(''));
        }, 1000);
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (chunk) => chunks.push(chunk));
        process.stdin.on('end', () => { clearTimeout(timer); resolve(chunks.join('')); });
        process.stdin.on('error', () => { clearTimeout(timer); resolve(''); });
        process.stdin.resume();
    });
}

// ── Connect to Chromium CDP with retry ──────────────────────────────

async function connectCDP(port, timeoutMs = 15000) {
    const url = `http://127.0.0.1:${port}`;
    const deadline = Date.now() + timeoutMs;
    let lastErr;
    while (Date.now() < deadline) {
        try {
            return await chromium.connectOverCDP(url);
        } catch (e) {
            lastErr = e;
            await new Promise(r => setTimeout(r, 500));
        }
    }
    throw new Error(`CDP not ready on port ${port}: ${lastErr?.message}`);
}

// ── Main ────────────────────────────────────────────────────────────

async function main() {
    const creds = await getCredentials();
    if (!creds.cdpPort) {
        console.error('[login] No CDP port — exiting');
        process.exit(1);
    }

    console.log(`[login] Connecting to CDP on port ${creds.cdpPort}...`);
    const browser = await connectCDP(creds.cdpPort);
    const page = browser.contexts()[0]?.pages()[0];
    if (!page) {
        console.error('[login] No page found');
        await browser.close();
        process.exit(1);
    }

    // Wait for the page to load (Chromium may still be navigating)
    await page.waitForLoadState('domcontentloaded', { timeout: 15000 }).catch(() => {});

    // ── Automate your login flow here ───────────────────────────────
    //
    // This example fills a simple username/password form.
    // Adapt the selectors and steps for your target application.

    // Fill the login form
    await page.fill('#username', creds.username);
    await page.fill('#password', creds.password);

    // Submit
    await page.click('button[type="submit"]');

    // Wait for navigation to confirm login succeeded
    try {
        await page.waitForURL('**/dashboard**', { timeout: 10000 });
        console.log('[login] Login successful');
    } catch {
        console.error('[login] Login may have failed — user can retry manually');
    }

    // Disconnect CDP — browser stays running for the user
    await browser.close();
}

main().catch((err) => {
    console.error(`[login] Error: ${err.message}`);
    process.exit(1);
});
```

**To use this script:**

1. Save it to `/opt/rustguac/scripts/login-example.js`
2. Make it executable: `chmod +x /opt/rustguac/scripts/login-example.js`
3. Install Playwright: `cd /opt/rustguac/scripts && npm install playwright-core`
4. Set the `login_script` field on an address book entry to `login-example.js`

### Example: Shell script with curl

Not every login needs a browser automation framework. If the target app accepts form POSTs, a shell script can set cookies directly:

```bash
#!/bin/bash
# login-cookie.sh — Set auth cookies in Chromium via CDP
#
# For apps where logging in is a simple POST that returns a session cookie.
# This approach is faster than Playwright but only works for basic form logins.

set -euo pipefail

# Read credentials from stdin JSON
CREDS=$(cat)
CDP_PORT=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['cdp_port'])")
USERNAME=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['username'])")
PASSWORD=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['password'])")
URL=$(echo "$CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['url'])")

# POST login form and capture cookies
COOKIES=$(curl -s -c - -X POST "$URL/api/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  2>/dev/null | grep -v '^#')

# Set each cookie in Chromium via CDP
# (This uses the CDP Network.setCookie command via the /json/protocol endpoint)
echo "[login] Cookies captured, injecting into browser..."

# Navigate Chromium to trigger a reload with the new cookies
# The user lands on the authenticated page
echo "[login] Done — user should see authenticated page"
```

### Combining autofill and login scripts

Autofill and login scripts can be used together on the same entry:

- **Autofill** pre-populates the password manager — useful if the script fails or for subsequent logins during the session
- **Login script** automates the initial login flow — handles complex cases like MFA, JavaScript-heavy forms, or multi-step wizards

The autofill database is written before Chromium launches, and the login script runs after. They don't interfere with each other.

### Configuration

| Config key | Default | Description |
|------------|---------|-------------|
| `login_scripts_dir` | `/opt/rustguac/scripts` | Directory containing login scripts |
| `login_script_timeout_secs` | `120` | Maximum script runtime before it's killed |
| `cdp_port_range_start` | `9200` | First CDP port in the allocation pool |
| `cdp_port_range_end` | `9299` | Last CDP port |

## Clipboard control

Clipboard copy and paste can be independently disabled per address book entry. This uses guacd's native `disable-copy` and `disable-paste` parameters.

| Field | Effect |
|-------|--------|
| `disable_copy` | Prevents server → client clipboard transfer (data loss prevention) |
| `disable_paste` | Prevents client → server clipboard transfer (prevents pasting malicious content) |

These work for all session types (SSH, RDP, VNC, Web), not just web sessions. See [Security: Clipboard control](security.md#clipboard-control) for details.

## URL placeholders

The entry URL supports credential placeholders that are URL-encoded and substituted before Chromium navigates:

```
https://app.example.com/login?user=$RUSTGUAC_USERNAME&pass=$RUSTGUAC_PASSWORD
```

| Placeholder | Substituted with |
|-------------|-----------------|
| `$RUSTGUAC_USERNAME` | Entry username (URL-encoded) |
| `$RUSTGUAC_PASSWORD` | Entry password (URL-encoded) |

This is useful for applications that accept credentials as URL parameters (e.g., some IPMI/KVM web consoles).

## SSH tunnels for web sessions

Web sessions support [multi-hop SSH tunnel chains](overview.md#ssh-tunnel--jump-hosts) to reach targets on isolated networks. When jump hosts are configured:

1. An SSH tunnel chain is established through the bastion hosts
2. The final hop forwards to the URL's host and port
3. The URL is rewritten to `{scheme}://127.0.0.1:{tunnel_port}{path}` before being passed to Chromium

**Note:** HTTPS targets will show certificate warnings when tunnelled, because the hostname changes from the original to `127.0.0.1`. The original URL is still displayed in the session list.

## Chromium security hardening

Every web session runs Chromium with a comprehensive managed policy and an isolated profile. See [Security: Web session hardening](security.md#web-session-hardening) for the full policy table.

**Warning:** The Chromium managed policy is installed globally at `/etc/chromium/policies/managed/rustguac.json`. This affects **all** Chromium instances on the machine — not just rustguac sessions. Do not install rustguac on a desktop machine where you want to use Chromium for normal browsing. rustguac is designed to run on a dedicated server or VM.

Key restrictions:

- DevTools UI is blocked by URL filter (`chrome://*` is in URLBlocklist), downloads, printing, and file dialogs are disabled
- Extensions cannot be installed
- Dangerous URL schemes (`file://`, `chrome://`, `javascript:`) are blocked
- Browser sign-in and sync are disabled
- Each session gets a fresh UUID-based profile directory, deleted on session end
- Chromium runs with its normal SUID sandbox (no `--no-sandbox`)

## API reference

### Create a web session

```
POST /api/sessions
```

```json
{
  "session_type": "web",
  "url": "https://app.example.com",
  "username": "operator",
  "password": "secret",
  "width": 1920,
  "height": 1080,
  "autofill": "[{\"url\":\"https://app.example.com\",\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}]",
  "allowed_domains": ["app.example.com"],
  "login_script": "my-login.js",
  "disable_copy": false,
  "disable_paste": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_type` | string | Yes | Must be `"web"` |
| `url` | string | Yes | Target URL (`http://` or `https://`) |
| `username` | string | No | Username for autofill/script substitution |
| `password` | string | No | Password for autofill/script substitution |
| `width` | integer | No | Browser width in pixels (default: 1920, range: 640–8192) |
| `height` | integer | No | Browser height in pixels (default: 1080, range: 480–8192) |
| `dpi` | integer | No | Display DPI (default: 96) |
| `autofill` | string | No | JSON array of autofill credentials (see [Native autofill](#native-autofill)) |
| `allowed_domains` | array | No | Domain allowlist (see [Domain allowlisting](#domain-allowlisting)) |
| `login_script` | string | No | Script filename in `login_scripts_dir` |
| `disable_copy` | boolean | No | Disable clipboard copy (default: false) |
| `disable_paste` | boolean | No | Disable clipboard paste (default: false) |
| `jump_hosts` | array | No | SSH tunnel hops (see [SSH tunnels](#ssh-tunnels-for-web-sessions)) |

### Address book entry fields

When creating entries via the Vault address book (UI or API), the same fields are available:

```json
{
  "type": "web",
  "url": "https://app.example.com",
  "username": "operator",
  "password": "secret",
  "display_name": "Internal App",
  "autofill": "[{\"url\":\"https://app.example.com\",\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}]",
  "allowed_domains": ["app.example.com"],
  "login_script": "my-login.js",
  "disable_copy": false,
  "disable_paste": false,
  "enable_recording": true
}
```

## Troubleshooting

**Autofill dropdown doesn't appear:**
- Verify the `url` in the autofill JSON matches the login form's origin (scheme + host + port). For example, `https://app.example.com` won't match a form at `https://app.example.com:8443`.
- Check that the autofill JSON is valid — the server logs a warning if parsing fails.
- Ensure the entry has a username and password set (the `$USERNAME`/`$PASSWORD` placeholders need values to substitute).

**Domain blocking is too strict:**
- Remember that subdomains are automatically included — adding `example.com` allows `*.example.com`.
- CDN domains may need to be added separately (e.g., `cdn.example.com`, `fonts.googleapis.com`).
- Check the browser's address bar — if it shows "This site can't be reached", the domain is being blocked.

**Login script doesn't run:**
- The script must be executable: `chmod +x /opt/rustguac/scripts/my-script.js`
- Check the `login_scripts_dir` config points to the right directory.
- Check rustguac logs for `[login-script]` messages — script stdout/stderr is captured.
- The script has a timeout (default 120s). Increase `login_script_timeout_secs` if needed.

**Browser shows a blank white screen:**
- The Xvnc display may not be ready. Check logs for Xvnc startup errors.
- Verify `chromium_path` and `xvnc_path` in the config point to valid binaries.
- Ensure the `rustguac` system user has a real home directory (`/home/rustguac`) — Chromium's crashpad handler crashes without one.

**"Controlled by automated test software" banner:**
- This appears when `allowed_domains` is set, because `--enable-automation` is used to suppress a different infobar about `--host-rules`. The banner is cosmetic and does not affect functionality.

**Certificate errors when using SSH tunnels:**
- Expected behaviour. When tunnelling, the URL is rewritten to `127.0.0.1:{port}`, which won't match the target's TLS certificate. The user can click through the warning or use HTTP if the tunnel is trusted.
