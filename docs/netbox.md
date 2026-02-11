# NetBox Integration

rustguac integrates with [NetBox](https://netbox.dev/) to provide one-click remote console access from device pages. No NetBox plugin is required — the integration uses NetBox's built-in Custom Links, Custom Fields, and Event Rules.

**Note:** NetBox Custom Links use **Jinja2** template syntax. Filter arguments use parentheses — `default('ssh')` — not Django's colon syntax (`default:'ssh'`).

## Custom Fields

Go to **Customization > Custom Fields** and create the following fields. Assign each to **dcim > device** (and **virtualization > virtual machine** if you use VMs).

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `console_enabled` | Boolean | false | Opt-in: enables remote console links on the device page |
| `console_mode` | Selection: `addressbook`, `adhoc` | — | How to connect: via address book entry (Vault credentials) or ad-hoc (direct to IP) |
| `remote_protocol` | Selection: `ssh`, `rdp`, `vnc`, `web` | — | Protocol for ad-hoc connections (address book entries have their own) |
| `remote_port` | Integer | — | Port override for ad-hoc connections (leave blank for protocol default) |

The `console_enabled` field is the master switch — no links appear until it's checked. The `console_mode` field controls which link is shown:

- **`addressbook`** — connects via a Vault address book entry. Credentials are managed in Vault and never appear in the URL. Requires a matching entry name (lowercase device name). Minimum role: **operator**.
- **`adhoc`** — connects directly to the device's primary IP. No stored credentials — the user sees guacd's login prompt. Minimum role: **poweruser**.

## Custom Links

Create **two** Custom Links in **Customization > Custom Links**. Each link only renders when `console_mode` matches its mode, so only one appears per device.

### Link 1: Address Book Console (green)

| Setting | Value |
|---------|-------|
| Content Types | dcim > device, virtualization > virtual machine |
| Name | Console |
| Button class | Green |
| New window | Yes |

**Link text:**
```
{% if object.primary_ip4 and object.cf.console_enabled and object.cf.console_mode == 'addressbook' %}Console{% endif %}
```

**Link URL:**
```
https://console.example.com/api/connect?scope=shared&folder=production&entry={{ object.name | lower }}
```

Replace `production` with your address book folder name. The entry name must match the lowercase device name in Vault.

### Link 2: Ad-hoc SSH (blue outline)

| Setting | Value |
|---------|-------|
| Content Types | dcim > device, virtualization > virtual machine |
| Name | Quick SSH |
| Button class | Blue (outline) |
| New window | Yes |

**Link text:**
```
{% if object.primary_ip4 and object.cf.console_enabled and object.cf.console_mode == 'adhoc' %}Quick SSH{% endif %}
```

**Link URL:**
```
https://console.example.com/api/connect?hostname={{ object.primary_ip4.address.ip }}&protocol={{ object.cf.remote_protocol | default('ssh') }}&port={{ object.cf.remote_port | default('') }}
```

### Enabling on a device

1. Edit the device in NetBox
2. Check **Console Enabled**
3. Set **Console Mode** to `addressbook` or `adhoc`
4. (Ad-hoc only) Optionally set **Remote Protocol** and **Remote Port**
5. Save — the appropriate button appears on the device page

Use NetBox's **bulk edit** to enable across multiple devices at once.

### Role Requirements

| Mode | Minimum role | Description |
|------|-------------|-------------|
| Address book | operator | Connects via Vault entry (credentials from Vault) |
| Ad-hoc | poweruser | Creates session directly to hostname |

## Webhook-Driven Address Book Sync

Automatically sync NetBox devices to rustguac's Vault-backed address book using Event Rules and Webhooks. This keeps address book entries in sync with NetBox — when a device is created or updated, the corresponding entry is created in Vault.

### Filtering: control what syncs

Use Event Rule **conditions** to sync only the devices you want. You can filter by any combination of:

**By console_enabled field** (recommended):
```json
{
  "and": [
    {"attr": "status.value", "value": "active"},
    {"attr": "custom_fields.console_enabled", "value": true}
  ]
}
```

**By tag**:
```json
{
  "and": [
    {"attr": "status.value", "value": "active"},
    {"attr": "tags.slug", "op": "contains", "value": "remote-console"}
  ]
}
```

**By site**:
```json
{
  "and": [
    {"attr": "status.value", "value": "active"},
    {"attr": "site.slug", "value": "dc1"}
  ]
}
```

**By device role**:
```json
{
  "and": [
    {"attr": "status.value", "value": "active"},
    {"attr": "role.slug", "value": "server"}
  ]
}
```

### Create webhook: device created/updated

1. **Create an Event Rule** (**Operations > Event Rules**):
   - Name: `rustguac-sync-create`
   - Content Types: dcim > device
   - Events: Object created, Object updated
   - Conditions: your filter (see above)
   - Action type: Webhook

2. **Create the Webhook**:
   - Name: `rustguac-sync-create`
   - URL: `https://console.example.com/api/addressbook/folders/shared/netbox-sync/entries`
   - HTTP method: POST
   - HTTP content type: `application/json`
   - Additional headers:
     ```
     Authorization: Bearer <admin-api-key>
     ```
   - Body template:
     ```json
     {
       "name": "{{ data.name | lower | regex_replace('[^a-z0-9_.\\-]', '-') }}",
       "session_type": "{{ data.custom_fields.remote_protocol | default('ssh') }}",
       "hostname": "{{ data.primary_ip4.address | cut('/') }}",
       "port": {{ data.custom_fields.remote_port | default(22) }},
       "display_name": "{{ data.name }} ({{ data.site.name }})",
       "prompt_credentials": true
     }
     ```

### Create webhook: device deleted

1. **Create an Event Rule**:
   - Name: `rustguac-sync-delete`
   - Content Types: dcim > device
   - Events: Object deleted
   - Action type: Webhook

2. **Create the Webhook**:
   - Name: `rustguac-sync-delete`
   - URL: `https://console.example.com/api/addressbook/folders/shared/netbox-sync/entries/{{ data.name | lower | regex_replace("[^a-z0-9_.-]", "-") }}`
   - HTTP method: DELETE
   - Additional headers:
     ```
     Authorization: Bearer <admin-api-key>
     ```

### Folder setup

Before webhooks can create entries, create the target folder via the API:

```bash
curl -X POST https://console.example.com/api/addressbook/folders \
  -H "Authorization: Bearer <admin-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "scope": "shared",
    "name": "netbox-sync",
    "allowed_groups": ["network-ops", "sysadmins"],
    "description": "Auto-synced from NetBox"
  }'
```

## Shared SSO

Both NetBox and rustguac support OIDC authentication. When configured with the same OIDC provider (Authentik, Keycloak, Okta, etc.), users authenticate once and get sessions in both applications. The Custom Link in NetBox opens rustguac, which recognises the existing SSO session — no second login prompt.

## Example: Full Setup

1. Configure rustguac with OIDC (see [Integrations > OIDC](integrations.md))
2. Configure NetBox with the same OIDC provider
3. Create the four custom fields (`console_enabled`, `console_mode`, `remote_protocol`, `remote_port`)
4. Create the two Custom Links (Console green, Quick SSH blue)
5. On devices you want to enable: check `console_enabled`, set `console_mode`
6. For address book mode: ensure matching entries exist in Vault (manually or via webhook sync)
7. Users click the button on a device page and land in a session
