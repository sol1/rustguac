# Roles and Access Control

## Roles and permissions

Every check on the server asks for a **permission**, and a role is a named set of permissions. There are four built-in roles, each granting everything the one below it does:

| Role | Adds | Description |
|------|------|-------------|
| **viewer** | `docs.view` | Read the docs. Can sign in, but can't open Connections. |
| **operator** | `connections.connect`, `credentials.self` | Open Connections and connect to entries in folders they can access, and save their own credential variables. |
| **poweruser** | `connections.adhoc`, `recordings.view`, `reports.view`, `tokens.self` | Ad-hoc connections (**Connect to a host**), recordings, reports, and their own API tokens. |
| **admin** | every permission | Everything, including any permission added in a later release. |

The permissions and what they allow:

| Permission | Allows |
|---|---|
| `connections.connect` | See folders and entries in Connections, connect to them, and list and end your own sessions and VDI containers |
| `credentials.self` | Save your own credential variables |
| `connections.adhoc` | Ad-hoc sessions to any host, ad-hoc `/api/connect` links, and the SSH host-key probe they use |
| `recordings.view` | List and play recordings and typescripts |
| `reports.view` | Reports |
| `tokens.self` | Create and revoke your own API tokens |
| `connections.edit` | Create, edit, move, copy and delete entries and folders, and folder default credentials. Sees and connects to every folder |
| `folders.manage_access` | Change who can open a folder (anyone with this can give themselves any folder) |
| `connections.unrestricted` | Ad-hoc and link sessions skip the [ad-hoc policy](api.md#post-apisessions) |
| `sessions.view_all` | See, thumbnail and end anyone's session |
| `sessions.shadow` | Shadow someone else's session |
| `recordings.delete` | Delete recordings |
| `admin.users` | Manage users and the API tokens issued to them |
| `admin.roles` | Set users' roles, and manage group-to-role mappings |
| `admin.audit` | Audit logs |
| `admin.system` | Detailed system status |
| `docs.view` | Documentation |

`GET /api/me` returns the caller's `roles` and `permissions`.

### Custom roles

Admins can build their own roles from these permissions: **Admin > Roles**, the API, or the CLI. A custom role can be assigned to users, mapped from OIDC groups, and used to cap API tokens, just like a built-in. The Roles section offers two starting points, both editable before saving:

| Template | Permissions | For |
|---|---|---|
| Connection editor | `connections.connect`, `connections.edit`, `credentials.self`, `docs.view` | Managing connections site wide, without folder access settings, reports, recordings or admin |
| Connect only | `connections.connect` | Contractors who only see the folders they're given and connect. Entries they use need stored or prompted credentials, since they can't save their own. |

Rules that keep this safe:

- **Nobody can grant what they don't hold.** A role, a role assignment, a group mapping or a token cap is refused if it would grant a permission the person making the change doesn't have.
- **Nobody changes their own role**, or edits or deletes a role they're using.
- **Nobody disables or deletes a user who holds more than they do.**
- **The last way to manage roles is kept.** A change that would leave no enabled admin API key and no enabled user holding `admin.roles` is refused.
- **Built-in roles can't be changed**, and their names (in any case) can't be used for custom roles.
- **A role in use can't simply be deleted.** Its users, group mappings and token caps have to move to another role first (the Admin page offers this; the CLI has `--reassign-to`). The role set as `[oidc] default_role` can't be deleted.
- **New permissions are off for custom roles.** A permission added in a later release isn't granted to any custom role until an admin adds it. `admin` gets every permission automatically.

Role names are lowercase letters, digits, `-` and `_`, and can't be changed after creation; the display name can.

### Seeing what someone can do

**Admin > Users > access** shows a user's own role, which group mappings apply to them (with their groups as of their last login), the roles in effect, and which role grants each permission. The same is available as `GET /api/users/{email}/access` and `rustguac show-user --email ...`.


## Authentication paths

rustguac supports three authentication methods, tried in order: admin API key, user API token, OIDC session cookie.

### API key admins

API key holders always have full **admin** access (level 4). There is no way to restrict an API key to a lower role. API keys are intended for automation, CI/CD, and system administration.

```bash
# Create an API key admin
rustguac add-admin --name automation

# With IP restrictions and expiry
rustguac add-admin --name ci-bot \
  --allowed-ips "10.0.0.0/8,192.168.1.0/24" \
  --expires "2026-12-31T00:00:00Z"
```

`--if-none` creates the admin only when no admin account exists yet, and otherwise exits successfully without creating anything. It is meant for first-run provisioning, such as a container entrypoint, and works wherever `db_path` points:

```bash
rustguac add-admin --name docker-admin --if-none
```

### User API tokens

User API tokens authenticate as the OIDC user who owns the token, with an effective role capped by the token's `max_role`. Tokens use the same `Authorization: Bearer <token>` header as admin API keys — rustguac tries admin keys first, then user tokens. See [User API tokens](#user-api-tokens) below for details.

### OIDC users

OIDC users are assigned a role through three mechanisms (in order of precedence):

1. **Group-to-role mappings** — evaluated on every OIDC login. If the user's OIDC groups match any mappings, the highest matching role is applied.
2. **Manual role assignment** — admins can set a user's role via CLI, API, or the Admin page.
3. **Default role** — new users get the `default_role` from OIDC config on first login (default: `operator`).

#### Only users you have added

With `auto_create_users = false` in `[oidc]`, rustguac does not create accounts on login: a user must be added first with `rustguac add-user --email <email> --role <role>`, `POST /api/users`, or **Add User** on the Admin page. Anyone else who authenticates with the identity provider is sent back to the login page with "You do not have an account here". The role the admin chose is kept; `default_role` is not applied, but group-to-role mappings still are.

```bash
rustguac add-user --email jsmith@example.com --role operator --name "J Smith"
```

Emails are matched ignoring case, so it does not matter whether the provider sends `JSmith@Example.com` or `jsmith@example.com`, and two users cannot differ only in case.

#### How a login is matched to a user

Users are found by email, but an email on its own is not proof of who someone is: some identity providers let people set or change their own address. So the first time a user logs in, rustguac records their provider account's **subject** (the OIDC `sub` claim, a permanent ID the provider never reuses), and from then on that user can only be signed in as by that same provider account. A login with the same email but a different subject is refused with "This sign-in does not match the account used here before", and logged as a warning. This applies whether or not `auto_create_users` is on.

A user an admin added who has not logged in yet has no subject, so their first login records it.

rustguac also refuses a login when the provider explicitly marks the email as unverified (`email_verified: false`), with "Your identity provider says your email address is not verified" on the login page and a warning in the log. Providers that do not send the claim are trusted as before.

Some providers send `false` for everyone. authentik's default `email` mapping does, so every login is refused until the mapping is changed; the [Authentik setup guide](integrations.md#authentik-setup-guide) has a mapping that marks it verified. Where the provider can't be changed, `allow_unverified_email = true` under `[oidc]` accepts these logins. Only do that if users can't set their own email at the provider: a user an admin added who has never logged in has no subject yet, so whoever the provider gives that email first gets the account. rustguac logs a warning at startup while it is on.

#### Moving to a different identity provider

Every user's subject changes when you switch providers (for example from JumpCloud to Entra ID), so after the switch everyone would be refused. Clear each user's recorded subject and their next login records the new one:

```bash
rustguac reset-oidc-subject --email jsmith@example.com
```

Their role, group mappings, tokens and credentials are kept. This is CLI-only on purpose: it needs shell access to the rustguac host, and each use is written to the CLI audit log. The same command fixes a single user whose provider account was deleted and recreated.

## Endpoint access control

### Session management

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/sessions` | poweruser | Create ad-hoc sessions. Non-admins get the [ad-hoc policy](security.md#ad-hoc-sessions-from-non-admins) |
| `GET /api/sessions` | operator | List all sessions |
| `GET /api/sessions/:id` | operator | View session details |
| `DELETE /api/sessions/:id` | operator | Non-admins can only delete their own sessions |

### Connections

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/addressbook/folders` | operator | Filtered by OIDC group membership |
| `GET /api/addressbook/folders/:scope/:folder/entries` | operator | Requires folder group access |
| `POST .../entries/:entry/connect` | operator | Creates session from connections entry |
| `POST /api/addressbook/adhoc/connect` | poweruser | Ad-hoc connection described as an entry (Connect to a host); the caller's own credential variables only, no folder defaults. Works without Vault |
| `POST /api/addressbook/folders` | admin | Create folders |
| `PUT /api/addressbook/folders/:scope/:folder` | admin | Update folder config |
| `DELETE /api/addressbook/folders/:scope/:folder` | admin | Delete folders |
| `POST .../entries` | admin | Create entries |
| `PUT .../entries/:entry` | admin | Update entries |
| `DELETE .../entries/:entry` | admin | Delete entries |

### Recordings

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/recordings` | operator | List recordings |
| `GET /api/recordings/:name` | operator | Download/play recording |
| `DELETE /api/recordings/:name` | admin | Delete recording |

### User management

| Endpoint | Required role |
|----------|--------------|
| `GET /api/users` | admin |
| `POST /api/users` | admin |
| `PUT /api/users/:email/role` | admin |
| `DELETE /api/users/:email` | admin |
| `POST /api/users/:email/disable` | admin |
| `POST /api/users/:email/enable` | admin |
| `DELETE /api/users/:email/sessions` | admin |

### Group-to-role mappings

| Endpoint | Required role |
|----------|--------------|
| `GET /api/admin/group-mappings` | admin |
| `POST /api/admin/group-mappings` | admin |
| `PUT /api/admin/group-mappings/:id` | admin |
| `DELETE /api/admin/group-mappings/:id` | admin |

### User API tokens (self-service)

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/me/tokens` | poweruser | Create a personal API token |
| `GET /api/me/tokens` | operator | List own tokens (metadata only) |
| `DELETE /api/me/tokens/:id` | poweruser | Revoke own token |

Operators can view their tokens (created by an admin on their behalf) but cannot create or revoke them.

### User API tokens (admin)

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/admin/user-tokens` | admin | Create token for any user |
| `GET /api/admin/user-tokens` | admin | List all user tokens |
| `DELETE /api/admin/user-tokens/:id` | admin | Revoke any user token |
| `GET /api/admin/token-audit` | admin | View token audit log |

### Public endpoints

| Endpoint | Auth required | Notes |
|----------|--------------|-------|
| `GET /api/health` | None | Always returns 200 |
| `GET /api/auth/status` | None | Returns OIDC enabled status |
| `GET /api/me` | Any authenticated | Returns current user info |
| `GET /api/docs` | `docs.view` | The documentation shown on the Docs page. Needed no login before 1.14 |

## Folder access control

Each Connections folder decides who can see it, in its `.config` entry in Vault:

- `allowed_groups`: OIDC groups that can see the folder.
- `allowed_users`: individual users who can see the folder, by login email (compared without regard to case). A user does not need to have logged in before being listed: access is checked from their identity when they use rustguac.

A user can see a folder if any of their groups is in `allowed_groups` **or** their email is in `allowed_users`.

- **Admins**, and anyone with `connections.edit`, bypass these checks and see all folders.
- **Everyone else** sees only folders that grant them access.
- If both lists are empty, the folder is visible only to admins and connection editors.
- Changing `allowed_groups`, `allowed_users` or `inherit_from_parent` needs `folders.manage_access`. Without it, a new top-level folder starts with both lists empty and a new subfolder inherits its parent's access.
- Folders the user cannot access are **hidden** from the tree, not shown-then-denied. This applies at every level, including subfolders.
- A folder the user cannot access is still shown if it leads to a subfolder they can, so a deeper grant is never orphaned out of the tree. Its own entries stay hidden; the user opens the subfolder. For example, a folder `users/jsmith` shared with `jsmith@example.com` shows `users` in jsmith's tree even if `users` itself is admin-only.
- The list of allowed users is only shown to admins. A user who can open a folder does not see who else can.

Because folder settings live in Vault, they apply on every rustguac instance sharing that Vault.

### Inheritance

A subfolder created with `inherit_from_parent: true` (the default for new subfolders) grants access to anyone who can access its parent. A subfolder with `inherit_from_parent: false` is gated solely by its own `allowed_groups` and `allowed_users`, independent of the parent.

The same rules bound [folder default credentials](credential-variables.md#folder-default-credentials): defaults set on a parent flow only into a subfolder that inherits and grants no groups or users of its own. Isolating a folder, or sharing it with anyone the parent doesn't include, keeps the parent's secrets out of it.

### Examples

A folder with `allowed_groups: ["engineering", "devops"]`:
- A user with OIDC groups `["engineering", "marketing"]` **can** access it (engineering matches)
- A user with OIDC groups `["marketing", "sales"]` **cannot** access it (no match)
- An admin **can** always access it regardless of groups

A folder per user, for example a personal VM:
```json
{ "allowed_groups": [], "allowed_users": ["jsmith@example.com"] }
```
Only jsmith (and admins) can see it. Create it with `POST /api/addressbook/folders`, add the VM as an entry, and jsmith finds it in Connections on their first login.

## Group-to-role mappings

Admins can configure automatic role assignment based on OIDC group membership. This is managed in the Admin page, via the API, or with the `map-group` CLI command.

### How it works

1. When a user logs in via OIDC, their group memberships are extracted from the JWT and recorded.
2. Their groups are checked against the `group_role_mappings` table.
3. If any groups match, the user gets **every role** their groups map to (the union of those roles' permissions), and those replace the role set on the user.
4. If no groups match, the user's own role applies.

For the built-in roles, the union is the same as the highest matching role, which is how mappings have always resolved. Permissions are worked out on each request from the groups recorded at the user's last login and the current mappings, so a mapping change applies straight away; a change to someone's groups at the identity provider applies at their next login. At login rustguac still records a single role on the user (the highest matching built-in, or the first matching custom role by name), which is what an older release would read after a downgrade.

### Example

| OIDC Group | Mapped Role |
|-----------|-------------|
| `sysadmin` | admin |
| `engineering` | poweruser |
| `support` | operator |

A user with groups `["engineering", "support"]` gets everything `poweruser` and `operator` grant, which is `poweruser`. With custom roles the union adds up: a user in both a `reporter` group and a `recordings` group gets both roles' permissions.

### Managing mappings from the CLI

```bash
# Map a group to a role
rustguac map-group --group sysadmin --role admin

# Change the role an existing group maps to
rustguac map-group --group sysadmin --role poweruser --force

# Roles must be one of: admin, poweruser, operator, viewer
```

Each OIDC group can hold only one mapping. Running `map-group` against a group that is already mapped to a *different* role leaves the existing mapping untouched and exits non-zero, so an unattended provisioning run cannot silently change who has access:

```
$ rustguac map-group --group sysadmin --role admin
Group 'sysadmin' is already mapped to role 'poweruser'. Re-run with --force to change it to 'admin'.
```

Add `--force` to change it. Mapping a group to the role it already has is a no-op and exits zero, so repeated runs of the same provisioning script are safe.

Mappings are applied during OIDC login, not at the moment you create them. A user who is already signed in keeps their current role until their next login. This cuts both ways: granting a role does not take effect immediately, and neither does lowering one, so to revoke access straight away change the mapping *and* disable the user or end their sessions.

Mappings created this way are identical to those made in the Admin page or through the API, and are listed alongside them.

## User API tokens

User API tokens allow OIDC users to authenticate via bearer token for automation and scripting (e.g., creating ad-hoc sessions via CI/CD, or integrating with monitoring tools).

### Who can create tokens

| User role | Self-service | Admin creates for them |
|-----------|-------------|----------------------|
| admin | Yes | Yes |
| poweruser | Yes | Yes |
| operator | No | Yes |
| viewer | No | No |

The primary use case is powerusers creating tokens for service account automation, and admins creating tokens for select operators who need API access.

### Effective role

Each token has an optional `max_role` cap, a built-in or custom role. A token gets only the permissions both its owner and its cap allow:

```
token permissions = user's current permissions ∩ permissions of max_role
```

This means:
- A poweruser who creates a token with `max_role: operator` gets operator-level access when using that token
- If an admin later demotes the user to operator, the token's effective access drops accordingly
- The `max_role` can never grant more access than the user currently has, and a cap can only be a role granting nothing beyond what its owner holds

### Token management UI

- **Tokens page** (`/tokens.html`) — self-service for powerusers and admins to create, view, and revoke their own tokens. Operators can view tokens created for them.
- **Admin page** (`/admin.html`) — admins can create tokens for any user, view all tokens across all users, revoke any token, and view the audit log.

## User management CLI

```bash
# List all OIDC users
rustguac list-users

# Add a user ahead of their first login (needed with auto_create_users = false)
rustguac add-user --email user@example.com --role operator --name "A User"

# Forget the identity provider account a user is bound to, after a provider
# migration or a recreated provider account (see "Moving to a different
# identity provider" above)
rustguac reset-oidc-subject --email user@example.com

# Set a user's role
rustguac set-role --email user@example.com --role poweruser

# Disable a user (blocks login)
rustguac disable-user --email user@example.com

# Delete a user
rustguac delete-user --email user@example.com
```

Re-enabling a disabled user is done from the Admin page or the API (`POST /api/users/{email}/enable`); there is no `enable-user` subcommand. Bear that in mind before disabling your own account from the shell.

## Role management CLI

```bash
# List built-in and custom roles with their permissions
rustguac list-roles

# Create a custom role (repeat --perm for each permission)
rustguac add-role --name connection-editor --display-name "Connection editor" \
    --perm connections.connect --perm connections.edit --perm credentials.self --perm docs.view

# Show what a user can do and why
rustguac show-user --email jsmith@example.com

# Delete a role, moving its users, group mappings and token caps first
rustguac delete-role --name connection-editor --reassign-to operator
```

`add-user`, `set-role` and `map-group` accept custom role names too. The CLI is the recovery path, so the rules about granting only what you hold don't apply to it; it's audited in the CLI audit log.

## Admin (API key) management CLI

```bash
# Create an admin
rustguac add-admin --name myadmin

# With IP restrictions
rustguac add-admin --name myadmin --allowed-ips "10.0.0.0/8,192.168.1.0/24"

# With expiry
rustguac add-admin --name myadmin --expires "2026-12-31T00:00:00Z"

# List admins
rustguac list-admins

# Disable/enable
rustguac disable-admin --name myadmin
rustguac enable-admin --name myadmin

# Rotate key (generates new key, invalidates old immediately)
rustguac rotate-key --name myadmin

# Delete
rustguac delete-admin --name myadmin
```

## CLI audit log

CLI commands act on the database directly, so they never pass through the authenticated API and its audit trail. Without a record of their own, a role grant or an account deletion made from a shell would leave no trace at all. The admin, user-role and group-mapping commands above therefore write to the `cli_audit_log` table.

| Recorded | Never recorded |
|----------|----------------|
| The action, its target, and a timestamp | API keys |
| Non-sensitive detail, such as the role granted or whether an IP allowlist and expiry were set | Passwords |
| The operating system user who ran the command | Full field values |

The actor is taken from `SUDO_USER` when present, so an action run through `sudo` is attributed to the person who ran it rather than to `root`, falling back to `USER` then `LOGNAME`. Only successful actions are recorded; a command that fails validation or finds nothing to change writes no entry.

There is no UI for this log yet. Read it with `sqlite3`:

```bash
sqlite3 -header -column /opt/rustguac/data/rustguac.db \
  "SELECT created_at, os_user, action, target, details
     FROM cli_audit_log ORDER BY id DESC LIMIT 20;"
```

```
created_at           os_user  action       target  details
-------------------  -------  -----------  ------  ------------------------------
2026-09-19 04:11:02  alice    map_group    staff   role=viewer
2026-09-19 04:11:05  alice    remap_group  staff   from=viewer to=admin
2026-09-19 04:11:07  alice    add_admin    ops     ip_allowlist=true expiry=false
2026-09-19 04:11:09  alice    rotate_key   ops
```

Entries are subject to the same retention cleanup as the API audit logs and are removed after 90 days.
