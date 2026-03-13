# Credential Variables

Credential variables let address book entries reference shared credentials by name instead of storing passwords directly. Users maintain their own credential values in Vault via the **My Credentials** dialog (gear menu). When a session launches, rustguac substitutes the variables from the user's saved values.

This gives a similar experience to LDAP credential passthrough in Apache Guacamole — users log in once and sessions just work — without rustguac needing to bind to LDAP. Credentials stay in Vault, never on disk or in the browser.

## How it works

1. **Admin** creates address book entries with variable references like `$corp_username` and `$corp_password` in the credential fields
2. **Users** open **My Credentials** from the gear menu and fill in their values (stored per-user in Vault)
3. **At connect time**, rustguac substitutes the variables. If all are set, the session launches silently. If any are missing, the user is prompted.

## Variable naming

Variables start with `$` and use the pattern `$<domain>_<suffix>`:

| Pattern | Purpose | Input type |
|---------|---------|------------|
| `$<domain>_username` | Username | Text |
| `$<domain>_password` | Password | Password (masked) |
| `$<domain>_domain` | AD/Windows domain | Text |
| `$<domain>_key` | SSH private key | Textarea |

The `<domain>` is a logical name chosen by the admin to group related credentials — for example `corp`, `jumpcloud`, `lab`, or `cloud-prod`. Multiple entries can reference the same domain, so users only configure their credentials once.

**Allowed characters:** lowercase letters, numbers, underscores, and hyphens. For example: `$corp_username`, `$jump-host_password`, `$cloud-prod_key`.

## Example

An admin creates two address book entries:

- **Production SSH** — username: `$corp_username`, password: `$corp_password`
- **Staging SSH** — username: `$corp_username`, password: `$corp_password`

Both reference the same `corp` domain. A user opens **My Credentials**, fills in their `corp` username and password once, and both entries work without further prompting.

An entry can also mix variables with static values. For example, an RDP entry might have a static hostname and port but use `$ad_username`, `$ad_password`, and `$ad_domain` for credentials.

## My Credentials dialog

Access via the gear icon in the top-right corner of the address book page. The dialog:

- Shows all credential variables used across entries the user has access to
- Groups variables by domain prefix
- Indicates how many entries use each variable
- Masks password and key fields (saved values are not shown, but a placeholder confirms they exist)
- Partial saves work — fill in what you have now, come back later for the rest

## Graceful degradation

- **All variables set** — session launches immediately, no prompting
- **Some missing** — credential prompt appears with known values pre-filled; user only needs to fill gaps
- **None set** — full credential prompt (same as entries without variables)

## Vault storage

User credentials are stored in Vault KV v2 at:

```
<base_path>/users/<sanitized_email>
```

Each user gets a single Vault secret containing all their credential key-value pairs. Variable names are the keys, plaintext values are the values. The Vault policy must allow read/write to this path for authenticated users.

### Required Vault policy

In addition to the existing address book policy, add:

```hcl
# User credential variables (read/write own credentials)
path "secret/data/rustguac/users/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/rustguac/users/*" {
  capabilities = ["list", "read", "delete"]
}
```

## API endpoints

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/api/me/credentials` | operator+ | List own saved variables (passwords masked) |
| `PUT` | `/api/me/credentials` | operator+ | Save/update own variables |
| `GET` | `/api/credential-variables` | operator+ | List all variables used across accessible entries |
