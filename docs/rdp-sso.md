# Remote Desktop single sign-on

Use `RDP_IDENTITY_PROVIDER=oidc` with the existing `[oidc]` configuration to enable the dedicated Remote Desktop launcher. Rustguac uses its own OIDC session cookie and requires the `connections.connect` permission. Configure the provider to return a verified email and use the same public origin for the launcher and the OIDC callback.

Open `/?quickConnect` to select a preconfigured desktop. A direct link such as `/?connectTo=desktop-1` starts automatically. The destination comes from the server configuration.

Set `RDP_TARGETS` to a JSON array:

```json
[
  {"public_host":"desktop.example.com","connect_to":"desktop-1","target_host":"windows-01.ad.example.com","label":"Office"}
]
```

For a single destination, set `RDP_TARGET_HOST` instead. Set `AD_LDAPS_URL`, `AD_BIND_DN`, `AD_BIND_PASSWORD`, `AD_USERS_OU`, `AD_RDP_GROUP_DN`, `AD_DOMAIN`, and `AD_CA_CERT_PATH`. Use a dedicated AD OU and delegate only account creation, account attributes, password reset and RDP group membership. Grant the configured group RDP access on the target Windows hosts. Keep RDP certificate verification enabled and configure guacd to trust the target certificates.

Set up the existing `[vault]` integration with KV v2 rights scoped to `<mount>/data/rdp-users/*`. The adapter needs create, read and update. The provider-issued stable identity owns the account from the dedicated OU. The email supplies the Windows login for the manual fallback and the prefix for generated logins. The manual fallback uses the password for the current RDP connection.

## Identity provider example

An identity provider authenticates the request and returns a verified email and a stable, provider-scoped account identifier. AD and the launcher share that interface across providers.

The optional `rdp-cloudflare-example` Cargo feature demonstrates an adapter that verifies Cloudflare Access application JWTs with Entra claims. Build with `cargo build --features rdp-cloudflare-example` and set `RDP_IDENTITY_PROVIDER=cloudflare` to use it. Configure `CF_ACCESS_TEAM_DOMAIN`, `CF_ENTRA_TENANT_ID`, and `CF_REQUIRED_ROLE`. Add `access_aud` to each target or set `CF_ACCESS_AUD` in single-target mode. Configure the Access application to forward the signed `roles`, `tid`, and `oid` claims.
