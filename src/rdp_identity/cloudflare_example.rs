//! Optional example that authenticates Cloudflare Access assertions backed by Entra ID.

use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode};
use futures_util::future::BoxFuture;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;

use super::{required, AuthFailure, Identity, IdentityProvider};

const IO_TIMEOUT: Duration = Duration::from_secs(10);
const JWT_HEADER: &str = "cf-access-jwt-assertion";

pub(crate) struct CloudflareAccess {
    issuer: String,
    tenant: Uuid,
    role: String,
    http: reqwest::Client,
    keys: Mutex<KeyCache>,
}

#[derive(Default)]
struct KeyCache {
    keys: Option<JwkSet>,
    refreshed: Option<Instant>,
    attempted: Option<Instant>,
}

#[derive(Deserialize)]
struct Claims {
    email: String,
    sub: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    custom: Option<EntraClaims>,
}

#[derive(Deserialize)]
struct EntraClaims {
    #[serde(default)]
    roles: Vec<String>,
    oid: Uuid,
    tid: Uuid,
}

impl CloudflareAccess {
    pub fn from_env() -> Result<Self, String> {
        let url = Url::parse(&required("CF_ACCESS_TEAM_DOMAIN")?)
            .map_err(|_| "CF_ACCESS_TEAM_DOMAIN must be an HTTPS origin")?;
        if url.scheme() != "https"
            || url.as_str() != format!("{}/", url.origin().ascii_serialization())
        {
            return Err("CF_ACCESS_TEAM_DOMAIN must be an HTTPS origin".into());
        }
        let issuer = url.origin().ascii_serialization();
        let tenant = required("CF_ENTRA_TENANT_ID")?
            .parse()
            .map_err(|_| "CF_ENTRA_TENANT_ID must be a UUID")?;
        let role = required("CF_REQUIRED_ROLE")?;
        let http = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(IO_TIMEOUT)
            .build()
            .map_err(|_| "Could not configure Cloudflare JWKS client")?;
        Ok(Self {
            issuer,
            tenant,
            role,
            http,
            keys: Mutex::new(KeyCache::default()),
        })
    }
}

impl IdentityProvider for CloudflareAccess {
    fn authenticate<'a>(
        &'a self,
        headers: &'a HeaderMap,
        audience: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Identity, AuthFailure>> {
        Box::pin(self.verify(headers, audience))
    }
}

impl CloudflareAccess {
    async fn verify(
        &self,
        headers: &HeaderMap,
        audience: Option<&str>,
    ) -> Result<Identity, AuthFailure> {
        let invalid = (
            StatusCode::UNAUTHORIZED,
            "A valid Cloudflare Access session is required.",
        );
        let forbidden = (
            StatusCode::FORBIDDEN,
            "Your Entra account does not have Remote Desktop access.",
        );
        let token = headers
            .get(JWT_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or(invalid)?;
        let jwt = decode_header(token).map_err(|_| invalid)?;
        let kid = jwt
            .kid
            .filter(|_| jwt.alg == Algorithm::RS256)
            .ok_or(invalid)?;

        let key = {
            let mut cache = self.keys.lock().await;
            let fresh = cache
                .refreshed
                .is_some_and(|time| time.elapsed() < Duration::from_secs(3600));
            let known = cache
                .keys
                .as_ref()
                .is_some_and(|keys| keys.find(&kid).is_some());
            let can_refresh = cache
                .attempted
                .is_none_or(|time| time.elapsed() >= Duration::from_secs(10));
            if (!fresh || !known) && can_refresh {
                cache.attempted = Some(Instant::now());
                if let Ok(response) = self
                    .http
                    .get(format!("{}/cdn-cgi/access/certs", self.issuer))
                    .send()
                    .await
                {
                    if let Ok(response) = response.error_for_status() {
                        if let Ok(keys) = response.json::<JwkSet>().await {
                            cache.keys = Some(keys);
                            cache.refreshed = Some(Instant::now());
                        }
                    }
                }
            }
            if cache
                .refreshed
                .is_none_or(|time| time.elapsed() >= Duration::from_secs(3600))
            {
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Cloudflare Access verification is temporarily unavailable.",
                ));
            }
            let key = cache
                .keys
                .as_ref()
                .and_then(|keys| keys.find(&kid))
                .ok_or(invalid)?;
            DecodingKey::try_from(key).map_err(|_| invalid)?
        };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[audience.ok_or(forbidden)?]);
        validation.set_required_spec_claims(&["aud", "iss", "exp", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 0;
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| invalid)?
            .claims;
        claims
            .into_identity(self.tenant, &self.role)
            .ok_or(forbidden)
    }
}

impl Claims {
    fn into_identity(self, tenant: Uuid, role: &str) -> Option<Identity> {
        let entra = self.custom?;
        if self.kind != "app"
            || self.sub.is_empty()
            || entra.tid != tenant
            || !entra.roles.iter().any(|value| value == role)
        {
            return None;
        }
        Identity::new(self.email, format!("entra:{}:{}", entra.tid, entra.oid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(email: &str, tenant: Uuid, object_id: Uuid) -> Claims {
        serde_json::from_value(serde_json::json!({
            "type": "app",
            "sub": "access-user",
            "email": email,
            "custom": { "tid": tenant, "oid": object_id, "roles": ["RemoteDesktop", "AnotherRole"] },
        }))
        .unwrap()
    }

    #[test]
    fn only_the_expected_role_and_tenant_grant_access() {
        let tenant = Uuid::new_v4();
        let oid = Uuid::new_v4();
        assert!(claims("user@example.com", tenant, oid)
            .into_identity(tenant, "RemoteDesktop")
            .is_some());
        assert!(claims("user@example.com", tenant, oid)
            .into_identity(tenant, "Remote")
            .is_none());
        assert!(claims("user@example.com", tenant, oid)
            .into_identity(Uuid::new_v4(), "RemoteDesktop")
            .is_none());
        let mut missing = claims("user@example.com", tenant, oid);
        missing.custom = None;
        assert!(missing.into_identity(tenant, "RemoteDesktop").is_none());
    }
}
