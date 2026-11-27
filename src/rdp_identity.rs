use axum::http::{HeaderMap, StatusCode};
use futures_util::future::BoxFuture;
use sha2::{Digest, Sha256};

use crate::perms::Perm;
use crate::{auth, db};

#[cfg(feature = "rdp-cloudflare-example")]
pub(crate) mod cloudflare_example;

pub(crate) type AuthFailure = (StatusCode, &'static str);

pub(crate) trait IdentityProvider: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        headers: &'a HeaderMap,
        audience: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Identity, AuthFailure>>;
}

#[derive(Clone)]
pub(crate) struct Identity {
    pub email: String,
    pub owner: String,
    pub fingerprint: String,
}

impl Identity {
    pub fn new(email: String, owner: String) -> Option<Self> {
        if owner.is_empty()
            || owner.len() > 200
            || !owner
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b':' | b'-' | b'_' | b'.'))
        {
            return None;
        }
        let (login, domain) = email.split_once('@')?;
        if login.is_empty()
            || domain.is_empty()
            || domain.contains('@')
            || email.len() > 254
            || email
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
        {
            return None;
        }
        let fingerprint = hex::encode(Sha256::digest(owner.as_bytes()));
        Some(Self {
            email,
            owner,
            fingerprint,
        })
    }
}

impl Identity {
    pub fn windows_login(&self) -> Option<&str> {
        let (login, _) = self.email.split_once('@')?;
        ((1..=20).contains(&login.len())
            && login
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'_' | b'-')))
        .then_some(login)
    }
}

pub(crate) fn required(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

pub(crate) struct NativeOidc {
    db: db::Db,
    issuer: String,
}

impl NativeOidc {
    pub fn new(db: db::Db, issuer: String) -> Self {
        Self { db, issuer }
    }
}

impl IdentityProvider for NativeOidc {
    fn authenticate<'a>(
        &'a self,
        headers: &'a HeaderMap,
        _audience: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Identity, AuthFailure>> {
        Box::pin(async move {
            let invalid = (StatusCode::UNAUTHORIZED, "Sign in to open Remote Desktop.");
            let forbidden = (
                StatusCode::FORBIDDEN,
                "Your account does not have Remote Desktop access.",
            );
            let token = auth::cookie_value(headers, "rustguac_session").ok_or(invalid)?;
            let db = self.db.clone();
            let issuer = self.issuer.clone();
            tokio::task::spawn_blocking(move || {
                let user = db::validate_auth_session(&db, &token).map_err(|_| invalid)?;
                let subject = user
                    .oidc_subject
                    .as_deref()
                    .filter(|sub| !sub.is_empty())
                    .ok_or(forbidden)?;
                let key =
                    serde_json::to_vec(&(&issuer, subject)).expect("OIDC identity is serializable");
                let owner = format!("oidc:{}", hex::encode(Sha256::digest(key)));
                if !auth::user_identity(&db, user.clone(), None).has_perm(Perm::ConnectionsConnect)
                {
                    return Err(forbidden);
                }
                Identity::new(user.email, owner).ok_or(forbidden)
            })
            .await
            .map_err(|_| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Could not verify your session.",
                )
            })?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_oidc_requires_a_session_and_connect_permission() {
        let db = db::init_db(std::path::Path::new(":memory:")).unwrap();
        let provider = NativeOidc::new(db.clone(), "https://identity.example.com".into());
        let mut headers = HeaderMap::new();
        let failure = provider.authenticate(&headers, None).await.err().unwrap();
        assert_eq!(failure.0, StatusCode::UNAUTHORIZED);

        for role in ["viewer", "operator"] {
            let email = format!("{role}@example.com");
            let user = db::upsert_user(&db, &email, role, Some(role), role, &[], true).unwrap();
            let token = db::create_auth_session(&db, user.id, 60).unwrap();
            headers.insert(
                axum::http::header::COOKIE,
                format!("rustguac_session={token}").parse().unwrap(),
            );
            let result = provider.authenticate(&headers, None).await;
            if role == "operator" {
                assert_eq!(result.unwrap().email, email);
            } else {
                assert_eq!(result.err().unwrap().0, StatusCode::FORBIDDEN);
            }
        }
    }

    #[test]
    fn derives_windows_login_from_verified_email() {
        let identity =
            Identity::new("jane.doe@example.com".into(), "provider:alice".into()).unwrap();
        assert_eq!(identity.windows_login(), Some("jane.doe"));
    }
}
