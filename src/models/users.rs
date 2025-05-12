use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "provider_type", rename_all = "lowercase")]
pub enum ProviderType {
    Email,
    Google,
    Facebook,
    Github,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct User {
    id: Uuid,
    email: String,
    password_hash: Option<String>,
    email_verified: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserProvider {
    id: i32,
    user_id: Uuid,
    provider: String,
    provider_user_id: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}
