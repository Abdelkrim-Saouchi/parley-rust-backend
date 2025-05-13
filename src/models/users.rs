use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "provider_type", rename_all = "lowercase")]
pub enum ProviderType {
    Email,
    Google,
    Facebook,
    Github,
}

#[derive(Debug, Clone, Serialize, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "account_status_type", rename_all = "lowercase")]
pub enum AccountStatus {
    Active,
    Suspended,
    Deleted,
    Unverified,
}

#[derive(Debug, Clone, Serialize, sqlx::Type)]
#[sqlx(type_name = "token_type")]
pub enum TokenType {
    #[sqlx(rename = "email_verification")]
    EmailVerification,
    #[sqlx(rename = "password_reset")]
    PasswordReset,
    #[sqlx(rename = "account_deletion")]
    AccountDeletion,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct User {
    id: Uuid,
    email: String,
    password_hash: Option<String>,
    email_verified: bool,
    account_status: AccountStatus,
    last_login: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserProfile {
    user_id: Uuid,
    first_name: String,
    last_name: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserLocation {
    id: i32,
    user_id: Uuid,
    country: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserProvider {
    id: i32,
    user_id: Uuid,
    provider: ProviderType,
    provider_user_id: String,
    provider_email: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    token_expires_at: Option<DateTime<Utc>>,
    provider_data: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct VerificationToken {
    id: Uuid,
    user_id: Uuid,
    token: String,
    token_type: TokenType,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
}
