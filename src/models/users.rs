use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified: bool,
    pub account_status: AccountStatus,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct UserProfile {
    pub user_id: Uuid,
    pub first_name: String,
    pub last_name: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
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
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub token_type: TokenType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}
