use crate::error::{AppError, AppResult};
use crate::handlers::v1::email_auth::{Login, Signup};
use crate::models::users::{AccountStatus, ProviderType, TokenType, User};
use anyhow::anyhow;
use sqlx::PgConnection;
use uuid::Uuid;
use sqlx::types::time::OffsetDateTime;

pub async fn insert_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    payload: &Signup,
    user_id: Uuid,
    hashed_password: String,
) -> AppResult<()> {
    let insert_user_result = sqlx::query!(
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)",
        user_id,
        payload.email,
        hashed_password
    )
    .execute(&mut **tx)
    .await;

    if let Err(e) = insert_user_result {
        if let Some(db_err) = e.as_database_error() {
            if db_err.is_unique_violation() {
                if db_err.constraint() == Some("users_email_key") {
                    return Err(AppError::BadRequest(anyhow!("Email already exists")));
                }
            }
        }
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to create user account! user insert failed!"
        )));
    }

    Ok(())
}

pub async fn insert_user_provider(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &Uuid,
    provider_type: ProviderType,
    provider_user_id_value: &str,
    provider_email_value: &str,
) -> AppResult<()> {
    let provider_insert_result = sqlx::query!(
        r#"
    INSERT INTO user_providers (user_id, provider, provider_user_id, provider_email)
    VALUES ($1, $2, $3, $4)
    "#,
        user_id,
        provider_type as ProviderType,
        provider_user_id_value,
        provider_email_value,
    )
    .execute(&mut **tx)
    .await;

    if let Err(e) = provider_insert_result {
        eprintln!("provider insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: provider insert failed!"
        )));
    }

    Ok(())
}

pub async fn insert_user_profile(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &Uuid,
    payload: &Signup,
) -> AppResult<()> {
    let user_profile_insert_result = sqlx::query!(
        r#"
    INSERT INTO user_profiles (user_id, first_name, last_name, display_name)
    VALUES ($1, $2, $3, $4)
    "#,
        user_id,
        payload.first_name,
        payload.last_name,
        payload.display_name,
    )
    .execute(&mut **tx)
    .await;

    if let Err(e) = user_profile_insert_result {
        eprintln!("user profile insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: user profile insert failed!"
        )));
    };

    Ok(())
}

pub async fn insert_user_location(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &Uuid,
) -> AppResult<()> {
    let user_location_insert_result = sqlx::query!(
        r#"
        INSERT INTO user_locations (user_id)
        VALUES ($1)
        "#,
        user_id,
    )
    .execute(&mut **tx)
    .await;

    if let Err(e) = user_location_insert_result {
        eprintln!("user location insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: user location insert failed!"
        )));
    };
    Ok(())
}

pub async fn insert_user_verification_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &Uuid,
    verification_token_id: &Uuid,
    verification_token: &str,
    token_type: TokenType,
    verification_token_expiration: chrono::DateTime<chrono::Utc>,
) -> AppResult<()> {
    let verification_token_insert_result = sqlx::query!(
        r#"
        INSERT INTO verification_tokens (id, user_id, token, token_type, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        verification_token_id,
        user_id,
        verification_token,
        token_type as TokenType,
        verification_token_expiration as chrono::DateTime<chrono::Utc>,
    )
    .execute(&mut **tx)
    .await;

    if let Err(e) = verification_token_insert_result {
        eprintln!("verification token insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: verification token insert failed!"
        )));
    };

    Ok(())
}

pub async fn get_user_by_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    payload: &Login,
) -> AppResult<User> {
    let user: Option<crate::models::users::User> =
        sqlx::query_as("SELECT * FROM users WHERE email = $1")
            .bind(&payload.email)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| {
                eprintln!("Database query error: {:?}", e);
                AppError::InternalServerError(anyhow!("Database error during login"))
            })?;

    match user {
        Some(user) => Ok(user),
        None => return Err(AppError::BadRequest(anyhow!("Invalid email or password"))),
    }
}

pub async fn find_user_by_email(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    email: &str,
) -> AppResult<User> {
    let user: Option<crate::models::users::User> =
        sqlx::query_as("SELECT * FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| {
                eprintln!("Database query error: {:?}", e);
                AppError::InternalServerError(anyhow!("Database error during login"))
            })?;

    match user {
        Some(user) => Ok(user),
        None => return Err(AppError::BadRequest(anyhow!("Invalid email or password"))),
    }
}

pub async fn find_user_id_by_provider(
    conn: &mut PgConnection,
    provider_type: ProviderType,
    provider_user_id: &str,
) -> AppResult<Option<Uuid>> {
    // Use query_scalar instead of query! to avoid prepared statement issues
    let result = sqlx::query_scalar::<_, Uuid>(
        "SELECT user_id FROM user_providers WHERE provider = $1 AND provider_user_id = $2"
    )
    .bind(provider_type as ProviderType)
    .bind(provider_user_id)
    .fetch_optional(conn)
    .await
    .map_err(|e| {
        eprintln!("Database query error: {:?}", e);
        AppError::InternalServerError(anyhow!("Database error during login"))
    })?;

    Ok(result)
}

#[allow(clippy::too_many_arguments)]
pub async fn link_provider_to_user(
    conn: &mut PgConnection,
    user_id: &Uuid,
    provider_type: ProviderType,
    provider_user_id: &str,
    provider_email: &str,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    provider_data: Option<&serde_json::Value>,
) -> AppResult<()> {
    let  provider_insert_result = sqlx::query!(
        r#"
        INSERT INTO user_providers (user_id, provider, provider_user_id, provider_email, access_token, refresh_token, token_expires_at, provider_data)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        user_id,
        provider_type as ProviderType,
        provider_user_id,
        provider_email,
        access_token,
        refresh_token,
        token_expires_at.map(|dt| OffsetDateTime::from_unix_timestamp(dt.timestamp()).unwrap()),
        provider_data,
    )
    .execute(&mut *conn)
    .await;

    if let Err(e) = provider_insert_result {
        eprintln!("provider insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: provider insert failed!"
        )));
    }

    Ok(())
}

pub async fn create_new_user_with_provider(
    conn: &mut PgConnection,
    user_id: &Uuid,
    email: &str,
    provider_type: ProviderType,
    provider_user_id: &str,
    provider_email: Option<&str>,
    access_token: Option<&str>,
    refresh_token: Option<&str>,
    token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    provider_data: Option<&serde_json::Value>,
    first_name: &str,
    last_name: &str,
    display_name: Option<&str>,
) -> AppResult<()> {
    sqlx::query!(
        "INSERT INTO users (id, email, password_hash, email_verified, account_status) VALUES ($1, $2, NULL, $3, $4)",
        user_id,
        email,
        provider_email.is_some(), // Assume email is verified if provided by OAuth
        AccountStatus::Active as AccountStatus // Default status for new OAuth users
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| {
         if let Some(db_err) = e.as_database_error() {
            if db_err.is_unique_violation() {
                if db_err.constraint() == Some("users_email_key") {
                     eprintln!("Unique violation during create_new_user_with_provider (email): {:?}", db_err);
                    return AppError::BadRequest(anyhow!("Email already exists"));
                }
            }
        }
        eprintln!("Database error during create_new_user_with_provider (user insert): {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to create user account!"))
    })?;

    // Insert user provider
    sqlx::query!(
        r#"
    INSERT INTO user_providers (user_id, provider, provider_user_id, provider_email, access_token, refresh_token, token_expires_at, provider_data)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    "#,
        user_id,
        provider_type as ProviderType, // Cast enum
        provider_user_id,
        provider_email,
        access_token,
        refresh_token,
        token_expires_at.map(|dt| OffsetDateTime::from_unix_timestamp(dt.timestamp()).unwrap()),
        provider_data
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| {
         if let Some(db_err) = e.as_database_error() {
            if db_err.is_unique_violation() {
                eprintln!("Database unique violation during create_new_user_with_provider (provider): {:?}", db_err);
                return AppError::BadRequest(anyhow!("Provider account already linked"));
            }
        }
        eprintln!("Database error during create_new_user_with_provider (provider insert): {:?}", e);
        AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: provider insert failed!"
        ))
    })?;

    // Insert user profile (use extracted name fields)
    sqlx::query!(
        r#"
    INSERT INTO user_profiles (user_id, first_name, last_name, display_name)
    VALUES ($1, $2, $3, $4)
    "#,
        user_id,
        first_name,
        last_name,
        display_name,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        eprintln!(
            "Database error during create_new_user_with_provider (profile insert): {:?}",
            e
        );
        AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: user profile insert failed!"
        ))
    })?;

    // Insert user location (default)
    sqlx::query!(
        r#"
        INSERT INTO user_locations (user_id)
        VALUES ($1)
        "#,
        user_id,
    )
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        eprintln!(
            "Database error during create_new_user_with_provider (location insert): {:?}",
            e
        );
        AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: user location insert failed!"
        ))
    })?;

    Ok(())
}
