use crate::error::{AppError, AppResult};
use crate::handlers::v1::email_auth::{Login, Signup};
use crate::models::users::{ProviderType, TokenType, User};
use anyhow::anyhow;
use uuid::Uuid;

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

pub async fn inset_user_provider(
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
