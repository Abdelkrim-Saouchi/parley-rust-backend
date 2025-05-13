use crate::app_state::AppState;
use crate::error::AppError;
use crate::error::AppResult;
use crate::models::users::{ProviderType, TokenType};
use anyhow::anyhow;
use axum::http::StatusCode;
use axum::{extract::State, response::IntoResponse, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Duration;
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

#[derive(Deserialize, Validate)]
pub struct Signup {
    #[serde(rename = "firstName")]
    #[validate(length(
        min = 1,
        max = 255,
        message = "First name is required and cannot be empty"
    ))]
    first_name: String,

    #[serde(rename = "lastName")]
    #[validate(length(
        min = 1,
        max = 255,
        message = "Last name is required and cannot be empty"
    ))]
    last_name: String,

    #[serde(rename = "displayName")]
    display_name: Option<String>,

    #[validate(email(message = "Invalid email format"))]
    #[validate(length(min = 1, max = 255, message = "Email is required and cannot be empty"))]
    email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    password: String,
}

pub async fn signup(
    State(state): State<AppState>,
    Json(mut payload): Json<Signup>,
) -> AppResult<impl IntoResponse> {
    let db_pool = state.db_pool;

    payload.email = payload.email.trim().to_string();
    payload.first_name = payload.first_name.trim().to_string();
    payload.last_name = payload.last_name.trim().to_string();
    if let Some(display_name) = payload.display_name.as_mut() {
        *display_name = display_name.trim().to_string();
    }

    payload.validate().map_err(|e| {
        let mut error_messages = String::new();
        for (field, errors) in e.field_errors() {
            for error in errors {
                error_messages.push_str(&format!(
                    "{}: {} ",
                    field,
                    error
                        .message
                        .as_ref()
                        .map_or("invalid value", |m| m.as_ref())
                ));
            }
        }
        AppError::BadRequest(anyhow!(error_messages.trim().to_string()))
    })?;

    let hash = hash(payload.password.as_bytes(), DEFAULT_COST)
        .map_err(|_| AppError::InternalServerError(anyhow!("Error processing signup!")))?;

    let user_id = uuid::Uuid::new_v4();

    let mut tx = db_pool
        .begin()
        .await
        .map_err(|_| AppError::InternalServerError(anyhow!("Database error during signup")))?;

    let user_insert_result = sqlx::query!(
        "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)",
        user_id,
        payload.email,
        hash
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = user_insert_result {
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

    let provider_type = ProviderType::Email;
    let provider_user_id_value = &payload.email;
    let provider_email_value = &payload.email;

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
    .execute(&mut *tx)
    .await;

    if let Err(e) = provider_insert_result {
        eprintln!("provider insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: provider insert failed!"
        )));
    }

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
    .execute(&mut *tx)
    .await;

    if let Err(e) = user_profile_insert_result {
        eprintln!("user profile insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: user profile insert failed!"
        )));
    };

    let user_location_insert_result = sqlx::query!(
        r#"
        INSERT INTO user_locations (user_id)
        VALUES ($1)
        "#,
        user_id,
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = user_location_insert_result {
        eprintln!("user location insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: user location insert failed!"
        )));
    };

    let verification_token_id = Uuid::new_v4();
    let verification_token = Uuid::new_v4().to_string();
    let verification_token_expiration = Utc::now() + Duration::hours(1);
    let token_type = TokenType::EmailVerification;

    let verification_token_insert_result = sqlx::query!(
        r#"
        INSERT INTO verification_tokens (id, user_id, token, token_type, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        verification_token_id,
        user_id,
        verification_token,
        token_type as TokenType,
        verification_token_expiration,
    )
    .execute(&mut *tx)
    .await;

    if let Err(e) = verification_token_insert_result {
        eprintln!("verification token insert failed: {:?}", e);
        return Err(AppError::InternalServerError(anyhow!(
            "Failed to finalize user account setup: verification token insert failed!"
        )));
    };

    tx.commit().await.map_err(|_| {
        AppError::InternalServerError(anyhow!("Database error during signup commit"))
    })?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({"id": user_id, "email": payload.email})),
    ))
}

pub async fn login() {
    todo!()
}
