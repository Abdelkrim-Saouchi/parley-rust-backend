use crate::app_state::AppState;
use crate::error::AppError;
use crate::error::AppResult;
use crate::models::users::{ProviderType, TokenType};
use crate::queries::users::insert_user;
use crate::queries::users::insert_user_location;
use crate::queries::users::insert_user_profile;
use crate::queries::users::insert_user_verification_token;
use crate::queries::users::inset_user_provider;
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
    pub first_name: String,

    #[serde(rename = "lastName")]
    #[validate(length(
        min = 1,
        max = 255,
        message = "Last name is required and cannot be empty"
    ))]
    pub last_name: String,

    #[serde(rename = "displayName")]
    pub display_name: Option<String>,

    #[validate(email(message = "Invalid email format"))]
    #[validate(length(min = 1, max = 255, message = "Email is required and cannot be empty"))]
    pub email: String,

    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
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

    // insert user to users table
    insert_user(&mut tx, &payload, user_id, hash).await?;

    let provider_type = ProviderType::Email;
    let provider_user_id_value = &payload.email;
    let provider_email_value = &payload.email;

    // insert user provider to user_providers table
    inset_user_provider(
        &mut tx,
        &user_id,
        provider_type,
        provider_user_id_value,
        provider_email_value,
    )
    .await?;

    // insert user profile to user_profiles table
    insert_user_profile(&mut tx, &user_id, &payload).await?;

    // insert user location to user_locations table
    insert_user_location(&mut tx, &user_id).await?;

    let verification_token_id = Uuid::new_v4();
    let verification_token = Uuid::new_v4().to_string();
    let verification_token_expiration = Utc::now() + Duration::hours(1);
    let token_type = TokenType::EmailVerification;

    // insert verification token to verification_tokens table
    insert_user_verification_token(
        &mut tx,
        &user_id,
        &verification_token_id,
        &verification_token,
        token_type,
        &verification_token_expiration,
    )
    .await?;

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
