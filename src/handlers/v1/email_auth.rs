use crate::app_state::AppState;
use crate::error::AppError;
use crate::error::AppResult;
use crate::models::sessions::UserSession;
use crate::models::users::AccountStatus;
use crate::models::users::{ProviderType, TokenType};
use crate::queries::users::activate_user;
use crate::queries::users::find_password_reset_token;
use crate::queries::users::find_user_by_email;
use crate::queries::users::find_verification_token;
use crate::queries::users::get_user_by_email;
use crate::queries::users::insert_user;
use crate::queries::users::insert_user_location;
use crate::queries::users::insert_user_profile;
use crate::queries::users::insert_user_provider;
use crate::queries::users::insert_user_verification_token;
use crate::queries::users::invalidate_password_reset_tokens;
use crate::queries::users::mark_verification_token_used;
use crate::queries::users::update_user_last_login;
use crate::queries::users::update_user_password;
use crate::utils::email::send_password_reset_email;
use crate::utils::email::send_verification_email;
use anyhow::anyhow;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{extract::State, response::IntoResponse, Json};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Duration;
use chrono::Utc;
use serde::Deserialize;
use sqlx::Acquire;
use tower_sessions::Session;
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

#[derive(Deserialize, Validate)]
pub struct Login {
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
    insert_user_provider(
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
        verification_token_expiration,
    )
    .await?;

    tx.commit().await.map_err(|_| {
        AppError::InternalServerError(anyhow!("Database error during signup commit"))
    })?;

    // Build the verification link
    let verification_link = format!(
        "{}/api/v1/users/verify/{}/{}",
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
        user_id,
        verification_token
    );

    // Send the verification email
    send_verification_email(&payload.email, &verification_link)
        .await
        .map_err(|e| {
            eprintln!("Email sending error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to send verification email"))
        })?;

    Ok((
        StatusCode::CREATED,
        Json(
            serde_json::json!({"id": user_id, "email": payload.email, "message": "User created successfully. Please check your email to verfiy your account"}),
        ),
    ))
}

#[derive(Deserialize)]
pub struct VerificationPath {
    user_id: Uuid,
    token: String,
}

pub async fn verify_email_handler(
    State(state): State<AppState>,
    Path(path): Path<VerificationPath>,
) -> AppResult<impl IntoResponse> {
    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        eprintln!("Database connection error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to get database connection"))
    })?;

    let mut tx = conn.begin().await.map_err(|e| {
        eprintln!("Transaction begin error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to begin transaction for verification"))
    })?;

    let verification_token = find_verification_token(&mut tx, path.user_id, &path.token)
        .await?
        .ok_or_else(|| AppError::BadRequest(anyhow!("Invalid or used verification token")))?;

    if verification_token.expires_at < Utc::now() {
        // Consider cleaning up expired tokens here or with a background job
        tx.rollback().await.map_err(|e| {
            eprintln!("Transaction rollback error: {:?}", e);
            AppError::InternalServerError(anyhow!(
                "Failed to rollback transaction after expired token"
            ))
        })?;
        return Err(AppError::BadRequest(anyhow!(
            "Verification token has expired. Please request a new one."
        )));
    }

    activate_user(&mut tx, path.user_id).await?;

    mark_verification_token_used(&mut tx, verification_token.id).await?;

    tx.commit().await.map_err(|e| {
        eprintln!("Transaction commit error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to commit transaction for verification"))
    })?;

    Ok((
        StatusCode::OK,
        Json(
            serde_json::json!({"message": "Email verified successfully. Your account is now active."}),
        ),
    ))
}

#[derive(Deserialize, Validate)]
pub struct ResendVerificationEmailRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(min = 1, max = 255, message = "Email is required and cannot be empty"))]
    pub email: String,
}

pub async fn resend_verification_email_hander(
    State(state): State<AppState>,
    Json(mut payload): Json<ResendVerificationEmailRequest>,
) -> AppResult<impl IntoResponse> {
    let db_pool = state.db_pool;

    payload.email = payload.email.trim().to_string();

    payload.validate().map_err(|e| {
        let mut error_messages = String::new();
        for (field, errors) in e.field_errors() {
            for error in errors {
                error_messages.push_str(&format!(
                    "{}: {}",
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

    let mut conn = db_pool.acquire().await.map_err(|e| {
        eprintln!("Database connection error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to get database connection"))
    })?;

    let mut tx = conn.begin().await.map_err(|e| {
        eprintln!("Transaction begin error: {:?}", e);
        AppError::InternalServerError(anyhow!(
            "Failed to begin transaction for resend verification"
        ))
    })?;

    // Find user by email
    let user = match find_user_by_email(&mut tx, &payload.email).await {
        Ok(user) => user,
        Err(AppError::BadRequest(_)) => {
            tx.commit().await.map_err(|e| {
                eprintln!("Transaction commit error after user not found: {:?}", e);
                AppError::InternalServerError(anyhow!("Database error during commit"))
            })?;
            return Err(AppError::BadRequest(anyhow!(
                "User not found with this email address"
            )));
        }
        Err(e) => {
            tx.rollback().await.map_err(|rb_e| {
                eprintln!("Transaction rollback error after db error: {:?}", rb_e);
                AppError::InternalServerError(anyhow!("Database error during rollback"))
            })?;
            return Err(e);
        }
    };

    if user.email_verified {
        tx.commit().await.map_err(|e| {
            eprintln!("Transaction commit error after already verified: {:?}", e);
            AppError::InternalServerError(anyhow!("Database error during commit"))
        })?;
        return Err(AppError::BadRequest(anyhow!("Email is already verified")));
    }

    sqlx::query("UPDATE verification_tokens SET used_at = NOW() WHERE user_id = $1 AND token_type = 'email_verification' AND used_at IS NULL")
        .bind(user.id)
        .execute(&mut *tx).await.map_err(|e| {
        eprintln!("Database update error (invalidate_tokens): {:?}", e);
        AppError::InternalServerError(anyhow!("Database error invalidating old tokens"))
    })?;

    // Generate a new verification token and expiration
    let verification_token_id = Uuid::new_v4();
    let verification_token = Uuid::new_v4().to_string();
    let verification_token_expiration = Utc::now() + Duration::hours(1);
    let token_type = TokenType::EmailVerification;

    insert_user_verification_token(
        &mut tx,
        &user.id,
        &verification_token_id,
        &verification_token,
        token_type,
        verification_token_expiration,
    )
    .await?;

    tx.commit().await.map_err(|e| {
        eprintln!("Transaction commit error: {:?}", e);
        AppError::InternalServerError(anyhow!(
            "Failed to commit transaction for resend verification"
        ))
    })?;

    // Build the new verification link

    let verification_link = format!(
        "{}/api/v1/users/verify/{}/{}",
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
        user.id,
        verification_token
    );

    println!("email to: {:?}", user.email);
    // Send the verification email
    send_verification_email(&user.email, &verification_link)
        .await
        .map_err(|e| {
            eprintln!("Email sending error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to send verification email"))
        })?;

    Ok((
        StatusCode::OK,
        Json(
            serde_json::json!({"message": "Verification email resent successfully. Please check your inbox."}),
        ),
    ))
}

#[derive(Deserialize, Validate)]
pub struct ForgotpasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(min = 1, max = 255, message = "Email is required and cannot be empty"))]
    pub email: String,
}

#[derive(Deserialize, Validate)]
pub struct ResetPasswordPayload {
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[serde(rename = "newPassword")]
    pub new_password: String,
    #[validate(length(min = 8, message = "Password must match"))]
    #[serde(rename = "passwordConfirmation")]
    pub password_confirmation: String,
}

pub async fn forgot_password_handler(
    State(state): State<AppState>,
    Json(mut payload): Json<ForgotpasswordRequest>,
) -> AppResult<impl IntoResponse> {
    let db_pool = state.db_pool;
    payload.email = payload.email.trim().to_string();
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
                        .map_or("Invalid value", |m| m.as_ref())
                ));
            }
        }
        AppError::BadRequest(anyhow!(error_messages.trim().to_string()))
    })?;

    let mut conn = db_pool.acquire().await.map_err(|e| {
        eprintln!("Database connection error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to get database connection"))
    })?;

    let user_result = find_user_by_email(&mut conn, &payload.email).await;

    if let Ok(user) = user_result {
        let mut tx = db_pool.begin().await.map_err(|e| {
            eprintln!("Transaction begin error: {:?}", e);
            AppError::InternalServerError(anyhow!(
                "Failed to begin transaction for password reset request"
            ))
        })?;

        // Invalidate any existing password reset tokens for this user
        invalidate_password_reset_tokens(&mut tx, user.id).await?;

        // Generate a new token and expiration
        let reset_token_id = Uuid::new_v4();
        let reset_token = Uuid::new_v4().to_string(); // Or a cryptographically secure random string
        let reset_token_expiration = Utc::now() + Duration::hours(1); // Token valid for 1 hour
        let token_type = TokenType::PasswordReset;

        // Insert the new token into the database
        insert_user_verification_token(
            &mut tx,
            &user.id,
            &reset_token_id,
            &reset_token,
            token_type,
            reset_token_expiration,
        )
        .await?;

        tx.commit().await.map_err(|e| {
            eprintln!("Transaction commit error: {:?}", e);
            AppError::InternalServerError(anyhow!(
                "Failed to commit transaction for password reset request"
            ))
        })?;

        // Build the password reset link (Frontend URL + route)
        // Ensure your frontend has a route like /reset-password/:user_id/:token
        let reset_link = format!(
            "{}/reset-password/{}/{}",
            std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3000/api/v1/users".to_string()),
            user.id,
            reset_token
        );

        // Send the password reset email
        if let Err(e) = send_password_reset_email(&user.email, &reset_link).await {
            eprintln!("Error sending password reset email: {:?}", e);
            // Log the error but don't return it to the user for security
        }
    }
    Ok((
        StatusCode::OK,
        Json(
            serde_json::json!({"message": "If an account with that email exists, a password reset link has been sent."}),
        ),
    ))
}

pub async fn reset_password_handler(
    State(state): State<AppState>,
    Path(path): Path<VerificationPath>,
    Json(payload): Json<ResetPasswordPayload>,
) -> AppResult<impl IntoResponse> {
    let db_pool = state.db_pool;

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
                        .map_or("Invalid value", |m| m.as_ref())
                ));
            }
        }
        AppError::BadRequest(anyhow!(error_messages.trim().to_string()))
    })?;

    if payload.new_password != payload.password_confirmation {
        return Err(AppError::BadRequest(anyhow!("Password do not match")));
    };

    let mut conn = db_pool.acquire().await.map_err(|e| {
        eprintln!("Database connection error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to get database connection"))
    })?;

    let mut tx = conn.begin().await.map_err(|e| {
        eprintln!("Transaction begin error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to begin transaction for password reset"))
    })?;

    // Find and validate the password reset token
    let reset_token = find_password_reset_token(&mut tx, path.user_id, &path.token).await?;

    let Some(reset_token) = reset_token else {
        tx.rollback().await.map_err(|e| {
            eprintln!("Transaction rollback error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to rollback transaction"))
        })?;
        return Err(AppError::BadRequest(anyhow!(
            "Invalid or expired password reset token"
        )));
    };

    if reset_token.expires_at < Utc::now() {
        tx.rollback().await.map_err(|e| {
            eprintln!("Transaction rollback error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to rollback transaction"))
        })?;
        return Err(AppError::BadRequest(anyhow!(
            "Password reset token has expired. Please request a new one."
        )));
    }

    if reset_token.used_at.is_some() {
        tx.rollback().await.map_err(|e| {
            eprintln!("Transaction rollback error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to rollback transaction"))
        })?;
        return Err(AppError::BadRequest(anyhow!(
            "Password reset token has already been used. Please request a new one."
        )));
    }
    // Hash the new password
    let hashed_password = hash(payload.new_password.as_bytes(), DEFAULT_COST).map_err(|e| {
        eprintln!("Bcrypt hashing error: {:?}", e);
        AppError::InternalServerError(anyhow!("Error processing new password"))
    })?;

    // Update the user's password in the database
    update_user_password(&mut tx, path.user_id, hashed_password).await?;

    // Mark the token as used
    mark_verification_token_used(&mut tx, reset_token.id).await?;

    tx.commit().await.map_err(|e| {
        eprintln!("Transaction commit error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to commit transaction for password reset"))
    })?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"message": "Password has been reset successfully."})),
    ))
}

pub async fn login(
    State(state): State<AppState>,
    session: Session,
    Json(mut payload): Json<Login>,
) -> AppResult<impl IntoResponse> {
    let db_pool = state.db_pool;
    payload.email = payload.email.trim().to_string();

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
                        .map_or("Invalid value", |m| m.as_ref())
                ));
            }
        }
        AppError::BadRequest(anyhow!(error_messages.trim().to_string()))
    })?;

    // Start a transaction to ensure consistent connection
    let mut tx = db_pool.begin().await.map_err(|e| {
        eprintln!("Transaction start error: {:?}", e);
        AppError::InternalServerError(anyhow!("Database error starting transaction"))
    })?;

    // Use a raw query with bind parameters to avoid prepared statement issues
    let user = get_user_by_email(&mut tx, &payload).await?;

    // Check if email is verified
    if !user.email_verified {
        return Err(AppError::Unauthorized(anyhow!(
            "Email not verified. Please check your inbox or request a new verification link."
        )));
    }

    // Check account status
    if user.account_status != AccountStatus::Active {
        return Err(AppError::Unauthorized(anyhow!(
            "Your account is not active. please contact support if you believe this is an error."
        )));
    };

    let password_hash = user
        .password_hash
        .ok_or_else(|| AppError::InternalServerError(anyhow!("User account has no password")))?;

    let password_matches = verify(payload.password.as_bytes(), &password_hash)
        .map_err(|_| AppError::InternalServerError(anyhow!("Error processing login!")))?;

    if !password_matches {
        return Err(AppError::BadRequest(anyhow!("Invalid email or password")));
    }

    let user_session_data = UserSession { user_id: user.id };
    session
        .insert("user", user_session_data)
        .await
        .map_err(|e| {
            eprintln!("Session insert error: {:?}", e);
            AppError::InternalServerError(anyhow!("failed to create session"))
        })?;

    // update last_login
    update_user_last_login(&mut tx, user.id).await?;

    // Commit the transaction
    tx.commit().await.map_err(|e| {
        eprintln!("Transaction commit error: {:?}", e);
        AppError::InternalServerError(anyhow!("Database error committing transaction"))
    })?;

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"message": "Login successful"})),
    ))
}

pub async fn logout(session: Session) -> AppResult<impl IntoResponse> {
    session.clear().await;
    Ok(StatusCode::OK)
}

pub async fn get_authenticated_user_id(session: Session) -> AppResult<impl IntoResponse> {
    let user_session = session.get::<UserSession>("user").await.map_err(|e| {
        eprintln!("Session get error: {:?}", e);
        AppError::InternalServerError(anyhow!("failed to get session"))
    })?;
    match user_session {
        Some(user_data) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({"id": user_data.user_id})),
        )),
        None => Err(AppError::Unauthorized(anyhow!("Unauthorized"))),
    }
}
