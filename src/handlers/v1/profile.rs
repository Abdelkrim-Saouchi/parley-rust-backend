use anyhow::anyhow;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use tower_sessions::Session;
use uuid::Uuid;
use validator::Validate;

use crate::{
    app_state::AppState,
    error::{AppError, AppResult},
    models::{sessions::UserSession, users::UserProfile},
    queries::users::{get_user_profile_by_id, update_user_profile_by_id},
};

pub async fn get_profile(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<String>,
) -> AppResult<impl IntoResponse> {
    // Check if the user is authenticated
    let user_session = session
        .get::<UserSession>("user")
        .await
        .map_err(|_| AppError::Unauthorized(anyhow!("Cannot find user session")))?;

    let user_session_id = match user_session {
        Some(user_session_data) => user_session_data.user_id,
        None => return Err(AppError::Unauthorized(anyhow!("user not Authenticated"))),
    };

    // Ensure the user_id in the path matches the authenticated user's ID
    let user_id = match user_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Err(AppError::BadRequest(anyhow!("Invalid user ID format"))),
    };

    if user_session_id != user_id {
        return Err(AppError::Forbidden(anyhow!(
            "You do not have permission to access this profile"
        )));
    }

    // Fetch the profile data from the database
    let db_pool = state.db_pool.clone();
    let mut conn = db_pool.acquire().await.map_err(|e| {
        AppError::InternalServerError(anyhow!("Failed to acquire database connection: {}", e))
    })?;

    let profile_data = get_user_profile_by_id(&mut conn, user_id).await?;

    if let Some(profile) = profile_data {
        // If profile exists, return it
        return Ok((
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!(profile)),
        ));
    } else {
        // If no profile exists, return a 404 Not Found
        return Err(AppError::NotFound(anyhow!(
            "Profile not found for user ID: {}",
            user_id
        )));
    }
}

#[derive(serde::Deserialize, Debug, Validate)]
pub struct ProfileUpdateData {
    #[validate(length(
        min = 1,
        max = 50,
        message = "First name must be between 1 and 50 characters long"
    ))]
    pub first_name: String,
    #[validate(length(
        min = 1,
        max = 50,
        message = "Last name must be between 1 and 50 characters long"
    ))]
    pub last_name: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

pub async fn update_profile(
    State(state): State<AppState>,
    session: Session,
    Path(user_id): Path<String>,
    axum::Json(mut profile_data): axum::Json<ProfileUpdateData>,
) -> AppResult<impl IntoResponse> {
    // Validate the profile data
    profile_data
        .validate()
        .map_err(|e| AppError::BadRequest(anyhow!("Invalid profile data: {}", e)))?;

    profile_data.first_name = profile_data.first_name.trim().to_string();
    profile_data.last_name = profile_data.last_name.trim().to_string();

    // Ensure the display name, if provided, is trimmed
    if let Some(display_name) = &mut profile_data.display_name {
        *display_name = display_name.trim().to_string();
    }
    // Ensure the avatar URL, if provided, is trimmed
    if let Some(avatar_url) = &mut profile_data.avatar_url {
        *avatar_url = avatar_url.trim().to_string();
    }

    // Check if the user is authenticated
    let user_session = session
        .get::<UserSession>("user")
        .await
        .map_err(|_| AppError::Unauthorized(anyhow!("Cannot find user session")))?;

    let user_session_id = match user_session {
        Some(user_session_data) => user_session_data.user_id,
        None => return Err(AppError::Unauthorized(anyhow!("user not Authenticated"))),
    };

    // Ensure the user_id in the path matches the authenticated user's ID
    let user_id = match user_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => return Err(AppError::BadRequest(anyhow!("Invalid user ID format"))),
    };

    if user_session_id != user_id {
        return Err(AppError::Forbidden(anyhow!(
            "You do not have permission to update this profile"
        )));
    }

    // Update the profile in the database
    let db_pool = state.db_pool.clone();
    let mut conn = db_pool.acquire().await.map_err(|e| {
        AppError::InternalServerError(anyhow!("Failed to acquire database connection: {}", e))
    })?;

    update_user_profile_by_id(&mut conn, user_id, &profile_data).await?;

    Ok((
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({"message": "Profile updated successfully"})),
    ))
}
