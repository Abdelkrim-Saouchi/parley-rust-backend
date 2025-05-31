use anyhow::anyhow;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    error::{AppError, AppResult},
    models::{sessions::UserSession, users::UserProfile},
    queries::users::get_user_profile_by_id,
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
