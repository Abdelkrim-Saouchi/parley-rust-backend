use axum::{extract::State, response::IntoResponse, Json};
use tower_sessions::Session;
use uuid::Uuid;
use validator::Validate;

use crate::{
    app_state::AppState,
    error::{AppError, AppResult},
    models::sessions::UserSession,
    queries::friends::insert_friend_request,
};

#[derive(serde::Deserialize, Validate)]
pub struct FriendRequestData {
    #[validate(length(min = 1, message = "Sender ID cannot be empty"))]
    pub receiver_id: String,
    pub message: Option<String>,
}

pub async fn send_friend_request(
    State(state): State<AppState>,
    session: Session,
    Json(mut payload): Json<FriendRequestData>,
) -> AppResult<impl IntoResponse> {
    payload
        .validate()
        .map_err(|e| AppError::BadRequest(anyhow::anyhow!("Invalid friend request data: {}", e)))?;

    payload.receiver_id = payload.receiver_id.trim().to_string();
    if let Some(message) = &mut payload.message {
        *message = message.trim().to_string();
    }

    let user_session = session
        .get::<UserSession>("user")
        .await
        .map_err(|_| AppError::Unauthorized(anyhow::anyhow!("Cannot find user session")))?;

    let user_id = match user_session {
        Some(user_data) => user_data.user_id,
        None => {
            return Err(AppError::Unauthorized(anyhow::anyhow!(
                "User session not found"
            )));
        }
    };

    let receiver_id = match Uuid::parse_str(&payload.receiver_id) {
        Ok(id) => id,
        Err(_) => {
            return Err(AppError::BadRequest(anyhow::anyhow!(
                "Invalid receiver ID format"
            )));
        }
    };
    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        AppError::InternalServerError(anyhow::anyhow!(
            "Failed to acquire database connection: {}",
            e
        ))
    })?;

    // Insert the friend request into the database
    insert_friend_request(&mut conn, user_id, receiver_id, payload.message)
        .await
        .map_err(|e| {
            AppError::InternalServerError(anyhow::anyhow!("Failed to send friend request: {}", e))
        })?;

    Ok((axum::http::StatusCode::OK, "Friend request sent"))
}
