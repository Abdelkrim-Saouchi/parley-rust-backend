use anyhow::anyhow;
use axum::{extract::State, response::IntoResponse, Json};
use sqlx::Acquire;
use tower_sessions::Session;
use uuid::Uuid;
use validator::Validate;

use crate::{
    app_state::AppState,
    error::{AppError, AppResult},
    models::{sessions::UserSession, users::FriendshipStatus},
    queries::friends::{
        get_sender_and_receiver_ids_with_friendship_status_from_friend_request,
        insert_friend_request, insert_new_friendship, update_friend_request_status_with_id,
    },
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

#[derive(serde::Deserialize, Validate)]
pub struct FriendRequestPayload {
    pub request_id: i32,
}

pub async fn accept_friend_request(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<FriendRequestPayload>,
) -> AppResult<impl IntoResponse> {
    // Get the current user's ID from the session
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

    payload
        .validate()
        .map_err(|e| AppError::BadRequest(anyhow::anyhow!("Invalid request ID: {}", e)))?;

    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        AppError::InternalServerError(anyhow::anyhow!(
            "Failed to acquire database connection: {}",
            e
        ))
    })?;

    // Start a transaction
    let mut tx = conn.begin().await.map_err(|e| {
        AppError::InternalServerError(anyhow::anyhow!("Database transaction failed: {}", e))
    })?;

    // Fetch the friend request details to get user IDs and verify the receiver
    // and status within the transaction.
    let request = get_sender_and_receiver_ids_with_friendship_status_from_friend_request(
        &mut *tx,
        payload.request_id,
    )
    .await?;

    let (requester_id, receiver_id, current_status) = request;

    // Verify the current user is the receiver
    if user_id != receiver_id {
        // Consider if requester should also be allowed to withdraw/cancel?
        // For acceptance, only receiver should be able to accept.
        return Err(AppError::Forbidden(anyhow!(
            "You are not authorized to accept this friend request"
        )));
    }

    // Check if the request is still pending
    if current_status != FriendshipStatus::Pending {
        return Err(AppError::BadRequest(anyhow!(
            "Friend request is not pending"
        )));
    }

    // Update the status of the friend request
    let request_status = FriendshipStatus::Accepted;
    update_friend_request_status_with_id(&mut *tx, payload.request_id, request_status).await?;

    // Insert the new friendship record
    insert_new_friendship(&mut *tx, requester_id, receiver_id).await?;

    // Commit the transaction
    tx.commit().await.map_err(|e| {
        AppError::InternalServerError(anyhow!("Failed to commit transaction: {}", e))
    })?;

    Ok((axum::http::StatusCode::OK, "Friend request accepted"))
}

pub async fn decline_friend_request(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<FriendRequestPayload>,
) -> AppResult<impl IntoResponse> {
    // Get the current user's ID from the session
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

    payload
        .validate()
        .map_err(|e| AppError::BadRequest(anyhow::anyhow!("Invalid request ID: {}", e)))?;

    let mut conn = state.db_pool.acquire().await.map_err(|e| {
        AppError::InternalServerError(anyhow::anyhow!(
            "Failed to acquire database connection: {}",
            e
        ))
    })?;

    // Start a transaction
    let mut tx = conn.begin().await.map_err(|e| {
        AppError::InternalServerError(anyhow::anyhow!("Database transaction failed: {}", e))
    })?;

    // Fetch the friend request details to get user IDs and verify the receiver
    // and status within the transaction.
    let request = get_sender_and_receiver_ids_with_friendship_status_from_friend_request(
        &mut *tx,
        payload.request_id,
    )
    .await?;

    let (_, receiver_id, current_status) = request;

    // Verify the current user is the receiver
    if user_id != receiver_id {
        // Consider if requester should also be allowed to withdraw/cancel?
        // For acceptance, only receiver should be able to accept.
        return Err(AppError::Forbidden(anyhow!(
            "You are not authorized to accept this friend request"
        )));
    }

    // Check if the request is still pending
    if current_status != FriendshipStatus::Pending {
        return Err(AppError::BadRequest(anyhow!(
            "Friend request is not pending"
        )));
    }

    // Update the status of the friend request
    let request_status = FriendshipStatus::Declined;
    update_friend_request_status_with_id(&mut *tx, payload.request_id, request_status)
        .await
        .map_err(|e| {
            AppError::InternalServerError(anyhow!("Failed to update friend request status: {}", e))
        })?;

    // Commit the transaction
    tx.commit().await.map_err(|e| {
        AppError::InternalServerError(anyhow!("Failed to commit transaction: {}", e))
    })?;

    Ok((axum::http::StatusCode::OK, "Friend request declined"))
}
