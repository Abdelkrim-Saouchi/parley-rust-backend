use crate::models::users::MemberRole;
use crate::queries::chats::{insert_chat, insert_chat_participant};
use axum::response::IntoResponse;
use axum::{extract::State, Json};

use sqlx::Acquire;
use tower_sessions::Session;

use crate::error::AppError;
use crate::models::sessions::UserSession;
use crate::models::users::ChatType;
use crate::{app_state::AppState, error::AppResult};

#[derive(serde::Deserialize)]
pub struct ChatRequestPayload {
    pub reciever_id: String,
}

pub async fn create_direct_chat(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<ChatRequestPayload>,
) -> AppResult<impl IntoResponse> {
    let user_session = session
        .get::<UserSession>("user")
        .await
        .map_err(|_| AppError::NotFound(anyhow::anyhow!("Failed to get session")))?;

    let user_id = match user_session {
        Some(user_data) => user_data.user_id,
        None => return Err(AppError::NotFound(anyhow::anyhow!("Failed to get user id"))),
    };

    let chat_type = ChatType::Direct;

    let mut conn =
        state.db_pool.acquire().await.map_err(|_| {
            AppError::InternalServerError(anyhow::anyhow!("Failed to get connection"))
        })?;

    let mut tx = conn.begin().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to start transaction"))
    })?;

    let id = uuid::Uuid::new_v4();
    let chat = insert_chat(&mut *tx, id, chat_type, user_id).await?;

    let role = MemberRole::Member;
    // add the sender to chat participants
    insert_chat_participant(&mut tx, chat.id, user_id, &role).await?;
    // add the reciever to chat participants
    let receiver_id = uuid::Uuid::parse_str(&payload.reciever_id)
        .map_err(|_| AppError::BadRequest(anyhow::anyhow!("Failed to parse reciever id")))?;
    insert_chat_participant(&mut tx, chat.id, receiver_id, &role).await?;

    tx.commit().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to commit transaction"))
    })?;

    Ok((axum::http::StatusCode::OK, "chat created"))
}
