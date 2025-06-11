use crate::models::users::InvitationStatus;
use crate::models::users::MemberRole;
use crate::queries::chats::insert_group_chat_invitation;
use crate::queries::chats::update_group_chat_invitation;
use crate::queries::chats::{insert_chat, insert_chat_participant, insert_group_chat};
use anyhow::anyhow;
use axum::response::IntoResponse;
use axum::{extract::State, Json};

use serde::Deserialize;
use sqlx::Acquire;
use tower_sessions::Session;
use validator::Validate;

use crate::error::AppError;
use crate::models::sessions::UserSession;
use crate::models::users::ChatType;
use crate::{app_state::AppState, error::AppResult};

#[derive(serde::Deserialize)]
pub struct ChatRequestPayload {
    pub reciever_id: String,
}

// Direct chat between users
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

// Group chat with users
#[derive(Deserialize, Validate)]
pub struct GroupChatRequestPayload {
    pub name: String,
    pub description: String,
}

pub async fn create_group_chat(
    State(state): State<AppState>,
    session: Session,
    Json(mut payload): Json<GroupChatRequestPayload>,
) -> AppResult<impl IntoResponse> {
    let user_session = session
        .get::<UserSession>("user")
        .await
        .map_err(|_| AppError::NotFound(anyhow::anyhow!("Failed to get session")))?;

    let user_id = match user_session {
        Some(user_data) => user_data.user_id,
        None => return Err(AppError::NotFound(anyhow::anyhow!("Failed to get user id"))),
    };

    let _ = payload
        .validate()
        .map_err(|_| AppError::BadRequest(anyhow!("Invalid inputs")));

    payload.name = payload.name.trim().to_string();
    payload.description = payload.description.trim().to_string();

    let chat_type = ChatType::Group;
    let role = MemberRole::Admin;
    let id = uuid::Uuid::new_v4();

    let mut conn =
        state.db_pool.acquire().await.map_err(|_| {
            AppError::InternalServerError(anyhow::anyhow!("Failed to get connection"))
        })?;

    let mut tx = conn.begin().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to start transaction"))
    })?;

    let chat = insert_group_chat(
        &mut *tx,
        id,
        chat_type,
        user_id,
        payload.name,
        payload.description,
    )
    .await?;

    insert_chat_participant(&mut tx, chat.id, user_id, &role).await?;

    tx.commit().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to commit transaction"))
    })?;

    Ok((axum::http::StatusCode::OK, "Group chat created"))
}

#[derive(Deserialize, Validate)]
pub struct GroupInvitationPayload {
    chat_id: String,
    invitee_id: String,
    message: Option<String>,
}

pub async fn send_group_invitation(
    State(state): State<AppState>,
    session: Session,
    Json(mut payload): Json<GroupInvitationPayload>,
) -> AppResult<impl IntoResponse> {
    let user_session = session
        .get::<UserSession>("user")
        .await
        .map_err(|_| AppError::NotFound(anyhow::anyhow!("Failed to get session")))?;

    let user_id = match user_session {
        Some(user_data) => user_data.user_id,
        None => return Err(AppError::NotFound(anyhow::anyhow!("Failed to get user id"))),
    };

    payload
        .validate()
        .map_err(|_| AppError::BadRequest(anyhow!("Invalid inputs")))?;

    payload.chat_id = payload.chat_id.trim().to_string();
    payload.invitee_id = payload.invitee_id.trim().to_string();

    if let Some(message) = payload.message {
        payload.message = Some(message.trim().to_string());
    }

    let chat_id = uuid::Uuid::parse_str(&payload.chat_id)
        .map_err(|_| AppError::BadRequest(anyhow!("Invalid chat id")))?;

    let invitee_id = uuid::Uuid::parse_str(&payload.invitee_id)
        .map_err(|_| AppError::BadRequest(anyhow!("Invalid invitee id")))?;

    if invitee_id == user_id {
        return Err(AppError::BadRequest(anyhow!("Cannot invite self")));
    }

    let mut conn =
        state.db_pool.acquire().await.map_err(|_| {
            AppError::InternalServerError(anyhow::anyhow!("Failed to get connection"))
        })?;

    insert_group_chat_invitation(
        &mut *conn,
        chat_id,
        user_id,
        invitee_id,
        payload.message.unwrap_or("".to_string()),
    )
    .await?;

    Ok((axum::http::StatusCode::OK, "Group invitation sent"))
}

#[derive(Deserialize, Validate)]
pub struct ResponseGroupInvitationPayload {
    pub invitation_id: i32,
}

pub async fn accept_group_invitation(
    State(state): State<AppState>,
    session: Session,
    Json(payload): Json<ResponseGroupInvitationPayload>,
) -> AppResult<impl IntoResponse> {
    let user_session = session
        .get::<UserSession>("user")
        .await
        .map_err(|_| AppError::NotFound(anyhow::anyhow!("Failed to get session")))?;

    let user_id = match user_session {
        Some(user_data) => user_data.user_id,
        None => return Err(AppError::NotFound(anyhow::anyhow!("Failed to get user id"))),
    };

    payload
        .validate()
        .map_err(|_| AppError::BadRequest(anyhow!("Invalid inputs")))?;

    let mut conn =
        state.db_pool.acquire().await.map_err(|_| {
            AppError::InternalServerError(anyhow::anyhow!("Failed to get connection"))
        })?;
    let mut tx = conn.begin().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to start transaction"))
    })?;

    let invitation =
        update_group_chat_invitation(&mut tx, payload.invitation_id, InvitationStatus::Accepted)
            .await?;

    let role = MemberRole::Member;
    insert_chat_participant(&mut tx, invitation.chat_id, user_id, &role).await?;

    tx.commit().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to commit transaction"))
    })?;

    Ok((axum::http::StatusCode::OK, "Group invitation accepted"))
}

pub async fn decline_group_invitation(
    State(state): State<AppState>,
    Json(payload): Json<ResponseGroupInvitationPayload>,
) -> AppResult<impl IntoResponse> {
    payload
        .validate()
        .map_err(|_| AppError::BadRequest(anyhow!("Invalid inputs")))?;

    let mut conn =
        state.db_pool.acquire().await.map_err(|_| {
            AppError::InternalServerError(anyhow::anyhow!("Failed to get connection"))
        })?;

    let _ = update_group_chat_invitation(
        &mut *conn,
        payload.invitation_id,
        InvitationStatus::Declined,
    )
    .await?;

    Ok((axum::http::StatusCode::OK, "Group invitation declined"))
}
