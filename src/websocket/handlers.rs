use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use tower_sessions::Session;
use uuid::Uuid;

use crate::{
    app_state::AppState,
    error::{AppError, AppResult},
    models::{
        sessions,
        users::MessageType,
        websocket::{IncomingMessage, WebSocketMessage},
    },
    queries::{
        chats::{get_user_chats, insert_message, is_user_in_chat, mark_message_as_read},
        users::get_user_profile_by_id,
    },
};
use serde_json;

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    sessions: Session,
) -> AppResult<Response> {
    let user_session = sessions
        .get::<sessions::UserSession>("user")
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

    Ok(ws.on_upgrade(move |socket| handle_websocket(socket, state, user_id)))
}

async fn handle_websocket(socket: WebSocket, state: AppState, user_id: uuid::Uuid) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<WebSocketMessage>();

    // Spawn task to handle outgoing messages
    let outgoing_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&message) {
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    // Get user's chats and join them
    let mut conn = match state.db_pool.acquire().await {
        Ok(conn) => conn,
        Err(_) => {
            eprintln!("Failed to acquire database connection");
            return;
        }
    };

    // Join user to their chats
    match get_user_chats(&mut conn, user_id).await {
        Ok(chat_ids) => {
            for chat_id in chat_ids {
                state
                    .websocket_manager
                    .join_chat(chat_id, user_id, tx.clone());

                // Notif other users in the chat
                if let Ok(Some(profile)) = get_user_profile_by_id(&mut conn, user_id).await {
                    let join_message = WebSocketMessage::UserJoined {
                        chat_id,
                        user_id,
                        username: profile.display_name.unwrap_or_else(|| {
                            format!("{} {}", profile.first_name, profile.last_name)
                        }),
                    };
                    state
                        .websocket_manager
                        .broadcast_to_chat(chat_id, join_message, Some(user_id))
                        .await;
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to get user chats for user {}: {}", user_id, e);
            return;
        }
    }

    // Handle incoming messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(e) = handle_text_message(&state, user_id, text.to_string()).await {
                    eprintln!("Error handling text message from user {}: {}", user_id, e);
                }
            }
            Ok(Message::Close(_)) => {
                eprintln!("User {} disconnected", user_id);
                break;
            }
            Err(e) => {
                eprintln!("Error receiving message from user {}: {}", user_id, e);
                break;
            }
            _ => {}
        }
    }

    // cleanup when connection closes
    state.websocket_manager.leave_all_chats(user_id);
    outgoing_task.abort();

    eprintln!("WebSocket handler finished for user {}", user_id);
}

async fn handle_text_message(state: &AppState, user_id: uuid::Uuid, text: String) -> AppResult<()> {
    // try to parse as JSON
    let parsed: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| AppError::BadRequest(anyhow::anyhow!("Invalid JSON")))?;

    let message_type = parsed["type"].as_str().ok_or_else(|| {
        AppError::BadRequest(anyhow::anyhow!(
            "Missing or invalid 'type' field in message"
        ))
    })?;

    match message_type {
        "send_message" => {
            let incoming: IncomingMessage = serde_json::from_value(parsed)
                .map_err(|_| AppError::BadRequest(anyhow::anyhow!("Invalid message format")))?;
            handle_send_message(state, user_id, incoming).await?;
        }
        "typing" => {
            handle_typing_indicator(state, user_id, parsed).await?;
        }
        "mark_read" => {
            handle_mark_read(state, user_id, parsed).await?;
        }
        "ping" => {
            let pong = WebSocketMessage::Pong;
            state.websocket_manager.send_to_user(user_id, pong).await;
        }
        _ => {
            let error = WebSocketMessage::Error {
                message: format!("Unknown message type: {}", message_type),
            };
            state.websocket_manager.send_to_user(user_id, error).await;
        }
    }

    Ok(())
}

async fn handle_send_message(
    state: &AppState,
    user_id: Uuid,
    incoming: IncomingMessage,
) -> AppResult<()> {
    let mut conn = state.db_pool.acquire().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Database connection failed"))
    })?;

    // Verify user is in the chat
    if !is_user_in_chat(&mut conn, incoming.chat_id, user_id).await? {
        return Err(AppError::Forbidden(anyhow::anyhow!("User not in chat")));
    }

    // Insert message into database
    let message_id = Uuid::new_v4();
    let timestamp = chrono::Utc::now();

    insert_message(
        &mut conn,
        message_id,
        incoming.chat_id,
        user_id,
        &incoming.content,
        &incoming.message_type,
        incoming.reply_to_message_id,
    )
    .await?;

    // Broadcast message to all users in the chat
    let ws_message = WebSocketMessage::Message {
        chat_id: incoming.chat_id,
        message_id,
        sender_id: user_id,
        content: incoming.content,
        message_type: incoming.message_type,
        reply_to_message_id: incoming.reply_to_message_id,
        timestamp,
    };

    state
        .websocket_manager
        .broadcast_to_chat(incoming.chat_id, ws_message, None)
        .await;

    Ok(())
}

async fn handle_typing_indicator(
    state: &AppState,
    user_id: Uuid,
    parsed: serde_json::Value,
) -> AppResult<()> {
    let chat_id = Uuid::parse_str(
        parsed["chat_id"]
            .as_str()
            .ok_or_else(|| AppError::BadRequest(anyhow::anyhow!("Missing chat_id")))?,
    )
    .map_err(|_| AppError::BadRequest(anyhow::anyhow!("Invalid chat_id")))?;

    let is_typing = parsed["is_typing"]
        .as_bool()
        .ok_or_else(|| AppError::BadRequest(anyhow::anyhow!("Missing is_typing")))?;

    let typing_message = WebSocketMessage::Typing {
        chat_id,
        user_id,
        is_typing,
    };

    state
        .websocket_manager
        .broadcast_to_chat(chat_id, typing_message, Some(user_id))
        .await;

    Ok(())
}

async fn handle_mark_read(
    state: &AppState,
    user_id: Uuid,
    parsed: serde_json::Value,
) -> AppResult<()> {
    let message_id = Uuid::parse_str(
        parsed["message_id"]
            .as_str()
            .ok_or_else(|| AppError::BadRequest(anyhow::anyhow!("Missing message_id")))?,
    )
    .map_err(|_| AppError::BadRequest(anyhow::anyhow!("Invalid message_id")))?;

    let chat_id = Uuid::parse_str(
        parsed["chat_id"]
            .as_str()
            .ok_or_else(|| AppError::BadRequest(anyhow::anyhow!("Missing chat_id")))?,
    )
    .map_err(|_| AppError::BadRequest(anyhow::anyhow!("Invalid chat_id")))?;

    let mut conn = state.db_pool.acquire().await.map_err(|_| {
        AppError::InternalServerError(anyhow::anyhow!("Database connection failed"))
    })?;

    // Mark message as read in database
    mark_message_as_read(&mut conn, message_id, user_id).await?;

    // Broadcast read receipt
    let read_message = WebSocketMessage::MessageRead {
        chat_id,
        message_id,
        user_id,
    };

    state
        .websocket_manager
        .broadcast_to_chat(chat_id, read_message, Some(user_id))
        .await;

    Ok(())
}
