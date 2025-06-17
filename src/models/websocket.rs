use crate::models::users::MessageType;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type")]
pub enum WebSocketMessage {
    #[serde(rename = "message")]
    Message {
        chat_id: Uuid,
        message_id: Uuid,
        sender_id: Uuid,
        content: String,
        message_type: MessageType,
        reply_to_message_id: Option<Uuid>,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    #[serde(rename = "typing")]
    Typing {
        chat_id: Uuid,
        user_id: Uuid,
        is_typing: bool,
    },
    #[serde(rename = "user_joined")]
    UserJoined {
        chat_id: Uuid,
        user_id: Uuid,
        username: String,
    },
    #[serde(rename = "user_left")]
    UserLeft {
        chat_id: Uuid,
        user_id: Uuid,
        username: String,
    },
    #[serde(rename = "message_read")]
    MessageRead {
        chat_id: Uuid,
        message_id: Uuid,
        user_id: Uuid,
    },
    #[serde(rename = "error")]
    Error { message: String },
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "pong")]
    Pong,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct IncomingMessage {
    pub chat_id: Uuid,
    pub content: String,
    pub message_type: MessageType,
    pub reply_to_message_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct UserConnection {
    pub user_id: Uuid,
    pub sender: tokio::sync::mpsc::UnboundedSender<WebSocketMessage>,
}

#[derive(Debug, Clone)]
pub struct ChatRoom {
    pub chat_id: Uuid,
    pub connections: std::sync::Arc<dashmap::DashMap<Uuid, UserConnection>>,
}
