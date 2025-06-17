use crate::models::websocket::{ChatRoom, UserConnection, WebSocketMessage};
use dashmap::DashMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct WebSocketManager {
    // Map of chat_id -> ChatRoom
    pub chat_rooms: Arc<DashMap<Uuid, ChatRoom>>,
    // Map of user_id -> Set of chat_ids they're connected to
    pub user_chats: Arc<DashMap<Uuid, Arc<DashMap<Uuid, ()>>>>,
}

impl WebSocketManager {
    pub fn new() -> Self {
        Self {
            chat_rooms: Arc::new(DashMap::new()),
            user_chats: Arc::new(DashMap::new()),
        }
    }

    pub fn join_chat(
        &self,
        chat_id: Uuid,
        user_id: Uuid,
        sender: tokio::sync::mpsc::UnboundedSender<WebSocketMessage>,
    ) {
        // Get or create the chat room
        let chat_room = self.chat_rooms.entry(chat_id).or_insert_with(|| ChatRoom {
            chat_id,
            connections: Arc::new(DashMap::new()),
        });

        // add user to chat room
        let user_connection = UserConnection { user_id, sender };
        chat_room.connections.insert(user_id, user_connection);

        // Track which chats the user is in
        let user_chat_set = self
            .user_chats
            .entry(user_id)
            .or_insert_with(|| Arc::new(DashMap::new()));
        user_chat_set.insert(chat_id, ());
        println!("User {} joined chat {}", user_id, chat_id);
    }

    pub fn leave_chat(&self, chat_id: Uuid, user_id: Uuid) {
        if let Some(chat_room) = self.chat_rooms.get(&chat_id) {
            chat_room.connections.remove(&user_id);

            // Remove from user's chat list
            if let Some(user_chats) = self.user_chats.get(&user_id) {
                user_chats.remove(&chat_id);
            }

            // Clena up empty chat room
            if chat_room.connections.is_empty() {
                self.chat_rooms.remove(&chat_id);
            }
        }
        println!("User {} left chat {}", user_id, chat_id);
    }

    pub fn leave_all_chats(&self, user_id: Uuid) {
        if let Some((_, user_chats)) = self.user_chats.remove(&user_id) {
            for chat_id in user_chats.iter() {
                if let Some(chat_room) = self.chat_rooms.get(&chat_id.key()) {
                    chat_room.connections.remove(&user_id);

                    // Clean up empty chat room
                    if chat_room.connections.is_empty() {
                        self.chat_rooms.remove(&chat_id.key());
                    }
                }
            }
        }

        println!("User {} left all chats", user_id);
    }

    pub async fn broadcast_to_chat(
        &self,
        chat_id: Uuid,
        message: WebSocketMessage,
        exclude_user: Option<Uuid>,
    ) {
        if let Some(chat_room) = self.chat_rooms.get(&chat_id) {
            for connection in chat_room.connections.iter() {
                let user_id = *connection.key();

                // Skip excluded user (usaully the sender)
                if let Some(exclude) = exclude_user {
                    if user_id == exclude {
                        continue;
                    }
                }
                if let Err(e) = connection.sender.send(message.clone()) {
                    eprintln!("Failed to send message to user {}: {}", user_id, e);
                    // Connetions is dead, remove it
                    chat_room.connections.remove(&user_id);
                }
            }
        }
    }

    pub async fn send_to_user(&self, user_id: Uuid, message: WebSocketMessage) -> bool {
        // Find the user in any chat room and send the message
        for chat_room in self.chat_rooms.iter() {
            if let Some(connection) = chat_room.connections.get(&user_id) {
                return match connection.sender.send(message) {
                    Ok(_) => true,
                    Err(e) => {
                        eprintln!("Failed to send message to user {}: {}", user_id, e);
                        // Connection is dead, remove it
                        chat_room.connections.remove(&user_id);
                        false
                    }
                };
            }
        }
        false
    }

    pub fn get_chat_users(&self, chat_id: Uuid) -> Vec<Uuid> {
        if let Some(chat_room) = self.chat_rooms.get(&chat_id) {
            chat_room.connections.iter().map(|k| *k.key()).collect()
        } else {
            Vec::new()
        }
    }

    pub fn is_user_in_chat(&self, chat_id: Uuid, user_id: Uuid) -> bool {
        if let Some(chat_room) = self.chat_rooms.get(&chat_id) {
            chat_room.connections.contains_key(&user_id)
        } else {
            false
        }
    }
}
