use crate::models::users::ChatType;
use crate::models::users::GroupVisibility;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use super::users::InvitationStatus;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Chat {
    pub id: Uuid,
    pub chat_type: ChatType,
    pub name: Option<String>,
    pub description: Option<String>,
    pub visibility: GroupVisibility,
    pub created_by: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct GroupInvitation {
    pub id: i32,
    pub chat_id: Uuid,
    pub inviter_id: Uuid,
    pub invitee_id: Uuid,
    pub status: InvitationStatus,
    pub message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub responded_at: Option<chrono::DateTime<chrono::Utc>>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}
