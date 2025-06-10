use crate::models::users::ChatType;
use crate::models::users::GroupVisibility;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

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
