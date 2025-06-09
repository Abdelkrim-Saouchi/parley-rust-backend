use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/*
id SERIAL PRIMARY KEY,
user1_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
user2_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

 */
#[derive(Serialize, sqlx::FromRow)]
pub struct Friendships {
    pub id: i32,
    pub user1_id: Uuid,
    pub user2_id: Uuid,
    pub created_at: DateTime<Utc>,
}
