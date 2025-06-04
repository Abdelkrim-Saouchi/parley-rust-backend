use sqlx::{pool::PoolConnection, Postgres};
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    models::users::FriendshipStatus,
};

pub async fn insert_friend_request(
    conn: &mut PoolConnection<Postgres>,
    user_id: Uuid,
    receiver_id: Uuid,
    message: Option<String>,
) -> AppResult<()> {
    let firend_request_status = FriendshipStatus::Pending;

    sqlx::query(
        "INSERT INTO friend_requests (sender_id, receiver_id, message, status) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(receiver_id)
    .bind(message)
    .bind(firend_request_status as FriendshipStatus)
    .execute(&mut **conn)
    .await
    .map_err(|e| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to send friend request: {}", e))
    })?;

    Ok(())
}
