use sqlx::{pool::PoolConnection, postgres::PgConnection, Postgres};
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
    .bind(firend_request_status)
    .execute(&mut **conn)
    .await
    .map_err(|e| {
        AppError::InternalServerError(anyhow::anyhow!("Failed to send friend request: {}", e))
    })?;

    Ok(())
}

pub async fn get_sender_and_receiver_ids_with_friendship_status_from_friend_request(
    conn: &mut PgConnection,
    request_id: i32,
) -> AppResult<(Uuid, Uuid, FriendshipStatus)> {
    let request: (Uuid, Uuid, FriendshipStatus) =
        sqlx::query_as("SELECT sender_id, receiver_id, status FROM friend_requests WHERE id = $1")
            .bind(request_id)
            .fetch_one(conn)
            .await
            .map_err(|e| match e {
                sqlx::Error::RowNotFound => {
                    AppError::NotFound(anyhow::anyhow!("Friend request not found"))
                }
                _ => AppError::InternalServerError(anyhow::anyhow!(
                    "Failed to fetch friend request: {}",
                    e
                )),
            })?;

    Ok(request)
}

pub async fn update_friend_request_status_with_id(
    conn: &mut PgConnection,
    request_id: i32,
    status: FriendshipStatus,
) -> AppResult<()> {
    sqlx::query("UPDATE friend_requests SET status = $1 WHERE id = $2")
        .bind(status)
        .bind(request_id)
        .execute(conn)
        .await
        .map_err(|e| {
            AppError::InternalServerError(anyhow::anyhow!(
                "Failed to update friend request status: {}",
                e
            ))
        })?;

    Ok(())
}

pub async fn insert_new_friendship(
    conn: &mut PgConnection,
    user1_id: Uuid,
    user2_id: Uuid,
) -> AppResult<()> {
    sqlx::query("INSERT INTO friendships (user1_id, user2_id) VALUES ($1, $2)")
        // Store user IDs in a consistent order to prevent duplicate entries
        // and simplify querying for existing friendships.
        // Assuming user1_id < user2_id lexicographically or numerically.
        .bind(std::cmp::min(user1_id, user2_id))
        .bind(std::cmp::max(user1_id, user2_id))
        .execute(conn)
        .await
        .map_err(|e| {
            // Check for unique constraint violation if friendship already exists
            if e.to_string().contains("unique constraint") {
                AppError::BadRequest(anyhow::anyhow!("Friendship already exists"))
            } else {
                AppError::InternalServerError(anyhow::anyhow!("Failed to create friendship: {}", e))
            }
        })?;

    Ok(())
}
