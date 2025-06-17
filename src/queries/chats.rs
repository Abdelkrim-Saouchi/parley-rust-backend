use uuid::Uuid;

use crate::error::AppResult;
use crate::models::chats::GroupInvitation;
use crate::models::users::InvitationStatus;
use crate::models::users::MemberRole;
use crate::models::users::MessageType;

// Direct chat between users
pub async fn insert_chat(
    conn: &mut sqlx::PgConnection,
    id: uuid::Uuid,
    chat_type: crate::models::users::ChatType,
    user_id: uuid::Uuid,
) -> crate::error::AppResult<crate::models::chats::Chat> {
    let chat: crate::models::chats::Chat = sqlx::query_as::<_, crate::models::chats::Chat>(
        "INSERT INTO chats (id, chat_type, created_by) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(id)
    .bind(chat_type)
    .bind(user_id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        println!("{:?}", e);
        crate::error::AppError::InternalServerError(
            anyhow::anyhow!("Failed to create direct chat",),
        )
    })?;

    Ok(chat)
}

pub async fn insert_group_chat(
    conn: &mut sqlx::PgConnection,
    id: uuid::Uuid,
    chat_type: crate::models::users::ChatType,
    user_id: uuid::Uuid,
    name: String,
    description: String,
) -> crate::error::AppResult<crate::models::chats::Chat> {
    let chat: crate::models::chats::Chat = sqlx::query_as::<_, crate::models::chats::Chat>(
        "INSERT INTO chats (id, chat_type, name, description, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(id)
    .bind(chat_type)
    .bind(name)
    .bind(description)
    .bind(user_id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        println!("{:?}", e);
        crate::error::AppError::InternalServerError(
            anyhow::anyhow!("Failed to create direct chat",),
        )
    })?;

    Ok(chat)
}

pub async fn insert_chat_participant(
    conn: &mut sqlx::PgConnection,
    chat_id: uuid::Uuid,
    user_id: uuid::Uuid,
    role: &MemberRole,
) -> crate::error::AppResult<()> {
    sqlx::query("INSERT INTO chat_participants (chat_id, user_id, role) VALUES ($1, $2, $3)")
        .bind(chat_id)
        .bind(user_id)
        .bind(role as &MemberRole)
        .execute(conn)
        .await
        .map_err(|e| {
            println!("{}", e);
            crate::error::AppError::InternalServerError(anyhow::anyhow!(
                "Failed to create chat participant"
            ))
        })?;

    Ok(())
}

// Group chat with users
pub async fn insert_group_chat_invitation(
    conn: &mut sqlx::PgConnection,
    chat_id: uuid::Uuid,
    inviter_id: uuid::Uuid,
    invitee_id: uuid::Uuid,
    message: String,
) -> crate::error::AppResult<()> {
    sqlx::query("INSERT INTO group_invitations (chat_id, inviter_id, invitee_id, message) VALUES ($1, $2, $3, $4)")
        .bind(chat_id)
        .bind(inviter_id)
        .bind(invitee_id)
        .bind(message)
        .execute(conn)
        .await
        .map_err(|e| {
            println!("{}", e);
            crate::error::AppError::InternalServerError(anyhow::anyhow!(
                "Failed to create group chat invitation"
            ))
        })?;

    Ok(())
}

pub async fn update_group_chat_invitation(
    conn: &mut sqlx::PgConnection,
    invitation_id: i32,
    status: InvitationStatus,
) -> crate::error::AppResult<GroupInvitation> {
    let invitation = sqlx::query_as::<_, GroupInvitation>(
        "UPDATE group_invitations SET status = $1 WHERE id = $2 RETURNING *",
    )
    .bind(status)
    .bind(invitation_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        println!("{}", e);
        crate::error::AppError::InternalServerError(anyhow::anyhow!(
            "Failed to update group invitation"
        ))
    })?;

    Ok(invitation)
}

pub async fn get_user_chats(conn: &mut sqlx::PgConnection, user_id: Uuid) -> AppResult<Vec<Uuid>> {
    let chat_ids = sqlx::query_scalar::<_, Uuid>(
        "SELECT chat_id FROM chat_participants WHERE user_id = $1 AND left_at IS NULL",
    )
    .bind(user_id)
    .fetch_all(conn)
    .await
    .map_err(|e| {
        eprintln!("Failed to get user chats: {}", e);
        crate::error::AppError::InternalServerError(anyhow::anyhow!("Failed to get user chats"))
    })?;

    Ok(chat_ids)
}

pub async fn is_user_in_chat(
    conn: &mut sqlx::PgConnection,
    chat_id: Uuid,
    user_id: Uuid,
) -> AppResult<bool> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM chat_participants WHERE chat_id = $1 AND user_id = $2 AND left_at IS NULL"
    )
    .bind(chat_id)
    .bind(user_id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        eprintln!("Failed to check if user is in chat: {}", e);
        crate::error::AppError::InternalServerError(anyhow::anyhow!("Failed to check chat membership"))
    })?;

    Ok(count > 0)
}

pub async fn insert_message(
    conn: &mut sqlx::PgConnection,
    message_id: Uuid,
    chat_id: Uuid,
    sender_id: Uuid,
    content: &str,
    message_type: &MessageType,
    reply_to_message_id: Option<Uuid>,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO messages (id, chat_id, sender_id, content, message_type, reply_to_message_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(message_id)
    .bind(chat_id)
    .bind(sender_id)
    .bind(content)
    .bind(message_type)
    .bind(reply_to_message_id)
    .execute(conn)
    .await
    .map_err(|e| {
        eprintln!("Failed to insert message: {}", e);
        crate::error::AppError::InternalServerError(anyhow::anyhow!("Failed to insert message"))
    })?;

    Ok(())
}

pub async fn mark_message_as_read(
    conn: &mut sqlx::PgConnection,
    message_id: Uuid,
    user_id: Uuid,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO message_receipts (message_id, user_id) VALUES ($1, $2)
         ON CONFLICT (message_id, user_id) DO NOTHING",
    )
    .bind(message_id)
    .bind(user_id)
    .execute(conn)
    .await
    .map_err(|e| {
        eprintln!("Failed to mark message as read: {}", e);
        crate::error::AppError::InternalServerError(anyhow::anyhow!(
            "Failed to mark message as read"
        ))
    })?;

    Ok(())
}
