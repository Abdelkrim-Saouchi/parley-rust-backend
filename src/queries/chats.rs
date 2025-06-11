use crate::models::chats::GroupInvitation;
use crate::models::users::InvitationStatus;
use crate::models::users::MemberRole;

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
