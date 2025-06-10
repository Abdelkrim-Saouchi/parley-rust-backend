use crate::models::users::MemberRole;

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
