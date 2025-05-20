use anyhow::{Context, Ok, Result};
use dotenvy::dotenv;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;

pub async fn connect_to_db() -> Result<PgPool> {
    dotenv().context("Failed to load .env file")?;
    let db_url = env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let pool = PgPoolOptions::new()
        .max_connections(20) // 20 concurrent connections
        .connect(&db_url)
        .await
        .context("Failed to connect to database")?;
    Ok(pool)
}
