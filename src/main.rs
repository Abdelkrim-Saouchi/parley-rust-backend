use tower_sessions::session_store::ExpiredDeletion;
use tower_sessions::{cookie::time::Duration, SessionManagerLayer};
use tower_sessions_sqlx_store::PostgresStore;

mod app_state;
mod db;
mod error;
mod handlers;
mod models;
mod queries;
mod routes;

#[tokio::main]
async fn main() {
    let pool = match db::connect_to_db().await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Error connecting to database: {}", e);
            std::process::exit(1);
        }
    };

    let session_store = PostgresStore::new(pool.clone());
    session_store
        .migrate()
        .await
        .expect("Session creation failed");

    // cleanup the expired sessions
    let cleanup_store = session_store.clone();
    let delete_expired_sessions = tokio::spawn(async move {
        cleanup_store
            .continuously_delete_expired(std::time::Duration::from_secs(3600))
            .await
    });

    let session_layer = SessionManagerLayer::new(session_store)
        .with_name("parley_cookie")
        .with_secure(false)
        .with_http_only(true)
        .with_same_site(tower_sessions::cookie::SameSite::Lax)
        .with_expiry(tower_sessions::Expiry::OnInactivity(Duration::days(1)));

    let state = app_state::AppState { db_pool: pool };
    let app = routes::create_routes()
        .with_state(state)
        .layer(session_layer);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    let _ = delete_expired_sessions
        .await
        .expect("Failed to delete expired sessions");
    axum::serve(listener, app).await.unwrap();
}
