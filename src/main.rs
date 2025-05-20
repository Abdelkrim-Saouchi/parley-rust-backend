use std::env;

use axum_helmet::{Helmet, HelmetLayer, ReferrerPolicy};
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
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
    dotenvy::dotenv().ok();

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
    let _delete_expired_sessions = tokio::spawn(async move {
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

    let helmet = Helmet::new().add(ReferrerPolicy::NoReferrerWhenDowngrade);

    let google_client_id =
        ClientId::new(env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"));
    let google_client_secret = ClientSecret::new(
        env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set"),
    );
    let google_auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid Google auth Url");
    let google_token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid Google token Url");
    let googel_redirect_uri =
        RedirectUrl::new(env::var("GOOGLE_REDIRECT_URI").expect("GOOGLE_REDIRECT_URI must be set"))
            .unwrap();

    let google_oauth_client = BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        google_auth_url,
        Some(google_token_url),
    )
    .set_redirect_uri(googel_redirect_uri);

    let state = app_state::AppState {
        db_pool: pool,
        google_oauth_client,
    };
    let app = routes::create_routes()
        .with_state(state)
        .layer(session_layer)
        .layer(HelmetLayer::new(helmet));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    // let _ = delete_expired_sessions
    //     .await
    //     .expect("Failed to delete expired sessions");
    axum::serve(listener, app).await.unwrap();
}
