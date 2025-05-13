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

    let state = app_state::AppState { db_pool: pool };
    let app = routes::create_routes().with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
