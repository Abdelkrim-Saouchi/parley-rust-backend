use oauth2::basic::BasicClient;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: sqlx::PgPool,
    pub google_oauth_client: BasicClient,
    pub github_oauth_client: BasicClient,
}
