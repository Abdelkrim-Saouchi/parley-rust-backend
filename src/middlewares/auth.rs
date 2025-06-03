use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use tower_sessions::Session;

use crate::models::sessions::UserSession;

pub async fn auth_middleware(
    session: Session,
    req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Check if the session has a user session
    match session.get::<UserSession>("user").await {
        Ok(Some(_user_session)) => {
            // User is authenticated, continue
            Ok(next.run(req).await)
        }
        Ok(None) => {
            // No user session found
            Err((StatusCode::UNAUTHORIZED, "Unauthorized".to_string()))
        }
        Err(e) => {
            // Session error
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}