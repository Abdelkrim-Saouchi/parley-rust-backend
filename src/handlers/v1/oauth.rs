use crate::error::{AppError, AppResult};
use crate::models::sessions::UserSession;
use crate::models::users::{ProviderType, User};

use crate::queries::users::{
    create_new_user_with_provider, find_user_by_email, find_user_id_by_provider,
    link_provider_to_user,
};
use anyhow::anyhow;
use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Redirect},
};
use chrono::{Duration, Utc};
use oauth2::{basic::BasicClient, AuthorizationCode, CsrfToken, Scope, TokenResponse};
use oauth2::{RequestTokenError, StandardErrorResponse};
use reqwest;
use serde::Deserialize;
use tower_sessions::Session;
use uuid::Uuid;

use crate::app_state::AppState;

#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    code: String,
    state: String,
}

fn get_oauth_client<'a>(state: &'a AppState, provider_name: &str) -> AppResult<&'a BasicClient> {
    match provider_name.to_lowercase().as_str() {
        "google" => Ok(&state.google_oauth_client),
        "github" => Ok(&state.github_oauth_client),
        _ => Err(AppError::BadRequest(anyhow!(
            "Unsupported OAuth provider: {}",
            provider_name
        ))),
    }
}

pub async fn oauth_login_handler(
    State(state): State<AppState>,
    session: Session,
    Path(provider_name): Path<String>,
) -> AppResult<impl IntoResponse> {
    let client = get_oauth_client(&state, &provider_name)?;

    let mut auth_req = client.authorize_url(|| CsrfToken::new_random());

    auth_req = match provider_name.to_lowercase().as_str() {
        "google" => auth_req.add_scopes(vec![
            Scope::new("openid".to_string()),
            Scope::new("email".to_string()),
            Scope::new("profile".to_string()),
        ]),
        "github" => auth_req.add_scopes(vec![
            Scope::new("read:user".to_string()),
            Scope::new("user:email".to_string()),
        ]),
        _ => {
            return Err(AppError::BadRequest(anyhow!(
                "Unsupported OAuth provider: {}",
                provider_name
            )))
        }
    };

    let (auth_url, csrf_state) = auth_req.url();

    session
        .insert(
            &format!("oauth_state_{}", provider_name),
            csrf_state.secret(),
        )
        .await
        .map_err(|e| {
            eprintln!("Session insert error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to store oauth state in session"))
        })?;

    Ok(Redirect::to(auth_url.as_str()))
}

pub async fn oauth_callback_handler(
    State(state): State<AppState>,
    session: Session,
    Path(provider_name): Path<String>,
    Query(query): Query<AuthCallbackQuery>,
) -> AppResult<impl IntoResponse> {
    let client = get_oauth_client(&state, &provider_name)?;

    let stored_state: Option<String> = session
        .get(&format!("oauth_state_{}", provider_name))
        .await
        .map_err(|e| {
            eprintln!("Session get error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to retrieve oauth state from session"))
        })?;

    let Some(stored_state) = stored_state else {
        return Err(AppError::Unauthorized(anyhow!(
            "OAuth state not found in session"
        )));
    };

    if stored_state != query.state {
        return Err(AppError::Unauthorized(anyhow!("OAuth state mismatch")));
    }

    let _: Option<String> = session
        .remove(&format!("oauth_state_{}", provider_name))
        .await
        .map_err(|e| {
            eprintln!("Session remove error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to remove oauth state from session"))
        })?;

    let code = AuthorizationCode::new(query.code);

    let token_response = client
        .exchange_code(code)
        .set_redirect_uri(std::borrow::Cow::Borrowed(client.redirect_url().unwrap()))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| {
            eprintln!("OAuth token exchange error for {}: {:?}", provider_name, e);

            match e {
                oauth2::RequestTokenError::Request(req_err) => {
                    AppError::InternalServerError(anyhow!("OAuth token request failed: {:?}", req_err))
                }
                oauth2::RequestTokenError::Parse(parse_err, response_body) => {
                    // Check if the response body contains a GitHub OAuth error response
                    let response_str = String::from_utf8_lossy(&response_body);
                    
                    // Try to parse as JSON to extract OAuth error information
                    if let Ok(error_json) = serde_json::from_slice::<serde_json::Value>(&response_body) {
                        if let Some(error_type) = error_json.get("error").and_then(|v| v.as_str()) {
                            let error_description = error_json
                                .get("error_description")
                                .and_then(|v| v.as_str())
                                .unwrap_or("No description provided");
                            
                            // Handle specific OAuth errors that should be user-facing
                            match error_type {
                                "bad_verification_code" | "invalid_grant" => {
                                    return AppError::BadRequest(anyhow!(
                                        "Invalid or expired authorization code. Please try logging in again."
                                    ));
                                }
                                _ => {
                                    return AppError::InternalServerError(anyhow!(
                                        "OAuth server returned an error for {}: {}: {}",
                                        provider_name,
                                        error_type,
                                        error_description
                                    ));
                                }
                            }
                        }
                    }
                    
                    // Fall back to original parse error handling if not a recognizable OAuth error
                    AppError::InternalServerError(anyhow!(
                        "Failed to parse OAuth provider response for {}: {:?} (Body: {})",
                        provider_name,
                        parse_err,
                        response_str
                    ))
                }
                oauth2::RequestTokenError::Other(other_err) => {
                    AppError::InternalServerError(anyhow!(
                        "An unexpected OAuth error occurred for {}: {:?}",
                        provider_name,
                        other_err
                    ))
                }
                oauth2::RequestTokenError::ServerResponse(server_err) => {
                    AppError::InternalServerError(anyhow!(
                        "OAuth server returned an error for {}: {:?}",
                        provider_name,
                        server_err
                    ))
                }
            }
        })?;

    let access_token = token_response.access_token().secret();
    let refresh_token = token_response
        .refresh_token()
        .map(|t| t.secret().to_string());
    let token_expires_at = token_response
        .expires_in()
        .map(|d| Utc::now() + Duration::seconds(d.as_secs() as i64));

    let user_info_url = match provider_name.to_lowercase().as_str() {
        "google" => "https://www.googleapis.com/oauth2/v2/userinfo",
        "github" => "https://api.github.com/user",
        _ => {
            return Err(AppError::InternalServerError(anyhow!(
                "Unsupported provider for user info fetch"
            )))
        }
    };

    let client = reqwest::Client::new();
    let provider_user_info: serde_json::Value = client
        .get(user_info_url)
        .bearer_auth(access_token)
        .header("User-Agent", "parley_backend")
        .send()
        .await
        .map_err(|e| {
            eprintln!("OAuth user info fetch error: {:?}", e);
            AppError::InternalServerError(anyhow!(
                "Failed to fetch user info from OAuth provider: {}",
                provider_name
            ))
        })?
        .json()
        .await
        .map_err(|e| {
            eprintln!("OAuth user info JSON error: {:?}", e);
            AppError::InternalServerError(anyhow!(
                "Failed to parse user info JSON from OAuth provider: {}",
                provider_name
            ))
        })?;

    let (provider_user_id, provider_email, first_name, last_name, display_name) =
        match provider_name.to_lowercase().as_str() {
            "google" => {
                let id = provider_user_info["id"].as_str().ok_or_else(|| {
                    AppError::InternalServerError(anyhow!("Google use ID not found"))
                })?;
                let email = provider_user_info["email"].as_str().ok_or_else(|| {
                    AppError::InternalServerError(anyhow!("Google email not found"))
                })?;
                let first_name = provider_user_info["given_name"].as_str().ok_or_else(|| {
                    AppError::InternalServerError(anyhow!("Google first name not found"))
                })?;
                let last_name = provider_user_info["family_name"].as_str().ok_or_else(|| {
                    AppError::InternalServerError(anyhow!("Google last name not found"))
                })?;
                let display_name = provider_user_info["name"].as_str().ok_or_else(|| {
                    AppError::InternalServerError(anyhow!("Google display name not found"))
                })?;

                if email.is_empty() {
                    return Err(AppError::InternalServerError(anyhow!(
                        "Google email not found"
                    )));
                }

                (
                    id.to_string(),
                    Some(email.to_string()),
                    first_name.to_string(),
                    last_name.to_string(),
                    Some(display_name.to_string()),
                )
            }

            "github" => {
                let id = provider_user_info["id"].as_f64().ok_or_else(|| {
                    AppError::InternalServerError(anyhow!("Github use ID not found"))
                })?;

                // Try to get email from main user object
                let mut email = provider_user_info["email"].as_str().map(|s| s.to_string());

                // If email is not present, fetch from /user/emails endpoint
                if email.is_none() {
                    let emails_url = "https://api.github.com/user/emails";
                    let emails_resp = reqwest::Client::new()
                        .get(emails_url)
                        .bearer_auth(access_token)
                        .header("User-Agent", "parley_backend")
                        .send()
                        .await
                        .map_err(|e| {
                            eprintln!("GitHub /user/emails fetch error: {:?}", e);
                            AppError::InternalServerError(anyhow!("Failed to fetch emails from GitHub"))
                        })?
                        .json::<serde_json::Value>()
                        .await
                        .map_err(|e| {
                            eprintln!("GitHub /user/emails JSON error: {:?}", e);
                            AppError::InternalServerError(anyhow!("Failed to parse emails from GitHub"))
                        })?;

                    if let Some(arr) = emails_resp.as_array() {
                        // Find the primary and verified email
                        if let Some(primary) = arr.iter().find(|e| {
                            e.get("primary").and_then(|v| v.as_bool()).unwrap_or(false)
                                && e.get("verified").and_then(|v| v.as_bool()).unwrap_or(false)
                        }) {
                            if let Some(email_str) = primary.get("email").and_then(|v| v.as_str()) {
                                email = Some(email_str.to_string());
                            }
                        } else if let Some(any_email) = arr.iter().find_map(|e| e.get("email").and_then(|v| v.as_str())) {
                            email = Some(any_email.to_string());
                        }
                    }
                }

                let display_name = provider_user_info["name"].as_str().map(|s| s.to_string());
                let (first, last) = display_name.as_ref().map_or(("", ""), |name| {
                    let parts: Vec<&str> = name.split_whitespace().collect();
                    if parts.len() > 1 {
                        (parts[0], parts[parts.len() - 1])
                    } else {
                        (name, "")
                    }
                });

                (
                    id.to_string(),
                    email,
                    first.to_string(),
                    last.to_string(),
                    display_name,
                )
            }
            _ => {
                return Err(AppError::InternalServerError(anyhow!(
                    "Unsupported provider for user info fetch"
                )))
            }
        };

    let provider_type: ProviderType = match provider_name.to_lowercase().as_str() {
        "google" => ProviderType::Google,
        "github" => ProviderType::Github,
        _ => {
            return Err(AppError::InternalServerError(anyhow!(
                "Unsupported provider for user info fetch"
            )))
        }
    };

    let mut tx = state.db_pool.begin().await.map_err(|e| {
        eprintln!("Transaction begin error: {:?}", e);
        AppError::InternalServerError(anyhow!(
            "Failed to begin transaction during Oauth login/signup"
        ))
    })?;

    let user_id = match find_user_id_by_provider(&mut tx, provider_type, &provider_user_id).await? {
        Some(existing_user_id) => {
            eprintln!("Logging in existing user via {} provider", provider_name);
            existing_user_id
        }
        None => {
            let user_by_email: Option<User> = if let Some(ref email) = provider_email {
                match find_user_by_email(&mut tx, email).await {
                    Ok(user) => Some(user),
                    Err(_) => None,
                }
            } else {
                None
            };

            match user_by_email {
                Some(user_by_email) => {
                    link_provider_to_user(
                        &mut tx,
                        &user_by_email.id,
                        provider_type,
                        &provider_user_id,
                        provider_email.as_deref().unwrap_or(""),
                        Some(access_token),
                        refresh_token.as_deref(),
                        token_expires_at,
                        Some(&provider_user_info),
                    )
                    .await?;
                    user_by_email.id
                }
                None => {
                    let new_user_id = Uuid::new_v4();
                    create_new_user_with_provider(
                        &mut tx,
                        &new_user_id,
                        provider_email.as_deref().unwrap_or(""),
                        provider_type,
                        &provider_user_id,
                        provider_email.as_deref(),
                        Some(access_token),
                        refresh_token.as_deref(),
                        token_expires_at,
                        Some(&provider_user_info),
                        &first_name,
                        &last_name,
                        display_name.as_deref(),
                    )
                    .await?;
                    new_user_id
                }
            }
        }
    };

    // create session
    let user_session_data = UserSession { user_id };
    session
        .insert("user", user_session_data)
        .await
        .map_err(|e| {
            eprintln!("Session insert error: {:?}", e);
            AppError::InternalServerError(anyhow!("Failed to store user session after Oauth"))
        })?;

    tx.commit().await.map_err(|e| {
        eprintln!("Transaction commit error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to commit transaction during Oauth"))
    })?;

    // redirect to home page or return Json
    Ok((
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "message": "Oauth login successful",
            "user_id": user_id,
            "provider": provider_name,
        })),
    ))
}

pub async fn oauth_logout_handler(
    State(state): State<AppState>,
    session: Session,
    Path(provider_name): Path<String>,
) -> AppResult<impl IntoResponse> {
    let pool_db = &state.db_pool;

    let user_id = match session.get::<UserSession>("user").await.map_err(|e| {
        eprintln!("Session get error: {:?}", e);
        AppError::InternalServerError(anyhow!("Failed to get session"))
    })? {
        Some(user_data) => Some(user_data.user_id),
        None => None,
    };

    session.clear().await;

    let Some(user_id) = user_id else {
        return Ok((
            axum::http::StatusCode::OK,
            axum::Json(serde_json::json!({"message": "Logged out"})),
        ));
    };

    match provider_name.to_lowercase().as_str() {
        "google" => {
            // Obtain a connection from the pool
            let mut conn = pool_db.acquire().await.map_err(|e| {
                eprintln!("Database connection error: {:?}", e);
                AppError::InternalServerError(anyhow!("Failed to get database connection"))
            })?;

            let provider_type = ProviderType::Google;

            // Use a simple query to avoid prepared statement issues
            let row = sqlx::query_scalar::<_, Option<String>>(
                "SELECT access_token FROM user_providers WHERE user_id = $1 AND provider = $2::provider_type AND access_token IS NOT NULL"
            )
            .bind(user_id)
            .bind(provider_type as ProviderType)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                eprintln!("Database query error (fetch_optional): {:?}", e);
                AppError::InternalServerError(anyhow!("Database error during logout (fetch): {}", e))
            })?;

            if let Some(access_token) = row {
                // Revoke the token with Google
                let client = reqwest::Client::new();
                client
                    .post("https://oauth2.googleapis.com/revoke")
                    .form(&[("token", access_token)])
                    .send()
                    .await
                    .map_err(|e| {
                        eprintln!("Google token revocation error: {:?}", e);
                        AppError::InternalServerError(anyhow!("Failed to revoke Google token"))
                    })?;

                // Update the database to clear the tokens
                sqlx::query(
                    "UPDATE user_providers
                     SET access_token = NULL, refresh_token = NULL, token_expires_at = NULL
                     WHERE user_id = $1 AND provider = $2::provider_type",
                )
                .bind(user_id)
                .bind(provider_type as ProviderType)
                .execute(&mut *conn) // Use the mutable reference to the connection
                .await
                .map_err(|e| {
                    eprintln!("Database update error: {:?}", e);
                    AppError::InternalServerError(anyhow!("Database error during logout"))
                })?;
            }
        }
        "github" => {
            // Obtain a connection from the pool
            let mut conn = pool_db.acquire().await.map_err(|e| {
                eprintln!("Database connection error: {:?}", e);
                AppError::InternalServerError(anyhow!("Failed to get database connection"))
            })?;

            let provider_type = ProviderType::Github;

            // Use a simple query to avoid prepared statement issues
            let row = sqlx::query_scalar::<_, Option<String>>(
                "SELECT access_token FROM user_providers WHERE user_id = $1 AND provider = $2::provider_type AND access_token IS NOT NULL"
            )
            .bind(user_id)
            .bind(provider_type as ProviderType)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                eprintln!("Database query error (fetch_optional): {:?}", e);
                AppError::InternalServerError(anyhow!("Database error during logout (fetch): {}", e))
            })?;

            if let Some(access_token) = row {
                let client = reqwest::Client::new();
                client
                    .post("https://api.github.com/authorizations/revoke")
                    .form(&[("credentials", access_token)])
                    .send()
                    .await
                    .map_err(|e| {
                        eprintln!("GitHub revoke API error: {:?}", e);
                        AppError::InternalServerError(anyhow!(
                            "Failed to revoke GitHub authorization"
                        ))
                    })?;

                // Update the database to clear the tokens
                sqlx::query(
                    "UPDATE user_providers
                     SET access_token = NULL, refresh_token = NULL, token_expires_at = NULL
                     WHERE user_id = $1 AND provider = $2::provider_type",
                )
                .bind(user_id)
                .bind(provider_type as ProviderType)
                .execute(&mut *conn) // Use the mutable reference to the connection
                .await
                .map_err(|e| {
                    eprintln!("Database update error: {:?}", e);
                    AppError::InternalServerError(anyhow!("Database error during logout"))
                })?;
            }
        }
        _ => {
            return Err(AppError::InternalServerError(anyhow!(
                "Unsupported provider for logout"
            )));
        }
    };

    Ok((
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "message": "Oauth login successful",
            "user_id": user_id,
            "provider": provider_name,
        })),
    ))
}
