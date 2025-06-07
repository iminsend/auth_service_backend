use serde::{Deserialize, Serialize};

/// Google OAuth 토큰 교환 응답
#[derive(Debug, Deserialize)]
pub struct GoogleTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i32,
    pub refresh_token: Option<String>,
    pub scope: String,
}

/// OAuth 로그인 URL 응답
#[derive(Debug, Serialize)]
pub struct OAuthLoginUrlResponse {
    pub login_url: String,
    pub state: String,
}