use serde::{Deserialize, Serialize};
use mongodb::bson::DateTime;
use crate::domain::entities::users::user::User;
use crate::config::AuthProvider;

/// 사용자 응답 DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub username: String,
    pub display_name: String,
    
    /// 인증 프로바이더 (로컬, Google, GitHub 등)
    pub auth_provider: AuthProvider,
    
    /// OAuth 사용자인지 여부 (편의 필드)
    pub is_oauth_user: bool,
    
    pub is_active: bool,
    pub is_email_verified: bool,
    pub roles: Vec<String>,
    pub profile_image_url: Option<String>,
    pub last_login_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        let User {
            id,
            email,
            username,
            display_name,
            auth_provider,
            is_active,
            is_email_verified,
            roles,
            profile_image_url,
            last_login_at,
            created_at,
            updated_at,
            ..
        } = user;
        
        let is_oauth_user = !matches!(auth_provider, AuthProvider::Local);
        
        Self {
            id: id.map(|id| id.to_hex()).unwrap_or_default(),
            email,
            username,
            display_name,
            auth_provider,
            is_oauth_user,
            is_active,
            is_email_verified,
            roles,
            profile_image_url,
            last_login_at,
            created_at,
            updated_at,
        }
    }
}

/// 사용자 생성 응답 DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserResponse {
    pub user: UserResponse,
    pub message: String,
}

/// 로그인 응답 DTO (JWT 토큰 포함)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub user: UserResponse,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    
    /// 리프레시 토큰 (선택사항)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl LoginResponse {
    /// 새 로그인 응답 생성
    pub fn new(user: User, access_token: String, expires_in: i64) -> Self {
        Self {
            user: UserResponse::from(user),
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: None,
        }
    }
    
    /// 리프레시 토큰과 함께 로그인 응답 생성
    pub fn with_refresh_token(user: User, access_token: String, expires_in: i64, refresh_token: String) -> Self {
        Self {
            user: UserResponse::from(user),
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some(refresh_token),
        }
    }
}
