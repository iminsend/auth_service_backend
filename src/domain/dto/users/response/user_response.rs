//! 사용자 응답 DTO 구현
//!
//! 사용자 도메인의 API 응답 DTO들을 정의합니다.
//! 데이터베이스 엔티티에서 클라이언트 응답으로의 안전한 변환을 담당합니다.

use serde::{Deserialize, Serialize};
use mongodb::bson::DateTime;
use crate::domain::entities::users::user::User;
use crate::config::AuthProvider;

/// 표준 사용자 정보 응답 DTO
///
/// 클라이언트에게 사용자 정보를 안전하게 전달하기 위한 응답 형식입니다.
/// 민감한 정보(비밀번호, 해시 등)는 제외하고 필요한 정보만 포함합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    /// 사용자 고유 식별자 (MongoDB ObjectId의 문자열 표현)
    pub id: String,
    /// 사용자 이메일 주소
    pub email: String,
    /// 사용자명 (로그인 ID)
    pub username: String,
    /// 화면 표시용 이름
    pub display_name: String,
    /// 인증 제공자 (로컬, Google, GitHub 등)
    pub auth_provider: AuthProvider,
    /// OAuth 사용자 여부 (편의 필드)
    pub is_oauth_user: bool,
    /// 계정 활성화 상태
    pub is_active: bool,
    /// 이메일 인증 완료 여부
    pub is_email_verified: bool,
    /// 사용자 역할 목록
    pub roles: Vec<String>,
    /// 프로필 이미지 URL (선택사항)
    pub profile_image_url: Option<String>,
    /// 마지막 로그인 시간 (선택사항)
    pub last_login_at: Option<DateTime>,
    /// 계정 생성 시간
    pub created_at: DateTime,
    /// 마지막 정보 수정 시간
    pub updated_at: DateTime,
}

impl From<User> for UserResponse {
    /// User 엔티티를 UserResponse로 변환
    ///
    /// 민감한 정보는 제외하고 클라이언트가 필요로 하는 정보만을 포함합니다.
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
            ..  // 비밀번호 등 민감한 필드는 명시적으로 제외
        } = user;
        
        // OAuth 사용자 여부 계산 (Local 이외의 모든 제공자는 OAuth)
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

/// 사용자 생성 완료 응답 DTO
///
/// 회원가입 API의 성공 응답으로 사용됩니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserResponse {
    /// 생성된 사용자 정보
    pub user: UserResponse,
    /// 성공 메시지
    pub message: String,
}

/// 로그인 성공 응답 DTO (JWT 토큰 포함)
///
/// OAuth 2.0 Bearer Token 스펙을 따르는 형식으로
/// JWT 액세스 토큰과 선택적 리프레시 토큰을 포함합니다.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    /// 로그인한 사용자 정보
    pub user: UserResponse,
    /// JWT 액세스 토큰
    pub access_token: String,
    /// 토큰 타입 (항상 "Bearer")
    pub token_type: String,
    /// 토큰 만료 시간 (초 단위)
    pub expires_in: i64,
    /// 리프레시 토큰 (선택사항)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl LoginResponse {
    /// 기본 로그인 응답 생성 (리프레시 토큰 없음)
    pub fn new(user: User, access_token: String, expires_in: i64) -> Self {
        Self {
            user: UserResponse::from(user),
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: None,
        }
    }
    
    /// 리프레시 토큰을 포함한 로그인 응답 생성
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
