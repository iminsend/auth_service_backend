use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::{Deserialize, Serialize};
use crate::config::AuthProvider;

/// OAuth 프로바이더 관련 추가 데이터
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthData {
    /// OAuth 프로바이더에서의 사용자 ID
    pub provider_user_id: String,
    
    /// OAuth 프로바이더에서 제공된 프로필 이미지 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_profile_image: Option<String>,
    
    /// OAuth 프로바이더에서 제공된 추가 정보
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_data: Option<serde_json::Value>,
}

/// 사용자 엔티티
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    /// 사용자 이메일 (unique)
    pub email: String,

    /// 사용자 이름
    pub username: String,

    /// 표시 이름
    pub display_name: String,

    /// 해시된 비밀번호 (OAuth 사용자의 경우 None)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,

    /// 인증 프로바이더
    pub auth_provider: AuthProvider,

    /// OAuth 관련 추가 데이터 (로컬 인증 사용자의 경우 None)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_data: Option<OAuthData>,

    /// 계정 활성화 여부
    pub is_active: bool,

    /// 이메일 인증 여부 (OAuth 사용자는 기본적으로 true)
    pub is_email_verified: bool,

    /// 사용자 역할
    pub roles: Vec<String>,

    /// 프로필 이미지 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_image_url: Option<String>,

    /// 마지막 로그인 시간
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<DateTime>,

    /// 생성 시간
    pub created_at: DateTime,

    /// 수정 시간
    pub updated_at: DateTime,
}

impl User {
    /// 새 로컬 사용자 생성 (이메일/패스워드)
    pub fn new_local(email: String, username: String, display_name: String, password_hash: String) -> Self {
        let now = DateTime::now();

        Self {
            id: None,
            email,
            username,
            display_name,
            password_hash: Some(password_hash),
            auth_provider: AuthProvider::Local,
            oauth_data: None,
            is_active: true,
            is_email_verified: false, // 로컬 사용자는 이메일 인증 필요
            roles: vec!["user".to_string()],
            profile_image_url: None,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// 새 OAuth 사용자 생성
    pub fn new_oauth(
        email: String,
        username: String,
        display_name: String,
        auth_provider: AuthProvider,
        provider_user_id: String,
        provider_profile_image: Option<String>,
    ) -> Self {
        let now = DateTime::now();

        let oauth_data = OAuthData {
            provider_user_id,
            provider_profile_image: provider_profile_image.clone(),
            provider_data: None,
        };

        Self {
            id: None,
            email,
            username,
            display_name,
            password_hash: None, // OAuth 사용자는 비밀번호 없음
            auth_provider,
            oauth_data: Some(oauth_data),
            is_active: true,
            is_email_verified: true, // OAuth 사용자는 이미 인증됨
            roles: vec!["user".to_string()],
            profile_image_url: provider_profile_image,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// 기존 생성자 (하위 호환성 유지)
    #[deprecated(note = "Use new_local instead")]
    pub fn new(email: String, username: String, display_name: String, password_hash: String) -> Self {
        Self::new_local(email, username, display_name, password_hash)
    }

    /// ID 문자열로 변환
    pub fn id_string(&self) -> Option<String> {
        self.id.as_ref().map(|id| id.to_hex())
    }

    /// 로컬 인증 사용자인지 확인
    pub fn is_local_auth(&self) -> bool {
        matches!(self.auth_provider, AuthProvider::Local)
    }

    /// OAuth 인증 사용자인지 확인
    pub fn is_oauth_auth(&self) -> bool {
        !self.is_local_auth()
    }

    /// 비밀번호 인증이 가능한 사용자인지 확인
    pub fn can_authenticate_with_password(&self) -> bool {
        self.is_local_auth() && self.password_hash.is_some()
    }

    /// OAuth 프로바이더에서의 사용자 ID 가져오기
    pub fn oauth_provider_id(&self) -> Option<&str> {
        self.oauth_data.as_ref().map(|data| data.provider_user_id.as_str())
    }
}
