use serde::{Deserialize, Serialize};

/// OAuth 프로바이더 관련 추가 데이터
///
/// OAuth 인증을 통해 가입한 사용자의 프로바이더별 고유 정보를 저장합니다.
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