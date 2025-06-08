//! 인증 요청관련 DTO
//!
//! 인증을 요청하는 사용자들의 요청 정보를 매핑합니다.
use serde::Deserialize;
use validator::Validate;

/// 리프레시 토큰 요청 구조체
#[derive(Debug, Deserialize, Validate)]
pub struct RefreshTokenRequest {
    #[validate(length(min = 1, message = "리프레시 토큰이 필요합니다"))]
    pub refresh_token: String,
}

/// 로컬 로그인 요청 구조체
#[derive(Debug, Deserialize, Validate)]
pub struct LocalLoginRequest {
    #[validate(email(message = "유효한 이메일 주소를 입력해주세요"))]
    pub email: String,

    #[validate(length(min = 1, message = "비밀번호를 입력해주세요"))]
    pub password: String,
}

/// OAuth 콜백 쿼리 파라미터 구조체
#[derive(Debug, Deserialize, Validate)]
pub struct OAuthCallbackQuery {
    #[validate(length(min = 1, message = "Authorization code가 필요합니다"))]
    pub code: String,

    #[validate(length(min = 1, message = "State가 필요합니다"))]
    pub state: String,

    /// 에러가 있을 경우 (사용자가 거부했거나 에러 발생)
    pub error: Option<String>,
    pub error_description: Option<String>,
}