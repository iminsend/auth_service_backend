//! Google OAuth 응답 DTO 모듈
//!
//! Google OAuth 2.0 인증 플로우에서 사용되는 응답 DTO들을 정의합니다.
//! OAuth 2.0 Authorization Code Grant 플로우를 지원합니다.

use serde::{Deserialize, Serialize};

/// Google OAuth 2.0 토큰 교환 응답
///
/// Google OAuth 2.0 API로부터 받는 토큰 응답을 표현합니다.
/// Authorization Code를 Access Token으로 교환할 때 Google이 반환하는 데이터입니다.
#[derive(Debug, Deserialize)]
pub struct GoogleTokenResponse {
    /// Google OAuth 액세스 토큰
    pub access_token: String,
    /// 토큰 타입 (항상 "Bearer")
    pub token_type: String,
    /// 토큰 만료 시간 (초 단위)
    pub expires_in: i32,
    /// 리프레시 토큰 (선택사항)
    pub refresh_token: Option<String>,
    /// 부여된 권한 범위
    pub scope: String,
}

/// OAuth 로그인 URL 응답
///
/// 클라이언트가 OAuth 로그인을 시작할 때 제공되는 응답입니다.
/// Google 인증 페이지로의 리다이렉트 URL과 CSRF 방지용 state 값을 포함합니다.
#[derive(Debug, Serialize)]
pub struct OAuthLoginUrlResponse {
    /// Google OAuth 인증 페이지 URL
    ///
    /// 클라이언트가 브라우저를 리다이렉트할 Google 인증 페이지의 전체 URL입니다.
    pub login_url: String,
    
    /// CSRF 방지용 state 파라미터
    ///
    /// 콜백에서 받은 state와 반드시 일치 확인해야 합니다.
    pub state: String,
}
