//! Google OAuth User Information Model
//!
//! Google OAuth 2.0 인증 플로우에서 반환되는 사용자 정보를 처리하기 위한 데이터 모델입니다.
//! Google의 UserInfo API와 호환되며 OpenID Connect 표준을 준수합니다.

use serde::{Deserialize, Serialize};

/// Google OAuth 2.0 사용자 정보 응답 구조체
///
/// Google의 OAuth 2.0 UserInfo API에서 반환되는 사용자 정보를 역직렬화합니다.
/// 
/// ## 사용 예제
///
/// ```rust,ignore
/// let user_info: GoogleUserInfo = client
///     .get("https://www.googleapis.com/oauth2/v2/userinfo")
///     .bearer_auth(&access_token)
///     .send()
///     .await?
///     .json()
///     .await?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    /// Google 사용자 고유 식별자 (21자리 숫자 문자열)
    pub id: String,
    /// 사용자 이메일 주소
    pub email: String,
    /// 사용자 전체 이름
    pub name: String,
    /// 사용자 이름 (Given Name)
    pub given_name: String,
    /// 사용자 성 (Family Name)
    pub family_name: String,
    /// 사용자 프로필 사진 URL (선택사항)
    pub picture: Option<String>,
    /// 이메일 검증 상태
    pub verified_email: bool,
}
