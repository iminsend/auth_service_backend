//! # Google OAuth 응답 DTO 모듈
//!
//! 이 모듈은 Google OAuth 2.0 인증 플로우에서 사용되는 응답 DTO들을 정의합니다.
//! Spring Security OAuth의 패턴을 참고하여 구현되었으며,
//! OAuth 2.0 Authorization Code Grant 플로우를 지원합니다.
//!
//! ## OAuth 2.0 플로우
//!
//! ```text
//! 1. Client → Backend: GET /auth/google/login
//!    Backend responds: OAuthLoginUrlResponse
//!    
//! 2. Client → Google: Redirect to login_url
//!    User authenticates with Google
//!    
//! 3. Google → Client: Redirect with authorization code
//!    Client → Backend: POST /auth/google/callback with code
//!    
//! 4. Backend → Google: Exchange code for tokens
//!    Google responds: GoogleTokenResponse
//!    
//! 5. Backend → Client: LoginResponse with JWT tokens
//! ```
//!
//! ## 보안 고려사항
//!
//! - **State 파라미터**: CSRF 공격 방지를 위한 랜덤 값
//! - **HTTPS 전용**: 모든 OAuth 통신은 HTTPS를 통해서만 수행
//! - **토큰 저장**: Google 토큰은 임시로만 사용하고 즉시 폐기
//! - **Scope 검증**: 요청한 권한과 실제 부여된 권한 확인 필수
//!
//! ## 에러 처리
//!
//! OAuth 플로우에서 발생할 수 있는 주요 에러:
//! - 인증 코드 만료
//! - State 파라미터 불일치
//! - 잘못된 클라이언트 자격증명
//! - 사용자 인증 거부

use serde::{Deserialize, Serialize};

/// Google OAuth 2.0 토큰 교환 응답
///
/// Google OAuth 2.0 API로부터 받는 토큰 응답을 표현합니다.
/// Authorization Code를 Access Token으로 교환할 때 Google이 반환하는 데이터입니다.
///
/// # OAuth 2.0 플로우에서의 역할
///
/// 1. 클라이언트가 인증 코드와 함께 콜백 요청
/// 2. 백엔드가 Google에 토큰 교환 요청
/// 3. **Google이 이 구조체 형태로 응답**
/// 4. 백엔드가 사용자 정보 조회 후 자체 JWT 토큰 발급
///
/// # Google API 응답 예제
///
/// ```json
/// {
///   "access_token": "ya29.a0AfH6SMC...",
///   "token_type": "Bearer",
///   "expires_in": 3600,
///   "refresh_token": "1//04-rNBBjx...",
///   "scope": "openid profile email"
/// }
/// ```
///
/// # 사용 예제
///
/// ```rust,ignore
/// // Google에 토큰 교환 요청
/// let token_response: GoogleTokenResponse = oauth_client
///     .exchange_code(auth_code)
///     .await?;
///
/// // Access Token으로 사용자 정보 조회
/// let user_info = google_api_client
///     .get_user_info(&token_response.access_token)
///     .await?;
///
/// // 자체 JWT 토큰 발급
/// let jwt_token = jwt_service.generate_token(&user_info)?;
/// ```
///
/// # 보안 주의사항
///
/// - **임시 사용**: 이 토큰들은 사용자 정보 조회 후 즉시 폐기
/// - **로그 금지**: 토큰 값은 로그에 출력하지 않음
/// - **만료 시간**: `expires_in` 값을 확인하여 토큰 유효성 관리
/// - **Scope 검증**: 요청한 권한이 모두 부여되었는지 확인
#[derive(Debug, Deserialize)]
pub struct GoogleTokenResponse {
    /// Google OAuth 액세스 토큰
    ///
    /// - Google API 호출 시 사용하는 토큰
    /// - 형식: Bearer 토큰 (Authorization: Bearer {access_token})
    /// - 사용자 정보 조회 후 즉시 폐기 권장
    /// - 절대 클라이언트에게 전달하지 않음
    pub access_token: String,
    
    /// 토큰 타입 (항상 "Bearer")
    ///
    /// OAuth 2.0 스펙에 따른 토큰 타입입니다.
    /// Google API 요청 시 Authorization 헤더 구성에 사용됩니다.
    pub token_type: String,
    
    /// 토큰 만료 시간 (초 단위)
    ///
    /// 액세스 토큰이 유효한 시간을 초 단위로 나타냅니다.
    /// 일반적으로 3600초(1시간)이며, 이 시간 내에 사용자 정보를 조회해야 합니다.
    pub expires_in: i32,
    
    /// 리프레시 토큰 (선택사항)
    ///
    /// - 액세스 토큰 갱신에 사용
    /// - 첫 번째 인증 시에만 제공되는 경우가 많음
    /// - 현재 시스템에서는 사용하지 않고 폐기함
    /// - 장기 연동이 필요한 경우에만 안전하게 저장
    pub refresh_token: Option<String>,
    
    /// 부여된 권한 범위
    ///
    /// Google에서 실제로 부여한 권한의 범위입니다.
    /// 요청한 scope와 일치하는지 확인하는 용도로 사용됩니다.
    /// 예: "openid profile email"
    pub scope: String,
}

/// OAuth 로그인 URL 응답
///
/// 클라이언트가 OAuth 로그인을 시작할 때 제공되는 응답입니다.
/// Google 인증 페이지로의 리다이렉트 URL과 CSRF 방지용 state 값을 포함합니다.
///
/// # OAuth 플로우에서의 역할
///
/// 1. **클라이언트가 GET /auth/google/login 요청**
/// 2. **백엔드가 이 구조체로 응답**
/// 3. 클라이언트가 login_url로 브라우저 리다이렉트
/// 4. 사용자가 Google에서 인증 완료
/// 5. Google이 state와 함께 콜백 URL로 리다이렉트
///
/// # JSON 응답 예제
///
/// ```json
/// {
///   "login_url": "https://accounts.google.com/oauth/authorize?client_id=123&redirect_uri=https%3A//example.com/callback&scope=openid+profile+email&response_type=code&state=abc123xyz",
///   "state": "abc123xyz"
/// }
/// ```
///
/// # 클라이언트 사용법
///
/// ```javascript
/// // 1. 로그인 URL 요청
/// const response = await fetch('/api/v1/auth/google/login');
/// const { login_url, state } = await response.json();
///
/// // 2. 브라우저를 Google 로그인 페이지로 리다이렉트
/// window.location.href = login_url;
///
/// // 3. 콜백에서 state 검증
/// // Google이 /callback?code=...&state=abc123xyz로 리다이렉트
/// if (received_state !== expected_state) {
///   throw new Error('State mismatch - possible CSRF attack');
/// }
/// ```
///
/// # 보안 고려사항
///
/// - **State 검증**: 콜백에서 받은 state와 반드시 일치 확인
/// - **URL 검증**: login_url이 Google 도메인인지 확인
/// - **HTTPS 필수**: OAuth 플로우는 반드시 HTTPS에서만 수행
/// - **만료 시간**: state는 일정 시간 후 만료되도록 구현
#[derive(Debug, Serialize)]
pub struct OAuthLoginUrlResponse {
    /// Google OAuth 인증 페이지 URL
    ///
    /// 클라이언트가 브라우저를 리다이렉트할 Google 인증 페이지의 전체 URL입니다.
    /// 다음 파라미터들이 포함됩니다:
    /// 
    /// - `client_id`: Google OAuth 앱의 클라이언트 ID
    /// - `redirect_uri`: 인증 완료 후 리다이렉트될 콜백 URL
    /// - `scope`: 요청하는 권한 범위 (openid, profile, email)
    /// - `response_type`: 항상 "code" (Authorization Code Grant)
    /// - `state`: CSRF 방지용 랜덤 문자열
    ///
    /// 예시: `https://accounts.google.com/oauth/authorize?client_id=...&redirect_uri=...&scope=openid+profile+email&response_type=code&state=abc123`
    pub login_url: String,
    
    /// CSRF 방지용 state 파라미터
    ///
    /// - 클라이언트는 이 값을 저장해두어야 함
    /// - Google 콜백에서 받은 state와 반드시 일치 확인
    /// - 랜덤하고 예측 불가능한 값 (UUID 등 사용)
    /// - 일정 시간 후 만료되도록 구현 권장
    ///
    /// 이 값이 일치하지 않으면 CSRF 공격의 가능성이 있으므로
    /// 인증 프로세스를 중단해야 합니다.
    pub state: String,
}
