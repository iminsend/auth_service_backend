//! # Google OAuth 2.0 Domain Models
//!
//! Google OAuth 2.0 인증 플로우와 관련된 도메인 모델들을 정의하는 모듈입니다.
//! Google의 OAuth 2.0 API와 OpenID Connect 표준을 준수하며,
//! 타입 안전하고 사용하기 쉬운 인터페이스를 제공합니다.
//!
//! ## 주요 구성 요소
//!
//! ### 현재 구현된 모델
//! - **`google_user`**: Google 사용자 정보 모델 (`GoogleUserInfo`)
//!
//! ### 향후 구현 예정 모델
//! - **`google_token`**: Google 액세스/리프레시 토큰 모델
//! - **`google_client`**: Google OAuth 클라이언트 설정 모델
//! - **`google_auth_request`**: Google 인증 요청 모델
//! - **`google_auth_response`**: Google 인증 응답 모델
//!
//! ## Google OAuth 2.0 플로우 지원
//!
//! ### Authorization Code Flow (권장)
//! ```text
//! 1. 사용자 → 인증 URL로 리다이렉트
//! 2. Google → 인증 후 authorization_code와 함께 리다이렉트
//! 3. 서버 → authorization_code를 access_token으로 교환
//! 4. 서버 → access_token으로 사용자 정보 조회
//! ```
//!
//! ```rust,ignore
//! use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
//! use crate::services::auth::GoogleAuthService;
//!
//! // Step 1: 인증 URL 생성
//! let auth_url = format!(
//!     "https://accounts.google.com/o/oauth2/v2/auth?{}",
//!     serde_urlencoded::to_string(&[
//!         ("client_id", &client_id),
//!         ("redirect_uri", &redirect_uri),
//!         ("response_type", "code"),
//!         ("scope", "openid email profile"),
//!         ("state", &csrf_token),
//!     ])?
//! );
//!
//! // Step 2-4: 코드 교환 및 사용자 정보 조회
//! let google_service = GoogleAuthService::instance();
//! let user_info: GoogleUserInfo = google_service
//!     .exchange_code_and_fetch_user(authorization_code, redirect_uri)
//!     .await?;
//! ```
//!
//! ### Implicit Flow (SPA/모바일)
//! ```text
//! 1. 클라이언트 → 인증 URL로 리다이렉트 (response_type=token)
//! 2. Google → access_token을 URL 프래그먼트로 반환
//! 3. 클라이언트 → access_token을 서버로 전송
//! 4. 서버 → 토큰 검증 및 사용자 정보 조회
//! ```
//!
//! ```rust,ignore
//! // 클라이언트에서 받은 토큰으로 사용자 정보 조회
//! let user_info: GoogleUserInfo = google_service
//!     .fetch_user_info_from_token(access_token)
//!     .await?;
//! ```
//!
//! ## Google API 엔드포인트
//!
//! ### 인증 관련 엔드포인트
//! ```text
//! 인증 URL: https://accounts.google.com/o/oauth2/v2/auth
//! 토큰 교환: https://oauth2.googleapis.com/token
//! 토큰 정보: https://oauth2.googleapis.com/tokeninfo
//! 토큰 폐기: https://oauth2.googleapis.com/revoke
//! ```
//!
//! ### 사용자 정보 엔드포인트
//! ```text
//! UserInfo API: https://www.googleapis.com/oauth2/v2/userinfo
//! People API: https://people.googleapis.com/v1/people/me
//! ```
//!
//! ## OAuth 스코프 정의
//!
//! ### 기본 스코프
//! | 스코프 | 설명 | 접근 가능한 정보 |
//! |--------|------|------------------|
//! | `openid` | OpenID Connect | `sub` (사용자 ID) |
//! | `email` | 이메일 주소 | `email`, `email_verified` |
//! | `profile` | 기본 프로필 | `name`, `given_name`, `family_name`, `picture` |
//!
//! ### 확장 스코프 (향후 지원)
//! | 스코프 | 설명 | 사용 사례 |
//! |--------|------|-----------|
//! | `https://www.googleapis.com/auth/userinfo.profile` | 상세 프로필 | 생년월일, 성별 등 |
//! | `https://www.googleapis.com/auth/contacts.readonly` | 연락처 읽기 | 주소록 통합 |
//! | `https://www.googleapis.com/auth/calendar.readonly` | 캘린더 읽기 | 일정 연동 |
//!
//! ## Spring Security OAuth2와의 비교
//!
//! ### Java/Spring 구현
//! ```java
//! @Configuration
//! @EnableWebSecurity
//! public class OAuth2LoginConfig {
//!     
//!     @Bean
//!     public ClientRegistrationRepository clientRegistrationRepository() {
//!         return new InMemoryClientRegistrationRepository(
//!             ClientRegistration.withRegistrationId("google")
//!                 .clientId("google-client-id")
//!                 .clientSecret("google-client-secret")
//!                 .scope("openid", "email", "profile")
//!                 .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
//!                 .tokenUri("https://oauth2.googleapis.com/token")
//!                 .userInfoUri("https://www.googleapis.com/oauth2/v2/userinfo")
//!                 .userNameAttributeName("id")
//!                 .clientName("Google")
//!                 .build()
//!         );
//!     }
//! }
//!
//! @RestController
//! public class OAuth2Controller {
//!     
//!     @GetMapping("/user")
//!     public Map<String, Object> user(OAuth2AuthenticationToken authentication) {
//!         OAuth2User oauth2User = authentication.getPrincipal();
//!         return oauth2User.getAttributes();
//!     }
//! }
//! ```
//!
//! ### Rust 구현 (이 모듈)
//! ```rust,ignore
//! use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
//! use crate::services::auth::GoogleAuthService;
//!
//! // OAuth 서비스 싱글톤 인스턴스
//! let google_service = GoogleAuthService::instance();
//!
//! // 사용자 정보 조회 (타입 안전)
//! let user_info: GoogleUserInfo = google_service
//!     .fetch_user_info(access_token)
//!     .await?;
//!
//! // 사용자 정보 활용
//! println!("사용자 ID: {}", user_info.id);
//! println!("이메일: {}", user_info.email);
//! if user_info.verified_email {
//!     println!("✅ 검증된 이메일");
//! }
//! ```
//!
//! ## 보안 모범 사례
//!
//! ### 1. CSRF 보호
//! ```rust,ignore
//! use uuid::Uuid;
//!
//! // 인증 요청 시 state 파라미터 사용
//! let csrf_token = Uuid::new_v4().to_string();
//! session.insert("oauth_state", &csrf_token)?;
//!
//! let auth_url = build_google_auth_url(&client_id, &redirect_uri, &csrf_token)?;
//!
//! // 콜백에서 state 검증
//! let received_state = query_params.get("state");
//! let stored_state = session.get::<String>("oauth_state")?;
//! if received_state != Some(&stored_state) {
//!     return Err(AuthError::CsrfTokenMismatch);
//! }
//! ```
//!
//! ### 2. 토큰 보안
//! ```rust,ignore
//! // 액세스 토큰은 메모리에만 저장, 로그에 노출 금지
//! #[derive(Debug)]
//! pub struct SecureGoogleToken {
//!     access_token: SecretString,  // 민감한 정보 보호
//!     expires_at: DateTime<Utc>,
//!     scopes: Vec<String>,
//! }
//!
//! impl fmt::Display for SecureGoogleToken {
//!     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//!         write!(f, "GoogleToken(***masked***)")
//!     }
//! }
//! ```
//!
//! ### 3. 스코프 최소화
//! ```rust,ignore
//! // 필요한 최소한의 스코프만 요청
//! const REQUIRED_SCOPES: &[&str] = &["openid", "email", "profile"];
//!
//! // 선택적 스코프는 사용자 동의 하에 요청
//! fn request_additional_scopes(user_consent: bool) -> Vec<&'static str> {
//!     let mut scopes = REQUIRED_SCOPES.to_vec();
//!     
//!     if user_consent {
//!         scopes.extend(&["https://www.googleapis.com/auth/contacts.readonly"]);
//!     }
//!     
//!     scopes
//! }
//! ```
//!
//! ## 에러 처리 및 복구
//!
//! ### Google API 에러 대응
//! ```rust,ignore
//! #[derive(Debug, thiserror::Error)]
//! pub enum GoogleOAuthError {
//!     #[error("Google 인증 서버 에러: {error} - {description}")]
//!     AuthServerError {
//!         error: String,
//!         description: Option<String>,
//!     },
//!     
//!     #[error("토큰이 만료되었습니다")]
//!     TokenExpired,
//!     
//!     #[error("사용자가 인증을 거부했습니다")]
//!     AccessDenied,
//!     
//!     #[error("잘못된 클라이언트 설정: {0}")]
//!     InvalidClient(String),
//!     
//!     #[error("네트워크 에러: {0}")]
//!     NetworkError(#[from] reqwest::Error),
//! }
//! ```
//!
//! ### 재시도 로직
//! ```rust,ignore
//! pub async fn fetch_user_info_with_retry(
//!     token: &str,
//!     max_retries: u32
//! ) -> Result<GoogleUserInfo, GoogleOAuthError> {
//!     let mut retries = 0;
//!     
//!     while retries <= max_retries {
//!         match fetch_google_user_info(token).await {
//!             Ok(user_info) => return Ok(user_info),
//!             Err(GoogleOAuthError::NetworkError(_)) if retries < max_retries => {
//!                 retries += 1;
//!                 let delay = Duration::from_millis(1000 * 2_u64.pow(retries));
//!                 tokio::time::sleep(delay).await;
//!             }
//!             Err(e) => return Err(e),
//!         }
//!     }
//!     
//!     unreachable!()
//! }
//! ```
//!
//! ## 성능 최적화
//!
//! ### 연결 풀링
//! ```rust,ignore
//! use reqwest::Client;
//! use std::time::Duration;
//!
//! pub fn create_optimized_http_client() -> Client {
//!     Client::builder()
//!         .timeout(Duration::from_secs(10))
//!         .pool_max_idle_per_host(10)
//!         .pool_idle_timeout(Duration::from_secs(30))
//!         .tcp_keepalive(Duration::from_secs(60))
//!         .build()
//!         .expect("HTTP 클라이언트 생성 실패")
//! }
//! ```
//!
//! ### 사용자 정보 캐싱
//! ```rust,ignore
//! use moka::future::Cache;
//! use std::time::Duration;
//!
//! pub struct GoogleUserInfoCache {
//!     cache: Cache<String, GoogleUserInfo>,
//! }
//!
//! impl GoogleUserInfoCache {
//!     pub fn new() -> Self {
//!         let cache = Cache::builder()
//!             .max_capacity(10_000)
//!             .time_to_live(Duration::from_secs(3600)) // 1시간 캐시
//!             .build();
//!             
//!         Self { cache }
//!     }
//!     
//!     pub async fn get_or_fetch(
//!         &self,
//!         token: &str
//!     ) -> Result<GoogleUserInfo, GoogleOAuthError> {
//!         if let Some(cached) = self.cache.get(token).await {
//!             return Ok(cached);
//!         }
//!         
//!         let user_info = fetch_google_user_info(token).await?;
//!         self.cache.insert(token.to_string(), user_info.clone()).await;
//!         Ok(user_info)
//!     }
//! }
//! ```
//!
//! ## 테스트 지원
//!
//! ### 모킹 유틸리티
//! ```rust,ignore
//! #[cfg(test)]
//! pub mod test_utils {
//!     use super::*;
//!     
//!     pub fn create_test_google_user() -> GoogleUserInfo {
//!         GoogleUserInfo {
//!             id: "test_google_id_123456789".to_string(),
//!             email: "test.user@example.com".to_string(),
//!             verified_email: true,
//!             name: "테스트 사용자".to_string(),
//!             given_name: "테스트".to_string(),
//!             family_name: "사용자".to_string(),
//!             picture: Some("https://example.com/test-avatar.jpg".to_string()),
//!         }
//!     }
//!     
//!     pub fn create_unverified_google_user() -> GoogleUserInfo {
//!         GoogleUserInfo {
//!             verified_email: false,
//!             ..create_test_google_user()
//!         }
//!     }
//! }
//! ```
//!
//! ## 확장 계획
//!
//! ### 단계별 개발 로드맵
//! 1. **Phase 1** (현재): 기본 사용자 정보 모델
//! 2. **Phase 2**: 토큰 관리 모델 (access/refresh token)
//! 3. **Phase 3**: 클라이언트 설정 모델
//! 4. **Phase 4**: 인증 요청/응답 모델
//! 5. **Phase 5**: People API 확장 지원
//! 6. **Phase 6**: Google Workspace 통합
//!
//! ### 호환성 매트릭스
//! | Google API | 지원 버전 | 상태 |
//! |------------|-----------|------|
//! | OAuth 2.0 | v2 | ✅ 지원 |
//! | OpenID Connect | 1.0 | ✅ 지원 |
//! | People API | v1 | 🔄 부분 지원 |
//! | Google+ API | v1 | ❌ 지원 안함 (Deprecated) |

pub mod google_user;