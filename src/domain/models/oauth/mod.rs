//! # OAuth Domain Models Module
//!
//! OAuth 2.0 인증 플로우와 관련된 도메인 모델들을 정의하는 모듈입니다.
//! 다양한 OAuth 프로바이더(Google, GitHub, Microsoft 등)와의 통합을 위한
//! 타입 안전한 데이터 모델과 비즈니스 로직을 제공합니다.
//!
//! ## 설계 철학
//!
//! ### 1. 프로바이더 독립성
//! 각 OAuth 프로바이더의 특성을 고려하면서도 공통 인터페이스 제공:
//! ```text
//! OAuth Models Architecture
//! ┌─────────────────────────────────────────────┐
//! │ Common OAuth Traits & Interfaces           │
//! ├─────────────────────────────────────────────┤
//! │ Google OAuth Models                         │
//! │ GitHub OAuth Models                         │
//! │ Microsoft OAuth Models                      │
//! │ ... (향후 확장)                             │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ### 2. 타입 안전성
//! Rust의 타입 시스템을 활용한 컴파일 타임 검증:
//! ```rust,ignore
//! // 잘못된 사용 방지
//! fn authenticate_google_user(token: GoogleAccessToken) {
//!     // GitHub 토큰을 실수로 전달하면 컴파일 에러
//!     // authenticate_github_user(token); // ❌ 컴파일 에러
//! }
//! ```
//!
//! ### 3. Spring Security OAuth2 패턴 적용
//! Spring Framework의 OAuth2 설계 패턴을 Rust로 적용:
//!
//! | Spring Security | Rust OAuth Models |
//! |-----------------|-------------------|
//! | `OAuth2User` | `GoogleUserInfo`, `GitHubUserInfo` |
//! | `OAuth2AuthenticationToken` | `OAuthToken` |
//! | `OAuth2AuthorizedClient` | `AuthorizedClient` |
//! | `ClientRegistration` | `OAuthClientConfig` |
//!
//! ## 모듈 구성
//!
//! ```text
//! oauth/
//! ├── mod.rs                      ← 이 파일 (모듈 진입점)
//! ├── google_oauth_model/         ← Google OAuth 통합
//! │   ├── mod.rs
//! │   ├── google_user.rs          ← Google 사용자 정보 모델
//! │   ├── google_token.rs         ← Google 토큰 모델 (향후)
//! │   └── google_client.rs        ← Google 클라이언트 설정 (향후)
//! ├── github_oauth_model/         ← GitHub OAuth 통합 (향후)
//! │   ├── mod.rs
//! │   ├── github_user.rs
//! │   └── github_token.rs
//! ├── microsoft_oauth_model/      ← Microsoft OAuth 통합 (향후)
//! │   └── ...
//! ├── common/                     ← 공통 OAuth 모델 (향후)
//! │   ├── oauth_token.rs          ← 범용 토큰 모델
//! │   ├── oauth_error.rs          ← OAuth 에러 처리
//! │   └── oauth_traits.rs         ← 공통 트레이트
//! └── validation/                 ← OAuth 검증 모델 (향후)
//!     ├── token_validator.rs
//!     └── scope_validator.rs
//! ```
//!
//! ## OAuth 2.0 플로우 지원
//!
//! ### Authorization Code Flow
//! ```rust,ignore
//! use crate::domain::models::oauth::google_oauth_model::GoogleOAuthRequest;
//! use crate::services::auth::GoogleAuthService;
//!
//! // 1. 인증 URL 생성
//! let auth_url = GoogleOAuthRequest::build_auth_url(
//!     &client_id,
//!     &redirect_uri,
//!     &["openid", "email", "profile"]
//! )?;
//!
//! // 2. 사용자 리다이렉트 후 코드 교환
//! let google_service = GoogleAuthService::instance();
//! let token_response = google_service
//!     .exchange_code_for_token(authorization_code)
//!     .await?;
//!
//! // 3. 사용자 정보 조회
//! let user_info = google_service
//!     .fetch_user_info(&token_response.access_token)
//!     .await?;
//! ```
//!
//! ### Implicit Flow (SPA용)
//! ```rust,ignore
//! // 프론트엔드에서 받은 액세스 토큰 검증
//! let token_info = google_service
//!     .validate_access_token(&access_token)
//!     .await?;
//!
//! if token_info.is_valid() {
//!     let user_info = google_service
//!         .fetch_user_info(&access_token)
//!         .await?;
//! }
//! ```
//!
//! ## 프로바이더별 특징
//!
//! ### Google OAuth
//! - **장점**: 높은 신뢰도, 전 세계적 사용자 기반
//! - **특징**: People API 연동, 풍부한 프로필 정보
//! - **스코프**: `openid`, `email`, `profile`
//! - **토큰 만료**: Access Token 1시간, Refresh Token 영구
//!
//! ```rust,ignore
//! use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
//!
//! let google_user = GoogleUserInfo {
//!     id: "123456789".to_string(),
//!     email: "user@gmail.com".to_string(),
//!     verified_email: true,
//!     name: "홍길동".to_string(),
//!     // ...
//! };
//! ```
//!
//! ### GitHub OAuth (향후 지원)
//! - **장점**: 개발자 친화적, Git 정보 접근
//! - **특징**: Repository 정보, 조직 멤버십
//! - **스코프**: `user:email`, `read:user`
//!
//! ### Microsoft OAuth (향후 지원)
//! - **장점**: 기업 환경 통합, Office 365 연동
//! - **특징**: Azure AD 통합, 조직 계정 지원
//! - **스코프**: `User.Read`, `offline_access`
//!
//! ## 보안 고려사항
//!
//! ### 토큰 보안
//! ```rust,ignore
//! #[derive(Debug, Clone)]
//! pub struct SecureToken {
//!     access_token: String,
//!     expires_at: DateTime<Utc>,
//!     scopes: Vec<String>,
//! }
//!
//! impl SecureToken {
//!     /// 토큰 만료 확인
//!     pub fn is_expired(&self) -> bool {
//!         Utc::now() > self.expires_at
//!     }
//!     
//!     /// 특정 스코프 권한 확인
//!     pub fn has_scope(&self, scope: &str) -> bool {
//!         self.scopes.contains(&scope.to_string())
//!     }
//!     
//!     /// 민감한 정보 마스킹 (로깅용)
//!     pub fn masked_token(&self) -> String {
//!         format!("{}...{}", 
//!             &self.access_token[..4],
//!             &self.access_token[self.access_token.len()-4..]
//!         )
//!     }
//! }
//! ```
//!
//! ### 사용자 정보 검증
//! ```rust,ignore
//! pub trait OAuthUserValidator {
//!     type UserInfo;
//!     type Error;
//!     
//!     /// 사용자 정보 검증
//!     fn validate_user_info(&self, user_info: &Self::UserInfo) -> Result<(), Self::Error>;
//!     
//!     /// 이메일 검증 상태 확인
//!     fn is_email_verified(&self, user_info: &Self::UserInfo) -> bool;
//!     
//!     /// 필수 정보 존재 확인
//!     fn has_required_fields(&self, user_info: &Self::UserInfo) -> bool;
//! }
//! ```
//!
//! ## 에러 처리 전략
//!
//! ### OAuth 관련 에러
//! ```rust,ignore
//! #[derive(Debug, thiserror::Error)]
//! pub enum OAuthError {
//!     #[error("인증 코드 교환 실패: {0}")]
//!     CodeExchangeFailed(String),
//!     
//!     #[error("액세스 토큰이 만료됨")]
//!     TokenExpired,
//!     
//!     #[error("사용자 정보 조회 실패: {0}")]
//!     UserInfoFetchFailed(String),
//!     
//!     #[error("검증되지 않은 이메일")]
//!     EmailNotVerified,
//!     
//!     #[error("필수 스코프 누락: {missing_scopes:?}")]
//!     MissingScopes { missing_scopes: Vec<String> },
//!     
//!     #[error("프로바이더 API 에러: {status_code} - {message}")]
//!     ProviderApiError { status_code: u16, message: String },
//! }
//! ```
//!
//! ### 재시도 로직
//! ```rust,ignore
//! use tokio::time::{sleep, Duration};
//!
//! pub async fn fetch_user_info_with_retry(
//!     token: &str,
//!     max_retries: u32
//! ) -> Result<GoogleUserInfo, OAuthError> {
//!     let mut retries = 0;
//!     
//!     loop {
//!         match fetch_user_info(token).await {
//!             Ok(user_info) => return Ok(user_info),
//!             Err(e) if retries < max_retries && e.is_retryable() => {
//!                 retries += 1;
//!                 let delay = Duration::from_millis(1000 * 2_u64.pow(retries));
//!                 sleep(delay).await;
//!             }
//!             Err(e) => return Err(e),
//!         }
//!     }
//! }
//! ```
//!
//! ## 성능 최적화
//!
//! ### 캐싱 전략
//! ```rust,ignore
//! use std::collections::HashMap;
//! use std::sync::{Arc, RwLock};
//!
//! pub struct UserInfoCache {
//!     cache: Arc<RwLock<HashMap<String, (GoogleUserInfo, DateTime<Utc>)>>>,
//!     ttl: Duration,
//! }
//!
//! impl UserInfoCache {
//!     pub async fn get_or_fetch(&self, token: &str) -> Result<GoogleUserInfo, OAuthError> {
//!         // 캐시 확인
//!         if let Some(cached) = self.get_cached(token) {
//!             return Ok(cached);
//!         }
//!         
//!         // API 호출 및 캐시 저장
//!         let user_info = fetch_user_info(token).await?;
//!         self.store_cache(token, &user_info);
//!         Ok(user_info)
//!     }
//! }
//! ```
//!
//! ### 배치 처리
//! ```rust,ignore
//! // 다중 사용자 정보 일괄 처리
//! pub async fn fetch_multiple_users(
//!     tokens: Vec<String>
//! ) -> Vec<Result<GoogleUserInfo, OAuthError>> {
//!     use futures::future::join_all;
//!     
//!     let futures: Vec<_> = tokens
//!         .into_iter()
//!         .map(|token| fetch_user_info(&token))
//!         .collect();
//!         
//!     join_all(futures).await
//! }
//! ```
//!
//! ## 테스트 전략
//!
//! ### 모킹과 테스트 더블
//! ```rust,ignore
//! #[cfg(test)]
//! pub mod test_utils {
//!     use super::*;
//!     
//!     pub fn create_mock_google_user() -> GoogleUserInfo {
//!         GoogleUserInfo {
//!             id: "test_google_id_123".to_string(),
//!             email: "test@example.com".to_string(),
//!             verified_email: true,
//!             name: "테스트 사용자".to_string(),
//!             given_name: "테스트".to_string(),
//!             family_name: "사용자".to_string(),
//!             picture: Some("https://example.com/avatar.jpg".to_string()),
//!         }
//!     }
//!     
//!     pub struct MockOAuthService {
//!         user_responses: HashMap<String, GoogleUserInfo>,
//!     }
//!     
//!     impl MockOAuthService {
//!         pub fn with_user(mut self, token: &str, user: GoogleUserInfo) -> Self {
//!             self.user_responses.insert(token.to_string(), user);
//!             self
//!         }
//!     }
//! }
//! ```
//!
//! ## 프라이버시 및 규정 준수
//!
//! ### GDPR 대응
//! ```rust,ignore
//! pub trait GdprCompliant {
//!     /// 사용자 데이터 내보내기
//!     async fn export_user_data(&self, user_id: &str) -> Result<serde_json::Value, Error>;
//!     
//!     /// 사용자 데이터 삭제
//!     async fn delete_user_data(&self, user_id: &str) -> Result<(), Error>;
//!     
//!     /// 데이터 처리 목적 반환
//!     fn data_processing_purposes(&self) -> Vec<String>;
//! }
//! ```
//!
//! ### 감사 로그
//! ```rust,ignore
//! #[derive(Debug, Serialize)]
//! pub struct OAuthAuditLog {
//!     pub timestamp: DateTime<Utc>,
//!     pub user_id: Option<String>,
//!     pub provider: String,
//!     pub action: String,
//!     pub ip_address: Option<String>,
//!     pub user_agent: Option<String>,
//!     pub result: String, // "success" | "failure"
//! }
//! ```
//!
//! ## 확장 가이드
//!
//! ### 새로운 OAuth 프로바이더 추가
//! 1. **모델 정의**: 프로바이더별 사용자 정보 모델 생성
//! 2. **토큰 모델**: 액세스/리프레시 토큰 구조 정의
//! 3. **검증 로직**: 사용자 정보 및 토큰 검증 구현
//! 4. **에러 처리**: 프로바이더별 에러 케이스 정의
//! 5. **테스트 코드**: 단위 및 통합 테스트 작성
//! 6. **문서화**: API 문서 및 사용 예제 작성
//!
//! ### OpenID Connect 지원
//! ```rust,ignore
//! // ID Token 처리를 위한 모델 확장
//! #[derive(Debug, Deserialize)]
//! pub struct OpenIdToken {
//!     pub sub: String,        // Subject (사용자 ID)
//!     pub aud: String,        // Audience (클라이언트 ID)
//!     pub iss: String,        // Issuer (인증 서버)
//!     pub exp: u64,           // Expiration
//!     pub iat: u64,           // Issued At
//!     pub email: Option<String>,
//!     pub email_verified: Option<bool>,
//! }
//! ```

pub mod google_oauth_model;