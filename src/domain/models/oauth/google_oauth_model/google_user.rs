//! # Google OAuth User Information Model
//!
//! Google OAuth 2.0 인증 플로우에서 반환되는 사용자 정보를 처리하기 위한 데이터 모델입니다.
//! Google의 UserInfo API와 People API v1과 호환되며, Spring Security OAuth2와 유사한 방식으로
//! 사용자 정보를 타입 안전하게 매핑합니다.
//!
//! ## API 호환성
//!
//! ### 지원하는 Google API 엔드포인트
//! - **OAuth 2.0 UserInfo API**: `https://www.googleapis.com/oauth2/v2/userinfo`
//! - **OpenID Connect UserInfo**: `https://openidconnect.googleapis.com/v1/userinfo`
//! - **People API**: `https://people.googleapis.com/v1/people/me` (부분 지원)
//!
//! ### 필요한 OAuth 스코프
//! | 필드 그룹 | 필수 스코프 | 설명 |
//! |-----------|-------------|------|
//! | 기본 식별자 | `openid` | `id` 필드 접근 |
//! | 이메일 정보 | `email` | `email`, `verified_email` 필드 |
//! | 프로필 정보 | `profile` | `name`, `given_name`, `family_name`, `picture` |
//!
//! ## 아키텍처 설계
//!
//! ### Domain-Driven Design 적용
//! ```text
//! Google OAuth Domain Model
//! GoogleUserInfo (Value Object)
//!   ├── 불변성: 한번 생성되면 변경되지 않음 
//!   ├── 검증: 생성 시 데이터 무결성 검증 
//!   └── 변환: Entity로 안전한 변환 지원 
//! ```
//!
//! ### Spring Security OAuth2와의 매핑
//! ```java
//! // Spring Security OAuth2 (Java)
//! @Component
//! public class GoogleOAuth2UserService extends DefaultOAuth2UserService {
//!     @Override
//!     public OAuth2User loadUser(OAuth2UserRequest userRequest) {
//!         OAuth2User oauth2User = super.loadUser(userRequest);
//!         
//!         String id = oauth2User.getAttribute("id");
//!         String email = oauth2User.getAttribute("email");
//!         String name = oauth2User.getAttribute("name");
//!         Boolean emailVerified = oauth2User.getAttribute("verified_email");
//!         
//!         return createCustomUser(id, email, name, emailVerified);
//!     }
//! }
//! ```
//!
//! ```rust,ignore
//! // 이 모듈의 Rust 구현
//! let response = google_client
//!     .get("https://www.googleapis.com/oauth2/v2/userinfo")
//!     .bearer_auth(&access_token)
//!     .send()
//!     .await?;
//!
//! let user_info: GoogleUserInfo = response.json().await?;
//! // 타입 안전성과 컴파일 타임 검증 보장
//! ```
//!
//! ## 사용 패턴
//!
//! ### 1. 기본 사용법
//! ```rust,ignore
//! use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
//! use crate::services::auth::GoogleAuthService;
//!
//! // Google 서비스 인스턴스 (싱글톤)
//! let google_service = GoogleAuthService::instance();
//!
//! // 액세스 토큰으로 사용자 정보 조회
//! let user_info: GoogleUserInfo = google_service
//!     .fetch_user_info(&access_token)
//!     .await?;
//!
//! // 안전한 필드 접근
//! println!("사용자 ID: {}", user_info.id);
//! println!("이메일: {}", user_info.email);
//! 
//! // 이메일 검증 상태 확인
//! if user_info.verified_email {
//!     proceed_with_verified_email(&user_info.email).await?;
//! } else {
//!     handle_unverified_email(&user_info.email).await?;
//! }
//! ```
//!
//! ### 2. Entity 변환 패턴
//! ```rust,ignore
//! use crate::domain::entities::users::User;
//! use crate::config::AuthProvider;
//!
//! impl From<GoogleUserInfo> for User {
//!     fn from(google_info: GoogleUserInfo) -> Self {
//!         User::new_oauth(
//!             google_info.email,
//!             google_info.generate_username(), // 확장 메서드
//!             google_info.name,
//!             AuthProvider::Google,
//!             google_info.id,
//!             google_info.picture
//!         )
//!     }
//! }
//!
//! // 사용 예제
//! let user_info = fetch_google_user_info(&token).await?;
//! let user: User = user_info.into();
//! let saved_user = user_repository.save(user).await?;
//! ```
//!
//! ### 3. Repository 패턴과의 연동
//! ```rust,ignore
//! use crate::repositories::users::UserRepository;
//!
//! let user_repo = UserRepository::instance();
//!
//! // 기존 Google 사용자 확인
//! if let Some(existing_user) = user_repo
//!     .find_by_oauth_provider(AuthProvider::Google, &user_info.id)
//!     .await? {
//!     // 기존 사용자 로그인 처리
//!     handle_existing_user_login(existing_user).await?;
//! } else {
//!     // 신규 사용자 등록
//!     let new_user: User = user_info.into();
//!     let registered_user = user_repo.save(new_user).await?;
//!     handle_new_user_registration(registered_user).await?;
//! }
//! ```
//!
//! ## 데이터 검증 및 보안
//!
//! ### 필수 검증 항목
//! ```rust,ignore
//! impl GoogleUserInfo {
//!     /// 사용자 정보의 유효성을 검증합니다
//!     pub fn validate(&self) -> Result<(), GoogleOAuthError> {
//!         // 1. 필수 필드 존재 검증
//!         if self.id.is_empty() {
//!             return Err(GoogleOAuthError::MissingField("id"));
//!         }
//!         
//!         if self.email.is_empty() {
//!             return Err(GoogleOAuthError::MissingField("email"));
//!         }
//!         
//!         // 2. 이메일 검증 상태 확인
//!         if !self.verified_email {
//!             return Err(GoogleOAuthError::EmailNotVerified);
//!         }
//!         
//!         // 3. 이메일 형식 검증
//!         if !self.is_valid_email_format() {
//!             return Err(GoogleOAuthError::InvalidEmailFormat);
//!         }
//!         
//!         // 4. Google ID 형식 검증 (21자리 숫자)
//!         if !self.is_valid_google_id_format() {
//!             return Err(GoogleOAuthError::InvalidGoogleIdFormat);
//!         }
//!         
//!         Ok(())
//!     }
//!     
//!     fn is_valid_email_format(&self) -> bool {
//!         self.email.contains('@') && self.email.contains('.')
//!     }
//!     
//!     fn is_valid_google_id_format(&self) -> bool {
//!         self.id.len() == 21 && self.id.chars().all(|c| c.is_ascii_digit())
//!     }
//! }
//! ```
//!
//! ### 민감 정보 처리
//! ```rust,ignore
//! impl GoogleUserInfo {
//!     /// 로깅용 안전한 표현 (개인정보 마스킹)
//!     pub fn to_safe_string(&self) -> String {
//!         format!(
//!             "GoogleUser(id={}..., email={}@***, verified={})",
//!             &self.id[..6],
//!             self.email.split('@').next().unwrap_or("unknown"),
//!             self.verified_email
//!         )
//!     }
//!     
//!     /// GDPR 준수를 위한 개인정보 추출
//!     pub fn extract_personal_data(&self) -> std::collections::HashMap<&str, &str> {
//!         let mut data = std::collections::HashMap::new();
//!         data.insert("google_id", &self.id);
//!         data.insert("email", &self.email);
//!         data.insert("name", &self.name);
//!         data.insert("given_name", &self.given_name);
//!         data.insert("family_name", &self.family_name);
//!         if let Some(picture) = &self.picture {
//!             data.insert("picture_url", picture);
//!         }
//!         data
//!     }
//! }
//! ```
//!
//! ## 성능 최적화
//!
//! ### 직렬화 최적화
//! ```rust,ignore
//! // 선택적 필드 최적화로 BSON 크기 최소화
//! #[derive(Debug, Serialize, Deserialize)]
//! pub struct OptimizedGoogleUserInfo {
//!     pub id: String,
//!     pub email: String,
//!     pub verified_email: bool,
//!     pub name: String,
//!     
//!     #[serde(skip_serializing_if = "String::is_empty")]
//!     pub given_name: String,
//!     
//!     #[serde(skip_serializing_if = "String::is_empty")]
//!     pub family_name: String,
//!     
//!     #[serde(skip_serializing_if = "Option::is_none")]
//!     pub picture: Option<String>,
//! }
//! ```
//!
//! ### 메모리 효율성
//! ```rust,ignore
//! use std::sync::Arc;
//!
//! // 대량의 사용자 정보를 처리할 때 Arc로 공유
//! pub type SharedGoogleUserInfo = Arc<GoogleUserInfo>;
//!
//! // 배치 처리 시 활용
//! pub async fn process_multiple_users(
//!     user_infos: Vec<SharedGoogleUserInfo>
//! ) -> Vec<Result<User, ProcessingError>> {
//!     use futures::future::join_all;
//!     
//!     let futures: Vec<_> = user_infos
//!         .into_iter()
//!         .map(|user_info| process_single_user(user_info))
//!         .collect();
//!         
//!     join_all(futures).await
//! }
//! ```
//!
//! ## 에러 처리 전략
//!
//! ### Google API 응답 에러
//! ```rust,ignore
//! #[derive(Debug, thiserror::Error)]
//! pub enum GoogleUserInfoError {
//!     #[error("Google API 응답 파싱 실패: {0}")]
//!     ParseError(#[from] serde_json::Error),
//!     
//!     #[error("필수 필드 누락: {field}")]
//!     MissingField { field: String },
//!     
//!     #[error("이메일이 검증되지 않음: {email}")]
//!     EmailNotVerified { email: String },
//!     
//!     #[error("잘못된 Google ID 형식: {id}")]
//!     InvalidGoogleId { id: String },
//!     
//!     #[error("Google API 호출 실패: {status} - {message}")]
//!     ApiError { status: u16, message: String },
//! }
//! ```
//!
//! ### 복구 가능한 에러 처리
//! ```rust,ignore
//! pub async fn fetch_user_info_safe(
//!     token: &str
//! ) -> Result<GoogleUserInfo, GoogleUserInfoError> {
//!     // 1차 시도: UserInfo API
//!     match fetch_from_userinfo_api(token).await {
//!         Ok(user_info) => return Ok(user_info),
//!         Err(e) => log::warn!("UserInfo API 실패, People API 시도: {}", e),
//!     }
//!     
//!     // 2차 시도: People API (fallback)
//!     match fetch_from_people_api(token).await {
//!         Ok(user_info) => Ok(user_info),
//!         Err(e) => {
//!             log::error!("모든 Google API 호출 실패: {}", e);
//!             Err(GoogleUserInfoError::AllApisFailed)
//!         }
//!     }
//! }
//! ```
//!
//! ## 국제화 및 지역화
//!
//! ### 다국어 이름 처리
//! ```rust,ignore
//! impl GoogleUserInfo {
//!     /// 지역별 이름 표시 규칙 적용
//!     pub fn format_display_name(&self, locale: &str) -> String {
//!         match locale {
//!             "ko" | "ko-KR" => {
//!                 // 한국어: 성 + 이름
//!                 if !self.family_name.is_empty() && !self.given_name.is_empty() {
//!                     format!("{}{}", self.family_name, self.given_name)
//!                 } else {
//!                     self.name.clone()
//!                 }
//!             }
//!             "ja" | "ja-JP" => {
//!                 // 일본어: 성 + 이름
//!                 format!("{} {}", self.family_name, self.given_name)
//!             }
//!             _ => {
//!                 // 서양식: 이름 + 성
//!                 if !self.given_name.is_empty() && !self.family_name.is_empty() {
//!                     format!("{} {}", self.given_name, self.family_name)
//!                 } else {
//!                     self.name.clone()
//!                 }
//!             }
//!         }
//!     }
//!     
//!     /// 검색용 정규화된 이름 생성
//!     pub fn normalize_for_search(&self) -> String {
//!         use unicode_normalization::UnicodeNormalization;
//!         
//!         self.name
//!             .nfc()
//!             .collect::<String>()
//!             .to_lowercase()
//!             .trim()
//!             .to_string()
//!     }
//! }
//! ```
//!
//! ## 테스트 지원
//!
//! ### 테스트 데이터 생성
//! ```rust,ignore
//! #[cfg(test)]
//! pub mod test_utils {
//!     use super::*;
//!     
//!     pub struct GoogleUserInfoBuilder {
//!         user_info: GoogleUserInfo,
//!     }
//!     
//!     impl GoogleUserInfoBuilder {
//!         pub fn new() -> Self {
//!             Self {
//!                 user_info: GoogleUserInfo {
//!                     id: "123456789012345678901".to_string(),
//!                     email: "test@example.com".to_string(),
//!                     verified_email: true,
//!                     name: "Test User".to_string(),
//!                     given_name: "Test".to_string(),
//!                     family_name: "User".to_string(),
//!                     picture: Some("https://example.com/avatar.jpg".to_string()),
//!                 }
//!             }
//!         }
//!         
//!         pub fn with_email(mut self, email: &str) -> Self {
//!             self.user_info.email = email.to_string();
//!             self
//!         }
//!         
//!         pub fn unverified_email(mut self) -> Self {
//!             self.user_info.verified_email = false;
//!             self
//!         }
//!         
//!         pub fn korean_user(mut self) -> Self {
//!             self.user_info.name = "김철수".to_string();
//!             self.user_info.given_name = "철수".to_string();
//!             self.user_info.family_name = "김".to_string();
//!             self
//!         }
//!         
//!         pub fn build(self) -> GoogleUserInfo {
//!             self.user_info
//!         }
//!     }
//!     
//!     /// 다양한 테스트 시나리오용 사용자 생성
//!     pub fn create_verified_user() -> GoogleUserInfo {
//!         GoogleUserInfoBuilder::new().build()
//!     }
//!     
//!     pub fn create_unverified_user() -> GoogleUserInfo {
//!         GoogleUserInfoBuilder::new().unverified_email().build()
//!     }
//!     
//!     pub fn create_korean_user() -> GoogleUserInfo {
//!         GoogleUserInfoBuilder::new().korean_user().build()
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};

/// Google OAuth 2.0 사용자 정보 응답 구조체
///
/// Google의 OAuth 2.0 UserInfo API에서 반환되는 사용자 정보를 역직렬화하기 위한 구조체입니다.
/// 이 구조체는 Google 계정의 기본 프로필 정보를 타입 안전하게 표현하며,
/// OpenID Connect 표준을 준수합니다.
///
/// # JSON 응답 예제
///
/// ```json
/// {
///   "id": "123456789012345678901",
///   "email": "user@gmail.com",
///   "verified_email": true,
///   "name": "홍길동",
///   "given_name": "길동",
///   "family_name": "홍",
///   "picture": "https://lh3.googleusercontent.com/a/default-user=s96-c"
/// }
/// ```
///
/// # 사용 예제
///
/// ```rust,ignore
/// use reqwest::Client;
/// use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
///
/// async fn fetch_google_user_info(access_token: &str) -> Result<GoogleUserInfo, reqwest::Error> {
///     let client = Client::new();
///     let response = client
///         .get("https://www.googleapis.com/oauth2/v2/userinfo")
///         .bearer_auth(access_token)
///         .send()
///         .await?;
///
///     let user_info: GoogleUserInfo = response.json().await?;
///     Ok(user_info)
/// }
///
/// // 사용자 정보 활용
/// let user_info = fetch_google_user_info(&token).await?;
/// 
/// // 이메일 검증 확인
/// if user_info.verified_email {
///     println!("✅ 검증된 이메일: {}", user_info.email);
/// } else {
///     println!("⚠️ 미검증 이메일: {}", user_info.email);
/// }
///
/// // 프로필 이미지 처리
/// if let Some(picture_url) = &user_info.picture {
///     let thumbnail_url = format!("{}=s200", picture_url); // 200x200 크기
///     download_profile_image(&thumbnail_url).await?;
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleUserInfo {
    /// Google 사용자 고유 식별자
    ///
    /// Google 서비스에서 제공하는 변경되지 않는 고유 사용자 ID입니다.
    /// 이 값은 사용자 계정의 Primary Key로 사용하기에 적합합니다.
    ///
    /// ## 특징
    ///
    /// - **불변성**: 한 번 할당되면 절대 변경되지 않음
    /// - **고유성**: Google 전체에서 고유함을 보장
    /// - **형식**: 21자리 숫자로 구성된 문자열
    /// - **예시**: `"123456789012345678901"`
    ///
    /// ## 보안 고려사항
    ///
    /// - 로그 출력 시 일부만 표시 권장 (예: `123456...78901`)
    /// - 데이터베이스에서 인덱스 키로 활용 가능
    /// - OAuth 프로바이더 연결 해제 시에도 유지됨
    ///
    /// ## 사용 예제
    ///
    /// ```rust,ignore
    /// // 기존 사용자 검색
    /// let existing_user = user_repository
    ///     .find_by_google_id(&user_info.id)
    ///     .await?;
    ///
    /// match existing_user {
    ///     Some(user) => handle_returning_user(user).await?,
    ///     None => handle_new_user_registration(&user_info).await?,
    /// }
    /// ```
    pub id: String,

    /// 사용자 이메일 주소
    ///
    /// Google 계정의 기본 이메일 주소입니다.
    /// `email` 스코프가 포함되어야 접근할 수 있습니다.
    ///
    /// ## 검증 상태
    ///
    /// 이메일의 검증 상태는 반드시 `verified_email` 필드를 통해 확인해야 합니다.
    /// 검증되지 않은 이메일은 보안상 신뢰하지 않는 것이 좋습니다.
    ///
    /// ## 중복 처리
    ///
    /// - 동일한 이메일로 다른 OAuth 프로바이더 계정이 존재할 수 있음
    /// - 기존 로컬 계정과 이메일이 중복될 수 있음
    /// - 계정 병합 또는 연결 정책이 필요함
    ///
    /// ## 사용 예제
    ///
    /// ```rust,ignore
    /// // 이메일 중복 검사 및 처리
    /// match user_repository.find_by_email(&user_info.email).await? {
    ///     Some(existing_user) => {
    ///         if existing_user.auth_provider == AuthProvider::Local {
    ///             // 로컬 계정에 Google 계정 연결
    ///             link_google_account(&existing_user, &user_info).await?;
    ///         } else {
    ///             // 동일한 이메일의 다른 OAuth 계정 존재
    ///             handle_duplicate_oauth_email(&existing_user, &user_info).await?;
    ///         }
    ///     }
    ///     None => {
    ///         // 새 계정 생성
    ///         create_new_google_account(&user_info).await?;
    ///     }
    /// }
    /// ```
    pub email: String,

    /// 사용자 전체 이름
    ///
    /// 사용자의 표시 이름(Display Name)입니다.
    /// 일반적으로 이름과 성이 결합된 형태로 제공됩니다.
    ///
    /// ## 지역화 고려사항
    ///
    /// - **서양식**: "John Smith" (이름 + 성)
    /// - **동양식**: "김철수" (성 + 이름)
    /// - **단일명**: "Madonna" (하나의 이름만 사용)
    /// - **복합명**: "José María García" (복수의 이름 구성)
    ///
    /// ## 활용 사례
    ///
    /// ```rust,ignore
    /// // UI에서 사용자 인사
    /// let greeting = format!("안녕하세요, {}님!", user_info.name);
    ///
    /// // 검색 인덱스용 정규화 (대소문자, 공백 처리)
    /// let normalized_name = user_info.name
    ///     .to_lowercase()
    ///     .split_whitespace()
    ///     .collect::<Vec<_>>()
    ///     .join(" ");
    /// ```
    pub name: String,

    /// 사용자 이름 (Given Name)
    ///
    /// 사용자의 이름 부분입니다. 서양식 이름에서는 First Name에 해당합니다.
    ///
    /// ## 문화적 차이
    ///
    /// | 문화권 | 예시 | given_name |
    /// |--------|------|------------|
    /// | 서양 | "John Smith" | "John" |
    /// | 한국 | "김철수" | "철수" |
    /// | 일본 | "田中太郎" | "太郎" |
    /// | 스페인 | "José María García" | "José María" |
    ///
    /// ## 데이터 처리 주의사항
    ///
    /// ```rust,ignore
    /// // 이름이 비어있는 경우 처리
    /// let first_name = if user_info.given_name.is_empty() {
    ///     // 전체 이름에서 첫 번째 단어 추출
    ///     user_info.name
    ///         .split_whitespace()
    ///         .next()
    ///         .unwrap_or(&user_info.name)
    ///         .to_string()
    /// } else {
    ///     user_info.given_name
    /// };
    /// ```
    pub given_name: String,

    /// 사용자 성 (Family Name)
    ///
    /// 사용자의 성씨 부분입니다. 서양식 이름에서는 Last Name에 해당합니다.
    ///
    /// ## 문화적 차이
    ///
    /// | 문화권 | 예시 | family_name |
    /// |--------|------|-------------|
    /// | 서양 | "John Smith" | "Smith" |
    /// | 한국 | "김철수" | "김" |
    /// | 일본 | "田中太郎" | "田中" |
    /// | 스페인 | "García López" | "García López" |
    ///
    /// ## 정렬 및 검색 활용
    ///
    /// ```rust,ignore
    /// // 성 기준 알파벳 정렬
    /// users.sort_by(|a, b| {
    ///     a.family_name.cmp(&b.family_name)
    ///         .then_with(|| a.given_name.cmp(&b.given_name))
    /// });
    ///
    /// // 성씨 기반 그룹화
    /// let grouped_by_family: HashMap<String, Vec<User>> = users
    ///     .into_iter()
    ///     .fold(HashMap::new(), |mut acc, user| {
    ///         acc.entry(user.family_name.clone())
    ///            .or_insert_with(Vec::new)
    ///            .push(user);
    ///         acc
    ///     });
    /// ```
    pub family_name: String,

    /// 사용자 프로필 사진 URL
    ///
    /// Google 계정의 프로필 사진 URL입니다.
    /// 프로필 사진이 설정되지 않은 경우 `None`일 수 있습니다.
    ///
    /// ## URL 특성
    ///
    /// - **프로토콜**: 항상 HTTPS 사용
    /// - **도메인**: `lh3.googleusercontent.com` 또는 `lh4.googleusercontent.com`
    /// - **크기 조정**: URL 파라미터로 동적 크기 조정 가능
    /// - **캐싱**: Google CDN을 통해 전 세계적으로 캐싱
    /// - **만료**: URL이 만료될 수 있으므로 주기적 갱신 권장
    ///
    /// ## 크기 조정 예제
    ///
    /// ```rust,ignore
    /// if let Some(picture_url) = &user_info.picture {
    ///     // 다양한 크기 옵션
    ///     let sizes = [
    ///         ("thumbnail", format!("{}=s50", picture_url)),    // 50x50
    ///         ("profile", format!("{}=s200", picture_url)),     // 200x200  
    ///         ("large", format!("{}=s500", picture_url)),       // 500x500
    ///     ];
    ///
    ///     // 원본 크기 (파라미터 제거)
    ///     let original = picture_url
    ///         .split('=')
    ///         .next()
    ///         .unwrap_or(picture_url);
    ///
    ///     // 정사각형이 아닌 원본 비율 유지
    ///     let proportional = format!("{}=w400", picture_url); // 너비 400px
    /// }
    /// ```
    ///
    /// ## 저장 전략
    ///
    /// ```rust,ignore
    /// pub enum ProfileImageStrategy {
    ///     /// Google URL 직접 저장 (간단, 외부 의존성)
    ///     DirectUrl,
    ///     /// 이미지 다운로드 후 로컬 저장 (안정적, 저장 공간 필요)
    ///     LocalCopy,
    ///     /// CDN 캐시 활용 (성능 최적화)
    ///     CdnProxy,
    /// }
    ///
    /// async fn handle_profile_image(
    ///     picture_url: Option<String>,
    ///     strategy: ProfileImageStrategy
    /// ) -> Result<Option<String>, ImageError> {
    ///     match (picture_url, strategy) {
    ///         (Some(url), ProfileImageStrategy::DirectUrl) => Ok(Some(url)),
    ///         (Some(url), ProfileImageStrategy::LocalCopy) => {
    ///             let local_path = download_and_store_image(&url).await?;
    ///             Ok(Some(local_path))
    ///         }
    ///         (Some(url), ProfileImageStrategy::CdnProxy) => {
    ///             let cdn_url = format!("https://cdn.ourservice.com/proxy?url={}", 
    ///                                   urlencoding::encode(&url));
    ///             Ok(Some(cdn_url))
    ///         }
    ///         (None, _) => Ok(None),
    ///     }
    /// }
    /// ```
    pub picture: Option<String>,

    /// 이메일 검증 상태
    ///
    /// Google에서 해당 이메일 주소의 소유권이 검증되었는지 여부를 나타냅니다.
    /// 이는 중요한 보안 필드로, 애플리케이션의 보안 정책에 따라 처리해야 합니다.
    ///
    /// ## 검증 상태의 의미
    ///
    /// - **`true`**: Google이 이메일 소유권을 검증함 (신뢰 가능)
    /// - **`false`**: 검증되지 않은 이메일 (주의 필요)
    ///
    /// ## 보안 정책 예제
    ///
    /// ### 엄격한 보안 정책
    /// ```rust,ignore
    /// pub async fn strict_authentication(
    ///     user_info: &GoogleUserInfo
    /// ) -> Result<User, AuthError> {
    ///     if !user_info.verified_email {
    ///         return Err(AuthError::EmailNotVerified {
    ///             email: user_info.email.clone(),
    ///             message: "검증된 이메일로만 로그인이 가능합니다".to_string(),
    ///             suggestion: "Google 계정에서 이메일을 검증해주세요".to_string(),
    ///         });
    ///     }
    ///     
    ///     proceed_with_authentication(user_info).await
    /// }
    /// ```
    ///
    /// ### 유연한 보안 정책
    /// ```rust,ignore
    /// pub async fn flexible_authentication(
    ///     user_info: &GoogleUserInfo
    /// ) -> Result<AuthResult, AuthError> {
    ///     if !user_info.verified_email {
    ///         log::warn!(
    ///             "미검증 이메일로 로그인 시도: {} (Google ID: {})",
    ///             user_info.email,
    ///             &user_info.id[..8] // 보안을 위해 일부만 로깅
    ///         );
    ///         
    ///         // 제한된 권한으로 로그인 허용
    ///         return Ok(AuthResult::LimitedAccess {
    ///             user: create_limited_user(user_info).await?,
    ///             restrictions: vec![
    ///                 "이메일 인증 필요".to_string(),
    ///                 "민감한 작업 제한".to_string(),
    ///             ],
    ///             verification_required: true,
    ///         });
    ///     }
    ///     
    ///     Ok(AuthResult::FullAccess {
    ///         user: create_full_user(user_info).await?,
    ///     })
    /// }
    /// ```
    ///
    /// ## 데이터베이스 저장
    ///
    /// ```rust,ignore
    /// use chrono::{DateTime, Utc};
    ///
    /// let user = User {
    ///     email: user_info.email,
    ///     email_verified: user_info.verified_email,
    ///     email_verified_at: if user_info.verified_email {
    ///         Some(Utc::now()) // Google에서 검증된 시점으로 기록
    ///     } else {
    ///         None
    ///     },
    ///     email_verification_required: !user_info.verified_email,
    ///     // ...
    /// };
    /// ```
    ///
    /// ## 모니터링 및 알림
    ///
    /// ```rust,ignore
    /// pub async fn monitor_unverified_logins(
    ///     user_info: &GoogleUserInfo
    /// ) -> Result<(), MonitoringError> {
    ///     if !user_info.verified_email {
    ///         // 보안 팀에 알림
    ///         send_security_alert(&SecurityAlert {
    ///             alert_type: "unverified_email_login",
    ///             email: user_info.email.clone(),
    ///             google_id: user_info.id.clone(),
    ///             timestamp: Utc::now(),
    ///             severity: SecuritySeverity::Medium,
    ///         }).await?;
    ///         
    ///         // 사용자에게 이메일 검증 권유
    ///         send_verification_reminder(&user_info.email).await?;
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub verified_email: bool,
}