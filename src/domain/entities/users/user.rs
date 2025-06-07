//! # User Entity Implementation
//!
//! 사용자 엔티티의 핵심 구현체입니다.
//! 로컬 인증과 OAuth 인증을 모두 지원하는 통합된 사용자 모델을 제공합니다.
//!
//! ## 설계 철학
//!
//! ### 1. 인증 방식 통합
//! 하나의 User 엔티티로 다양한 인증 방식을 지원:
//! - **로컬 인증**: 전통적인 이메일/패스워드 방식
//! - **OAuth 인증**: Google, GitHub 등 외부 인증 서비스
//! - **하이브리드**: 향후 다중 인증 방식 연결 지원
//!
//! ### 2. 타입 안전성
//! Rust의 타입 시스템을 활용한 컴파일 타임 검증:
//! ```rust,ignore
//! // 잘못된 사용 시 컴파일 에러
//! let oauth_user = User::new_oauth(...);
//! if oauth_user.password_hash.is_some() { // 항상 false이므로 Warning
//!     // OAuth 사용자는 비밀번호가 없음
//! }
//! ```
//!
//! ### 3. 도메인 불변성
//! 비즈니스 규칙을 코드로 강제:
//! - OAuth 사용자는 자동으로 이메일 인증됨
//! - 로컬 사용자는 비밀번호 해시 필수
//! - 생성 시점의 데이터 일관성 보장
//!
//! ## MongoDB 문서 매핑
//!
//! ### 컬렉션 스키마
//! ```javascript
//! {
//!   "_id": ObjectId("..."),                    // MongoDB 기본 ID
//!   "email": "user@example.com",              // 고유 식별자
//!   "username": "unique_username",            // 사용자명 (고유)
//!   "display_name": "User Display Name",      // 표시명
//!   "password_hash": "$2b$12$...",           // bcrypt 해시 (로컬 인증만)
//!   "auth_provider": "local",                 // 인증 방식
//!   "oauth_data": {                           // OAuth 전용 데이터
//!     "provider_user_id": "google_123456",
//!     "provider_profile_image": "https://...",
//!     "provider_data": { /* 추가 메타데이터 */ }
//!   },
//!   "is_active": true,                        // 계정 활성화 상태
//!   "is_email_verified": true,                // 이메일 인증 상태
//!   "roles": ["user", "premium"],             // 역할 기반 권한
//!   "profile_image_url": "https://...",       // 프로필 이미지
//!   "last_login_at": ISODate("..."),          // 마지막 로그인
//!   "created_at": ISODate("..."),             // 생성 시간
//!   "updated_at": ISODate("...")              // 수정 시간
//! }
//! ```
//!
//! ## 사용 패턴
//!
//! ### 1. 로컬 사용자 생성
//! ```rust,ignore
//! use bcrypt::{hash, DEFAULT_COST};
//! use crate::domain::entities::users::User;
//!
//! // 비밀번호 해싱
//! let password_hash = hash("user_password", DEFAULT_COST)?;
//!
//! // 로컬 사용자 생성
//! let user = User::new_local(
//!     "user@example.com".to_string(),
//!     "unique_username".to_string(),
//!     "John Doe".to_string(),
//!     password_hash
//! );
//!
//! // 특징: is_email_verified = false (이메일 인증 필요)
//! assert!(!user.is_email_verified);
//! assert!(user.can_authenticate_with_password());
//! ```
//!
//! ### 2. OAuth 사용자 생성
//! ```rust,ignore
//! use crate::config::AuthProvider;
//!
//! // Google OAuth 사용자 생성
//! let oauth_user = User::new_oauth(
//!     "user@gmail.com".to_string(),
//!     "google_username".to_string(),
//!     "Google User".to_string(),
//!     AuthProvider::Google,
//!     "google_unique_id_123".to_string(),
//!     Some("https://lh3.googleusercontent.com/...".to_string())
//! );
//!
//! // 특징: is_email_verified = true (자동 인증)
//! assert!(oauth_user.is_email_verified);
//! assert!(!oauth_user.can_authenticate_with_password());
//! assert_eq!(oauth_user.oauth_provider_id(), Some("google_unique_id_123"));
//! ```
//!
//! ### 3. Repository 패턴과 연동
//! ```rust,ignore
//! use crate::repositories::users::UserRepository;
//!
//! let user_repo = UserRepository::instance();
//!
//! // 이메일로 사용자 조회
//! let user = user_repo.find_by_email("user@example.com").await?;
//!
//! // OAuth 프로바이더로 사용자 조회
//! let oauth_user = user_repo
//!     .find_by_oauth_provider(AuthProvider::Google, "google_id_123")
//!     .await?;
//!
//! // 사용자명으로 조회
//! let user_by_username = user_repo.find_by_username("unique_username").await?;
//! ```
//!
//! ## 비즈니스 로직 메서드
//!
//! ### 인증 관련 헬퍼 메서드
//! ```rust,ignore
//! let user = get_user_from_somewhere();
//!
//! // 인증 방식 확인
//! if user.is_local_auth() {
//!     // 로컬 인증 사용자 처리
//!     if user.can_authenticate_with_password() {
//!         // 비밀번호 검증 로직
//!     }
//! } else if user.is_oauth_auth() {
//!     // OAuth 인증 사용자 처리
//!     if let Some(provider_id) = user.oauth_provider_id() {
//!         // OAuth 프로바이더 연동 로직
//!     }
//! }
//! ```
//!
//! ### ID 처리
//! ```rust,ignore
//! // MongoDB ObjectId를 문자열로 변환
//! if let Some(id_str) = user.id_string() {
//!     // JWT 토큰에 사용자 ID 포함
//!     let token_claims = TokenClaims {
//!         sub: id_str,
//!         email: user.email.clone(),
//!         // ...
//!     };
//! }
//! ```
//!
//! ## 검증 및 보안
//!
//! ### 이메일 검증
//! ```rust,ignore
//! // 이메일 형식 검증 (생성 전)
//! fn validate_email(email: &str) -> Result<(), ValidationError> {
//!     use regex::Regex;
//!     let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
//!     
//!     if !email_regex.is_match(email) {
//!         return Err(ValidationError::InvalidEmail);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### 사용자명 검증
//! ```rust,ignore
//! // 사용자명 규칙 검증
//! fn validate_username(username: &str) -> Result<(), ValidationError> {
//!     if username.len() < 3 || username.len() > 30 {
//!         return Err(ValidationError::InvalidUsernameLength);
//!     }
//!     
//!     if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
//!         return Err(ValidationError::InvalidUsernameFormat);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## 성능 최적화
//!
//! ### 필드별 최적화 전략
//! ```rust,ignore
//! // Optional 필드들은 BSON에서 제외하여 문서 크기 최소화
//! #[serde(skip_serializing_if = "Option::is_none")]
//! pub oauth_data: Option<OAuthData>,
//!
//! // 자주 변경되지 않는 필드들
//! pub email: String,           // 인덱스 키, 캐시 키로 활용
//! pub auth_provider: AuthProvider, // 쿼리 최적화용
//! ```
//!
//! ### 인덱스 활용 쿼리
//! ```javascript
//! // 효율적인 쿼리 패턴
//! db.users.find({"email": "user@example.com"})  // 고유 인덱스 활용
//! db.users.find({"auth_provider": "google", "oauth_data.provider_user_id": "123"})  // 복합 인덱스
//! db.users.find({"is_active": true, "roles": "admin"})  // 역할 기반 쿼리
//! ```
//!
//! ## 마이그레이션 고려사항
//!
//! ### 스키마 진화
//! ```rust,ignore
//! // 새로운 필드 추가 시
//! #[derive(Serialize, Deserialize)]
//! pub struct User {
//!     // 기존 필드들...
//!     
//!     /// 새로운 필드 (기본값 제공)
//!     #[serde(default)]
//!     pub new_feature_flag: bool,
//!     
//!     /// 더 이상 사용하지 않는 필드 (하위 호환성)
//!     #[serde(skip_serializing_if = "Option::is_none")]
//!     pub deprecated_field: Option<String>,
//! }
//! ```
//!
//! ### 데이터 마이그레이션
//! ```javascript
//! // MongoDB 마이그레이션 스크립트 예시
//! db.users.updateMany(
//!   { "auth_provider": { $exists: false } },
//!   { $set: { "auth_provider": "local" } }
//! )
//! ```

use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::{Deserialize, Serialize};
use crate::config::AuthProvider;

/// OAuth 프로바이더 관련 추가 데이터
/// 
/// OAuth 인증을 통해 가입한 사용자의 프로바이더별 고유 정보를 저장합니다.
/// 프로바이더에서 제공하는 추가 데이터와 프로필 정보를 포함합니다.
/// 
/// # 필드 설명
/// 
/// * `provider_user_id` - OAuth 프로바이더에서의 고유 사용자 ID (필수)
/// * `provider_profile_image` - 프로바이더에서 제공한 프로필 이미지 URL (선택)
/// * `provider_data` - 프로바이더별 추가 메타데이터 (선택)
/// 
/// # 예제
/// 
/// ```rust,ignore
/// let google_oauth_data = OAuthData {
///     provider_user_id: "google_123456789".to_string(),
///     provider_profile_image: Some("https://lh3.googleusercontent.com/...".to_string()),
///     provider_data: Some(json!({
///         "google_plus_id": "legacy_gplus_id",
///         "locale": "ko_KR"
///     })),
/// };
/// ```
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
/// 
/// 시스템의 모든 사용자를 표현하는 핵심 도메인 엔티티입니다.
/// 로컬 인증(이메일/패스워드)과 OAuth 인증을 모두 지원하는 통합 모델을 제공합니다.
/// 
/// # 인증 방식별 특징
/// 
/// ## 로컬 인증 사용자
/// - `auth_provider`: `AuthProvider::Local`
/// - `password_hash`: 해시된 비밀번호 저장
/// - `is_email_verified`: 초기값 `false` (이메일 인증 필요)
/// - `oauth_data`: `None`
/// 
/// ## OAuth 인증 사용자
/// - `auth_provider`: `AuthProvider::Google`, `AuthProvider::GitHub` 등
/// - `password_hash`: `None` (비밀번호 없음)
/// - `is_email_verified`: 초기값 `true` (프로바이더에서 인증됨)
/// - `oauth_data`: 프로바이더별 데이터 포함
/// 
/// # MongoDB 매핑
/// 
/// 이 구조체는 MongoDB의 `users` 컬렉션과 직접 매핑됩니다:
/// - `id` 필드는 MongoDB의 `_id` 필드로 저장
/// - Optional 필드들은 `null` 값 시 BSON에서 제외
/// - DateTime 필드는 MongoDB의 ISODate 타입으로 저장
/// 
/// # 필드별 제약 조건
/// 
/// * `email` - 시스템 전체에서 고유해야 함
/// * `username` - 시스템 전체에서 고유해야 함
/// * `roles` - 최소한 "user" 역할은 포함해야 함
/// * `auth_provider` - 사용자의 인증 방식 결정
/// 
/// # 예제
/// 
/// ```rust,ignore
/// use crate::domain::entities::users::{User, OAuthData};
/// use crate::config::AuthProvider;
/// 
/// // 로컬 사용자 생성
/// let local_user = User::new_local(
///     "user@example.com".to_string(),
///     "johndoe".to_string(),
///     "John Doe".to_string(),
///     "$2b$12$...".to_string() // bcrypt 해시
/// );
/// 
/// // OAuth 사용자 생성
/// let oauth_user = User::new_oauth(
///     "user@gmail.com".to_string(),
///     "googleuser".to_string(),
///     "Google User".to_string(),
///     AuthProvider::Google,
///     "google_id_123".to_string(),
///     Some("https://lh3.googleusercontent.com/...".to_string())
/// );
/// 
/// // 인증 방식 확인
/// assert!(local_user.is_local_auth());
/// assert!(oauth_user.is_oauth_auth());
/// assert!(local_user.can_authenticate_with_password());
/// assert!(!oauth_user.can_authenticate_with_password());
/// ```
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
    /// 
    /// 전통적인 이메일과 패스워드를 사용하는 로컬 인증 사용자를 생성합니다.
    /// 생성된 사용자는 이메일 인증이 필요한 상태로 시작됩니다.
    /// 
    /// # 인자
    /// 
    /// * `email` - 사용자 이메일 (고유해야 함)
    /// * `username` - 사용자명 (고유해야 함)
    /// * `display_name` - 표시될 이름
    /// * `password_hash` - bcrypt 등으로 해시된 비밀번호
    /// 
    /// # 반환값
    /// 
    /// 로컬 인증용으로 설정된 새 User 인스턴스
    /// 
    /// # 특징
    /// 
    /// - `auth_provider`: `AuthProvider::Local`
    /// - `is_email_verified`: `false` (이메일 인증 필요)
    /// - `oauth_data`: `None`
    /// - `roles`: `["user"]`
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// use bcrypt::{hash, DEFAULT_COST};
    /// 
    /// let password_hash = hash("secure_password", DEFAULT_COST)?;
    /// let user = User::new_local(
    ///     "user@example.com".to_string(),
    ///     "john_doe".to_string(),
    ///     "John Doe".to_string(),
    ///     password_hash
    /// );
    /// 
    /// assert!(user.is_local_auth());
    /// assert!(!user.is_email_verified); // 이메일 인증 필요
    /// assert!(user.can_authenticate_with_password());
    /// ```
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
    /// 
    /// Google, GitHub 등의 OAuth 프로바이더를 통해 인증된 사용자를 생성합니다.
    /// OAuth 사용자는 이미 프로바이더에서 인증되었으므로 이메일 인증이 완료된 상태로 시작됩니다.
    /// 
    /// # 인자
    /// 
    /// * `email` - 프로바이더에서 제공한 이메일
    /// * `username` - 시스템에서 사용할 사용자명
    /// * `display_name` - 프로바이더에서 제공한 표시 이름
    /// * `auth_provider` - OAuth 프로바이더 (Google, GitHub 등)
    /// * `provider_user_id` - 프로바이더에서의 고유 사용자 ID
    /// * `provider_profile_image` - 프로바이더에서 제공한 프로필 이미지 URL
    /// 
    /// # 반환값
    /// 
    /// OAuth 인증용으로 설정된 새 User 인스턴스
    /// 
    /// # 특징
    /// 
    /// - `password_hash`: `None` (비밀번호 없음)
    /// - `is_email_verified`: `true` (자동 인증)
    /// - `oauth_data`: 프로바이더 정보 포함
    /// - `roles`: `["user"]`
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// use crate::config::AuthProvider;
    /// 
    /// let oauth_user = User::new_oauth(
    ///     "user@gmail.com".to_string(),
    ///     "google_user".to_string(),
    ///     "Google User".to_string(),
    ///     AuthProvider::Google,
    ///     "google_123456789".to_string(),
    ///     Some("https://lh3.googleusercontent.com/...".to_string())
    /// );
    /// 
    /// assert!(oauth_user.is_oauth_auth());
    /// assert!(oauth_user.is_email_verified); // 자동 인증됨
    /// assert!(!oauth_user.can_authenticate_with_password());
    /// assert_eq!(oauth_user.oauth_provider_id(), Some("google_123456789"));
    /// ```
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
    /// 
    /// # ⚠️ Deprecated
    /// 
    /// 이 메서드는 더 이상 권장되지 않습니다. 대신 `new_local`을 사용하세요.
    /// 향후 버전에서 제거될 예정입니다.
    #[deprecated(note = "Use new_local instead")]
    pub fn new(email: String, username: String, display_name: String, password_hash: String) -> Self {
        Self::new_local(email, username, display_name, password_hash)
    }

    /// ID 문자열로 변환
    /// 
    /// MongoDB ObjectId를 16진수 문자열로 변환합니다.
    /// JWT 토큰이나 URL 파라미터에서 사용하기 위한 문자열 형태의 ID를 제공합니다.
    /// 
    /// # 반환값
    /// 
    /// * `Some(String)` - ObjectId의 16진수 문자열 표현
    /// * `None` - ID가 아직 설정되지 않은 경우 (저장 전 상태)
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// let user = get_saved_user(); // DB에서 가져온 사용자
    /// 
    /// if let Some(id_str) = user.id_string() {
    ///     // JWT 클레임에 사용
    ///     let token_claims = TokenClaims {
    ///         sub: id_str,
    ///         email: user.email.clone(),
    ///         // ...
    ///     };
    /// }
    /// ```
    pub fn id_string(&self) -> Option<String> {
        self.id.as_ref().map(|id| id.to_hex())
    }

    /// 로컬 인증 사용자인지 확인
    /// 
    /// 사용자가 이메일/패스워드 방식의 로컬 인증을 사용하는지 확인합니다.
    /// 
    /// # 반환값
    /// 
    /// * `true` - 로컬 인증 사용자
    /// * `false` - OAuth 인증 사용자
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// if user.is_local_auth() {
    ///     // 비밀번호 변경, 이메일 인증 등 로컬 인증 관련 처리
    ///     handle_local_auth_user(&user);
    /// }
    /// ```
    pub fn is_local_auth(&self) -> bool {
        matches!(self.auth_provider, AuthProvider::Local)
    }

    /// OAuth 인증 사용자인지 확인
    /// 
    /// 사용자가 Google, GitHub 등의 OAuth 프로바이더를 통해 인증하는지 확인합니다.
    /// 
    /// # 반환값
    /// 
    /// * `true` - OAuth 인증 사용자
    /// * `false` - 로컬 인증 사용자
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// if user.is_oauth_auth() {
    ///     // OAuth 토큰 갱신, 프로바이더 연동 등 OAuth 관련 처리
    ///     handle_oauth_user(&user);
    /// }
    /// ```
    pub fn is_oauth_auth(&self) -> bool {
        !self.is_local_auth()
    }

    /// 비밀번호 인증이 가능한 사용자인지 확인
    /// 
    /// 사용자가 비밀번호를 통한 인증이 가능한지 확인합니다.
    /// 로컬 인증 사용자이면서 password_hash가 설정된 경우에만 true를 반환합니다.
    /// 
    /// # 반환값
    /// 
    /// * `true` - 비밀번호 인증 가능 (로컬 인증 + 비밀번호 해시 존재)
    /// * `false` - 비밀번호 인증 불가능 (OAuth 사용자 또는 비밀번호 없음)
    /// 
    /// # 사용 사례
    /// 
    /// - 로그인 시 비밀번호 검증 여부 결정
    /// - 비밀번호 변경 기능 활성화 여부 결정
    /// - 계정 보안 설정 UI 표시 여부 결정
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// // 로그인 처리
    /// if user.can_authenticate_with_password() {
    ///     // 비밀번호 검증 수행
    ///     if bcrypt::verify(input_password, &user.password_hash.unwrap())? {
    ///         // 인증 성공
    ///     }
    /// } else {
    ///     // OAuth 리다이렉트 또는 에러 처리
    /// }
    /// ```
    pub fn can_authenticate_with_password(&self) -> bool {
        self.is_local_auth() && self.password_hash.is_some()
    }

    /// OAuth 프로바이더에서의 사용자 ID 가져오기
    /// 
    /// OAuth 인증 사용자의 경우 프로바이더에서 할당한 고유 사용자 ID를 반환합니다.
    /// 이 ID는 프로바이더와의 연동 시 사용됩니다.
    /// 
    /// # 반환값
    /// 
    /// * `Some(&str)` - OAuth 프로바이더의 사용자 ID
    /// * `None` - 로컬 인증 사용자이거나 OAuth 데이터가 없는 경우
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// if let Some(provider_id) = user.oauth_provider_id() {
    ///     // 프로바이더 API 호출 시 사용
    ///     let profile_data = oauth_client
    ///         .get_user_profile(provider_id)
    ///         .await?;
    /// }
    /// ```
    pub fn oauth_provider_id(&self) -> Option<&str> {
        self.oauth_data.as_ref().map(|data| data.provider_user_id.as_str())
    }
}