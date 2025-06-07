//! # Domain Models Module
//!
//! 도메인의 비즈니스 모델과 값 객체(Value Objects)를 정의하는 모듈입니다.
//! 이 모듈은 DDD(Domain Driven Design)의 핵심 개념인 도메인 모델을 구현하며,
//! entities와는 구별되는 역할을 담당합니다.
//!
//! ## Entities vs Models 구분
//!
//! ### Entities (`../entities/`)
//! - **영속성**: 데이터베이스에 직접 저장되는 객체
//! - **정체성**: 고유한 식별자(ID)를 가짐
//! - **생명주기**: 생성, 수정, 삭제의 완전한 생명주기
//! - **예시**: `User`, `Session`, `RefreshToken` 등
//!
//! ### Models (`./`)
//! - **비즈니스 로직**: 도메인의 핵심 비즈니스 규칙 포함
//! - **값 객체**: 식별자보다는 값 자체가 중요
//! - **불변성**: 일반적으로 불변 객체로 설계
//! - **예시**: `GoogleOAuthModel`, `TokenPair`, `ValidationResult` 등
//!
//! ## 아키텍처 패턴
//!
//! ### DDD 레이어 구조
//! ```text
//! Domain Layer
//! ├── entities/         ← 영속성 엔티티 (MongoDB 문서)
//! ├── models/          ← 도메인 모델 & 값 객체 (이 모듈)
//! ├── dto/             ← 데이터 전송 객체
//! └── services/        ← 도메인 서비스 (비즈니스 로직)
//! ```
//!
//! ### Spring Framework와의 비교
//! | Spring | Rust Domain Models |
//! |--------|-------------------|
//! | `@Entity` | `../entities/` |
//! | `@Embeddable` | `./models/` (값 객체) |
//! | `@Service` | `../services/` |
//! | `@Component` | 도메인 모델의 메서드 |
//!
//! ## 주요 역할
//!
//! ### 1. 값 객체 (Value Objects)
//! ```rust,ignore
//! #[derive(Debug, Clone, PartialEq, Eq)]
//! pub struct Email(String);
//!
//! impl Email {
//!     pub fn new(email: String) -> Result<Self, ValidationError> {
//!         // 이메일 형식 검증 로직
//!         if Self::is_valid(&email) {
//!             Ok(Email(email))
//!         } else {
//!             Err(ValidationError::InvalidEmail)
//!         }
//!     }
//!     
//!     fn is_valid(email: &str) -> bool {
//!         // 이메일 검증 비즈니스 로직
//!         email.contains('@') && email.contains('.')
//!     }
//! }
//! ```
//!
//! ### 2. 도메인 서비스 모델
//! ```rust,ignore
//! #[derive(Debug, Clone)]
//! pub struct AuthenticationResult {
//!     pub success: bool,
//!     pub user_id: Option<String>,
//!     pub error_code: Option<AuthError>,
//!     pub requires_2fa: bool,
//! }
//!
//! impl AuthenticationResult {
//!     pub fn success(user_id: String) -> Self {
//!         Self {
//!             success: true,
//!             user_id: Some(user_id),
//!             error_code: None,
//!             requires_2fa: false,
//!         }
//!     }
//!     
//!     pub fn failure(error: AuthError) -> Self {
//!         Self {
//!             success: false,
//!             user_id: None,
//!             error_code: Some(error),
//!             requires_2fa: false,
//!         }
//!     }
//! }
//! ```
//!
//! ### 3. 외부 시스템 통합 모델
//! OAuth 프로바이더, 결제 시스템 등 외부 API와의 통합을 위한 모델들:
//! ```rust,ignore
//! #[derive(Debug, Serialize, Deserialize)]
//! pub struct GoogleOAuthResponse {
//!     pub access_token: String,
//!     pub token_type: String,
//!     pub expires_in: u64,
//!     pub refresh_token: Option<String>,
//!     pub scope: String,
//! }
//!
//! impl GoogleOAuthResponse {
//!     pub fn is_expired(&self) -> bool {
//!         // 토큰 만료 확인 로직
//!         false // 실제 구현 필요
//!     }
//! }
//! ```
//!
//! ## 설계 원칙
//!
//! ### 1. 불변성 (Immutability)
//! ```rust,ignore
//! // ✅ 좋은 예: 불변 값 객체
//! #[derive(Debug, Clone, PartialEq)]
//! pub struct Money {
//!     amount: u64,      // 센트 단위
//!     currency: Currency,
//! }
//!
//! impl Money {
//!     pub fn add(&self, other: &Money) -> Result<Money, MoneyError> {
//!         if self.currency != other.currency {
//!             return Err(MoneyError::CurrencyMismatch);
//!         }
//!         Ok(Money {
//!             amount: self.amount + other.amount,
//!             currency: self.currency,
//!         })
//!     }
//! }
//! ```
//!
//! ### 2. 도메인 규칙 캡슐화
//! ```rust,ignore
//! #[derive(Debug, Clone)]
//! pub struct Password(String);
//!
//! impl Password {
//!     pub fn new(plain_password: String) -> Result<Self, PasswordError> {
//!         Self::validate(&plain_password)?;
//!         let hashed = bcrypt::hash(plain_password, bcrypt::DEFAULT_COST)
//!             .map_err(|_| PasswordError::HashingFailed)?;
//!         Ok(Password(hashed))
//!     }
//!     
//!     fn validate(password: &str) -> Result<(), PasswordError> {
//!         if password.len() < 8 {
//!             return Err(PasswordError::TooShort);
//!         }
//!         if !password.chars().any(|c| c.is_uppercase()) {
//!             return Err(PasswordError::NoUppercase);
//!         }
//!         // 추가 검증 규칙...
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ### 3. 타입 안전성
//! ```rust,ignore
//! // 원시 타입 대신 도메인 타입 사용
//! pub struct UserId(String);
//! pub struct SessionId(String);
//! pub struct TokenId(String);
//!
//! // 컴파일 타임에 타입 안전성 보장
//! fn authenticate_user(user_id: UserId) -> AuthResult {
//!     // UserId만 받으므로 실수로 다른 ID 전달 불가
//! }
//! ```
//!
//! ## 사용 패턴
//!
//! ### Service Layer와의 연동
//! ```rust,ignore
//! use crate::domain::models::oauth::GoogleOAuthModel;
//! use crate::services::auth::GoogleAuthService;
//!
//! let google_service = GoogleAuthService::instance();
//!
//! // OAuth 모델을 통한 안전한 인증 처리
//! let oauth_request = GoogleOAuthModel::new(
//!     authorization_code,
//!     redirect_uri,
//!     client_id
//! )?;
//!
//! let auth_result = google_service
//!     .authenticate(oauth_request)
//!     .await?;
//! ```
//!
//! ### Entity 변환
//! ```rust,ignore
//! use crate::domain::entities::users::User;
//! use crate::domain::models::oauth::GoogleUserInfo;
//!
//! impl From<GoogleUserInfo> for User {
//!     fn from(google_info: GoogleUserInfo) -> Self {
//!         User::new_oauth(
//!             google_info.email,
//!             google_info.generate_username(),
//!             google_info.name,
//!             AuthProvider::Google,
//!             google_info.id,
//!             google_info.picture
//!         )
//!     }
//! }
//! ```
//!
//! ## 모듈 구성
//!
//! ```text
//! models/
//! ├── mod.rs              ← 이 파일 (모듈 진입점)
//! ├── oauth/              ← OAuth 관련 모델들
//! │   ├── mod.rs
//! │   ├── google_oauth_model/
//! │   └── github_oauth_model/  ← 향후 추가 예정
//! ├── auth/               ← 인증 관련 모델들 (향후)
//! │   ├── token_models.rs
//! │   └── session_models.rs
//! ├── validation/         ← 검증 관련 모델들 (향후)
//! │   ├── email_validator.rs
//! │   └── password_validator.rs
//! └── shared/             ← 공통 모델들 (향후)
//!     ├── result_models.rs
//!     └── error_models.rs
//! ```
//!
//! ## 성능 고려사항
//!
//! ### 메모리 효율성
//! ```rust,ignore
//! // 작은 값 객체는 Copy trait 구현
//! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//! pub struct StatusCode(u16);
//!
//! // 큰 객체는 Arc로 공유
//! use std::sync::Arc;
//! pub type SharedOAuthModel = Arc<GoogleOAuthModel>;
//! ```
//!
//! ### 직렬화 최적화
//! ```rust,ignore
//! #[derive(Serialize, Deserialize)]
//! pub struct ApiResponse<T> {
//!     #[serde(skip_serializing_if = "Option::is_none")]
//!     pub data: Option<T>,
//!     
//!     #[serde(skip_serializing_if = "Vec::is_empty")]
//!     pub errors: Vec<String>,
//! }
//! ```
//!
//! ## 테스트 전략
//!
//! ### 단위 테스트
//! ```rust,ignore
//! #[cfg(test)]
//! mod tests {
//!     use super::*;
//!
//!     #[test]
//!     fn test_email_validation() {
//!         // 유효한 이메일
//!         let valid_email = Email::new("test@example.com".to_string());
//!         assert!(valid_email.is_ok());
//!
//!         // 무효한 이메일
//!         let invalid_email = Email::new("invalid-email".to_string());
//!         assert!(invalid_email.is_err());
//!     }
//! }
//! ```
//!
//! ## 확장 가이드
//!
//! ### 새로운 값 객체 추가
//! 1. 도메인 규칙 정의
//! 2. 검증 로직 구현
//! 3. 직렬화/역직렬화 지원
//! 4. 단위 테스트 작성
//! 5. 문서화
//!
//! ### 외부 시스템 통합 모델 추가
//! 1. API 스펙 분석
//! 2. 요청/응답 모델 정의
//! 3. 에러 처리 모델 정의
//! 4. Entity 변환 로직 구현
//! 5. 통합 테스트 작성

pub mod oauth;