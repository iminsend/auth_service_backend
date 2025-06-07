//! # Users Entity Module
//!
//! 사용자 도메인의 핵심 엔티티들을 정의하는 모듈입니다.
//! 인증 서비스의 가장 중요한 엔티티인 User와 관련된 모든 데이터 구조를 포함합니다.
//!
//! ## 주요 구성 요소
//!
//! ### User Entity
//! - **로컬 인증**: 이메일/패스워드 기반 인증
//! - **OAuth 인증**: Google, GitHub 등 외부 인증 프로바이더 지원
//! - **하이브리드 지원**: 단일 사용자가 여러 인증 방식 사용 가능
//!
//! ### OAuthData
//! - OAuth 프로바이더별 고유 데이터 저장
//! - 프로필 이미지, 추가 메타데이터 관리
//! - 프로바이더별 사용자 ID 매핑
//!
//! ## 아키텍처 설계
//!
//! ### Spring Security 패턴 적용
//! ```text
//! Spring Security UserDetails ≈ Rust User Entity
//! ┌─────────────────────────────────────────────┐
//! │ User (Core Entity)                          │
//! │ ├── Local Authentication                    │
//! │ │   ├── email + password_hash               │
//! │ │   └── email verification                  │
//! │ └── OAuth Authentication                    │
//! │     ├── provider + provider_user_id         │
//! │     └── automatic email verification        │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ### 데이터베이스 스키마 설계
//! ```javascript
//! // MongoDB Collection: users
//! {
//!   "_id": ObjectId,
//!   "email": String,            // 고유 인덱스
//!   "username": String,         // 고유 인덱스
//!   "auth_provider": String,    // "local" | "google" | "github"
//!   "oauth_data": {             // OAuth 사용자만
//!     "provider_user_id": String,
//!     "provider_profile_image": String?,
//!     "provider_data": Object?
//!   },
//!   "is_active": Boolean,
//!   "roles": [String],
//!   // ... 기타 필드
//! }
//! ```
//!
//! ## 사용 예제
//!
//! ### Repository와 함께 사용
//! ```rust,ignore
//! use crate::domain::entities::users::User;
//! use crate::repositories::users::UserRepository;
//!
//! // Repository 싱글톤 인스턴스
//! let user_repo = UserRepository::instance();
//!
//! // 로컬 사용자 생성
//! let local_user = User::new_local(
//!     "user@example.com".to_string(),
//!     "username".to_string(),
//!     "Display Name".to_string(),
//!     hashed_password
//! );
//!
//! // OAuth 사용자 생성
//! let oauth_user = User::new_oauth(
//!     "user@gmail.com".to_string(),
//!     "oauth_username".to_string(),
//!     "OAuth User".to_string(),
//!     AuthProvider::Google,
//!     "google_user_id_123".to_string(),
//!     Some("https://lh3.googleusercontent.com/...".to_string())
//! );
//!
//! // 데이터베이스 저장
//! let saved_user = user_repo.save(local_user).await?;
//! ```
//!
//! ### Service 레이어와 연동
//! ```rust,ignore
//! use crate::services::users::UserService;
//! use crate::services::auth::TokenService;
//!
//! let user_service = UserService::instance();
//! let token_service = TokenService::instance();
//!
//! // 사용자 인증 및 토큰 발급
//! if let Some(user) = user_service.authenticate_user(email, password).await? {
//!     let tokens = token_service.generate_tokens(&user).await?;
//!     // 인증 성공 처리
//! }
//! ```
//!
//! ## 비즈니스 규칙
//!
//! ### 인증 방식별 특징
//! 1. **로컬 인증**
//!    - 이메일 인증 필수 (`is_email_verified: false` → `true`)
//!    - 비밀번호 해시 저장 필수
//!    - 비밀번호 변경 가능
//!
//! 2. **OAuth 인증**
//!    - 이메일 자동 인증 (`is_email_verified: true`)
//!    - 비밀번호 해시 없음 (`password_hash: None`)
//!    - 프로바이더별 고유 ID 저장
//!
//! ### 보안 고려사항
//! - **이메일 고유성**: 동일 이메일로 다른 인증 방식 가입 불가
//! - **사용자명 고유성**: 시스템 전체에서 고유한 사용자명 필수
//! - **역할 기반 접근 제어**: `roles` 필드를 통한 권한 관리
//! - **계정 상태 관리**: `is_active` 플래그로 계정 비활성화 가능
//!
//! ## 성능 최적화
//!
//! ### 인덱스 설계
//! ```javascript
//! // 권장 MongoDB 인덱스
//! db.users.createIndex({ "email": 1 }, { unique: true })
//! db.users.createIndex({ "username": 1 }, { unique: true })
//! db.users.createIndex({ "auth_provider": 1, "oauth_data.provider_user_id": 1 })
//! db.users.createIndex({ "is_active": 1 })
//! db.users.createIndex({ "created_at": -1 })
//! ```
//!
//! ### 캐싱 전략
//! - 자주 조회되는 사용자 정보는 Redis 캐싱
//! - 세션 기반 사용자 정보 메모리 캐시
//! - OAuth 프로바이더 ID 기반 빠른 조회
//!
//! ## 확장성 고려사항
//!
//! ### 다중 OAuth 프로바이더 지원
//! ```rust,ignore
//! // 향후 확장을 위한 구조
//! pub struct User {
//!     // 기존 필드들...
//!     pub linked_accounts: Vec<OAuthData>, // 다중 OAuth 계정 연결
//! }
//! ```
//!
//! ### 사용자 프로필 확장
//! ```rust,ignore
//! pub struct UserProfile {
//!     pub user_id: ObjectId,
//!     pub bio: Option<String>,
//!     pub website: Option<String>,
//!     pub location: Option<String>,
//!     // 추가 프로필 정보
//! }
//! ```

pub mod user;