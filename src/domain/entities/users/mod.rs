//! Users Entity Module
//!
//! 사용자 도메인의 핵심 엔티티들을 정의하는 모듈입니다.
//! 로컬 인증과 OAuth 인증을 모두 지원하는 User 엔티티를 포함합니다.
//!
//! # 주요 구성 요소
//!
//! ### User Entity
//! - **로컬 인증**: 이메일/패스워드 기반 인증
//! - **OAuth 인증**: Google, GitHub 등 외부 인증 프로바이더 지원
//! - **하이브리드 지원**: 단일 사용자가 여러 인증 방식 사용 가능
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! use crate::domain::entities::users::User;
//!
//! // 로컬 사용자 생성
//! let user = User::new_local(
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
//!     None
//! );
//! ```

pub mod user;
