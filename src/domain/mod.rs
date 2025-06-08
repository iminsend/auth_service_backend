//! # Domain Layer Module
//!
//! 도메인 계층을 구성하는 핵심 모듈로, 비즈니스 로직과 도메인 규칙을 담당합니다.
//! Domain-Driven Design (DDD) 원칙에 따라 설계되었습니다.
//!
//! ## 모듈 구성
//!
//! ### [`entities`] - 핵심 도메인 엔티티
//! 
//! 비즈니스의 핵심 개념을 나타내는 영속 가능한 객체들입니다.
//! MongoDB에 저장되는 도메인 객체로 비즈니스 규칙과 제약 사항을 포함합니다.
//!
//! ```rust,ignore
//! #[derive(Debug, Clone, Serialize, Deserialize)]
//! pub struct User {
//!     #[serde(rename = "_id")]
//!     pub id: ObjectId,
//!     pub email: String,
//!     pub name: String,
//!     pub provider: AuthProvider,
//!     pub created_at: chrono::DateTime<chrono::Utc>,
//! }
//! ```
//!
//! ### [`dto`] - 데이터 전송 객체
//!
//! API 경계에서 데이터를 전송하기 위한 객체들입니다.
//! 입력 데이터 유효성 검증과 API 계약을 담당합니다.
//!
//! ```rust,ignore
//! #[derive(Debug, Deserialize, Validate)]
//! pub struct CreateUserRequest {
//!     #[validate(email)]
//!     pub email: String,
//!     #[validate(length(min = 2, max = 50))]
//!     pub name: String,
//! }
//! ```
//!
//! ### [`models`] - 외부 시스템 통합 모델
//!
//! 외부 API나 서비스와의 통합을 위한 데이터 모델들입니다.
//! OAuth, 써드파티 서비스 연동, 캐시 등에 사용됩니다.
//!
//! ```rust,ignore
//! #[derive(Debug, Deserialize)]
//! pub struct GoogleUserInfo {
//!     pub id: String,
//!     pub email: String,
//!     pub name: String,
//! }
//! ```

pub mod entities;
pub mod dto;
pub mod models;

pub use dto::*;
pub use models::*;
