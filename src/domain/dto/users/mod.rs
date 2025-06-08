//! User Data Transfer Objects Module
//!
//! 사용자 관련 API의 요청/응답 데이터 구조를 정의하는 모듈입니다.
//! 클라이언트와 서버 간의 사용자 데이터 교환을 위한 계약을 정의합니다.
//!
//! # 주요 DTOs
//!
//! ## Request DTOs
//! - `CreateUserRequest` - 회원가입 요청
//! - `LoginRequest` - 로그인 요청
//! - `UpdateUserRequest` - 사용자 정보 수정 요청
//!
//! ## Response DTOs
//! - `UserResponse` - 기본 사용자 정보 (민감한 정보 제외)
//! - `LoginResponse` - 인증 성공 시 JWT 토큰과 사용자 정보
//! - `GoogleOAuthResponse` - Google OAuth 인증 응답
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use crate::domain::dto::users::{CreateUserRequest, UserResponse};
//!
//! pub async fn register(
//!     request: web::Json<CreateUserRequest>
//! ) -> Result<HttpResponse, AppError> {
//!     request.validate()?;
//!     let user = user_service.create_user(request.into_inner()).await?;
//!     Ok(HttpResponse::Created().json(UserResponse::from(user)))
//! }
//! ```

pub mod request;
pub mod response;

// Re-exports for convenience
pub use request::*;
pub use response::*;
