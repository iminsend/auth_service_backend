//! HTTP Request Handlers Module
//!
//! HTTP 요청을 처리하는 핸들러 함수들을 정의하는 모듈입니다.
//! ActixWeb 프레임워크를 기반으로 구현되었습니다.
//!
//! # 모듈 구성
//!
//! ### 현재 구현된 핸들러
//! - **`auth`**: 인증 관련 엔드포인트 (로그인, OAuth 등)
//! - **`users`**: 사용자 관리 엔드포인트 (생성, 조회, 삭제)
//! - **`protected`**: 인증이 필요한 보호된 엔드포인트
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse};
//! use crate::services::users::UserService;
//!
//! #[actix_web::post("/users")]
//! pub async fn create_user(
//!     payload: web::Json<CreateUserRequest>,
//! ) -> Result<HttpResponse, AppError> {
//!     let service = UserService::instance();
//!     let response = service.create_user(payload.into_inner()).await?;
//!     Ok(HttpResponse::Created().json(response))
//! }
//! ```
pub mod users;
pub mod auth;
