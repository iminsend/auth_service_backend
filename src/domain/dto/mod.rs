//! User Request DTOs Module
//!
//! 사용자 관련 API 요청을 위한 데이터 전송 객체들을 정의합니다.
//! 클라이언트와 서버 간의 데이터 계약을 명확히 정의하고 유효성 검증을 제공합니다.
//!
//! ## 설계 원칙
//!
//! * **API 계약**: 클라이언트가 기대할 수 있는 명확한 데이터 구조
//! * **유효성 검증**: validator crate를 통한 런타임 검증
//! * **도메인 분리**: Entity와 DTO의 명확한 분리로 보안과 유연성 확보
//!
//! ## 사용 예제
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse};
//! use crate::domain::dto::users::CreateUserRequest;
//!
//! pub async fn create_user(
//!     request: web::Json<CreateUserRequest>
//! ) -> Result<HttpResponse, AppError> {
//!     // 유효성 검증
//!     request.validate()?;
//!     
//!     // 서비스 호출
//!     let user = user_service.create_user(request.into_inner()).await?;
//!     
//!     // 응답 생성
//!     Ok(HttpResponse::Created().json(UserResponse::from(user)))
//! }
//! ```
//!
//! ## 명명 규칙
//!
//! * **Request DTO**: `{Action}{Entity}Request` (예: `CreateUserRequest`)
//! * **필수 필드**: 기본 타입 사용
//! * **선택적 필드**: `Option<T>` 사용

pub mod users;

pub use users::*;
