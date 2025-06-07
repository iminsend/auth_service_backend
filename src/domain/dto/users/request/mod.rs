//! # 사용자 관련 요청 DTO 모듈
//!
//! 이 모듈은 사용자 도메인과 관련된 HTTP 요청 데이터 전송 객체(DTO)들을 정의합니다.
//! Spring Boot의 `@RequestBody`와 유사한 역할을 하며, 클라이언트로부터 받은 JSON 데이터를
//! 구조화된 Rust 타입으로 변환하고 검증하는 역할을 담당합니다.
//!
//! ## 주요 기능
//!
//! - **타입 안전성**: 컴파일 타임에 데이터 구조 검증
//! - **자동 역직렬화**: `serde`를 통한 JSON ↔ Rust 타입 변환
//! - **입력 검증**: `validator` 크레이트를 통한 비즈니스 규칙 검증
//! - **에러 메시지**: 한국어 메시지 지원으로 사용자 친화적 에러 응답
//!
//! ## 사용 패턴
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use crate::domain::dto::users::request::CreateUserRequest;
//!
//! #[actix_web::post("/users")]
//! async fn create_user(
//!     req: web::Json<CreateUserRequest>
//! ) -> Result<HttpResponse> {
//!     // 자동으로 JSON → CreateUserRequest 변환 및 검증 수행
//!     let validated_data = req.into_inner();
//!     
//!     // 비즈니스 로직 처리...
//!     Ok(HttpResponse::Created().json("사용자가 생성되었습니다"))
//! }
//! ```
//!
//! ## 검증 계층
//!
//! 이 모듈의 DTO들은 다음과 같은 다층 검증을 수행합니다:
//!
//! 1. **구문 검증**: JSON 구조와 타입 일치성
//! 2. **형식 검증**: 이메일, 길이, 패턴 등 기본 형식 규칙
//! 3. **비즈니스 검증**: 도메인 특화 규칙 (비밀번호 강도, 중복 확인 등)
//!
//! ## 에러 핸들링
//!
//! 검증 실패 시 `validator::ValidationErrors`가 발생하며,
//! 이는 상위 에러 핸들러에서 HTTP 400 Bad Request 응답으로 변환됩니다.

pub mod create_user;

pub use create_user::CreateUserRequest;
