//! 미들웨어 모듈
//!
//! ActixWeb 애플리케이션의 요청 처리 파이프라인에서 사용되는 미들웨어들을 제공합니다.
//! Spring Boot의 Filter와 Interceptor와 유사한 역할을 수행하며,
//! 횡단 관심사(Cross-cutting concerns)를 처리합니다.
//!
//! # 제공 미들웨어
//!
//! ### 1. 인증 미들웨어 (AuthMiddleware)
//! - JWT 토큰 기반 인증 검증
//! - Bearer 토큰 추출 및 검증
//! - 사용자 정보를 request extension에 저장
//! - 선택적/강제 인증 모드 지원
//!
//! # 사용 방법
//!
//! ## 글로벌 미들웨어 등록
//! ```rust,ignore
//! use actix_web::{App, HttpServer};
//! use crate::middlewares::auth_middleware::AuthMiddleware;
//!
//! HttpServer::new(|| {
//!     App::new()
//!         .wrap(AuthMiddleware::optional()) // 모든 라우트에 선택적 인증
//!         .service(/* 라우트들 */)
//! })
//! ```
//!
//! ## 특정 스코프에만 적용
//! ```rust,ignore
//! use actix_web::{web, App};
//!
//! App::new()
//!     .service(
//!         web::scope("/api/protected")
//!             .wrap(AuthMiddleware::required()) // 보호된 라우트에만 강제 인증
//!             .route("/users", web::get().to(get_users))
//!             .route("/admin", web::get().to(admin_only))
//!     )
//!     .service(
//!         web::scope("/api/public")
//!             .route("/status", web::get().to(health_check))
//!     )
//! ```

pub mod auth_middleware;
mod auth_inner;

// 미들웨어 재export
pub use auth_middleware::{AuthMiddleware};
