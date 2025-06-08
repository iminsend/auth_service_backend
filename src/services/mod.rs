//! 비즈니스 로직을 담당하는 서비스 계층 모듈
//!
//! `#[service]` 매크로를 사용하여 싱글톤으로 관리되는 서비스들을 제공합니다.
//! 도메인별로 모듈화되어 사용자 관리와 인증/보안 기능을 담당합니다.
//!
//! # Features
//!
//! - 사용자 생명주기 관리 (생성, 조회, 수정, 삭제)
//! - JWT 토큰 기반 인증 시스템
//! - OAuth 2.0 소셜 로그인 (Google)
//! - 자동 의존성 주입 및 싱글톤 관리
//!
//! # Examples
//!
//! ```rust,ignore
//! use crate::services::{users::UserService, auth::TokenService};
//!
//! let user_service = UserService::instance();
//! let token_service = TokenService::instance();
//! ```

pub mod users;
pub mod auth;
