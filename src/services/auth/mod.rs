//! 인증 및 보안 서비스 모듈
//! 
//! JWT 기반 토큰 인증과 OAuth 2.0 소셜 로그인을 담당하는 서비스들을 제공합니다.
//! 다양한 인증 방식을 지원하여 안전한 사용자 인증을 보장합니다.
//!
//! # Features
//!
//! - JWT 액세스/리프레시 토큰 관리
//! - Google OAuth 2.0 소셜 로그인
//! - 토큰 생성, 검증, 갱신
//! - 역할 기반 권한 관리
//!
//! # Security
//!
//! - HMAC-SHA256 토큰 서명
//! - CSRF 방지 (OAuth State 매개변수)
//! - 토큰 만료 시간 관리
//! - HTTPS 강제 (OAuth 플로우)
//!
//! # Examples
//!
//! ```rust,ignore
//! use crate::services::auth::{TokenService, GoogleAuthService};
//! 
//! // JWT 토큰 생성
//! let token_service = TokenService::instance();
//! let tokens = token_service.generate_token_pair(&user)?;
//! 
//! // Google OAuth 인증
//! let google_auth = GoogleAuthService::instance();
//! let login_url = google_auth.get_login_url()?;
//! ```

pub mod token_service;
pub mod google_auth_service;
pub mod jwt_rsa_service;
pub mod rsa_service;

pub use token_service::*;
pub use google_auth_service::*;
pub use jwt_rsa_service::*;
pub use rsa_service::*;
