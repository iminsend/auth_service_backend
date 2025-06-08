//! # 사용자 관련 응답 DTO 모듈
//!
//! 사용자 도메인과 관련된 HTTP 응답 데이터 전송 객체(DTO)들을 정의합니다.
//! 비즈니스 로직 처리 결과를 클라이언트에게 안전하고 일관된 형태로 전달합니다.
//!
//! # 응답 DTO 종류
//!
//! ## 기본 사용자 응답
//! - `UserResponse` - 표준 사용자 정보 응답 (민감한 정보 제외)
//! - `CreateUserResponse` - 회원가입 완료 응답
//!
//! ## 인증 관련 응답
//! - `LoginResponse` - JWT 토큰을 포함한 로그인 응답
//!
//! ## OAuth 관련 응답
//! - `GoogleTokenResponse` - Google OAuth 토큰 교환 결과
//! - `OAuthLoginUrlResponse` - OAuth 인증 URL 제공

pub mod user_response;
pub mod google_oauth_response;

pub use user_response::{UserResponse, CreateUserResponse, LoginResponse};
pub use google_oauth_response::{GoogleTokenResponse, OAuthLoginUrlResponse};
