//! OAuth Domain Models Module
//!
//! OAuth 2.0 인증 플로우와 관련된 도메인 모델들을 정의하는 모듈입니다.
//! 다양한 OAuth 프로바이더(Google, GitHub 등)와의 통합을 위한 타입 안전한 데이터 모델을 제공합니다.
//!
//! ## 지원하는 OAuth 프로바이더
//!
//! ### Google OAuth
//! - **스코프**: `openid`, `email`, `profile`
//! - **토큰 만료**: Access Token 1시간, Refresh Token 영구
//! - **특징**: 높은 신뢰도, 전 세계적 사용자 기반
//!
//! ## 사용 예제
//!
//! ```rust,ignore
//! use crate::domain::models::oauth::google_oauth_model::GoogleUserInfo;
//! use crate::services::auth::GoogleAuthService;
//!
//! // OAuth 인증 플로우
//! let google_service = GoogleAuthService::instance();
//! let token_response = google_service
//!     .exchange_code_for_token(authorization_code)
//!     .await?;
//!
//! let user_info = google_service
//!     .fetch_user_info(&token_response.access_token)
//!     .await?;
//! ```

pub mod google_oauth_model;
