//! Google OAuth 2.0 Domain Models
//!
//! Google OAuth 2.0 인증 플로우와 관련된 도메인 모델들을 정의하는 모듈입니다.
//! Google의 OAuth 2.0 API와 OpenID Connect 표준을 준수합니다.
//!
//! ## 주요 구성 요소
//!
//! ### 현재 구현된 모델
//! - **`google_user`**: Google 사용자 정보 모델 (`GoogleUserInfo`)
//!
//! ### OAuth 스코프
//! | 스코프 | 설명 | 접근 가능한 정보 |
//! |--------|------|------------------|
//! | `openid` | OpenID Connect | `sub` (사용자 ID) |
//! | `email` | 이메일 주소 | `email`, `email_verified` |
//! | `profile` | 기본 프로필 | `name`, `given_name`, `family_name`, `picture` |
//!
//! ## 사용 예제
//!
//! ```rust,ignore
//! use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
//! use crate::services::auth::GoogleAuthService;
//!
//! let google_service = GoogleAuthService::instance();
//! let user_info: GoogleUserInfo = google_service
//!     .fetch_user_info(access_token)
//!     .await?;
//! ```

pub mod google_user;
pub mod oauth_provider;
