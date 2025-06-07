//! # 사용자 관련 응답 DTO 모듈
//!
//! 이 모듈은 사용자 도메인과 관련된 HTTP 응답 데이터 전송 객체(DTO)들을 정의합니다.
//! Spring Boot의 `@ResponseBody`와 유사한 역할을 하며, 비즈니스 로직 처리 결과를
//! 클라이언트에게 안전하고 일관된 형태로 전달하는 역할을 담당합니다.
//!
//! ## 설계 철학
//!
//! - **데이터 은닉**: 민감한 정보(비밀번호, 내부 ID 등)는 응답에서 제외
//! - **일관성**: 모든 응답이 동일한 구조와 네이밍 컨벤션 따름
//! - **확장성**: 새로운 필드 추가 시 하위 호환성 유지
//! - **타입 안전성**: 컴파일 타임에 응답 구조 검증
//!
//! ## 응답 DTO 계층 구조
//!
//! ### 기본 사용자 응답
//! - `UserResponse` - 표준 사용자 정보 응답
//! - 프로필 조회, 사용자 목록 등에서 사용
//!
//! ### 인증 관련 응답  
//! - `LoginResponse` - JWT 토큰을 포함한 로그인 응답
//! - `CreateUserResponse` - 회원가입 완료 응답
//!
//! ### OAuth 관련 응답
//! - `GoogleTokenResponse` - Google OAuth 토큰 교환 결과
//! - `OAuthLoginUrlResponse` - OAuth 인증 URL 제공
//!
//! ## 사용 패턴
//!
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use crate::domain::dto::users::response::{UserResponse, LoginResponse};
//!
//! // 일반 사용자 정보 응답
//! #[actix_web::get("/users/{id}")]
//! async fn get_user(path: web::Path<String>) -> Result<HttpResponse> {
//!     let user = user_service.find_by_id(&path).await?;
//!     let response = UserResponse::from(user);
//!     Ok(HttpResponse::Ok().json(response))
//! }
//!
//! // JWT 토큰을 포함한 로그인 응답
//! #[actix_web::post("/auth/login")]
//! async fn login(req: web::Json<LoginRequest>) -> Result<HttpResponse> {
//!     let (user, token) = auth_service.authenticate(&req).await?;
//!     let response = LoginResponse::new(user, token, 3600);
//!     Ok(HttpResponse::Ok().json(response))
//! }
//! ```
//!
//! ## JSON 응답 예제
//!
//! ### 표준 사용자 응답
//! ```json
//! {
//!   "id": "507f1f77bcf86cd799439011",
//!   "email": "user@example.com",
//!   "username": "john_doe",
//!   "display_name": "John Doe",
//!   "auth_provider": "Local",
//!   "is_oauth_user": false,
//!   "is_active": true,
//!   "is_email_verified": true,
//!   "roles": ["user"],
//!   "profile_image_url": null,
//!   "last_login_at": "2024-06-07T12:00:00Z",
//!   "created_at": "2024-06-01T10:00:00Z",
//!   "updated_at": "2024-06-07T12:00:00Z"
//! }
//! ```
//!
//! ### 로그인 응답
//! ```json
//! {
//!   "user": { /* UserResponse 객체 */ },
//!   "access_token": "eyJhbGciOiJIUzI1NiIs...",
//!   "token_type": "Bearer",
//!   "expires_in": 3600,
//!   "refresh_token": "eyJhbGciOiJIUzI1NiIs..." // 선택사항
//! }
//! ```
//!
//! ## 보안 고려사항
//!
//! - **비밀번호 제외**: 응답에 비밀번호 해시나 솔트 포함하지 않음
//! - **토큰 보안**: JWT 토큰은 HTTPS를 통해서만 전송
//! - **권한 기반 필터링**: 사용자 권한에 따른 필드 노출 제어
//! - **로그 안전**: 민감한 정보는 로그에 출력되지 않도록 `Debug` 구현 주의

pub mod user_response;
pub mod google_oauth_response;

pub use user_response::{UserResponse, CreateUserResponse, LoginResponse};
