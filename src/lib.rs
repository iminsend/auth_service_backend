//! 인센드 인증 서비스 백엔드
//!
//! Rust 기반의 현대적인 인증 및 사용자 관리 서비스입니다.
//! JWT 토큰 기반 인증, Google OAuth 2.0 소셜 로그인, 
//! 그리고 싱글톤 매크로를 활용한 의존성 주입을 제공합니다.
//!
//! # Features
//!
//! - **사용자 관리**: 로컬 계정 생성, 프로필 관리, 계정 삭제
//! - **JWT 인증**: 액세스/리프레시 토큰 기반 상태 없는 인증
//! - **OAuth 2.0**: Google 소셜 로그인 지원
//! - **싱글톤 DI**: 매크로 기반 자동 의존성 주입
//! - **MongoDB**: 사용자 데이터 영구 저장
//! - **Redis**: 캐싱 및 세션 관리
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐
//! │   HTTP Routes   │ ← REST API 엔드포인트
//! └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │    Handlers     │ ← 요청/응답 처리
//! └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │    Services     │ ← 비즈니스 로직
//! └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Repositories   │ ← 데이터 액세스
//! └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │ MongoDB + Redis │ ← 저장소
//! └─────────────────┘
//! ```
//!
//! # Examples
//!
//! ```rust,ignore
//! use auth_service_backend::services::users::UserService;
//! use auth_service_backend::services::auth::TokenService;
//!
//! // 싱글톤 서비스 인스턴스 가져오기
//! let user_service = UserService::instance();
//! let token_service = TokenService::instance();
//!
//! // 사용자 생성 및 토큰 발급
//! let user = user_service.create_user(request).await?;
//! let tokens = token_service.generate_token_pair(&user)?;
//! ```

pub mod core;
pub mod config;
pub mod db;
pub mod caching;
pub mod domain;
pub mod repositories;
pub mod services;
pub mod utils;
pub mod routes;
pub mod handlers;
pub mod errors;
pub mod middlewares;
