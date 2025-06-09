//! JWT 토큰 관리 리포지토리 모듈
//!
//! 이 모듈은 JWT 토큰의 저장, 검증, 무효화를 담당합니다.
//! Redis를 사용하여 다음과 같은 기능을 제공합니다:
//!
//! # Features
//!
//! - **Refresh Token 관리**: 사용자별 refresh token 저장 및 검증
//! - **Access Token Blacklist**: 로그아웃된 토큰의 무효화 관리
//! - **TTL 자동 관리**: Redis TTL을 통한 자동 만료 처리
//! - **패턴 기반 정리**: 사용자별 토큰 일괄 삭제 지원
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::repositories::tokens::token_repository::TokenRepository;
//!
//! let token_repo = TokenRepository::instance();
//!
//! // Refresh token 저장
//! token_repo.store_refresh_token("user123", "refresh_token", 86400).await?;
//!
//! // Token blacklist에 추가
//! token_repo.blacklist_token("jwt_id", 3600).await?;
//! ```

pub mod token_repository;

pub use token_repository::*;
