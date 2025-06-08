//! 사용자 관리 서비스 모듈
//! 
//! 사용자 생명주기와 관련된 비즈니스 로직을 담당하는 서비스들을 제공합니다.
//! 사용자 등록, 인증, 프로필 관리 등의 핵심 기능을 구현합니다.
//!
//! # Features
//!
//! - 사용자 등록 및 검증
//! - 비밀번호 해싱 및 인증
//! - 프로필 관리 및 업데이트
//! - 계정 상태 관리
//!
//! # Security
//!
//! - bcrypt 비밀번호 해싱
//! - 이메일/사용자명 중복 방지
//! - 입력값 검증
//! - 타이밍 공격 방지
//!
//! # Examples
//!
//! ```rust,ignore
//! use crate::services::users::UserService;
//! use crate::domain::dto::users::request::CreateUserRequest;
//! 
//! let user_service = UserService::instance();
//! let request = CreateUserRequest { /* ... */ };
//! let response = user_service.create_user(request).await?;
//! ```

pub mod user_service;
