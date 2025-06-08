//! Domain Models Module
//!
//! 도메인의 비즈니스 모델과 값 객체(Value Objects)를 정의하는 모듈입니다.
//! Entities 와는 구별되는 역할을 담당합니다.
//!
//! ## Entities vs Models 구분
//!
//! ### Entities (`../entities/`)
//! - **영속성**: 데이터베이스에 직접 저장되는 객체
//! - **정체성**: 고유한 식별자(ID)를 가짐
//! - **예시**: `User`, `Session` 등
//!
//! ### Models (`./`)
//! - **비즈니스 로직**: 도메인의 핵심 비즈니스 규칙 포함
//! - **값 객체**: 식별자보다는 값 자체가 중요
//! - **불변성**: 일반적으로 불변 객체로 설계
//! - **예시**: `GoogleOAuthModel`, `TokenPair` 등
pub mod oauth;
pub mod token;
pub mod auth;
