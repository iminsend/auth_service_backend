//! 설정 관리 모듈
//!
//! 환경 변수 기반의 설정값들을 중앙집중식으로 관리합니다.
//!
//! # 모듈 구성
//!
//! - [`data_config`] - 데이터베이스, 서버, 환경 관련 설정
//! - [`auth_config`] - 인증, OAuth, JWT 관련 설정
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! use crate::config::{Environment, ServerConfig, JwtConfig};
//!
//! let env = Environment::current();
//! let host = ServerConfig::host();
//! let port = ServerConfig::port();
//! let secret = JwtConfig::secret();
//! ```

pub mod data_config;
pub mod auth_config;

pub use data_config::*;
pub use auth_config::*;
