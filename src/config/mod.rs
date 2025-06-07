//! # Configuration Module
//!
//! 백엔드 서비스의 설정 관리를 담당하는 모듈입니다.
//! Spring Framework의 `@Configuration` 클래스와 유사한 역할을 수행하며,
//! 환경 변수 기반의 설정값들을 중앙집중식으로 관리합니다.
//!
//! ## 모듈 구성
//!
//! - [`data_config`] - 데이터베이스, 서버, 환경 관련 설정
//! - [`auth_config`] - 인증, OAuth, JWT 관련 설정
//!
//! ## 설계 원칙
//!
//! ### 1. 환경 분리 (Environment Separation)
//! 
//! 개발, 테스트, 스테이징, 프로덕션 환경별로 다른 설정값을 제공합니다.
//! Spring Profile과 유사한 방식으로 동작합니다.
//!
//! ### 2. 보안 우선 (Security First)
//!
//! - 민감한 정보는 환경 변수로만 제공
//! - 기본값은 개발 환경에서만 안전
//! - 프로덕션에서는 필수 설정값 누락 시 패닉
//!
//! ### 3. 타입 안전성 (Type Safety)
//!
//! - 설정값의 타입 검증
//! - 컴파일 타임 설정 검증
//! - 런타임 설정값 파싱 오류 처리
//!
//! ## 사용 예제
//!
//! ```rust,ignore
//! use crate::config::{Environment, ServerConfig, JwtConfig};
//!
//! // 현재 환경 확인
//! let env = Environment::current();
//! println!("Current environment: {:?}", env);
//!
//! // 서버 설정
//! let host = ServerConfig::host();
//! let port = ServerConfig::port();
//! println!("Server will bind to {}:{}", host, port);
//!
//! // JWT 설정
//! let secret = JwtConfig::secret();
//! let expiration = JwtConfig::expiration_hours();
//! ```
//!
//! ## 환경 변수 설정 가이드
//!
//! ### 필수 환경 변수 (프로덕션)
//!
//! ```bash
//! # 서버 설정
//! export HOST="0.0.0.0"
//! export PORT="8080"
//!
//! # JWT 설정
//! export JWT_SECRET="your-super-secret-key"
//! export JWT_EXPIRATION_HOURS="24"
//!
//! # Google OAuth (사용 시)
//! export GOOGLE_CLIENT_ID="your-client-id"
//! export GOOGLE_CLIENT_SECRET="your-client-secret"
//! export GOOGLE_REDIRECT_URI="https://yourdomain.com/auth/google/callback"
//! ```
//!
//! ### 선택적 환경 변수
//!
//! ```bash
//! # 환경 설정
//! export ENVIRONMENT="production"  # development, test, staging, production
//!
//! # 보안 설정
//! export BCRYPT_COST="12"          # 4-15 범위
//! export OAUTH_STATE_SECRET="oauth-secret"
//! ```
//!
//! ## Spring과의 비교
//!
//! | Spring | Rust (이 프로젝트) |
//! |--------|-------------------|
//! | `@Configuration` | `pub struct Config` |
//! | `@Value("${property}")` | `env::var("PROPERTY")` |
//! | `@Profile("dev")` | `Environment::Development` |
//! | `application.yml` | `.env` 파일 |
//! | `@ConfigurationProperties` | 구조체 기반 설정 |

pub mod data_config;
pub mod auth_config;

pub use data_config::*;
pub use auth_config::*;
