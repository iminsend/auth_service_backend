//! 데이터 액세스 계층을 담당하는 리포지토리 모듈
//!
//! `#[repository]` 매크로를 사용하여 싱글톤으로 관리되는 리포지토리들을 제공합니다.
//! MongoDB를 주 저장소로 사용하고 Redis를 통한 캐싱을 지원합니다.
//!
//! # Features
//!
//! - 싱글톤 패턴을 통한 메모리 효율적인 인스턴스 관리
//! - MongoDB와 Redis를 활용한 멀티레이어 캐싱
//! - 자동 의존성 주입을 통한 간편한 설정
//!
//! # Examples
//!
//! ```rust,ignore
//! use crate::repositories::users::UserRepository;
//!
//! let user_repo = UserRepository::instance();
//! let user = user_repo.find_by_email("user@example.com").await?;
//! ```

pub mod users;
