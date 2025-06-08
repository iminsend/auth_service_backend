//! 사용자 데이터 액세스 계층을 담당하는 리포지토리 모듈
//! 
//! [`UserRepository`](user_repo::UserRepository)를 통해 MongoDB 기반 사용자 데이터 관리와 
//! Redis 캐싱을 제공합니다. `#[repository]` 매크로를 사용하여 싱글톤으로 관리됩니다.
//! 
//! # Examples
//! 
//! ```rust,ignore
//! use crate::repositories::users::user_repo::UserRepository;
//! 
//! let user_repo = UserRepository::instance();
//! let user = user_repo.find_by_email("user@example.com").await?;
//! ```

pub mod user_repo;
