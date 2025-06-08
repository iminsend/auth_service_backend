//! 핵심 프레임워크 모듈
//!
//! 싱글톤 기반 의존성 주입 시스템과 통합 에러 처리를 제공합니다.
//!
//! # 모듈 구성
//!
//! - [`registry`] - 의존성 주입 컨테이너 및 서비스 레지스트리
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use crate::core::registry::ServiceLocator;
//!
//! #[repository(collection = "users")]
//! struct UserRepository {
//!     db: Arc<Database>,
//! }
//!
//! #[service]
//! struct UserService {
//!     user_repo: Arc<UserRepository>,
//! }
//!
//! // 사용
//! let user_service = UserService::instance();
//! ```
//!
//! # 애플리케이션 초기화
//!
//! ```rust,ignore
//! #[actix_web::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 인프라 컴포넌트 등록
//!     let database = Database::connect("mongodb://localhost").await?;
//!     ServiceLocator::set(database);
//!     
//!     // 모든 서비스/리포지토리 초기화
//!     ServiceLocator::initialize_all().await?;
//!     
//!     // 웹 서버 시작
//!     HttpServer::new(|| App::new())
//!         .bind("0.0.0.0:8080")?
//!         .run()
//!         .await
//! }
//! ```

pub mod registry;

pub use crate::errors::errors::*;
pub use registry::*;
