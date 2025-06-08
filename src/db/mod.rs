//! Database Connection Management Module
//!
//! MongoDB 데이터베이스 연결 관리를 담당하는 모듈입니다.
//! 연결 풀링, 자동 재연결, 설정 관리 등의 기능을 제공합니다.
//!
//! # 환경 변수 설정
//!
//! ```bash
//! # MongoDB 연결 URI
//! export MONGODB_URI="mongodb://username:password@host:port/database"
//!
//! # 사용할 데이터베이스 이름
//! export DATABASE_NAME="your_database_name"
//! ```
//!
//! # 기본 사용법
//!
//! ```rust,ignore
//! use crate::db::Database;
//! use crate::core::registry::ServiceLocator;
//!
//! #[actix_web::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let database = Database::new().await?;
//!     ServiceLocator::set(database);
//!     ServiceLocator::initialize_all().await?;
//!     Ok(())
//! }
//! ```

use mongodb::{Client, options::ClientOptions};
use std::env;
use log::info;

/// MongoDB 데이터베이스 연결 래퍼
///
/// MongoDB 클라이언트와 데이터베이스 연결을 관리하며, 
/// 리포지토리 계층에서 데이터베이스 작업을 위한 기본 인터페이스를 제공합니다.
#[derive(Clone)]
pub struct Database {
    /// MongoDB 클라이언트 인스턴스
    client: Client,
    /// 사용할 데이터베이스 이름
    database_name: String,
}

impl Database {
    /// 새 MongoDB 데이터베이스 연결을 생성합니다.
    ///
    /// 환경 변수에서 연결 정보를 읽어와 MongoDB 클라이언트를 초기화하고,
    /// 연결 상태를 검증한 후 Database 인스턴스를 반환합니다.
    ///
    /// ## 환경 변수
    /// - `MONGODB_URI`: MongoDB 연결 URI (기본값: "mongodb://localhost:27017")
    /// - `DATABASE_NAME`: 데이터베이스 이름 (기본값: "insend_auth_dev")
    ///
    /// ## 사용 예제
    /// ```rust,ignore
    /// use crate::db::Database;
    ///
    /// let database = Database::new().await?;
    /// ```
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // 환경 변수에서 MongoDB URI 읽기
        let mongodb_uri = env::var("MONGODB_URI")
            .unwrap_or_else(|_| "mongodb://localhost:27017".to_string());
        
        // 환경 변수에서 데이터베이스 이름 읽기
        let database_name = env::var("DATABASE_NAME")
            .unwrap_or_else(|_| "insend_auth_dev".to_string());

        // MongoDB 클라이언트 옵션 파싱
        let mut client_options = ClientOptions::parse(&mongodb_uri).await?;
        
        // 애플리케이션 이름 설정 (모니터링 및 로깅에 유용)
        client_options.app_name = Some("insend_auth".to_string());

        // MongoDB 클라이언트 생성
        let client = Client::with_options(client_options)?;

        // 연결 테스트
        client
            .database(&database_name)
            .run_command(mongodb::bson::doc! { "ping": 1 })
            .await?;

        // 연결 성공 로그 출력
        info!("✅ MongoDB 연결 성공: {}", database_name);

        Ok(Self {
            client,
            database_name,
        })
    }

    /// MongoDB 데이터베이스 인스턴스를 반환합니다.
    ///
    /// 실제 MongoDB 작업을 위한 `mongodb::Database` 인스턴스를 반환합니다.
    /// 리포지토리에서 컬렉션에 접근할 때 사용됩니다.
    ///
    /// ## 사용 예제
    /// ```rust,ignore
    /// let users_collection = database.get_database().collection::<User>("users");
    /// ```
    pub fn get_database(&self) -> mongodb::Database {
        self.client.database(&self.database_name)
    }

    /// MongoDB 클라이언트 인스턴스를 반환합니다.
    ///
    /// 고급 사용 사례나 클라이언트 레벨의 작업이 필요한 경우
    /// (예: 세션 관리, 트랜잭션 등)에 사용됩니다.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// 데이터베이스 이름을 반환합니다.
    pub fn database_name(&self) -> &str {
        &self.database_name
    }
}
