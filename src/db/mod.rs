//! # Database Connection Management Module
//!
//! MongoDB 데이터베이스 연결 관리를 담당하는 모듈입니다.
//! Spring Data MongoDB의 `MongoTemplate`과 유사한 역할을 수행하며,
//! 연결 풀링, 자동 재연결, 설정 관리 등의 기능을 제공합니다.
//!
//! ## Spring Data MongoDB 와의 비교
//!
//! | Spring Data MongoDB | 이 모듈 | 비고 |
//! |---------------------|---------|------|
//! | `MongoTemplate` | `Database` | 핵심 데이터베이스 인터페이스 |
//! | `@EnableMongoRepositories` | `#[repository]` 매크로 | 리포지토리 자동 등록 |
//! | `application.yml` 설정 | 환경 변수 | 설정 관리 방식 |
//! | Connection Pool | MongoDB Driver 내장 | 자동 연결 풀 관리 |
//! | Health Check | `ping` 명령어 | 연결 상태 확인 |
//!
//! ## 설계 철학
//!
//! ### 1. 단순성 우선 (Simplicity First)
//! - 복잡한 ORM 없이 MongoDB 네이티브 기능 직접 활용
//! - 명시적 쿼리 작성을 통한 성능 최적화
//! - 타입 안전성을 유지하면서도 유연한 스키마 지원
//!
//! ### 2. 성능 최적화 (Performance Optimized)
//! - 내장 연결 풀을 통한 효율적인 연결 관리
//! - 지연 평가와 스트리밍을 통한 메모리 사용량 최적화
//! - 인덱스 힌트와 집계 파이프라인 최적화 지원
//!
//! ### 3. 환경별 설정 (Environment Configuration)
//! - 개발/테스트/프로덕션 환경별 다른 설정 지원
//! - 환경 변수 기반 설정으로 보안성 향상
//! - Docker 및 Kubernetes 환경 친화적
//!
//! ## 환경 변수 설정 가이드
//!
//! ### 필수 환경 변수
//!
//! ```bash
//! # MongoDB 연결 URI
//! export MONGODB_URI="mongodb://username:password@host:port/database"
//!
//! # 사용할 데이터베이스 이름
//! export DATABASE_NAME="your_database_name"
//! ```
//!
//! ### 환경별 설정 예제
//!
//! #### 개발 환경 (.env.dev)
//! ```bash
//! MONGODB_URI=mongodb://localhost:27017
//! DATABASE_NAME=auth_service_dev
//! ```
//!
//! #### 테스트 환경 (.env.test)
//! ```bash
//! MONGODB_URI=mongodb://localhost:27017
//! DATABASE_NAME=auth_service_test
//! ```
//!
//! #### 프로덕션 환경 (.env.prod)
//! ```bash
//! MONGODB_URI=mongodb://user:pass@cluster.mongodb.net:27017/db?retryWrites=true&w=majority
//! DATABASE_NAME=auth_service_prod
//! ```
//!
//! #### MongoDB Atlas 클러스터
//! ```bash
//! MONGODB_URI=mongodb+srv://username:password@cluster0.abcde.mongodb.net/?retryWrites=true&w=majority
//! DATABASE_NAME=production_db
//! ```
//!
//! ## 사용 패턴
//!
//! ### 1. 기본 설정 (main.rs)
//!
//! ```rust,ignore
//! use crate::db::Database;
//! use crate::core::registry::ServiceLocator;
//!
//! #[actix_web::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. 데이터베이스 연결 생성
//!     let database = Database::new().await?;
//!     
//!     // 2. DI 컨테이너에 등록 (Spring의 @Bean과 동일)
//!     ServiceLocator::set(database);
//!     
//!     // 3. 모든 리포지토리 초기화
//!     ServiceLocator::initialize_all().await?;
//!     
//!     // 4. 웹 서버 시작
//!     HttpServer::new(|| {
//!         App::new()
//!             .route("/users", web::get().to(get_users))
//!     })
//!     .bind("0.0.0.0:8080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ### 2. 리포지토리에서 사용
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use mongodb::{Collection, bson::doc};
//! use crate::db::Database;
//!
//! #[repository(collection = "users")]
//! pub struct UserRepository {
//!     db: Arc<Database>,  // 자동 주입됨
//! }
//!
//! impl UserRepository {
//!     /// 사용자 컬렉션 접근
//!     pub fn collection(&self) -> Collection<User> {
//!         // Database의 get_database() 메서드 활용
//!         self.db.get_database().collection("users")
//!     }
//!     
//!     /// 사용자 생성
//!     pub async fn create(&self, user: User) -> Result<User, AppError> {
//!         let result = self.collection()
//!             .insert_one(&user, None)
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         Ok(user)
//!     }
//!     
//!     /// 이메일로 사용자 검색
//!     pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
//!         let user = self.collection()
//!             .find_one(doc! { "email": email }, None)
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         Ok(user)
//!     }
//! }
//! ```
//!
//! ### 3. 고급 쿼리 패턴
//!
//! ```rust,ignore
//! use mongodb::options::{FindOptions, IndexOptions};
//! use mongodb::bson::{doc, Bson};
//! use futures::stream::TryStreamExt;
//!
//! impl UserRepository {
//!     /// 페이지네이션이 있는 사용자 목록 조회
//!     pub async fn find_with_pagination(
//!         &self,
//!         page: u64,
//!         limit: u64,
//!     ) -> Result<Vec<User>, AppError> {
//!         let skip = page * limit;
//!         let options = FindOptions::builder()
//!             .skip(skip)
//!             .limit(limit as i64)
//!             .sort(doc! { "created_at": -1 })
//!             .build();
//!         
//!         let cursor = self.collection()
//!             .find(doc! {}, options)
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         let users: Vec<User> = cursor
//!             .try_collect()
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         Ok(users)
//!     }
//!     
//!     /// 집계 파이프라인 사용 예제
//!     pub async fn get_user_statistics(&self) -> Result<UserStats, AppError> {
//!         let pipeline = vec![
//!             doc! { "$group": {
//!                 "_id": null,
//!                 "total_users": { "$sum": 1 },
//!                 "active_users": {
//!                     "$sum": {
//!                         "$cond": [{ "$eq": ["$status", "active"] }, 1, 0]
//!                     }
//!                 }
//!             }}
//!         ];
//!         
//!         let mut cursor = self.collection()
//!             .aggregate(pipeline, None)
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         let result = cursor.try_next()
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?
//!             .ok_or_else(|| AppError::DatabaseError("No results found".to_string()))?;
//!         
//!         let stats: UserStats = mongodb::bson::from_document(result)
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         Ok(stats)
//!     }
//! }
//! ```
//!
//! ## 성능 최적화 가이드
//!
//! ### 1. 인덱스 관리
//!
//! ```rust,ignore
//! use mongodb::options::IndexOptions;
//! use mongodb::IndexModel;
//!
//! impl UserRepository {
//!     /// 필수 인덱스 생성 (초기화 시 호출)
//!     pub async fn create_indexes(&self) -> Result<(), AppError> {
//!         let email_index = IndexModel::builder()
//!             .keys(doc! { "email": 1 })
//!             .options(IndexOptions::builder()
//!                 .unique(true)
//!                 .name("email_unique".to_string())
//!                 .build())
//!             .build();
//!         
//!         let created_at_index = IndexModel::builder()
//!             .keys(doc! { "created_at": -1 })
//!             .options(IndexOptions::builder()
//!                 .name("created_at_desc".to_string())
//!                 .build())
//!             .build();
//!         
//!         self.collection()
//!             .create_indexes(vec![email_index, created_at_index], None)
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ### 2. 연결 풀 튜닝
//!
//! ```bash
//! # 연결 풀 최적화 (URI 파라미터)
//! MONGODB_URI="mongodb://host:port/db?maxPoolSize=50&minPoolSize=5&maxIdleTimeMS=30000"
//! ```
//!
//! ### 3. 배치 작업 최적화
//!
//! ```rust,ignore
//! impl UserRepository {
//!     /// 대량 삽입 최적화
//!     pub async fn bulk_insert(&self, users: Vec<User>) -> Result<(), AppError> {
//!         // 배치 크기로 나누어 처리 (메모리 최적화)
//!         const BATCH_SIZE: usize = 1000;
//!         
//!         for chunk in users.chunks(BATCH_SIZE) {
//!             self.collection()
//!                 .insert_many(chunk, None)
//!                 .await
//!                 .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         }
//!         
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ## 트러블슈팅
//!
//! ### 일반적인 문제들
//!
//! #### 1. 연결 실패
//! ```text
//! Error: Failed to connect to MongoDB
//! 해결: MONGODB_URI 환경 변수 확인, 네트워크 연결 상태 점검
//! ```
//!
//! #### 2. 인증 실패  
//! ```text
//! Error: Authentication failed
//! 해결: 사용자명/비밀번호 확인, 데이터베이스 권한 점검
//! ```
//!
//! #### 3. 인덱스 관련 오류
//! ```text
//! Error: Duplicate key error
//! 해결: 유니크 인덱스 제약 조건 확인, 기존 데이터 정리
//! ```
//!
//! #### 4. 타임아웃 오류
//! ```text
//! Error: Operation timed out
//! 해결: 쿼리 최적화, 인덱스 추가, 네트워크 설정 확인
//! ```
//!
//! ## Spring Data MongoDB 마이그레이션 가이드
//!
//! ### Spring 에서 이 시스템으로 변환
//!
//! | Spring Data MongoDB | 이 시스템 | 변환 예제 |
//! |---------------------|-----------|-----------|
//! | `@Document` | `serde::Serialize + Deserialize` | 구조체에 serde 적용 |
//! | `MongoRepository<T, ID>` | `#[repository]` 매크로 | 커스텀 리포지토리 구현 |
//! | `@Query` | MongoDB 네이티브 쿼리 | `doc!` 매크로 사용 |
//! | `@DBRef` | 수동 참조 관리 | ObjectId 필드로 관계 표현 |
//! | `MongoTemplate.save()` | `collection().insert_one()` | 명시적 CRUD 연산 |

use mongodb::{Client, options::ClientOptions};
use std::env;

/// MongoDB 데이터베이스 연결 래퍼
///
/// Spring Data MongoDB의 `MongoTemplate` 역할을 하는 구조체입니다.
/// MongoDB 클라이언트와 데이터베이스 연결을 관리하며, 
/// 리포지토리 계층에서 데이터베이스 작업을 위한 기본 인터페이스를 제공합니다.
///
/// ## 주요 기능
///
/// - **자동 연결 관리**: 연결 풀링과 자동 재연결 지원
/// - **환경별 설정**: 환경 변수 기반 설정 관리
/// - **연결 상태 검증**: ping을 통한 연결 상태 확인
/// - **타입 안전성**: 제네릭을 활용한 컴파일 타임 타입 검증
/// - **DI 통합**: ServiceLocator와 완전 통합
///
/// ## Spring Data MongoDB 와의 비교
///
/// ```java
/// // Spring Data MongoDB
/// @Configuration
/// public class MongoConfig {
///     @Bean
///     public MongoTemplate mongoTemplate() {
///         return new MongoTemplate(mongoClient(), "database_name");
///     }
/// }
///
/// @Repository
/// public class UserRepository {
///     @Autowired
///     private MongoTemplate mongoTemplate;
///     
///     public User save(User user) {
///         return mongoTemplate.save(user);
///     }
/// }
/// ```
///
/// ```rust,ignore
/// // 이 시스템
/// // main.rs 모듈에서 설정
/// let database = Database::new().await?;
/// ServiceLocator::set(database);
///
/// // 리포지토리에서 사용
/// #[repository(collection = "users")]
/// struct UserRepository {
///     db: Arc<Database>,  // 자동 주입
/// }
///
/// impl UserRepository {
///     async fn save(&self, user: User) -> Result<User, AppError> {
///         self.collection().insert_one(user, None).await?;
///         Ok(user)
///     }
/// }
/// ```
///
/// ## 사용 예제
///
/// ```rust,ignore
/// use crate::db::Database;
///
/// // 1. 데이터베이스 연결 생성
/// let db = Database::new().await?;
///
/// // 2. 특정 컬렉션 접근
/// let users_collection = db.get_database().collection::<User>("users");
///
/// // 3. CRUD 작업
/// let user = User { name: "John".to_string(), email: "john@example.com".to_string() };
/// users_collection.insert_one(&user, None).await?;
/// ```
#[derive(Clone)]
pub struct Database {
    /// MongoDB 클라이언트 인스턴스
    /// 
    /// 내부적으로 연결 풀을 관리하며, 여러 스레드에서 안전하게 공유할 수 있습니다.
    /// Spring의 MongoClient와 동일한 역할을 수행합니다.
    client: Client,
    
    /// 사용할 데이터베이스 이름
    /// 
    /// 환경 변수 `DATABASE_NAME`에서 로드되며, 기본값은 "insend_auth_dev"입니다.
    /// 환경별로 다른 데이터베이스를 사용할 수 있도록 지원합니다.
    database_name: String,
}

impl Database {
    /// 새 MongoDB 데이터베이스 연결을 생성합니다.
    ///
    /// 환경 변수에서 연결 정보를 읽어와 MongoDB 클라이언트를 초기화하고,
    /// 연결 상태를 검증한 후 Database 인스턴스를 반환합니다.
    ///
    /// ## 환경 변수
    ///
    /// - `MONGODB_URI`: MongoDB 연결 URI (기본값: "mongodb://localhost:27017")
    /// - `DATABASE_NAME`: 데이터베이스 이름 (기본값: "insend_auth_dev")
    ///
    /// ## Spring 과의 비교
    ///
    /// ### Spring Boot 설정
    /// ```yaml
    /// # application.yml
    /// spring:
    ///   data:
    ///     mongodb:
    ///       uri: mongodb://localhost:27017
    ///       database: auth_service_dev
    ///       auto-index-creation: true
    /// ```
    ///
    /// ### 이 시스템 설정
    /// ```bash
    /// # .env
    /// MONGODB_URI=mongodb://localhost:27017
    /// DATABASE_NAME=auth_service_dev
    /// ```
    ///
    /// ## 연결 URI 형식
    ///
    /// ### 로컬 개발
    /// ```bash,ignore
    /// mongodb://localhost:27017
    /// ```
    ///
    /// ### 인증이 필요한 경우
    /// ```bash,ignore
    /// mongodb://username:password@host:port/database
    /// ```
    ///
    /// ### MongoDB Atlas (클라우드)
    /// ```bash,ignore
    /// mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
    /// ```
    ///
    /// ### 레플리카 셋
    /// ```bash,ignore
    /// mongodb://host1:port1,host2:port2,host3:port3/database?replicaSet=myReplicaSet
    /// ```
    ///
    /// ## 연결 옵션 최적화
    ///
    /// 프로덕션 환경에서는 다음과 같은 연결 옵션을 추가할 수 있습니다:
    ///
    /// ```bash,ignore
    /// mongodb://host:port/db?maxPoolSize=50&minPoolSize=5&maxIdleTimeMS=30000&connectTimeoutMS=10000
    /// ```
    ///
    /// - `maxPoolSize`: 최대 연결 수 (기본값: 100)
    /// - `minPoolSize`: 최소 연결 수 (기본값: 0)
    /// - `maxIdleTimeMS`: 유휴 연결 유지 시간 (기본값: 0 = 무제한)
    /// - `connectTimeoutMS`: 연결 타임아웃 (기본값: 10000ms)
    /// - `serverSelectionTimeoutMS`: 서버 선택 타임아웃 (기본값: 30000ms)
    ///
    /// # 반환값
    ///
    /// - `Ok(Database)`: 연결 성공 시 Database 인스턴스
    /// - `Err(Box<dyn std::error::Error>)`: 연결 실패 시 에러
    ///
    /// # 에러 시나리오
    ///
    /// ## 1. 연결 실패
    /// ```text
    /// Error: Failed to connect to MongoDB at mongodb://localhost:27017
    /// 원인: MongoDB 서버가 실행되지 않음
    /// 해결: MongoDB 서버 시작 또는 URI 확인
    /// ```
    ///
    /// ## 2. 인증 실패
    /// ```text
    /// Error: Authentication failed
    /// 원인: 잘못된 사용자명/비밀번호
    /// 해결: 인증 정보 확인
    /// ```
    ///
    /// ## 3. 네트워크 문제
    /// ```text
    /// Error: Connection timeout
    /// 원인: 네트워크 연결 불가 또는 방화벽
    /// 해결: 네트워크 설정 확인
    /// ```
    ///
    /// ## 4. 데이터베이스 권한 문제
    /// ```text
    /// Error: Not authorized on database
    /// 원인: 데이터베이스 접근 권한 없음
    /// 해결: 사용자 권한 확인 및 설정
    /// ```
    ///
    /// # 사용 예제
    ///
    /// ```rust,ignore
    /// use crate::db::Database;
    /// use crate::core::registry::ServiceLocator;
    ///
    /// #[actix_web::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     // 환경 변수 설정 (또는 .env 파일)
    ///     std::env::set_var("MONGODB_URI", "mongodb://localhost:27017");
    ///     std::env::set_var("DATABASE_NAME", "my_app_dev");
    ///     
    ///     // 데이터베이스 연결 생성
    ///     let database = Database::new().await?;
    ///     
    ///     // DI 컨테이너에 등록 (Spring의 @Bean과 동일)
    ///     ServiceLocator::set(database);
    ///     
    ///     // 애플리케이션 시작...
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # 연결 상태 모니터링
    ///
    /// 연결 성공 시 다음과 같은 로그가 출력됩니다:
    /// ```text
    /// ✅ MongoDB 연결 성공: your_database_name
    /// ```
    ///
    /// 이는 `ping` 명령어를 통해 실제 연결 상태를 검증한 결과입니다.
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

        // 연결 테스트 (Spring Boot의 health check와 동일)
        // ping 명령어로 실제 연결 상태 검증
        client
            .database(&database_name)
            .run_command(mongodb::bson::doc! { "ping": 1 })
            .await?;

        // 연결 성공 로그 출력
        println!("✅ MongoDB 연결 성공: {}", database_name);

        Ok(Self {
            client,
            database_name,
        })
    }

    /// MongoDB 데이터베이스 인스턴스를 반환합니다.
    ///
    /// 이 메서드는 실제 MongoDB 작업을 위한 `mongodb::Database` 인스턴스를 반환합니다.
    /// 리포지토리에서 컬렉션에 접근할 때 사용되며, Spring Data MongoDB의
    /// `MongoTemplate`과 유사한 역할을 수행합니다.
    ///
    /// ## Spring 과의 비교
    ///
    /// ### Spring Data MongoDB
    /// ```java
    /// @Autowired
    /// private MongoTemplate mongoTemplate;
    ///
    /// public void someMethod() {
    ///     MongoCollection<Document> collection = 
    ///         mongoTemplate.getCollection("users");
    /// }
    /// ```
    ///
    /// ### 이 시스템
    /// ```rust,ignore
    /// #[repository]
    /// struct UserRepository {
    ///     db: Arc<Database>,
    /// }
    ///
    /// impl UserRepository {
    ///     fn collection(&self) -> Collection<User> {
    ///         self.db.get_database().collection("users")
    ///     }
    /// }
    /// ```
    ///
    /// ## 사용 패턴
    ///
    /// ### 1. 직접 컬렉션 접근
    /// ```rust,ignore
    /// let users_collection = database.get_database().collection::<User>("users");
    /// let posts_collection = database.get_database().collection::<Post>("posts");
    /// ```
    ///
    /// ### 2. 리포지토리 매크로와 함께 사용
    /// ```rust,ignore
    /// #[repository(collection = "users")]
    /// struct UserRepository {
    ///     db: Arc<Database>,
    /// }
    ///
    /// impl UserRepository {
    ///     pub fn collection(&self) -> Collection<User> {
    ///         // 매크로가 자동 생성하는 메서드
    ///         self.db.get_database().collection(self.collection_name())
    ///     }
    /// }
    /// ```
    ///
    /// ### 3. 트랜잭션 지원
    /// ```rust,ignore
    /// use mongodb::options::TransactionOptions;
    ///
    /// async fn transfer_money(&self, from: &str, to: &str, amount: f64) -> Result<(), AppError> {
    ///     let mut session = self.db.client.start_session(None).await?;
    ///     
    ///     session.start_transaction(TransactionOptions::default()).await?;
    ///     
    ///     // 계좌 간 이체 로직...
    ///     
    ///     session.commit_transaction().await?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// ### 4. 관리 작업
    /// ```rust,ignore
    /// use mongodb::bson::doc;
    ///
    /// impl Database {
    ///     /// 데이터베이스 통계 조회
    ///     pub async fn get_stats(&self) -> Result<Document, AppError> {
    ///         let stats = self.get_database()
    ///             .run_command(doc! { "dbStats": 1 })
    ///             .await
    ///             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    ///         
    ///         Ok(stats)
    ///     }
    ///     
    ///     /// 컬렉션 목록 조회
    ///     pub async fn list_collections(&self) -> Result<Vec<String>, AppError> {
    ///         let collections = self.get_database()
    ///             .list_collection_names(None)
    ///             .await
    ///             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
    ///         
    ///         Ok(collections)
    ///     }
    /// }
    /// ```
    ///
    /// # 반환값
    ///
    /// `mongodb::Database` 인스턴스를 반환합니다. 이 인스턴스를 통해:
    /// - 컬렉션 접근: `database.collection::<T>("collection_name")`
    /// - 관리 명령 실행: `database.run_command(command)`
    /// - 트랜잭션 관리: `database.client.start_session()`
    /// - 인덱스 관리: `collection.create_index()`
    ///
    /// # 스레드 안전성
    ///
    /// MongoDB 클라이언트는 내부적으로 스레드 안전하며, 여러 스레드에서
    /// 동시에 사용할 수 있습니다. Arc<Database>로 감싸서 여러 리포지토리에서
    /// 안전하게 공유할 수 있습니다.
    ///
    /// # 성능 고려사항
    ///
    /// - **연결 풀링**: MongoDB 드라이버가 자동으로 연결 풀을 관리
    /// - **지연 연결**: 실제 작업 시점에 연결이 생성됨
    /// - **연결 재사용**: 동일한 Database 인스턴스는 연결을 재사용
    /// - **자동 복구**: 네트워크 장애 시 자동으로 재연결 시도
    pub fn get_database(&self) -> mongodb::Database {
        self.client.database(&self.database_name)
    }

    /// MongoDB 클라이언트 인스턴스를 반환합니다.
    ///
    /// 고급 사용 사례나 클라이언트 레벨의 작업이 필요한 경우
    /// (예: 세션 관리, 트랜잭션, 클러스터 모니터링 등)에 사용됩니다.
    ///
    /// # 사용 예제
    ///
    /// ```rust,ignore
    /// // 세션 생성 (트랜잭션용)
    /// let mut session = database.client().start_session(None).await?;
    ///
    /// // 클러스터 정보 조회
    /// let topology = database.client().topology().await;
    /// ```
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// 데이터베이스 이름을 반환합니다.
    ///
    /// 현재 연결된 데이터베이스의 이름을 문자열로 반환합니다.
    /// 로깅이나 디버깅 목적으로 사용할 수 있습니다.
    ///
    /// # 반환값
    ///
    /// 데이터베이스 이름 문자열
    ///
    /// # 사용 예제
    ///
    /// ```rust,ignore
    /// println!("Current database: {}", database.database_name());
    /// ```
    pub fn database_name(&self) -> &str {
        &self.database_name
    }
}
