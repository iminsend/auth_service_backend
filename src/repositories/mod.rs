//! # Repository Layer Module
//!
//! 데이터 접근 계층(Data Access Layer)을 담당하는 리포지토리 모듈입니다.
//! Spring Data JPA의 Repository 패턴을 Rust와 MongoDB 환경에 맞게 구현하였으며,
//! 싱글톤 매크로와 Redis 캐싱을 활용한 고성능 데이터 접근을 제공합니다.
//!
//! ## 아키텍처 위치
//!
//! ```text
//! Clean Architecture Layer Structure
//! ┌─────────────────────────────────────────────┐
//!   Web Layer (Handlers)                          ← HTTP 요청 처리
//! ├─────────────────────────────────────────────┤
//!   Service Layer (Business Logic)                ← 비즈니스 로직
//! ├─────────────────────────────────────────────┤
//!   Repository Layer (이 모듈)                     ← 데이터 접근 추상화
//! ├─────────────────────────────────────────────┤
//!   Infrastructure Layer                          ← 외부 시스템 연동
//!   ├── MongoDB Database                         
//!   ├── Redis Cache                              
//!   └── External APIs                            
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Spring Data JPA와의 비교
//!
//! ### Spring Data JPA Repository
//! ```java
//! @Repository
//! public interface UserRepository extends JpaRepository<User, Long> {
//!     
//!     @Cacheable(value = "users", key = "#email")
//!     Optional<User> findByEmail(String email);
//!     
//!     @Query("SELECT u FROM User u WHERE u.username = :username")
//!     Optional<User> findByUsername(@Param("username") String username);
//!     
//!     @Modifying
//!     @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.id = :id")
//!     int updateLastLoginTime(@Param("id") Long id, @Param("loginTime") LocalDateTime loginTime);
//! }
//!
//! @Service
//! public class UserService {
//!     @Autowired
//!     private UserRepository userRepository; // 의존성 주입
//! }
//! ```
//!
//! ### 이 모듈의 Rust 구현
//! ```rust,ignore
//! use singleton_macro::repository;
//! use crate::domain::entities::users::User;
//!
//! #[repository(name = "user", collection = "users")]
//! pub struct UserRepository {
//!     db: Arc<Database>,        // MongoDB 연결
//!     redis: Arc<RedisClient>,  // Redis 캐시
//! }
//!
//! impl UserRepository {
//!     /// 이메일로 사용자 검색 (자동 캐싱)
//!     pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
//!         // 1. Redis 캐시 확인
//!         let cache_key = format!("user:email:{}", email);
//!         if let Ok(Some(cached)) = self.redis.get::<User>(&cache_key).await {
//!             return Ok(Some(cached));
//!         }
//!         
//!         // 2. MongoDB 조회
//!         let user = self.collection::<User>()
//!             .find_one(doc! { "email": email })
//!             .await?;
//!         
//!         // 3. 캐시에 저장
//!         if let Some(ref user) = user {
//!             self.redis.set_with_expiry(&cache_key, user, 600).await?;
//!         }
//!         
//!         Ok(user)
//!     }
//! }
//!
//! // 서비스에서 싱글톤 사용
//! impl UserService {
//!     pub async fn get_user_by_email(&self, email: &str) -> Result<User, ServiceError> {
//!         let user_repo = UserRepository::instance(); // 싱글톤 접근
//!         user_repo.find_by_email(email).await?
//!             .ok_or(ServiceError::UserNotFound)
//!     }
//! }
//! ```
//!
//! ## 핵심 특징
//!
//! ### 1. 싱글톤 패턴 적용
//! ```rust,ignore
//! // 매크로를 통한 자동 싱글톤 구현
//! #[repository(name = "user", collection = "users")]
//! pub struct UserRepository {
//!     db: Arc<Database>,
//!     redis: Arc<RedisClient>,
//! }
//!
//! // 생성되는 메서드들:
//! impl UserRepository {
//!     pub fn instance() -> Arc<Self> { /* 자동 생성 */ }
//!     fn new() -> Self { /* 의존성 자동 주입 */ }
//!     pub fn collection<T>() -> Collection<T> { /* MongoDB 컬렉션 접근 */ }
//!     pub fn cache_key(&self, id: &str) -> String { /* Redis 키 생성 */ }
//!     pub async fn invalidate_cache(&self, id: &str) -> Result<(), Error> { /* 캐시 무효화 */ }
//! }
//! ```
//!
//! ### 2. 다층 캐싱 전략
//! ```text
//! Cache Hierarchy
//! ┌─────────────────────────────────────────────┐
//! │ Application Memory (Arc<T> 공유 인스턴스)  │ ← L1 Cache
//! ├─────────────────────────────────────────────┤
//! │ Redis Cache (TTL 기반)                     │ ← L2 Cache
//! ├─────────────────────────────────────────────┤
//! │ MongoDB Database (영구 저장소)             │ ← Persistent Store
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ### 3. 타입 안전한 데이터 접근
//! ```rust,ignore
//! // 컴파일 타임 타입 검증
//! let user: Option<User> = user_repo.find_by_id("user_id").await?;
//! let users: Vec<User> = user_repo.find_by_role("admin").await?;
//!
//! // MongoDB BSON ↔ Rust 구조체 자동 변환
//! #[derive(Serialize, Deserialize)]
//! pub struct User {
//!     #[serde(rename = "_id")]
//!     pub id: Option<ObjectId>,
//!     pub email: String,
//!     // ...
//! }
//! ```
//!
//! ## 성능 최적화
//!
//! ### 인덱스 전략
//! ```rust,ignore
//! impl UserRepository {
//!     pub async fn create_indexes(&self) -> Result<(), AppError> {
//!         let collection = self.collection::<User>();
//!         
//!         // 1. 유니크 인덱스 (데이터 무결성)
//!         let email_index = IndexModel::builder()
//!             .keys(doc! { "email": 1 })
//!             .options(IndexOptions::builder().unique(true).build())
//!             .build();
//!         
//!         // 2. 복합 인덱스 (쿼리 성능)
//!         let role_status_index = IndexModel::builder()
//!             .keys(doc! { "roles": 1, "is_active": 1 })
//!             .build();
//!         
//!         // 3. 부분 인덱스 (저장 공간 최적화)
//!         let oauth_index = IndexModel::builder()
//!             .keys(doc! { "oauth_data.provider_user_id": 1 })
//!             .options(IndexOptions::builder()
//!                 .partial_filter_expression(doc! { "oauth_data": { "$exists": true } })
//!                 .build())
//!             .build();
//!         
//!         collection.create_indexes([email_index, role_status_index, oauth_index]).await?;
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ### 캐시 무효화 전략
//! ```rust,ignore
//! impl UserRepository {
//!     pub async fn update_user(&self, id: &str, update: Document) -> Result<Option<User>, AppError> {
//!         // 1. 데이터베이스 업데이트
//!         let updated_user = self.collection::<User>()
//!             .find_one_and_update(
//!                 doc! { "_id": ObjectId::parse_str(id)? },
//!                 doc! { "$set": update }
//!             )
//!             .await?;
//!         
//!         // 2. 관련 캐시 무효화
//!         if let Some(ref user) = updated_user {
//!             self.invalidate_cache(id).await?;                    // ID 기반 캐시
//!             self.invalidate_cache(&format!("email:{}", user.email)).await?; // 이메일 기반 캐시
//!             self.invalidate_collection_cache(Some("active")).await?;        // 컬렉션 캐시
//!         }
//!         
//!         Ok(updated_user)
//!     }
//! }
//! ```
//!
//! ## 트랜잭션 지원
//!
//! ### MongoDB 트랜잭션
//! ```rust,ignore
//! impl UserRepository {
//!     pub async fn transfer_user_role(
//!         &self,
//!         from_user_id: &str,
//!         to_user_id: &str,
//!         role: &str
//!     ) -> Result<(), AppError> {
//!         let mut session = self.db.client().start_session().await?;
//!         
//!         session.start_transaction().await?;
//!         
//!         // 원자적 작업
//!         let result = async {
//!             // 1. 기존 사용자에서 역할 제거
//!             self.collection::<User>()
//!                 .update_one_with_session(
//!                     doc! { "_id": ObjectId::parse_str(from_user_id)? },
//!                     doc! { "$pull": { "roles": role } },
//!                     &mut session
//!                 )
//!                 .await?;
//!             
//!             // 2. 새 사용자에게 역할 추가
//!             self.collection::<User>()
//!                 .update_one_with_session(
//!                     doc! { "_id": ObjectId::parse_str(to_user_id)? },
//!                     doc! { "$addToSet": { "roles": role } },
//!                     &mut session
//!                 )
//!                 .await?;
//!             
//!             Ok::<(), AppError>(())
//!         }.await;
//!         
//!         match result {
//!             Ok(_) => {
//!                 session.commit_transaction().await?;
//!                 // 캐시 무효화
//!                 self.invalidate_cache(from_user_id).await?;
//!                 self.invalidate_cache(to_user_id).await?;
//!             }
//!             Err(e) => {
//!                 session.abort_transaction().await?;
//!                 return Err(e);
//!             }
//!         }
//!         
//!         Ok(())
//!     }
//! }
//! ```
//!
//! ## 에러 처리 및 복구
//!
//! ### 자동 재시도 메커니즘
//! ```rust,ignore
//! use backoff::{ExponentialBackoff, Error as BackoffError};
//!
//! impl UserRepository {
//!     async fn find_with_retry<T, F, Fut>(&self, operation: F) -> Result<T, AppError>
//!     where
//!         F: Fn() -> Fut,
//!         Fut: Future<Output = Result<T, mongodb::error::Error>>,
//!     {
//!         let backoff = ExponentialBackoff::default();
//!         
//!         backoff::future::retry(backoff, || async {
//!             match operation().await {
//!                 Ok(result) => Ok(result),
//!                 Err(e) if e.is_network_error() => Err(BackoffError::transient(e)),
//!                 Err(e) => Err(BackoffError::permanent(e)),
//!             }
//!         })
//!         .await
//!         .map_err(|e| AppError::DatabaseError(e.to_string()))
//!     }
//! }
//! ```
//!
//! ### 캐시 실패 시 Fallback
//! ```rust,ignore
//! impl UserRepository {
//!     pub async fn find_by_email_resilient(&self, email: &str) -> Result<Option<User>, AppError> {
//!         // 1차: Redis 캐시 시도
//!         match self.redis.get::<User>(&cache_key).await {
//!             Ok(Some(user)) => return Ok(Some(user)),
//!             Ok(None) => {}, // 캐시 미스
//!             Err(e) => {
//!                 log::warn!("Redis 캐시 실패, DB로 폴백: {}", e);
//!                 // 캐시 실패 시 DB로 폴백
//!             }
//!         }
//!         
//!         // 2차: MongoDB 조회
//!         let user = self.collection::<User>()
//!             .find_one(doc! { "email": email })
//!             .await
//!             .map_err(|e| AppError::DatabaseError(e.to_string()))?;
//!         
//!         // 3차: 백그라운드 캐시 복구 (fire-and-forget)
//!         if let Some(ref user) = user {
//!             let redis = self.redis.clone();
//!             let cache_key = cache_key.clone();
//!             let user_clone = user.clone();
//!             
//!             tokio::spawn(async move {
//!                 if let Err(e) = redis.set_with_expiry(&cache_key, &user_clone, 600).await {
//!                     log::error!("백그라운드 캐시 복구 실패: {}", e);
//!                 }
//!             });
//!         }
//!         
//!         Ok(user)
//!     }
//! }
//! ```
//!
//! ## 모듈 구성
//!
//! ```text
//! repositories/
//! ├── mod.rs                  ← 이 파일 (모듈 진입점)
//! ├── users/                  ← 사용자 관련 리포지토리
//! │   ├── mod.rs
//! │   ├── user_repo.rs        ← UserRepository 구현
//! │   └── user_profile_repo.rs ← UserProfileRepository (향후)
//! ├── auth/                   ← 인증 관련 리포지토리 (향후)
//! │   ├── session_repo.rs     ← SessionRepository
//! │   └── token_repo.rs       ← RefreshTokenRepository
//! ├── shared/                 ← 공통 리포지토리 기능 (향후)
//! │   ├── base_repo.rs        ← 기본 CRUD 작업
//! │   ├── cache_manager.rs    ← 캐시 관리 유틸리티
//! │   └── transaction_manager.rs ← 트랜잭션 관리
//! └── migrations/             ← 데이터 마이그레이션 (향후)
//!     ├── user_migrations.rs
//!     └── index_migrations.rs
//! ```
//!
//! ## 사용 예제
//!
//! ### Service Layer에서의 활용
//! ```rust,ignore
//! use crate::repositories::users::UserRepository;
//! use crate::services::users::UserService;
//!
//! #[service]
//! pub struct UserService {
//!     user_repo: Arc<UserRepository>, // 자동 의존성 주입
//! }
//!
//! impl UserService {
//!     pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, ServiceError> {
//!         // 1. 비즈니스 로직 검증
//!         self.validate_user_request(&request)?;
//!         
//!         // 2. 비밀번호 해싱
//!         let password_hash = bcrypt::hash(&request.password, bcrypt::DEFAULT_COST)?;
//!         
//!         // 3. 사용자 엔티티 생성
//!         let user = User::new_local(
//!             request.email,
//!             request.username,
//!             request.display_name,
//!             password_hash
//!         );
//!         
//!         // 4. 리포지토리를 통한 저장
//!         let saved_user = self.user_repo.create(user).await?;
//!         
//!         // 5. 이벤트 발행 (이메일 인증 등)
//!         self.event_publisher.publish(UserCreatedEvent::new(&saved_user)).await?;
//!         
//!         Ok(saved_user)
//!     }
//!     
//!     pub async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, ServiceError> {
//!         // 1. 사용자 조회 (캐시 활용)
//!         let user = self.user_repo
//!             .find_by_email(email)
//!             .await?
//!             .ok_or(ServiceError::InvalidCredentials)?;
//!         
//!         // 2. 비밀번호 검증
//!         if !bcrypt::verify(password, &user.password_hash.unwrap_or_default())? {
//!             return Err(ServiceError::InvalidCredentials);
//!         }
//!         
//!         // 3. 마지막 로그인 시간 업데이트
//!         self.user_repo
//!             .update(&user.id_string().unwrap(), doc! { 
//!                 "last_login_at": mongodb::bson::DateTime::now() 
//!             })
//!             .await?;
//!         
//!         Ok(user)
//!     }
//! }
//! ```
//!
//! ## 테스트 전략
//!
//! ### 통합 테스트
//! ```rust,ignore
//! #[cfg(test)]
//! mod integration_tests {
//!     use super::*;
//!     use testcontainers::{clients::Cli, images::mongo::Mongo, Container};
//!     
//!     struct TestContext {
//!         _mongo_container: Container<'static, Mongo>,
//!         user_repo: Arc<UserRepository>,
//!     }
//!     
//!     impl TestContext {
//!         async fn new() -> Self {
//!             let docker = Cli::default();
//!             let mongo_container = docker.run(Mongo::default());
//!             
//!             // 테스트용 DB 연결 설정
//!             let db_url = format!("mongodb://localhost:{}", mongo_container.get_host_port_ipv4(27017));
//!             let database = Database::connect(&db_url).await.unwrap();
//!             
//!             // 리포지토리 인스턴스 생성
//!             let user_repo = UserRepository::instance();
//!             user_repo.create_indexes().await.unwrap();
//!             
//!             Self {
//!                 _mongo_container: mongo_container,
//!                 user_repo,
//!             }
//!         }
//!     }
//!     
//!     #[tokio::test]
//!     async fn test_user_crud_operations() {
//!         let ctx = TestContext::new().await;
//!         
//!         // CREATE
//!         let user = User::new_local(
//!             "test@example.com".to_string(),
//!             "testuser".to_string(),
//!             "Test User".to_string(),
//!             "hashed_password".to_string()
//!         );
//!         let created_user = ctx.user_repo.create(user).await.unwrap();
//!         
//!         // READ
//!         let found_user = ctx.user_repo
//!             .find_by_email("test@example.com")
//!             .await
//!             .unwrap()
//!             .unwrap();
//!         assert_eq!(created_user.email, found_user.email);
//!         
//!         // UPDATE
//!         let updated = ctx.user_repo
//!             .update(&created_user.id_string().unwrap(), doc! { 
//!                 "display_name": "Updated Name" 
//!             })
//!             .await
//!             .unwrap()
//!             .unwrap();
//!         assert_eq!(updated.display_name, "Updated Name");
//!         
//!         // DELETE
//!         let deleted = ctx.user_repo
//!             .delete(&created_user.id_string().unwrap())
//!             .await
//!             .unwrap();
//!         assert!(deleted);
//!     }
//! }
//! ```
//!
//! ## 성능 모니터링
//!
//! ### 메트릭 수집
//! ```rust,ignore
//! use prometheus::{Counter, Histogram, register_counter, register_histogram};
//!
//! lazy_static! {
//!     static ref DB_QUERY_COUNTER: Counter = register_counter!(
//!         "repository_db_queries_total",
//!         "Total number of database queries"
//!     ).unwrap();
//!     
//!     static ref CACHE_HIT_COUNTER: Counter = register_counter!(
//!         "repository_cache_hits_total", 
//!         "Total number of cache hits"
//!     ).unwrap();
//!     
//!     static ref QUERY_DURATION: Histogram = register_histogram!(
//!         "repository_query_duration_seconds",
//!         "Time spent on database queries"
//!     ).unwrap();
//! }
//!
//! impl UserRepository {
//!     pub async fn find_by_email_with_metrics(&self, email: &str) -> Result<Option<User>, AppError> {
//!         let _timer = QUERY_DURATION.start_timer();
//!         
//!         // 캐시 확인
//!         if let Ok(Some(user)) = self.redis.get::<User>(&cache_key).await {
//!             CACHE_HIT_COUNTER.inc();
//!             return Ok(Some(user));
//!         }
//!         
//!         // DB 쿼리
//!         DB_QUERY_COUNTER.inc();
//!         let user = self.collection::<User>()
//!             .find_one(doc! { "email": email })
//!             .await?;
//!         
//!         Ok(user)
//!     }
//! }
//! ```

pub mod users;