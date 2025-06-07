//! # 사용자 리포지토리 구현
//! 
//! 사용자 엔티티의 데이터 액세스 계층을 담당하는 리포지토리입니다.
//! MongoDB를 주 저장소로 사용하고, Redis를 통한 캐싱을 지원합니다.
//! 
//! ## 특징
//! 
//! - **하이브리드 스토리지**: MongoDB + Redis 캐싱
//! - **자동 의존성 주입**: 싱글톤 매크로를 통한 DI
//! - **스마트 캐싱**: 조회 성능 최적화를 위한 다단계 캐싱
//! - **데이터 무결성**: 유니크 제약 조건 및 인덱스 관리

use std::sync::Arc;
use mongodb::{bson::{doc, oid::ObjectId}, options::IndexOptions, IndexModel};
use crate::{
    caching::redis::RedisClient,
    core::registry::Repository,
    db::Database,
    domain::entities::users::user::User,
};
use singleton_macro::repository;
use crate::errors::errors::AppError;

/// 사용자 데이터 액세스 리포지토리
/// 
/// 이 리포지토리는 사용자 엔티티의 CRUD 연산을 담당하며,
/// MongoDB 컬렉션과 Redis 캐시를 통합하여 최적화된 데이터 액세스를 제공합니다.
/// 
/// ## 캐싱 전략
/// 
/// ### L1 Cache (Redis)
/// - **TTL**: 10분 (600초)
/// - **키 패턴**: 
///   - 개별 사용자: `user:{user_id}`
///   - 이메일 조회: `user:email:{email}`
///   - 컬렉션 메타: `userrepository:collection`
/// 
/// ### L2 Storage (MongoDB)
/// - **컬렉션명**: `users`
/// - **인덱스**: email(unique), username(unique), created_at(desc)
/// 
/// ## 성능 최적화
/// 
/// - **읽기 우선 캐싱**: 모든 조회 연산에서 캐시 우선 확인
/// - **쓰기 후 캐시 무효화**: 데이터 변경 시 관련 캐시 자동 갱신
/// - **인덱스 기반 조회**: 이메일, 사용자명 조회 최적화
/// 
/// ## 에러 처리
/// 
/// 모든 메서드는 `Result<T, AppError>` 타입을 반환하며,
/// 다음과 같은 에러 상황을 처리합니다:
/// 
/// - **DatabaseError**: MongoDB 연결 오류, 쿼리 실행 오류
/// - **ValidationError**: 잘못된 ObjectId 형식 등 입력값 검증 오류
/// - **ConflictError**: 이메일/사용자명 중복 등 비즈니스 규칙 위반
/// 
/// ## 사용 예제
/// 
/// ```rust,ignore
/// use crate::repositories::users::user_repo::UserRepository;
/// use crate::domain::entities::users::user::User;
/// 
/// async fn user_operations() -> Result<(), AppError> {
///     let repo = UserRepository::instance();
///     
///     // 사용자 생성
///     let new_user = User {
///         email: "john@example.com".to_string(),
///         username: "john_doe".to_string(),
///         password_hash: "hashed_password".to_string(),
///         // ... 기타 필드
///     };
///     
///     let created = repo.create(new_user).await?;
///     let user_id = created.id.unwrap().to_hex();
///     
///     // 이메일로 조회 (캐시 활용)
///     let found = repo.find_by_email("john@example.com").await?;
///     
///     // ID로 조회 (캐시 활용)
///     let by_id = repo.find_by_id(&user_id).await?;
///     
///     // 업데이트
///     let update_doc = doc! { "last_login": chrono::Utc::now() };
///     let updated = repo.update(&user_id, update_doc).await?;
///     
///     // 삭제
///     let deleted = repo.delete(&user_id).await?;
///     
///     Ok(())
/// }
/// ```
#[repository(name = "user", collection = "users")]
pub struct UserRepository {
    /// MongoDB 데이터베이스 연결
    /// 
    /// 자동 주입되는 데이터베이스 컴포넌트입니다.
    /// `users` 컬렉션에 대한 모든 MongoDB 연산을 담당합니다.
    db: Arc<Database>,
    
    /// Redis 캐시 클라이언트
    /// 
    /// 자동 주입되는 Redis 클라이언트입니다.
    /// 조회 성능 향상을 위한 캐싱 레이어를 제공합니다.
    redis: Arc<RedisClient>,
}

impl UserRepository {
    /// 이메일 주소로 사용자 조회
    /// 
    /// 주어진 이메일 주소를 가진 사용자를 조회합니다.
    /// 캐시 우선 조회를 통해 성능을 최적화합니다.
    /// 
    /// # 인자
    /// 
    /// * `email` - 조회할 사용자의 이메일 주소
    /// 
    /// # 반환값
    /// 
    /// * `Ok(Some(User))` - 사용자를 찾은 경우
    /// * `Ok(None)` - 해당 이메일의 사용자가 없는 경우
    /// * `Err(AppError)` - 데이터베이스 오류 또는 기타 에러
    /// 
    /// # 캐싱 정책
    /// 
    /// - **캐시 키**: `user:email:{email}`
    /// - **TTL**: 600초 (10분)
    /// - **캐시 미스**: MongoDB에서 조회 후 캐시에 저장
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// let repo = UserRepository::instance();
    /// let user = repo.find_by_email("alice@example.com").await?;
    /// 
    /// match user {
    ///     Some(u) => println!("사용자 찾음: {}", u.username),
    ///     None => println!("사용자 없음"),
    /// }
    /// ```
    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        // 캐시에서 먼저 확인
        let cache_key = format!("user:email:{}", email);

        if let Ok(Some(cached)) = self.redis.get::<User>(&cache_key).await {
            return Ok(Some(cached));
        }

        // DB 에서 조회
        let user = self.collection::<User>()
            .find_one(doc! { "email": email })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // 캐시에 저장 (10분)
        if let Some(ref user) = user {
            let _ = self.redis
                .set_with_expiry(&cache_key, user, 600)
                .await;
        }

        Ok(user)
    }

    /// 사용자명으로 사용자 조회
    /// 
    /// 주어진 사용자명을 가진 사용자를 조회합니다.
    /// 사용자명은 시스템 전체에서 유니크하므로 최대 1개의 결과만 반환됩니다.
    /// 
    /// # 인자
    /// 
    /// * `username` - 조회할 사용자명
    /// 
    /// # 반환값
    /// 
    /// * `Ok(Some(User))` - 사용자를 찾은 경우
    /// * `Ok(None)` - 해당 사용자명의 사용자가 없는 경우
    /// * `Err(AppError)` - 데이터베이스 오류
    /// 
    /// # 성능 고려사항
    /// 
    /// - **인덱스 활용**: `username` 필드의 유니크 인덱스 사용
    /// - **캐싱 없음**: 사용자명 조회는 상대적으로 빈도가 낮아 캐싱하지 않음
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// let repo = UserRepository::instance();
    /// 
    /// // 사용자명 중복 확인
    /// if repo.find_by_username("new_user").await?.is_some() {
    ///     return Err(AppError::ConflictError("사용자명이 이미 사용 중입니다".to_string()));
    /// }
    /// ```
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
        self.collection::<User>()
            .find_one(doc! { "username": username })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))
    }

    /// ID로 사용자 조회
    /// 
    /// MongoDB ObjectId를 사용하여 사용자를 조회합니다.
    /// 가장 빈번한 조회 패턴이므로 적극적인 캐싱을 적용합니다.
    /// 
    /// # 인자
    /// 
    /// * `id` - MongoDB ObjectId의 16진수 문자열 표현
    /// 
    /// # 반환값
    /// 
    /// * `Ok(Some(User))` - 사용자를 찾은 경우
    /// * `Ok(None)` - 해당 ID의 사용자가 없는 경우
    /// * `Err(AppError::ValidationError)` - 잘못된 ObjectId 형식
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 오류
    /// 
    /// # 캐싱 정책
    /// 
    /// - **캐시 키**: `user:{id}` (리포지토리 매크로의 `cache_key()` 사용)
    /// - **TTL**: 600초 (10분)
    /// - **캐시 미스**: MongoDB에서 조회 후 캐시에 저장
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// let repo = UserRepository::instance();
    /// let user_id = "507f1f77bcf86cd799439011"; // 24자리 16진수
    /// 
    /// match repo.find_by_id(user_id).await? {
    ///     Some(user) => {
    ///         println!("사용자 정보: {} ({})", user.username, user.email);
    ///     },
    ///     None => {
    ///         return Err(AppError::NotFoundError("사용자를 찾을 수 없습니다".to_string()));
    ///     }
    /// }
    /// ```
    pub async fn find_by_id(&self, id: &str) -> Result<Option<User>, AppError> {
        let object_id = ObjectId::parse_str(id)
            .map_err(|_| AppError::ValidationError("유효하지 않은 ID 형식입니다".to_string()))?;

        let cache_key = self.cache_key(id);

        // 캐시 확인
        if let Ok(Some(cached)) = self.redis.get::<User>(&cache_key).await {
            return Ok(Some(cached));
        }

        // DB 조회
        let user = self.collection::<User>()
            .find_one(doc! { "_id": object_id })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // 캐시 저장
        if let Some(ref user) = user {
            let _ = self.redis
                .set_with_expiry(&cache_key, user, 600)
                .await;
        }

        Ok(user)
    }

    /// 새 사용자 생성
    /// 
    /// 새로운 사용자를 데이터베이스에 저장합니다.
    /// 이메일과 사용자명의 중복 여부를 사전에 검증하고,
    /// 성공 시 관련 캐시를 무효화합니다.
    /// 
    /// # 인자
    /// 
    /// * `user` - 생성할 사용자 정보 (ID는 자동 할당됨)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(User)` - 생성된 사용자 (ID 포함)
    /// * `Err(AppError::ConflictError)` - 이메일 또는 사용자명 중복
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 오류
    /// 
    /// # 비즈니스 규칙
    /// 
    /// 1. **이메일 유니크성**: 동일한 이메일로 두 번째 계정 생성 불가
    /// 2. **사용자명 유니크성**: 동일한 사용자명으로 두 번째 계정 생성 불가
    /// 3. **ID 자동 할당**: MongoDB가 자동으로 ObjectId 생성
    /// 
    /// # 캐시 관리
    /// 
    /// - **컬렉션 캐시 무효화**: 사용자 목록 관련 캐시 제거
    /// - **개별 캐시는 영향 없음**: 아직 조회되지 않은 새 사용자이므로
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// let repo = UserRepository::instance();
    /// 
    /// let new_user = User {
    ///     id: None, // 자동 할당됨
    ///     email: "bob@example.com".to_string(),
    ///     username: "bob_smith".to_string(),
    ///     password_hash: hash_password("secret123"),
    ///     created_at: chrono::Utc::now(),
    ///     updated_at: chrono::Utc::now(),
    /// };
    /// 
    /// let created_user = repo.create(new_user).await?;
    /// println!("새 사용자 ID: {}", created_user.id.unwrap().to_hex());
    /// ```
    pub async fn create(&self, mut user: User) -> Result<User, AppError> {
        // 중복 확인
        if self.find_by_email(&user.email).await?.is_some() {
            return Err(AppError::ConflictError("이미 사용 중인 이메일입니다".to_string()));
        }

        if self.find_by_username(&user.username).await?.is_some() {
            return Err(AppError::ConflictError("이미 사용 중인 사용자명입니다".to_string()));
        }

        // DB에 저장
        let result = self.collection::<User>()
            .insert_one(&user)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        user.id = Some(result.inserted_id.as_object_id().unwrap());

        // 컬렉션 캐시 무효화
        let _ = self.invalidate_collection_cache(None).await;

        Ok(user)
    }

    /// 사용자 정보 업데이트
    /// 
    /// 기존 사용자의 정보를 부분적으로 업데이트합니다.
    /// 업데이트 후 최신 사용자 정보를 반환하고 관련 캐시를 무효화합니다.
    /// 
    /// # 인자
    /// 
    /// * `id` - 업데이트할 사용자의 ID (ObjectId 문자열)
    /// * `update_doc` - 업데이트할 필드들을 포함한 MongoDB Document
    /// 
    /// # 반환값
    /// 
    /// * `Ok(Some(User))` - 업데이트된 사용자 정보
    /// * `Ok(None)` - 해당 ID의 사용자가 존재하지 않음
    /// * `Err(AppError::ValidationError)` - 잘못된 ObjectId 형식
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 오류
    /// 
    /// # 업데이트 연산
    /// 
    /// - **MongoDB `$set` 연산자 사용**: 지정된 필드만 변경
    /// - **원자적 연산**: find_one_and_update로 조회와 업데이트를 동시에
    /// - **최신 데이터 반환**: ReturnDocument::After 옵션 사용
    /// 
    /// # 캐시 관리
    /// 
    /// - **개별 캐시 무효화**: 해당 사용자의 모든 캐시 키 제거
    /// - **이메일 캐시 주의**: 이메일 변경 시 기존 이메일 키는 수동 무효화 필요
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// use mongodb::bson::doc;
    /// 
    /// let repo = UserRepository::instance();
    /// let user_id = "507f1f77bcf86cd799439011";
    /// 
    /// // 마지막 로그인 시간 업데이트
    /// let update_doc = doc! {
    ///     "last_login": chrono::Utc::now(),
    ///     "login_count": { "$inc": 1 }
    /// };
    /// 
    /// let updated_user = repo.update(user_id, update_doc).await?;
    /// 
    /// match updated_user {
    ///     Some(user) => println!("업데이트 완료: {}", user.username),
    ///     None => println!("사용자를 찾을 수 없습니다"),
    /// }
    /// ```
    pub async fn update(&self, id: &str, update_doc: mongodb::bson::Document) -> Result<Option<User>, AppError> {
        let object_id = ObjectId::parse_str(id)
            .map_err(|_| AppError::ValidationError("유효하지 않은 ID 형식입니다".to_string()))?;

        let options = mongodb::options::FindOneAndUpdateOptions::builder()
            .return_document(mongodb::options::ReturnDocument::After)
            .build();

        let updated_user = self.collection::<User>()
            .find_one_and_update(
                doc! { "_id": object_id },
                doc! { "$set": update_doc },
            )
            .with_options(options)
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        // 캐시 무효화
        if updated_user.is_some() {
            let _ = self.invalidate_cache(id).await;
        }

        Ok(updated_user)
    }

    /// 사용자 삭제
    /// 
    /// 지정된 ID의 사용자를 데이터베이스에서 영구적으로 삭제합니다.
    /// 삭제 성공 시 관련된 모든 캐시를 무효화합니다.
    /// 
    /// # 인자
    /// 
    /// * `id` - 삭제할 사용자의 ID (ObjectId 문자열)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(true)` - 사용자가 성공적으로 삭제됨
    /// * `Ok(false)` - 해당 ID의 사용자가 존재하지 않음 (삭제할 것이 없음)
    /// * `Err(AppError::ValidationError)` - 잘못된 ObjectId 형식
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 오류
    /// 
    /// # 삭제 정책
    /// 
    /// - **물리적 삭제**: 데이터베이스에서 완전히 제거 (소프트 삭제 아님)
    /// - **연관 데이터**: 사용자와 연관된 다른 데이터는 별도 처리 필요
    /// - **복구 불가**: 삭제된 데이터는 복구할 수 없음
    /// 
    /// # 캐시 관리
    /// 
    /// - **개별 캐시 무효화**: 해당 사용자의 ID 기반 캐시 제거
    /// - **컬렉션 캐시 무효화**: 사용자 목록 관련 캐시 제거
    /// - **이메일 캐시**: 사용자 정보를 알 수 없으므로 수동 관리 필요
    /// 
    /// # 보안 고려사항
    /// 
    /// - **권한 확인**: 호출 전에 삭제 권한 확인 필요
    /// - **감사 로그**: 중요한 작업이므로 감사 로그 기록 권장
    /// - **데이터 백업**: 삭제 전 중요 데이터 백업 고려
    /// 
    /// # 예제
    /// 
    /// ```rust,ignore
    /// let repo = UserRepository::instance();
    /// let user_id = "507f1f77bcf86cd799439011";
    /// 
    /// // 사용자 존재 여부 확인 (선택사항)
    /// let user = repo.find_by_id(user_id).await?;
    /// if user.is_none() {
    ///     return Err(AppError::NotFoundError("삭제할 사용자가 없습니다".to_string()));
    /// }
    /// 
    /// // 사용자 삭제
    /// let deleted = repo.delete(user_id).await?;
    /// 
    /// if deleted {
    ///     println!("사용자가 성공적으로 삭제되었습니다");
    /// } else {
    ///     println!("삭제할 사용자를 찾을 수 없습니다");
    /// }
    /// ```
    pub async fn delete(&self, id: &str) -> Result<bool, AppError> {
        let object_id = ObjectId::parse_str(id)
            .map_err(|_| AppError::ValidationError("유효하지 않은 ID 형식입니다".to_string()))?;

        let result = self.collection::<User>()
            .delete_one(doc! { "_id": object_id })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        if result.deleted_count > 0 {
            // 캐시 무효화
            let _ = self.invalidate_cache(id).await;
            let _ = self.invalidate_collection_cache(None).await;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// 데이터베이스 인덱스 생성
    /// 
    /// 사용자 컬렉션에 필요한 모든 인덱스를 생성합니다.
    /// 애플리케이션 초기화 시점에 한 번 실행하여 쿼리 성능을 최적화합니다.
    /// 
    /// # 생성되는 인덱스
    /// 
    /// 1. **이메일 유니크 인덱스**
    ///    - 필드: `email` (오름차순)
    ///    - 속성: UNIQUE
    ///    - 목적: 중복 이메일 방지 및 이메일 조회 최적화
    /// 
    /// 2. **사용자명 유니크 인덱스**
    ///    - 필드: `username` (오름차순)
    ///    - 속성: UNIQUE
    ///    - 목적: 중복 사용자명 방지 및 사용자명 조회 최적화
    /// 
    /// 3. **생성일 인덱스**
    ///    - 필드: `created_at` (내림차순)
    ///    - 속성: 일반 인덱스
    ///    - 목적: 최근 사용자 조회 및 정렬 최적화
    /// 
    /// # 반환값
    /// 
    /// * `Ok(())` - 모든 인덱스가 성공적으로 생성됨
    /// * `Err(AppError::DatabaseError)` - 인덱스 생성 중 오류 발생
    /// 
    /// # 성능 영향
    /// 
    /// - **조회 성능 향상**: 인덱싱된 필드의 조회 속도 대폭 개선
    /// - **쓰기 성능 영향**: 인덱스 유지로 인한 약간의 쓰기 성능 오버헤드
    /// - **저장 공간**: 인덱스로 인한 추가 저장 공간 사용
    /// 
    /// # 호출 시점
    /// 
    /// 일반적으로 애플리케이션 초기화 시점에 호출됩니다:
    /// 
    /// ```rust,ignore
    /// // main.rs 또는 초기화 코드에서
    /// async fn initialize_database() -> Result<(), AppError> {
    ///     let user_repo = UserRepository::instance();
    ///     user_repo.create_indexes().await?;
    ///     
    ///     println!("사용자 리포지토리 인덱스 생성 완료");
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # 주의사항
    /// 
    /// - **기존 데이터**: 이미 중복 데이터가 있는 경우 유니크 인덱스 생성 실패
    /// - **백그라운드 생성**: 대용량 컬렉션의 경우 인덱스 생성에 시간 소요
    /// - **MongoDB 버전**: 사용하는 MongoDB 버전의 인덱스 기능 확인 필요
    pub async fn create_indexes(&self) -> Result<(), AppError> {
        let collection = self.collection::<User>();

        // 이메일 유니크 인덱스
        let email_index = IndexModel::builder()
            .keys(doc! { "email": 1 })
            .options(IndexOptions::builder()
                .unique(true)
                .name("email_unique".to_string())
                .build())
            .build();

        // 사용자명 유니크 인덱스
        let username_index = IndexModel::builder()
            .keys(doc! { "username": 1 })
            .options(IndexOptions::builder()
                .unique(true)
                .name("username_unique".to_string())
                .build())
            .build();

        // 생성일 인덱스
        let created_at_index = IndexModel::builder()
            .keys(doc! { "created_at": -1 })
            .options(IndexOptions::builder()
                .name("created_at_desc".to_string())
                .build())
            .build();

        collection
            .create_indexes([email_index, username_index, created_at_index])
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}
