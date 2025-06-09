//! 사용자 데이터 액세스를 담당하는 리포지토리 구현
//! 
//! MongoDB를 주 저장소로 사용하고 Redis를 통한 캐싱을 지원합니다.

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
/// MongoDB 컬렉션과 Redis 캐시를 통합하여 사용자 데이터를 관리합니다.
/// 캐시 우선 조회를 통해 성능을 최적화합니다.
#[repository(name = "user", collection = "users")]
pub struct UserRepository {
    /// MongoDB 데이터베이스 연결
    db: Arc<Database>,
    /// Redis 캐시 클라이언트
    redis: Arc<RedisClient>,
}

impl UserRepository {
    /// 이메일 주소로 사용자 조회
    /// 
    /// # Arguments
    /// 
    /// * `email` - 조회할 사용자의 이메일 주소
    /// 
    /// # Returns
    /// 
    /// * `Ok(Some(User))` - 사용자를 찾은 경우
    /// * `Ok(None)` - 해당 이메일의 사용자가 없는 경우
    /// 
    /// # Errors
    /// 
    /// * `AppError::DatabaseError` - MongoDB 연결 오류 또는 쿼리 실행 오류
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let repo = UserRepository::instance();
    /// let user = repo.find_by_email("alice@example.com").await?;
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

        // 캐시에 저장 (사용자 정보는 짧은 TTL - 5분)
        if let Some(ref user) = user {
            let _ = self.redis
                .set_with_expiry(&cache_key, user, 300) // 5분으로 단축
                .await;
        }

        Ok(user)
    }

    /// 사용자명으로 사용자 조회
    /// 
    /// # Arguments
    /// 
    /// * `username` - 조회할 사용자명
    /// 
    /// # Returns
    /// 
    /// * `Ok(Some(User))` - 사용자를 찾은 경우
    /// * `Ok(None)` - 해당 사용자명의 사용자가 없는 경우
    /// 
    /// # Errors
    /// 
    /// * `AppError::DatabaseError` - MongoDB 연결 오류 또는 쿼리 실행 오류
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
        self.collection::<User>()
            .find_one(doc! { "username": username })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))
    }

    /// ID로 사용자 조회
    /// 
    /// # Arguments
    /// 
    /// * `id` - MongoDB ObjectId의 16진수 문자열 표현
    /// 
    /// # Returns
    /// 
    /// * `Ok(Some(User))` - 사용자를 찾은 경우
    /// * `Ok(None)` - 해당 ID의 사용자가 없는 경우
    /// 
    /// # Errors
    /// 
    /// * `AppError::ValidationError` - 잘못된 ObjectId 형식
    /// * `AppError::DatabaseError` - MongoDB 연결 오류 또는 쿼리 실행 오류
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
    /// # Arguments
    /// 
    /// * `user` - 생성할 사용자 정보 (ID는 자동 할당됨)
    /// 
    /// # Returns
    /// 
    /// * `Ok(User)` - 생성된 사용자 (ID 포함)
    /// 
    /// # Errors
    /// 
    /// * `AppError::ConflictError` - 이메일 또는 사용자명 중복
    /// * `AppError::DatabaseError` - MongoDB 연결 오류 또는 삽입 오류
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
    /// # Arguments
    /// 
    /// * `id` - 업데이트할 사용자의 ID (ObjectId 문자열)
    /// * `update_doc` - 업데이트할 필드들을 포함한 MongoDB Document
    /// 
    /// # Returns
    /// 
    /// * `Ok(Some(User))` - 업데이트된 사용자 정보
    /// * `Ok(None)` - 해당 ID의 사용자가 존재하지 않음
    /// 
    /// # Errors
    /// 
    /// * `AppError::ValidationError` - 잘못된 ObjectId 형식
    /// * `AppError::DatabaseError` - MongoDB 연결 오류 또는 업데이트 오류
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
    /// # Arguments
    /// 
    /// * `id` - 삭제할 사용자의 ID (ObjectId 문자열)
    /// 
    /// # Returns
    /// 
    /// * `Ok(true)` - 사용자가 성공적으로 삭제됨
    /// * `Ok(false)` - 해당 ID의 사용자가 존재하지 않음
    /// 
    /// # Errors
    /// 
    /// * `AppError::ValidationError` - 잘못된 ObjectId 형식
    /// * `AppError::DatabaseError` - MongoDB 연결 오류 또는 삭제 오류
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
    /// # Returns
    /// 
    /// * `Ok(())` - 모든 인덱스가 성공적으로 생성됨
    /// 
    /// # Errors
    /// 
    /// * `AppError::DatabaseError` - 인덱스 생성 중 오류 발생
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
