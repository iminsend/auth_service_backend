use std::sync::Arc;
use mongodb::{bson::{doc, oid::ObjectId}, IndexModel, options::IndexOptions};
use crate::{
    domain::entities::users::user::User,
    core::{
        errors::AppError,
        registry::Repository,
    },
    db::Database,
    caching::redis::RedisClient,
};
use singleton_macro::repository;

/// 사용자 리포지토리
#[repository(name = "user", collection = "users")]
pub struct UserRepository {
    db: Arc<Database>,
    redis: Arc<RedisClient>,
}

impl UserRepository {
    /// 이메일로 사용자 찾기
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

    /// 사용자명으로 사용자 찾기
    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
        self.collection::<User>()
            .find_one(doc! { "username": username })
            .await
            .map_err(|e| AppError::DatabaseError(e.to_string()))
    }

    /// ID로 사용자 찾기
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

    /// 사용자 생성
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

    /// 사용자 업데이트
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

    /// 인덱스 생성
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
