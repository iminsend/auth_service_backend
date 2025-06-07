use std::sync::Arc;
use bcrypt::hash;
use singleton_macro::service;
use crate::{
    domain::{
        entities::users::user::User,
        dto::users::{
            request::CreateUserRequest,
            response::{UserResponse, CreateUserResponse},
        },
    },
    repositories::users::user_repo::UserRepository,
    core::{
        errors::AppError,
    },
};
use crate::config::PasswordConfig;

/// 사용자 서비스
#[service(name = "user")]
pub struct UserService {
    user_repo: Arc<UserRepository>,
}

impl UserService {
    /// 사용자 생성
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<CreateUserResponse, AppError> {
        let start_time = std::time::Instant::now();
        
        // 환경별 bcrypt cost 사용
        let bcrypt_cost = PasswordConfig::bcrypt_cost();
        
        // 비밀번호 해싱
        let hash_start = std::time::Instant::now();
        let password_hash = hash(&request.password, bcrypt_cost)
            .map_err(|e| AppError::InternalError(format!("비밀번호 해싱 실패: {}", e)))?;
        let hash_duration = hash_start.elapsed();
        
        log::info!("Password hashing took: {:?}", hash_duration);

        // 사용자 엔티티 생성 (로컬 인증)
        let user = User::new_local(
            request.email,
            request.username,
            request.display_name,
            password_hash,
        );

        // 저장
        let created_user = self.user_repo.create(user).await?;
        
        let total_duration = start_time.elapsed();
        log::info!("Total user creation took: {:?}", total_duration);

        Ok(CreateUserResponse {
            user: UserResponse::from(created_user),
            message: "사용자가 성공적으로 생성되었습니다".to_string(),
        })
    }

    /// ID로 사용자 조회
    pub async fn get_user_by_id(&self, id: &str) -> Result<UserResponse, AppError> {
        let user = self.user_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("사용자를 찾을 수 없습니다".to_string()))?;

        Ok(UserResponse::from(user))
    }

    /// 이메일로 사용자 조회
    pub async fn get_user_by_email(&self, email: &str) -> Result<UserResponse, AppError> {
        let user = self.user_repo
            .find_by_email(email)
            .await?
            .ok_or_else(|| AppError::NotFound("사용자를 찾을 수 없습니다".to_string()))?;

        Ok(UserResponse::from(user))
    }

    /// 사용자 삭제
    pub async fn delete_user(&self, id: &str) -> Result<(), AppError> {
        let deleted = self.user_repo.delete(id).await?;

        if !deleted {
            return Err(AppError::NotFound("사용자를 찾을 수 없습니다".to_string()));
        }

        Ok(())
    }

    /// 비밀번호 검증 (로컬 인증 사용자만)
    pub async fn verify_password(&self, email: &str, password: &str) -> Result<User, AppError> {
        let start_time = std::time::Instant::now();
        
        let user = self.user_repo
            .find_by_email(email)
            .await?
            .ok_or_else(|| AppError::AuthenticationError("잘못된 이메일 또는 비밀번호입니다".to_string()))?;

        // OAuth 사용자인 경우 비밀번호 인증 불가
        if !user.can_authenticate_with_password() {
            return Err(AppError::AuthenticationError("OAuth 계정입니다. 해당 프로바이더로 로그인해주세요".to_string()));
        }

        // 로컬 사용자의 비밀번호 검증
        let password_hash = user.password_hash.as_ref()
            .ok_or_else(|| AppError::InternalError("비밀번호 해시가 없습니다".to_string()))?;

        let verify_start = std::time::Instant::now();
        let is_valid = bcrypt::verify(password, password_hash)
            .map_err(|e| AppError::InternalError(format!("비밀번호 검증 실패: {}", e)))?;
        let verify_duration = verify_start.elapsed();
        
        log::debug!("Password verification took: {:?}", verify_duration);

        if !is_valid {
            return Err(AppError::AuthenticationError("잘못된 이메일 또는 비밀번호입니다".to_string()));
        }

        if !user.is_active {
            return Err(AppError::AuthenticationError("비활성화된 계정입니다".to_string()));
        }

        let total_duration = start_time.elapsed();
        log::debug!("Total password verification took: {:?}", total_duration);

        Ok(user)
    }
}
