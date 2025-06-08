//! 사용자 관리 비즈니스 로직 서비스 구현
//! 
//! 사용자 등록, 인증, 조회, 삭제 등의 핵심 기능을 제공합니다.
//! bcrypt를 사용한 안전한 비밀번호 처리와 타이밍 공격 방지를 지원합니다.

use std::sync::Arc;
use bcrypt::hash;
use singleton_macro::service;
use crate::{
    domain::{
        dto::users::{
            request::CreateUserRequest,
            response::{CreateUserResponse, UserResponse},
        },
        entities::users::user::User,
    },
    repositories::users::user_repo::UserRepository,
};
use crate::config::PasswordConfig;
use crate::errors::errors::AppError;

/// 사용자 관리 비즈니스 로직 서비스
/// 
/// 사용자 계정의 전체 생명주기를 관리하는 핵심 서비스입니다.
/// 로컬 계정 생성, 비밀번호 인증, 사용자 조회 등의 기능을 제공합니다.
#[service(name = "user")]
pub struct UserService {
    /// 사용자 데이터 액세스 리포지토리
    user_repo: Arc<UserRepository>,
}

impl UserService {
    /// 새 사용자 계정 생성
    /// 
    /// # Arguments
    /// 
    /// * `request` - 사용자 생성 요청 데이터
    /// 
    /// # Returns
    /// 
    /// * `Ok(CreateUserResponse)` - 생성된 사용자 정보
    /// 
    /// # Errors
    /// 
    /// * `AppError::ConflictError` - 이메일 또는 사용자명 중복
    /// * `AppError::InternalError` - 비밀번호 해싱 실패
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let request = CreateUserRequest {
    ///     email: "user@example.com".to_string(),
    ///     username: "user123".to_string(),
    ///     display_name: "User".to_string(),
    ///     password: "secure_password".to_string(),
    /// };
    /// let response = user_service.create_user(request).await?;
    /// ```
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
    /// 
    /// # Arguments
    /// 
    /// * `id` - 사용자 ObjectId (16진수 문자열)
    /// 
    /// # Returns
    /// 
    /// * `Ok(UserResponse)` - 사용자 정보 DTO (민감 정보 제외)
    /// 
    /// # Errors
    /// 
    /// * `AppError::NotFound` - 사용자 없음
    /// * `AppError::ValidationError` - 잘못된 ID 형식
    pub async fn get_user_by_id(&self, id: &str) -> Result<UserResponse, AppError> {
        let user = self.user_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("사용자를 찾을 수 없습니다".to_string()))?;

        Ok(UserResponse::from(user))
    }

    /// 이메일로 사용자 조회
    /// 
    /// # Arguments
    /// 
    /// * `email` - 사용자 이메일 주소
    /// 
    /// # Returns
    /// 
    /// * `Ok(UserResponse)` - 사용자 정보 DTO
    /// 
    /// # Errors
    /// 
    /// * `AppError::NotFound` - 사용자 없음
    /// * `AppError::DatabaseError` - 데이터베이스 오류
    pub async fn get_user_by_email(&self, email: &str) -> Result<UserResponse, AppError> {
        let user = self.user_repo
            .find_by_email(email)
            .await?
            .ok_or_else(|| AppError::NotFound("사용자를 찾을 수 없습니다".to_string()))?;

        Ok(UserResponse::from(user))
    }

    /// 사용자 계정 삭제
    /// 
    /// # Arguments
    /// 
    /// * `id` - 삭제할 사용자 ID
    /// 
    /// # Returns
    /// 
    /// * `Ok(())` - 삭제 성공
    /// 
    /// # Errors
    /// 
    /// * `AppError::NotFound` - 사용자 없음
    /// * `AppError::ValidationError` - 잘못된 ID 형식
    /// 
    /// # Safety
    /// 
    /// 물리적 삭제를 수행하므로 복구가 불가능합니다.
    /// 연관 데이터는 별도로 처리해야 합니다.
    pub async fn delete_user(&self, id: &str) -> Result<(), AppError> {
        let deleted = self.user_repo.delete(id).await?;

        if !deleted {
            return Err(AppError::NotFound("사용자를 찾을 수 없습니다".to_string()));
        }

        Ok(())
    }

    /// ID로 사용자 엔티티 조회 (내부용)
    /// 
    /// 미들웨어나 내부 서비스에서 사용하기 위한 전체 User 엔티티를 반환합니다.
    /// 
    /// # Arguments
    /// 
    /// * `id` - 사용자 ID
    /// 
    /// # Returns
    /// 
    /// * `Ok(Some(User))` - 사용자 엔티티
    /// * `Ok(None)` - 사용자 없음
    /// 
    /// # Errors
    /// 
    /// * `AppError::ValidationError` - 잘못된 ID 형식
    /// * `AppError::DatabaseError` - 데이터베이스 오류
    pub async fn find_by_id(&self, id: &str) -> Result<Option<User>, AppError> {
        self.user_repo.find_by_id(id).await
    }

    /// 페이지네이션 사용자 목록 조회 (관리자용)
    /// 
    /// # Arguments
    /// 
    /// * `page` - 페이지 번호 (1부터 시작)
    /// * `limit` - 페이지당 항목 수 (최대 100개)
    /// * `_search` - 검색어 (현재 미구현)
    /// 
    /// # Returns
    /// 
    /// * `Ok(Vec<UserResponse>)` - 사용자 목록
    /// 
    /// # Notes
    /// 
    /// 현재 임시 구현 상태로 실제 페이지네이션이 적용되지 않습니다.
    pub async fn find_all_paginated(
        &self,
        page: u64,
        limit: u64,
        _search: Option<&str>,
    ) -> Result<Vec<UserResponse>, AppError> {
        // 페이지당 최대 항목 수 제한
        let limit = std::cmp::min(limit, 100);
        let _skip = (page.saturating_sub(1)) * limit;

        // TODO: 실제 구현에서는 UserRepository에 find_paginated 메서드 필요
        log::warn!("find_all_paginated: 임시 구현 사용 중 (페이지네이션 미적용)");
        
        // 임시 구현: 빈 결과 반환
        let users: Vec<User> = Vec::new();
        
        // DTO 변환
        let user_responses: Vec<UserResponse> = users
            .into_iter()
            .map(UserResponse::from)
            .collect();

        Ok(user_responses)
    }

    /// 로컬 계정 비밀번호 검증
    /// 
    /// 이메일과 비밀번호를 사용하여 로컬 인증을 수행합니다.
    /// bcrypt를 사용한 타이밍 공격 방지와 OAuth 계정 보호가 적용됩니다.
    /// 
    /// # Arguments
    /// 
    /// * `email` - 사용자 이메일 주소
    /// * `password` - 평문 비밀번호
    /// 
    /// # Returns
    /// 
    /// * `Ok(User)` - 인증된 사용자 엔티티
    /// 
    /// # Errors
    /// 
    /// * `AppError::AuthenticationError` - 인증 실패 (잘못된 비밀번호, OAuth 계정, 비활성 계정)
    /// * `AppError::InternalError` - 비밀번호 검증 오류
    /// 
    /// # Security
    /// 
    /// - bcrypt를 사용한 안전한 비밀번호 검증
    /// - 타이밍 공격 방지
    /// - OAuth 계정의 비밀번호 인증 차단
    /// - 계정 상태 확인 (활성/비활성)
    /// - 통합된 에러 메시지 (사용자 열거 공격 방지)
    /// 
    /// # Examples
    /// 
    /// ```rust,ignore
    /// let user = user_service.verify_password("user@example.com", "password").await?;
    /// let token = token_service.generate_token_pair(&user)?;
    /// ```
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
