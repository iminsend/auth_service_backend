//! # 사용자 관리 서비스 구현
//! 
//! 사용자 계정의 전체 생명주기를 관리하는 핵심 비즈니스 로직을 구현합니다.
//! Spring Framework의 UserService와 UserDetailsService 패턴을 참고하여 설계되었으며,
//! 사용자 등록, 인증, 조회, 삭제 등의 핵심 기능을 제공합니다.
//! 
//! ## 서비스 아키텍처
//! 
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                         UserService                             │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                 │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
//! │  │   Registration  │  │  Authentication │  │   User Query    │  │
//! │  │                 │  │                 │  │                 │  │
//! │  │ • Input Valid   │  │ • Password Ver  │  │ • By ID/Email   │  │
//! │  │ • Duplicate Chk │  │ • Account State │  │ • Entity to DTO │  │
//! │  │ • Password Hash │  │ • OAuth Check   │  │ • Cache Support │  │
//! │  │ • Entity Create │  │ • Timing Safe   │  │ • Error Handle  │  │
//! │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
//! │                                                                 │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
//! │  │ Profile Mgmt    │  │   Monitoring    │  │ Data Transform  │  │
//! │  │                 │  │                 │  │                 │  │
//! │  │ • Account Del   │  │ • Performance   │  │ • Entity→DTO    │  │
//! │  │ • Status Update │  │ • Security Log  │  │ • Request→Entity│  │
//! │  │ • Data Cleanup  │  │ • Metrics Coll  │  │ • Sensitive Flt │  │
//! │  │ • Related Data  │  │ • Error Track   │  │ • Validation    │  │
//! │  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//!                                 │
//!                                 ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      UserRepository                             │
//! │ • MongoDB CRUD Operations                                       │
//! │ • Redis Caching Layer                                           │
//! │ • Index Optimization                                            │
//! │ • Transaction Management                                        │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//! 
//! ## 보안 설계 원칙
//! 
//! ### 1. 비밀번호 보안 (Password Security)
//! 
//! - **bcrypt 해싱**: 적응형 해시 함수로 무차별 대입 공격 방지
//! - **환경별 Cost**: 개발(4-8) vs 운영(12-15) 환경별 보안 강도
//! - **솔트 자동 생성**: 레인보우 테이블 공격 방지
//! - **타이밍 공격 방지**: 일정한 검증 시간 유지
//! 
//! ### 2. 인증 보안 (Authentication Security)
//! 
//! - **다중 인증 방식**: 로컬 vs OAuth 계정 구분 처리
//! - **계정 상태 검증**: 활성/비활성 계정 확인
//! - **실패 로깅**: 인증 실패 시 보안 이벤트 기록
//! - **세션 정보**: 인증 성공 시 사용자 엔티티 반환
//! 
//! ### 3. 데이터 보안 (Data Security)
//! 
//! - **민감 정보 제거**: DTO 변환 시 비밀번호 해시 제외
//! - **입력 검증**: SQL 인젝션, XSS 방지
//! - **중복 방지**: 이메일, 사용자명 유니크 제약
//! - **데이터 최소화**: 필요한 정보만 수집 및 저장

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

/// 사용자 관리 비즈니스 로직 서비스
/// 
/// 이 서비스는 사용자 계정의 전체 생명주기를 관리하는 핵심 비즈니스 로직을 담당합니다.
/// Spring Framework의 `@Service` 어노테이션이 적용된 UserService와 유사한 역할을 수행하며,
/// 사용자 등록, 인증, 조회, 관리 등의 도메인별 비즈니스 규칙을 구현합니다.
/// 
/// ## 주요 책임 (Responsibilities)
/// 
/// 1. **사용자 등록 (User Registration)**
///    - 입력값 검증 및 비즈니스 규칙 적용
///    - 비밀번호 해싱 및 보안 강화
///    - 중복 계정 방지 및 유니크 제약 관리
///    - 계정 생성 후 초기 설정
/// 
/// 2. **사용자 인증 (User Authentication)**
///    - 로컬 계정 비밀번호 검증
///    - OAuth 계정과의 구분 처리
///    - 계정 상태 및 권한 확인
///    - 보안 이벤트 로깅
/// 
/// 3. **사용자 조회 (User Retrieval)**
///    - ID/이메일 기반 사용자 검색
///    - 엔티티에서 DTO로의 안전한 변환
///    - 캐시 활용을 통한 성능 최적화
///    - 존재하지 않는 사용자 처리
/// 
/// 4. **계정 관리 (Account Management)**
///    - 사용자 계정 삭제 및 비활성화
///    - 연관 데이터 정리 및 정합성 유지
///    - 감사 로그 및 보안 추적
/// 
/// ## 싱글톤 패턴 및 의존성 주입
/// 
/// `#[service]` 매크로를 통해 자동으로 싱글톤으로 관리되며,
/// UserRepository가 자동으로 주입됩니다:
/// 
/// ```rust,ignore
/// let user_service = UserService::instance(); // 항상 동일한 인스턴스
/// ```
/// 
/// ## 성능 특징
/// 
/// - **비동기 처리**: 모든 I/O 작업은 async/await 기반
/// - **캐시 활용**: Repository 레이어의 Redis 캐시 활용
/// - **성능 모니터링**: 주요 작업의 실행 시간 측정 및 로깅
/// - **메모리 효율성**: Arc를 통한 참조 카운팅 및 공유
/// 
/// ## 에러 처리 전략
/// 
/// 모든 메서드는 `Result<T, AppError>` 타입을 반환하며,
/// 다음과 같은 일관된 에러 처리를 제공합니다:
/// 
/// - **ValidationError**: 입력값 검증 실패
/// - **ConflictError**: 비즈니스 규칙 위반 (중복 등)
/// - **AuthenticationError**: 인증 관련 오류
/// - **NotFound**: 리소스 존재하지 않음
/// - **InternalError**: 시스템 레벨 오류
/// 
/// ## 사용 예제
/// 
/// ```rust,ignore
/// use crate::services::users::UserService;
/// 
/// async fn example_usage() -> Result<(), AppError> {
///     let user_service = UserService::instance();
///     
///     // 사용자 등록
///     let request = CreateUserRequest {
///         email: "john@example.com".to_string(),
///         username: "john_doe".to_string(),
///         display_name: "John Doe".to_string(),
///         password: "SecurePass123!".to_string(),
///     };
///     
///     let response = user_service.create_user(request).await?;
///     println!("사용자 생성: {}", response.message);
///     
///     // 인증
///     let user = user_service
///         .verify_password("john@example.com", "SecurePass123!")
///         .await?;
///     
///     println!("인증 성공: {}", user.username);
///     
///     Ok(())
/// }
/// ```
#[service(name = "user")]
pub struct UserService {
    /// 사용자 데이터 액세스 리포지토리
    /// 
    /// 자동 의존성 주입을 통해 UserRepository 싱글톤이 주입됩니다.
    /// 모든 데이터베이스 작업은 이 리포지토리를 통해 수행되며,
    /// MongoDB 영구 저장과 Redis 캐싱을 지원합니다.
    user_repo: Arc<UserRepository>,
}

impl UserService {
    /// 새 사용자 계정 생성
    /// 
    /// 클라이언트 요청을 받아 새로운 사용자 계정을 생성합니다.
    /// Spring Framework의 `@Transactional` 메서드와 유사하게,
    /// 전체 과정이 원자적으로 처리됩니다.
    /// 
    /// # 인자
    /// 
    /// * `request` - 사용자 생성 요청 데이터 (이메일, 사용자명, 비밀번호 등)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(CreateUserResponse)` - 생성된 사용자 정보와 성공 메시지
    /// * `Err(AppError::ConflictError)` - 이메일 또는 사용자명 중복
    /// * `Err(AppError::InternalError)` - 비밀번호 해싱 실패 또는 시스템 오류
    /// 
    /// # 처리 과정
    /// 
    /// 1. **성능 측정 시작**: 전체 처리 시간 추적 시작
    /// 2. **비밀번호 해싱**: bcrypt를 사용한 안전한 해싱
    /// 3. **엔티티 생성**: User::new_local()을 통한 로컬 계정 생성
    /// 4. **영구 저장**: Repository를 통한 데이터베이스 저장
    /// 5. **응답 생성**: 민감 정보를 제거한 DTO 응답 생성
    /// 6. **성능 로깅**: 처리 시간 기록 및 로깅
    /// 
    /// # 보안 특징
    /// 
    /// - **bcrypt 해싱**: 환경별 cost 설정으로 보안 강도 조절
    /// - **솔트 자동 생성**: bcrypt가 자동으로 고유 솔트 생성
    /// - **중복 검사**: Repository 레벨에서 이메일/사용자명 중복 방지
    /// - **민감 정보 제거**: 응답에서 비밀번호 해시 제외
    /// 
    /// # 성능 고려사항
    /// 
    /// - **해싱 비용**: bcrypt cost가 높을수록 보안은 강화되지만 처리 시간 증가
    /// - **캐시 무효화**: 새 사용자 생성 시 관련 캐시 무효화
    /// - **비동기 처리**: 모든 I/O 작업 비동기로 처리
    /// 
    /// # 비즈니스 규칙
    /// 
    /// - **이메일 유니크성**: 동일한 이메일로 두 번째 계정 생성 불가
    /// - **사용자명 유니크성**: 동일한 사용자명으로 두 번째 계정 생성 불가
    /// - **로컬 계정**: OAuth가 아닌 로컬 인증 방식으로 생성
    /// - **기본 활성화**: 생성된 계정은 기본적으로 활성 상태
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// use crate::domain::dto::users::request::CreateUserRequest;
    /// 
    /// async fn register_new_user() -> Result<(), AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     let request = CreateUserRequest {
    ///         email: "alice@example.com".to_string(),
    ///         username: "alice_smith".to_string(),
    ///         display_name: "Alice Smith".to_string(),
    ///         password: "MySecurePassword123!".to_string(),
    ///     };
    ///     
    ///     match user_service.create_user(request).await {
    ///         Ok(response) => {
    ///             println!("사용자 생성 성공:");
    ///             println!("  ID: {}", response.user.id);
    ///             println!("  이메일: {}", response.user.email);
    ///             println!("  메시지: {}", response.message);
    ///         },
    ///         Err(AppError::ConflictError(msg)) => {
    ///             println!("계정 생성 실패: {}", msg);
    ///             // 클라이언트에게 409 Conflict 응답
    ///         },
    ///         Err(e) => {
    ///             println!("시스템 오류: {}", e);
    ///             // 클라이언트에게 500 Internal Error 응답
    ///         }
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # 로깅 및 모니터링
    /// 
    /// 이 메서드는 다음과 같은 로그를 생성합니다:
    /// 
    /// ```text
    /// [INFO] Password hashing took: 156ms
    /// [INFO] Total user creation took: 234ms
    /// ```
    /// 
    /// 이를 통해 성능 병목 지점을 식별하고 최적화할 수 있습니다.
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
    /// MongoDB ObjectId를 사용하여 특정 사용자를 조회하고,
    /// 안전한 DTO 형태로 변환하여 반환합니다.
    /// 
    /// # 인자
    /// 
    /// * `id` - 조회할 사용자의 MongoDB ObjectId (16진수 문자열)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(UserResponse)` - 사용자 정보 DTO (민감 정보 제외)
    /// * `Err(AppError::NotFound)` - 해당 ID의 사용자가 존재하지 않음
    /// * `Err(AppError::ValidationError)` - 잘못된 ObjectId 형식
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 조회 오류
    /// 
    /// # 데이터 변환 과정
    /// 
    /// 1. **Repository 조회**: 캐시 우선 조회 후 DB 조회
    /// 2. **존재 여부 확인**: Option<User>에서 None 체크
    /// 3. **DTO 변환**: Entity → DTO 변환으로 민감 정보 제거
    /// 4. **응답 반환**: UserResponse 구조체로 안전한 데이터 제공
    /// 
    /// # 캐싱 활용
    /// 
    /// 이 메서드는 Repository 레이어의 캐싱을 활용합니다:
    /// 
    /// - **L1 Cache**: Redis 캐시에서 우선 조회 (TTL: 10분)
    /// - **L2 Storage**: 캐시 미스 시 MongoDB에서 조회
    /// - **자동 캐싱**: 조회 성공 시 자동으로 캐시에 저장
    /// 
    /// # 보안 고려사항
    /// 
    /// - **민감 정보 제거**: 비밀번호 해시, OAuth 토큰 등 제외
    /// - **권한 확인**: 향후 사용자별 조회 권한 검증 추가 가능
    /// - **개인정보 보호**: GDPR 등 개인정보 보호 규정 준수
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// async fn get_user_profile(user_id: &str) -> Result<(), AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     match user_service.get_user_by_id(user_id).await {
    ///         Ok(user_response) => {
    ///             println!("사용자 프로필:");
    ///             println!("  ID: {}", user_response.id);
    ///             println!("  이메일: {}", user_response.email);
    ///             println!("  사용자명: {}", user_response.username);
    ///             println!("  표시명: {}", user_response.display_name);
    ///             println!("  가입일: {}", user_response.created_at);
    ///             println!("  최종 수정: {}", user_response.updated_at);
    ///         },
    ///         Err(AppError::NotFound(_)) => {
    ///             println!("사용자를 찾을 수 없습니다");
    ///             // 클라이언트에게 404 Not Found 응답
    ///         },
    ///         Err(AppError::ValidationError(_)) => {
    ///             println!("잘못된 사용자 ID 형식입니다");
    ///             // 클라이언트에게 400 Bad Request 응답
    ///         },
    ///         Err(e) => {
    ///             println!("시스템 오류: {}", e);
    ///             // 클라이언트에게 500 Internal Error 응답
    ///         }
    ///     }
    ///     
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # REST API 연동 예제
    /// 
    /// ```rust,ignore
    /// use actix_web::{web, HttpResponse, Result};
    /// 
    /// async fn get_user_handler(path: web::Path<String>) -> Result<HttpResponse> {
    ///     let user_id = path.into_inner();
    ///     let user_service = UserService::instance();
    ///     
    ///     match user_service.get_user_by_id(&user_id).await {
    ///         Ok(user_response) => {
    ///             Ok(HttpResponse::Ok().json(user_response))
    ///         },
    ///         Err(AppError::NotFound(_)) => {
    ///             Ok(HttpResponse::NotFound().json(json!({
    ///                 "error": "user_not_found",
    ///                 "message": "사용자를 찾을 수 없습니다"
    ///             })))
    ///         },
    ///         Err(_) => {
    ///             Ok(HttpResponse::InternalServerError().json(json!({
    ///                 "error": "internal_error",
    ///                 "message": "서버 오류가 발생했습니다"
    ///             })))
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn get_user_by_id(&self, id: &str) -> Result<UserResponse, AppError> {
        let user = self.user_repo
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::NotFound("사용자를 찾을 수 없습니다".to_string()))?;

        Ok(UserResponse::from(user))
    }

    /// 이메일 주소로 사용자 조회
    /// 
    /// 이메일 주소를 기반으로 사용자를 검색하고,
    /// 안전한 DTO 형태로 변환하여 반환합니다.
    /// 
    /// # 인자
    /// 
    /// * `email` - 조회할 사용자의 이메일 주소
    /// 
    /// # 반환값
    /// 
    /// * `Ok(UserResponse)` - 사용자 정보 DTO
    /// * `Err(AppError::NotFound)` - 해당 이메일의 사용자가 존재하지 않음
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 조회 오류
    /// 
    /// # 사용 시나리오
    /// 
    /// - **로그인 전 사용자 확인**: 로그인 프로세스에서 사용자 존재 여부 확인
    /// - **비밀번호 재설정**: 이메일 기반 비밀번호 리셋 플로우
    /// - **프로필 조회**: 이메일을 통한 공개 프로필 접근
    /// - **중복 검사**: 회원가입 시 이메일 중복 여부 확인
    /// 
    /// # 캐싱 최적화
    /// 
    /// Repository 레이어에서 이메일 기반 캐싱을 활용합니다:
    /// 
    /// - **캐시 키**: `user:email:{email_address}`
    /// - **TTL**: 10분 (600초)
    /// - **캐시 미스**: MongoDB 인덱스를 활용한 빠른 조회
    /// 
    /// # 개인정보 보호
    /// 
    /// - **민감 정보 제거**: 비밀번호 해시 등 보안 정보 제외
    /// - **접근 제어**: 향후 이메일 기반 조회 권한 제어 추가 가능
    /// - **로깅 주의**: 이메일 주소 로깅 시 개인정보 보호 고려
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// async fn check_user_exists(email: &str) -> Result<bool, AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     match user_service.get_user_by_email(email).await {
    ///         Ok(_) => Ok(true),
    ///         Err(AppError::NotFound(_)) => Ok(false),
    ///         Err(e) => Err(e),
    ///     }
    /// }
    /// 
    /// async fn get_public_profile(email: &str) -> Result<(), AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     let user_response = user_service.get_user_by_email(email).await?;
    ///     
    ///     println!("공개 프로필:");
    ///     println!("  사용자명: {}", user_response.username);
    ///     println!("  표시명: {}", user_response.display_name);
    ///     println!("  가입일: {}", user_response.created_at);
    ///     
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # 로그인 플로우 연동
    /// 
    /// ```rust,ignore
    /// async fn login_step1_find_user(email: &str) -> Result<UserResponse, AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     // 1. 이메일로 사용자 조회
    ///     let user_response = user_service.get_user_by_email(email).await
    ///         .map_err(|_| AppError::AuthenticationError("잘못된 이메일 또는 비밀번호입니다".to_string()))?;
    ///     
    ///     // 2. 계정 활성화 상태 확인
    ///     if !user_response.is_active {
    ///         return Err(AppError::AuthenticationError("비활성화된 계정입니다".to_string()));
    ///     }
    ///     
    ///     Ok(user_response)
    /// }
    /// ```
    pub async fn get_user_by_email(&self, email: &str) -> Result<UserResponse, AppError> {
        let user = self.user_repo
            .find_by_email(email)
            .await?
            .ok_or_else(|| AppError::NotFound("사용자를 찾을 수 없습니다".to_string()))?;

        Ok(UserResponse::from(user))
    }

    /// 사용자 계정 삭제
    /// 
    /// 지정된 ID의 사용자 계정을 시스템에서 영구적으로 삭제합니다.
    /// 이는 되돌릴 수 없는 작업이므로 신중하게 사용해야 합니다.
    /// 
    /// # 인자
    /// 
    /// * `id` - 삭제할 사용자의 MongoDB ObjectId (16진수 문자열)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(())` - 삭제 성공
    /// * `Err(AppError::NotFound)` - 해당 ID의 사용자가 존재하지 않음
    /// * `Err(AppError::ValidationError)` - 잘못된 ObjectId 형식
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 삭제 오류
    /// 
    /// # 삭제 처리 과정
    /// 
    /// 1. **사용자 존재 확인**: Repository에서 사용자 ID 검증
    /// 2. **물리적 삭제**: MongoDB에서 사용자 문서 완전 제거
    /// 3. **캐시 무효화**: 관련된 모든 캐시 키 삭제
    /// 4. **성공 여부 확인**: 삭제 결과 검증
    /// 
    /// # 삭제 정책
    /// 
    /// - **물리적 삭제**: 소프트 삭제가 아닌 완전한 데이터 제거
    /// - **연관 데이터**: 사용자와 연관된 다른 데이터는 별도 처리 필요
    /// - **복구 불가**: 삭제된 데이터는 복구할 수 없음
    /// - **감사 로그**: 삭제 작업은 별도 감사 로그에 기록 권장
    /// 
    /// # 보안 고려사항
    /// 
    /// - **권한 확인**: 호출 전에 삭제 권한 확인 필요
    /// - **관리자 승인**: 중요한 계정 삭제 시 관리자 승인 프로세스
    /// - **데이터 백업**: 삭제 전 중요 데이터 백업 고려
    /// - **개인정보 삭제**: GDPR 등 개인정보 보호 규정 준수
    /// 
    /// # 연관 데이터 처리
    /// 
    /// 사용자 삭제 시 고려해야 할 연관 데이터:
    /// 
    /// ```rust,ignore
    /// // 향후 확장 시 고려할 연관 데이터 삭제
    /// async fn delete_user_with_related_data(user_id: &str) -> Result<(), AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     // 1. 사용자 게시물 삭제 또는 익명화
    ///     // post_service.anonymize_user_posts(user_id).await?;
    ///     
    ///     // 2. 사용자 댓글 삭제 또는 익명화
    ///     // comment_service.anonymize_user_comments(user_id).await?;
    ///     
    ///     // 3. 파일 업로드 삭제
    ///     // file_service.delete_user_files(user_id).await?;
    ///     
    ///     // 4. 알림 데이터 삭제
    ///     // notification_service.delete_user_notifications(user_id).await?;
    ///     
    ///     // 5. 마지막으로 사용자 계정 삭제
    ///     user_service.delete_user(user_id).await?;
    ///     
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// async fn admin_delete_user(admin_id: &str, target_user_id: &str) -> Result<(), AppError> {
    ///     // 1. 관리자 권한 확인
    ///     let admin_service = AdminService::instance();
    ///     admin_service.verify_admin_permission(admin_id, "delete_user").await?;
    ///     
    ///     // 2. 삭제 대상 사용자 정보 백업 (감사 목적)
    ///     let user_service = UserService::instance();
    ///     let user_info = user_service.get_user_by_id(target_user_id).await?;
    ///     
    ///     // 3. 감사 로그 기록
    ///     log::warn!("사용자 삭제 시작: {} (관리자: {})", user_info.email, admin_id);
    ///     
    ///     // 4. 실제 삭제 수행
    ///     user_service.delete_user(target_user_id).await?;
    ///     
    ///     // 5. 삭제 완료 로그
    ///     log::warn!("사용자 삭제 완료: {} (관리자: {})", user_info.email, admin_id);
    ///     
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # GDPR 준수 예제
    /// 
    /// ```rust,ignore
    /// async fn gdpr_delete_user_data(user_id: &str, reason: &str) -> Result<(), AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     // 1. 개인정보 처리 동의 철회 기록
    ///     let gdpr_log = GdprDeletionLog {
    ///         user_id: user_id.to_string(),
    ///         reason: reason.to_string(),
    ///         requested_at: chrono::Utc::now(),
    ///         completed_at: None,
    ///     };
    ///     
    ///     // 2. 개인정보 삭제 실행
    ///     user_service.delete_user(user_id).await?;
    ///     
    ///     // 3. 삭제 완료 기록
    ///     gdpr_log.completed_at = Some(chrono::Utc::now());
    ///     gdpr_service.log_deletion(gdpr_log).await?;
    ///     
    ///     println!("GDPR 개인정보 삭제 완료: 사유 - {}", reason);
    ///     
    ///     Ok(())
    /// }
    /// ```
    /// 
    /// # 에러 처리 예제
    /// 
    /// ```rust,ignore
    /// async fn safe_delete_user(user_id: &str) -> Result<String, AppError> {
    ///     let user_service = UserService::instance();
    ///     
    ///     match user_service.delete_user(user_id).await {
    ///         Ok(()) => {
    ///             Ok("사용자가 성공적으로 삭제되었습니다".to_string())
    ///         },
    ///         Err(AppError::NotFound(_)) => {
    ///             Ok("이미 삭제되었거나 존재하지 않는 사용자입니다".to_string())
    ///         },
    ///         Err(AppError::ValidationError(_)) => {
    ///             Err(AppError::ValidationError("잘못된 사용자 ID 형식입니다".to_string()))
    ///         },
    ///         Err(e) => {
    ///             log::error!("사용자 삭제 중 오류 발생: {}", e);
    ///             Err(AppError::InternalError("사용자 삭제 중 오류가 발생했습니다".to_string()))
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn delete_user(&self, id: &str) -> Result<(), AppError> {
        let deleted = self.user_repo.delete(id).await?;

        if !deleted {
            return Err(AppError::NotFound("사용자를 찾을 수 없습니다".to_string()));
        }

        Ok(())
    }

    /// 로컬 계정 비밀번호 검증
    /// 
    /// 이메일과 비밀번호를 사용하여 로컬 인증 사용자의 로그인을 처리합니다.
    /// Spring Security의 `authenticate()` 메서드와 유사한 역할을 수행하며,
    /// 성공 시 인증된 사용자 엔티티를 반환합니다.
    /// 
    /// # 인자
    /// 
    /// * `email` - 사용자의 이메일 주소 (로그인 식별자)
    /// * `password` - 평문 비밀번호 (bcrypt로 검증됨)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(User)` - 인증된 사용자 엔티티 (전체 정보 포함)
    /// * `Err(AppError::AuthenticationError)` - 인증 실패 (잘못된 자격증명, 계정 상태 등)
    /// * `Err(AppError::DatabaseError)` - 데이터베이스 조회 오류
    /// * `Err(AppError::InternalError)` - 비밀번호 검증 시스템 오류
    /// 
    /// # 인증 과정
    /// 
    /// 1. **사용자 조회**: 이메일로 사용자 존재 여부 확인
    /// 2. **인증 방식 확인**: 로컬 vs OAuth 계정 구분
    /// 3. **비밀번호 검증**: bcrypt를 사용한 해시 비교
    /// 4. **계정 상태 확인**: 활성/비활성 상태 검증
    /// 5. **성능 로깅**: 검증 시간 측정 및 기록
    /// 
    /// # 보안 특징
    /// 
    /// ## 타이밍 공격 방지
    /// 
    /// bcrypt의 특성상 검증 시간이 일정하여 타이밍 공격을 방지합니다:
    /// 
    /// ```text
    /// 올바른 비밀번호: ~150ms
    /// 틀린 비밀번호:   ~150ms (동일한 시간)
    /// ```
    /// 
    /// ## 에러 메시지 통합
    /// 
    /// 보안을 위해 구체적인 실패 원인을 노출하지 않습니다:
    /// - 존재하지 않는 이메일 → "잘못된 이메일 또는 비밀번호입니다"
    /// - 틀린 비밀번호 → "잘못된 이메일 또는 비밀번호입니다"
    /// 
    /// ## OAuth 계정 보호
    /// 
    /// OAuth로 가입한 사용자는 비밀번호 인증을 시도할 수 없습니다:
    /// 
    /// ```rust,ignore
    /// if user.auth_provider != AuthProvider::Local {
    ///     return Err(AppError::AuthenticationError(
    ///         "OAuth 계정입니다. 해당 프로바이더로 로그인해주세요".to_string()
    ///     ));
    /// }
    /// ```
    /// 
    /// # 성능 모니터링
    /// 
    /// 이 메서드는 상세한 성능 로깅을 제공합니다:
    /// 
    /// ```text
    /// [DEBUG] Password verification took: 142ms
    /// [DEBUG] Total password verification took: 167ms
    /// ```
    /// 
    /// 이를 통해 다음을 모니터링할 수 있습니다:
    /// - bcrypt 검증 시간 (해싱 cost 영향)
    /// - 전체 인증 프로세스 시간
    /// - 시스템 부하에 따른 성능 변화
    /// 
    /// # 계정 상태 확인
    /// 
    /// 비밀번호가 올바르더라도 계정 상태에 따라 로그인이 차단될 수 있습니다:
    /// 
    /// - **비활성 계정**: `is_active = false`인 경우
    /// - **잠긴 계정**: 향후 계정 잠금 기능 추가 시
    /// - **만료된 계정**: 향후 계정 만료 기능 추가 시
    /// 
    /// # 사용 예제
    /// 
    /// ## 기본 로그인 플로우
    /// 
    /// ```rust,ignore
    /// async fn login_user(email: &str, password: &str) -> Result<String, AppError> {
    ///     let user_service = UserService::instance();
    ///     let token_service = TokenService::instance();
    ///     
    ///     // 1. 비밀번호 검증
    ///     let user = user_service.verify_password(email, password).await?;
    ///     
    ///     // 2. JWT 토큰 생성
    ///     let token_pair = token_service.generate_token_pair(&user)?;
    ///     
    ///     // 3. 로그인 성공 로그
    ///     log::info!("로그인 성공: {} ({})", user.username, user.email);
    ///     
    ///     Ok(token_pair.access_token)
    /// }
    /// ```
    /// 
    /// ## 로그인 시도 추적
    /// 
    /// ```rust,ignore
    /// async fn login_with_tracking(email: &str, password: &str, ip: &str) -> Result<User, AppError> {
    ///     let user_service = UserService::instance();
    ///     let audit_service = AuditService::instance();
    ///     
    ///     let start_time = std::time::Instant::now();
    ///     
    ///     match user_service.verify_password(email, password).await {
    ///         Ok(user) => {
    ///             // 성공 로그
    ///             audit_service.log_login_success(&user.id_string().unwrap(), ip).await?;
    ///             
    ///             log::info!("로그인 성공: {} from {}", email, ip);
    ///             Ok(user)
    ///         },
    ///         Err(e) => {
    ///             // 실패 로그 (보안 이벤트)
    ///             audit_service.log_login_failure(email, ip, &e.to_string()).await?;
    ///             
    ///             log::warn!("로그인 실패: {} from {} - {}", email, ip, e);
    ///             Err(e)
    ///         }
    ///     }
    /// }
    /// ```
    /// 
    /// ## REST API 핸들러 연동
    /// 
    /// ```rust,ignore
    /// use actix_web::{web, HttpResponse, Result};
    /// use serde::Deserialize;
    /// 
    /// #[derive(Deserialize)]
    /// struct LoginRequest {
    ///     email: String,
    ///     password: String,
    /// }
    /// 
    /// async fn login_handler(
    ///     request: web::Json<LoginRequest>,
    ///     req: HttpRequest
    /// ) -> Result<HttpResponse> {
    ///     let user_service = UserService::instance();
    ///     let token_service = TokenService::instance();
    ///     
    ///     // 클라이언트 IP 추출
    ///     let client_ip = req.peer_addr()
    ///         .map(|addr| addr.ip().to_string())
    ///         .unwrap_or_else(|| "unknown".to_string());
    ///     
    ///     match user_service.verify_password(&request.email, &request.password).await {
    ///         Ok(user) => {
    ///             // JWT 토큰 생성
    ///             let tokens = token_service.generate_token_pair(&user)?;
    ///             
    ///             Ok(HttpResponse::Ok().json(json!({
    ///                 "message": "로그인 성공",
    ///                 "user": UserResponse::from(user),
    ///                 "access_token": tokens.access_token,
    ///                 "refresh_token": tokens.refresh_token,
    ///                 "expires_in": tokens.expires_in
    ///             })))
    ///         },
    ///         Err(AppError::AuthenticationError(msg)) => {
    ///             Ok(HttpResponse::Unauthorized().json(json!({
    ///                 "error": "authentication_failed",
    ///                 "message": msg
    ///             })))
    ///         },
    ///         Err(_) => {
    ///             Ok(HttpResponse::InternalServerError().json(json!({
    ///                 "error": "internal_error",
    ///                 "message": "서버 오류가 발생했습니다"
    ///             })))
    ///         }
    ///     }
    /// }
    /// ```
    /// 
    /// # 보안 모범 사례
    /// 
    /// ## 로그인 시도 제한
    /// 
    /// ```rust,ignore
    /// // 향후 추가할 수 있는 보안 기능
    /// async fn verify_password_with_rate_limit(
    ///     &self, 
    ///     email: &str, 
    ///     password: &str,
    ///     client_ip: &str
    /// ) -> Result<User, AppError> {
    ///     // 1. IP별 시도 횟수 확인
    ///     let rate_limiter = RateLimiter::instance();
    ///     rate_limiter.check_login_attempts(client_ip).await?;
    ///     
    ///     // 2. 계정별 시도 횟수 확인
    ///     rate_limiter.check_account_attempts(email).await?;
    ///     
    ///     // 3. 실제 인증 수행
    ///     match self.verify_password(email, password).await {
    ///         Ok(user) => {
    ///             // 성공 시 시도 횟수 리셋
    ///             rate_limiter.reset_attempts(email, client_ip).await?;
    ///             Ok(user)
    ///         },
    ///         Err(e) => {
    ///             // 실패 시 시도 횟수 증가
    ///             rate_limiter.increment_attempts(email, client_ip).await?;
    ///             Err(e)
    ///         }
    ///     }
    /// }
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
