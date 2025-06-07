//! # 사용자 응답 DTO 구현
//!
//! 이 모듈은 사용자 도메인의 핵심 응답 DTO들을 정의합니다.
//! 데이터베이스 엔티티에서 클라이언트 응답으로의 변환과 
//! 인증 관련 응답 구조를 담당합니다.
//!
//! ## 변환 계층
//!
//! ```text
//! Database Entity (User) 
//!     ↓ From trait
//! Response DTO (UserResponse)
//!     ↓ JSON Serialization  
//! HTTP Response Body
//! ```
//!
//! ## 민감한 정보 처리
//!
//! 응답 DTO는 다음 원칙을 따릅니다:
//! - **비밀번호**: 절대 노출하지 않음
//! - **내부 ObjectId**: 문자열로 변환하여 노출
//! - **역할 정보**: 문자열 배열로 단순화
//! - **OAuth 상태**: 편의 필드로 계산하여 제공

use serde::{Deserialize, Serialize};
use mongodb::bson::DateTime;
use crate::domain::entities::users::user::User;
use crate::config::AuthProvider;

/// 표준 사용자 정보 응답 DTO
///
/// 이 구조체는 클라이언트에게 사용자 정보를 안전하게 전달하기 위한 응답 형식입니다.
/// 데이터베이스 엔티티에서 민감한 정보(비밀번호, 해시 등)를 제외하고
/// 클라이언트가 필요로 하는 정보만을 포함합니다.
///
/// # 사용 시나리오
///
/// - **프로필 조회**: `/api/v1/users/{id}` GET 요청 응답
/// - **사용자 목록**: `/api/v1/users` GET 요청의 배열 요소
/// - **검색 결과**: 사용자 검색 API의 결과 아이템
/// - **중첩 응답**: 다른 엔티티의 연관 사용자 정보
///
/// # JSON 응답 예제
///
/// ```json
/// {
///   "id": "507f1f77bcf86cd799439011",
///   "email": "user@example.com", 
///   "username": "john_doe",
///   "display_name": "John Doe",
///   "auth_provider": "Local",
///   "is_oauth_user": false,
///   "is_active": true,
///   "is_email_verified": true,
///   "roles": ["user", "premium"],
///   "profile_image_url": "https://example.com/avatar.jpg",
///   "last_login_at": "2024-06-07T12:00:00Z",
///   "created_at": "2024-06-01T10:00:00Z", 
///   "updated_at": "2024-06-07T12:00:00Z"
/// }
/// ```
///
/// # 보안 고려사항
///
/// - 비밀번호 해시나 솔트는 절대 포함되지 않음
/// - 내부 MongoDB ObjectId는 문자열로 변환하여 노출
/// - 사용자의 권한 레벨에 따른 필드 필터링은 상위 레이어에서 처리
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    /// 사용자 고유 식별자 (MongoDB ObjectId의 문자열 표현)
    ///
    /// MongoDB의 ObjectId를 16진수 문자열로 변환한 값입니다.
    /// 클라이언트에서 사용자를 식별할 때 사용됩니다.
    pub id: String,
    
    /// 사용자 이메일 주소
    ///
    /// - 로그인 인증에 사용
    /// - 알림 발송 주소
    /// - 시스템 내 유일성 보장
    pub email: String,
    
    /// 사용자명 (로그인 ID)
    ///
    /// - URL 친화적 식별자
    /// - 프로필 페이지 경로에 사용 (예: /users/john_doe)
    /// - 대소문자 구분 없이 유일성 보장
    pub username: String,
    
    /// 화면 표시용 이름
    ///
    /// - UI에서 사용자에게 보여지는 이름
    /// - 유니코드 문자 지원 (한글, 이모지 등)
    /// - 중복 허용
    pub display_name: String,
    
    /// 인증 제공자 (로컬, Google, GitHub 등)
    ///
    /// 사용자가 어떤 방식으로 가입했는지를 나타냅니다.
    /// 클라이언트에서 적절한 로그인 방식을 안내할 때 사용됩니다.
    pub auth_provider: AuthProvider,
    
    /// OAuth 사용자 여부 (편의 필드)
    ///
    /// `auth_provider`가 Local이 아닌 경우 true입니다.
    /// 클라이언트에서 비밀번호 변경 기능 표시 여부 등을 결정할 때 사용됩니다.
    pub is_oauth_user: bool,
    
    /// 계정 활성화 상태
    ///
    /// - false인 경우 로그인 불가
    /// - 관리자에 의한 계정 비활성화 또는 임시 정지 상태
    pub is_active: bool,
    
    /// 이메일 인증 완료 여부
    ///
    /// - 회원가입 후 이메일 인증 완료 상태
    /// - 일부 기능은 이메일 인증 완료 후에만 사용 가능
    pub is_email_verified: bool,
    
    /// 사용자 역할 목록
    ///
    /// - 권한 관리를 위한 역할 정보
    /// - 예: ["user", "admin", "premium", "moderator"]
    /// - 클라이언트에서 UI 요소 표시/숨김 결정에 사용
    pub roles: Vec<String>,
    
    /// 프로필 이미지 URL (선택사항)
    ///
    /// - 사용자 아바타 이미지의 공개 URL
    /// - None인 경우 기본 아바타 사용
    /// - OAuth 로그인 시 제공자의 프로필 이미지 사용 가능
    pub profile_image_url: Option<String>,
    
    /// 마지막 로그인 시간 (선택사항)
    ///
    /// - 보안 목적으로 사용자에게 표시
    /// - 비정상적인 로그인 감지에 활용
    pub last_login_at: Option<DateTime>,
    
    /// 계정 생성 시간
    ///
    /// 사용자 가입 일시입니다. 변경되지 않는 값입니다.
    pub created_at: DateTime,
    
    /// 마지막 정보 수정 시간
    ///
    /// 프로필 정보나 설정이 마지막으로 변경된 시간입니다.
    pub updated_at: DateTime,
}

impl From<User> for UserResponse {
    /// User 엔티티를 UserResponse로 변환
    ///
    /// 이 구현은 데이터베이스 엔티티에서 API 응답 DTO로의 안전한 변환을 담당합니다.
    /// 민감한 정보는 제외하고 클라이언트가 필요로 하는 정보만을 포함합니다.
    ///
    /// # 변환 규칙
    ///
    /// - **ObjectId → String**: MongoDB ObjectId를 16진수 문자열로 변환
    /// - **OAuth 상태 계산**: `auth_provider`가 Local이 아니면 `is_oauth_user = true`
    /// - **민감 정보 제외**: 비밀번호, 해시, 솔트 등은 포함하지 않음
    /// - **Optional 필드 유지**: None 값은 그대로 전달
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// let user: User = user_repository.find_by_id("123").await?;
    /// let response: UserResponse = UserResponse::from(user);
    /// // 또는
    /// let response: UserResponse = user.into();
    /// ```
    fn from(user: User) -> Self {
        let User {
            id,
            email,
            username,
            display_name,
            auth_provider,
            is_active,
            is_email_verified,
            roles,
            profile_image_url,
            last_login_at,
            created_at,
            updated_at,
            ..  // 비밀번호 등 민감한 필드는 명시적으로 제외
        } = user;
        
        // OAuth 사용자 여부 계산 (Local 이외의 모든 제공자는 OAuth)
        let is_oauth_user = !matches!(auth_provider, AuthProvider::Local);
        
        Self {
            id: id.map(|id| id.to_hex()).unwrap_or_default(),
            email,
            username,
            display_name,
            auth_provider,
            is_oauth_user,
            is_active,
            is_email_verified,
            roles,
            profile_image_url,
            last_login_at,
            created_at,
            updated_at,
        }
    }
}

/// 사용자 생성 완료 응답 DTO
///
/// 회원가입 API의 성공 응답으로 사용됩니다.
/// 생성된 사용자 정보와 함께 성공 메시지를 포함하여
/// 클라이언트에게 명확한 피드백을 제공합니다.
///
/// # 사용 시나리오
///
/// - **회원가입 완료**: `/api/v1/users` POST 요청의 성공 응답
/// - **관리자 사용자 생성**: 관리자 패널에서 사용자 생성 시
///
/// # JSON 응답 예제
///
/// ```json
/// {
///   "user": {
///     "id": "507f1f77bcf86cd799439011",
///     "email": "newuser@example.com",
///     "username": "new_user",
///     "display_name": "New User",
///     "auth_provider": "Local",
///     "is_oauth_user": false,
///     "is_active": true,
///     "is_email_verified": false,
///     "roles": ["user"],
///     "profile_image_url": null,
///     "last_login_at": null,
///     "created_at": "2024-06-07T12:00:00Z",
///     "updated_at": "2024-06-07T12:00:00Z"
///   },
///   "message": "회원가입이 완료되었습니다. 이메일을 확인해주세요."
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserResponse {
    /// 생성된 사용자 정보
    ///
    /// 방금 생성된 사용자의 전체 정보입니다.
    /// 클라이언트가 즉시 사용자 정보를 표시할 수 있도록 합니다.
    pub user: UserResponse,
    
    /// 성공 메시지
    ///
    /// 사용자에게 표시할 친화적인 메시지입니다.
    /// 이메일 인증 안내, 다음 단계 설명 등을 포함할 수 있습니다.
    pub message: String,
}

/// 로그인 성공 응답 DTO (JWT 토큰 포함)
///
/// 로그인 API의 성공 응답으로 사용됩니다.
/// OAuth 2.0 Bearer Token 스펙을 따르는 형식으로
/// JWT 액세스 토큰과 선택적 리프레시 토큰을 포함합니다.
///
/// # 사용 시나리오
///
/// - **로컬 로그인**: 이메일/비밀번호 로그인 성공
/// - **OAuth 로그인**: Google, GitHub 등 외부 제공자 로그인 성공  
/// - **토큰 갱신**: 리프레시 토큰을 통한 액세스 토큰 갱신
///
/// # JSON 응답 예제
///
/// ```json
/// {
///   "user": {
///     "id": "507f1f77bcf86cd799439011",
///     "email": "user@example.com",
///     "username": "john_doe",
///     "display_name": "John Doe",
///     "auth_provider": "Local",
///     "is_oauth_user": false,
///     "is_active": true,
///     "is_email_verified": true,
///     "roles": ["user"],
///     "profile_image_url": null,
///     "last_login_at": "2024-06-07T11:30:00Z",
///     "created_at": "2024-06-01T10:00:00Z",
///     "updated_at": "2024-06-07T12:00:00Z"
///   },
///   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///   "token_type": "Bearer",
///   "expires_in": 3600,
///   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
/// }
/// ```
///
/// # 보안 고려사항
///
/// - **HTTPS 전용**: 토큰은 반드시 HTTPS를 통해서만 전송
/// - **토큰 만료**: `expires_in` 값을 클라이언트에서 확인하여 토큰 갱신 처리
/// - **리프레시 토큰**: 보안상 중요하므로 별도 저장소에 안전하게 보관
/// - **로그**: 액세스 토큰은 로그에 출력하지 않도록 주의
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    /// 로그인한 사용자 정보
    ///
    /// 인증에 성공한 사용자의 전체 프로필 정보입니다.
    /// 클라이언트가 사용자 정보를 저장하고 UI에 표시할 수 있도록 합니다.
    pub user: UserResponse,
    
    /// JWT 액세스 토큰
    ///
    /// - API 요청 시 Authorization 헤더에 포함
    /// - 형식: `Authorization: Bearer {access_token}`
    /// - 만료 시간은 `expires_in` 필드 참조
    pub access_token: String,
    
    /// 토큰 타입 (항상 "Bearer")
    ///
    /// OAuth 2.0 스펙에 따른 토큰 타입입니다.
    /// 클라이언트가 Authorization 헤더를 구성할 때 사용합니다.
    pub token_type: String,
    
    /// 토큰 만료 시간 (초 단위)
    ///
    /// 액세스 토큰이 만료되는 시간을 초 단위로 나타냅니다.
    /// 클라이언트는 이 시간을 기준으로 토큰 갱신을 준비해야 합니다.
    pub expires_in: i64,
    
    /// 리프레시 토큰 (선택사항)
    ///
    /// - 액세스 토큰 갱신에 사용
    /// - 더 긴 만료 시간을 가짐
    /// - 보안상 중요하므로 안전한 저장소에 보관 필요
    /// - None인 경우 JSON에서 제외됨
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl LoginResponse {
    /// 기본 로그인 응답 생성 (리프레시 토큰 없음)
    ///
    /// 일반적인 로그인 시나리오에서 사용되는 생성자입니다.
    /// 리프레시 토큰이 필요하지 않은 경우나 별도로 관리하는 경우 사용합니다.
    ///
    /// # 인자
    ///
    /// * `user` - 인증된 사용자 엔티티
    /// * `access_token` - 생성된 JWT 액세스 토큰
    /// * `expires_in` - 토큰 만료 시간 (초 단위)
    ///
    /// # 반환값
    ///
    /// 리프레시 토큰이 None인 LoginResponse 인스턴스
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// let user = authenticate_user(credentials).await?;
    /// let token = jwt_service.generate_token(&user)?;
    /// let response = LoginResponse::new(user, token, 3600); // 1시간 만료
    /// ```
    pub fn new(user: User, access_token: String, expires_in: i64) -> Self {
        Self {
            user: UserResponse::from(user),
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: None,
        }
    }
    
    /// 리프레시 토큰을 포함한 로그인 응답 생성
    ///
    /// 장기간 인증 유지가 필요한 클라이언트(모바일 앱 등)를 위해
    /// 리프레시 토큰을 함께 제공하는 경우 사용합니다.
    ///
    /// # 인자
    ///
    /// * `user` - 인증된 사용자 엔티티
    /// * `access_token` - 생성된 JWT 액세스 토큰
    /// * `expires_in` - 액세스 토큰 만료 시간 (초 단위)
    /// * `refresh_token` - 생성된 리프레시 토큰
    ///
    /// # 반환값
    ///
    /// 리프레시 토큰을 포함한 LoginResponse 인스턴스
    ///
    /// # 예제
    ///
    /// ```rust,ignore
    /// let user = authenticate_user(credentials).await?;
    /// let access_token = jwt_service.generate_access_token(&user)?;
    /// let refresh_token = jwt_service.generate_refresh_token(&user)?;
    /// 
    /// let response = LoginResponse::with_refresh_token(
    ///     user, 
    ///     access_token, 
    ///     3600,           // 액세스 토큰 1시간
    ///     refresh_token
    /// );
    /// ```
    ///
    /// # 보안 고려사항
    ///
    /// - 리프레시 토큰은 데이터베이스나 Redis에 별도 저장 권장
    /// - 리프레시 토큰 사용 시 기존 토큰 무효화 고려
    /// - 클라이언트는 리프레시 토큰을 안전한 저장소에 보관해야 함
    pub fn with_refresh_token(user: User, access_token: String, expires_in: i64, refresh_token: String) -> Self {
        Self {
            user: UserResponse::from(user),
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some(refresh_token),
        }
    }
}
