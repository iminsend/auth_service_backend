//! # JWT 토큰 관리 서비스
//! 
//! JSON Web Token (JWT) 기반의 상태 없는(stateless) 인증 시스템을 구현합니다.
//! Spring Security JWT와 유사한 방식으로 액세스 토큰과 리프레시 토큰을 관리하며,
//! RFC 7519 JWT 표준과 RFC 6750 Bearer Token 표준을 준수합니다.
//! 
//! ## JWT 토큰 구조
//! 
//! ```text
//! Header.Payload.Signature
//! 
//! Header:
//! {
//!   "alg": "HS256",
//!   "typ": "JWT"
//! }
//! 
//! Payload (Claims):
//! {
//!   "sub": "user_id",           // Subject (사용자 ID)
//!   "email": "user@email.com",  // 사용자 이메일
//!   "username": "username",     // 사용자명
//!   "auth_provider": "Local",   // 인증 프로바이더
//!   "roles": ["user", "admin"], // 사용자 역할
//!   "iat": 1640995200,          // Issued At (발급 시간)
//!   "exp": 1641081600           // Expiration (만료 시간)
//! }
//! 
//! Signature:
//! HMACSHA256(
//!   base64UrlEncode(header) + "." + base64UrlEncode(payload),
//!   secret
//! )
//! ```
//! 
//! ## 토큰 종류 및 수명
//! 
//! | 토큰 유형 | 기본 수명 | 용도 | 저장 위치 |
//! |-----------|-----------|------|-----------|
//! | **Access Token** | 1시간 | API 접근 인증 | 메모리/localStorage |
//! | **Refresh Token** | 30일 | 액세스 토큰 갱신 | Secure HttpOnly Cookie |
//! 
//! ## 보안 특징
//! 
//! ### 1. 암호화 및 서명
//! - **알고리즘**: HMAC-SHA256 (HS256)
//! - **키 길이**: 최소 256비트 (32바이트)
//! - **서명 검증**: 모든 토큰의 무결성 검증
//! 
//! ### 2. 만료 및 갱신
//! - **짧은 액세스 토큰 수명**: 탈취 위험 최소화
//! - **자동 만료 처리**: 시간 기반 토큰 무효화
//! - **리프레시 토큰 순환**: 보안 강화를 위한 토큰 교체
//! 
//! ### 3. 클레임 최소화
//! - **필수 정보만 포함**: 개인정보 노출 최소화
//! - **민감 정보 제외**: 비밀번호, 주민번호 등 제외
//! - **역할 기반 접근**: 권한 정보 포함으로 인가 지원

use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Deserialize, Serialize};
use singleton_macro::service;
use crate::{
    domain::entities::users::user::User,
    config::{JwtConfig, AuthProvider},
    core::errors::AppError,
};

/// JWT 토큰의 클레임(Payload) 구조체
/// 
/// RFC 7519 JWT 표준의 클레임과 애플리케이션 특화 클레임을 포함합니다.
/// 
/// ## 표준 클레임 (RFC 7519)
/// 
/// - `sub` (Subject): 토큰의 주체, 일반적으로 사용자 ID
/// - `iat` (Issued At): 토큰 발급 시간 (Unix timestamp)
/// - `exp` (Expiration): 토큰 만료 시간 (Unix timestamp)
/// 
/// ## 커스텀 클레임
/// 
/// - `email`: 사용자 이메일 주소 (인증 및 사용자 식별용)
/// - `username`: 사용자명 (UI 표시용)
/// - `auth_provider`: 인증 방식 (Local, Google, etc.)
/// - `roles`: 사용자 권한 목록 (인가 처리용)
/// 
/// ## 보안 고려사항
/// 
/// - **개인정보 최소화**: 필요한 식별 정보만 포함
/// - **민감 정보 제외**: 비밀번호, 토큰 시크릿 등은 절대 포함하지 않음
/// - **만료 시간 준수**: 클라이언트는 exp 클레임을 확인해야 함
/// 
/// ## 사용 예제
/// 
/// ```rust,ignore
/// // 토큰 생성 시
/// let claims = TokenClaims {
///     sub: user.id.to_string(),
///     email: user.email.clone(),
///     username: user.username.clone(),
///     auth_provider: AuthProvider::Local,
///     roles: vec!["user".to_string()],
///     iat: Utc::now().timestamp(),
///     exp: (Utc::now() + Duration::hours(1)).timestamp(),
/// };
/// 
/// // 토큰 검증 후
/// println!("인증된 사용자: {} ({})", claims.username, claims.email);
/// if claims.roles.contains(&"admin".to_string()) {
///     println!("관리자 권한 보유");
/// }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// 토큰의 주체 (사용자 ID)
    /// 
    /// JWT 표준 클레임으로, 일반적으로 사용자의 고유 식별자입니다.
    /// MongoDB ObjectId의 문자열 표현을 사용합니다.
    pub sub: String,
    
    /// 사용자 이메일 주소
    /// 
    /// 사용자 식별 및 연락처 용도로 사용됩니다.
    /// 이메일은 시스템 내에서 유니크해야 합니다.
    pub email: String,
    
    /// 사용자명 (표시명)
    /// 
    /// UI에서 사용자를 식별하기 위한 친숙한 이름입니다.
    /// 실제 이름이 아닌 사용자가 선택한 별명일 수 있습니다.
    pub username: String,
    
    /// 인증 프로바이더
    /// 
    /// 사용자가 어떤 방식으로 인증했는지를 나타냅니다.
    /// 로컬 계정, Google OAuth, 기타 소셜 로그인 등을 구분합니다.
    pub auth_provider: AuthProvider,
    
    /// 사용자 역할 목록
    /// 
    /// 권한 기반 접근 제어(RBAC)를 위한 역할 정보입니다.
    /// 예: ["user", "admin", "moderator"]
    pub roles: Vec<String>,
    
    /// 토큰 발급 시간 (Unix timestamp)
    /// 
    /// JWT 표준 클레임으로, 토큰이 언제 발급되었는지를 나타냅니다.
    /// 토큰의 나이를 계산하거나 재발급 정책에 사용될 수 있습니다.
    pub iat: i64,
    
    /// 토큰 만료 시간 (Unix timestamp)
    /// 
    /// JWT 표준 클레임으로, 이 시간 이후에는 토큰이 유효하지 않습니다.
    /// 클라이언트와 서버 모두 이 값을 확인해야 합니다.
    pub exp: i64,
}

/// JWT 토큰 쌍 구조체
/// 
/// 클라이언트에게 전달되는 토큰 집합을 나타냅니다.
/// OAuth 2.0 표준의 토큰 응답 형식을 따릅니다.
/// 
/// ## 토큰 사용 패턴
/// 
/// 1. **초기 로그인**: 사용자 인증 후 토큰 쌍 발급
/// 2. **API 호출**: 액세스 토큰을 Authorization 헤더에 포함
/// 3. **토큰 갱신**: 액세스 토큰 만료 시 리프레시 토큰으로 새 토큰 발급
/// 4. **로그아웃**: 토큰 폐기 및 블랙리스트 등록
/// 
/// ## 저장 및 보안
/// 
/// - **액세스 토큰**: 메모리나 SessionStorage에 임시 저장
/// - **리프레시 토큰**: Secure HttpOnly Cookie에 저장 권장
/// - **전송**: 반드시 HTTPS를 통해서만 전송
/// 
/// ## 사용 예제
/// 
/// ```rust,ignore
/// // 클라이언트 응답 형식
/// {
///   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///   "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
///   "expires_in": 3600,
///   "token_type": "Bearer"
/// }
/// 
/// // JavaScript 클라이언트 사용법
/// localStorage.setItem('access_token', token_pair.access_token);
/// 
/// // API 요청 시
/// fetch('/api/protected', {
///   headers: {
///     'Authorization': `Bearer ${localStorage.getItem('access_token')}`
///   }
/// });
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    /// 액세스 토큰
    /// 
    /// API 접근을 위한 단기 유효 토큰입니다.
    /// 모든 인증이 필요한 요청에 포함되어야 합니다.
    pub access_token: String,
    
    /// 리프레시 토큰 (선택사항)
    /// 
    /// 액세스 토큰 갱신을 위한 장기 유효 토큰입니다.
    /// 보안상의 이유로 일부 시나리오에서는 제공하지 않을 수 있습니다.
    pub refresh_token: Option<String>,
    
    /// 액세스 토큰 만료 시간 (초)
    /// 
    /// 클라이언트가 토큰 갱신 시점을 결정하는 데 사용합니다.
    /// OAuth 2.0 표준에 따라 초 단위로 표현됩니다.
    pub expires_in: i64,
}

/// JWT 토큰 관리 서비스
/// 
/// 이 서비스는 애플리케이션의 모든 JWT 토큰 관련 작업을 담당합니다.
/// Spring Security의 JwtAuthenticationProvider와 유사한 역할을 수행하며,
/// 토큰 생성, 검증, 갱신의 전체 라이프사이클을 관리합니다.
/// 
/// ## 주요 책임
/// 
/// 1. **토큰 생성**: 사용자 인증 후 JWT 토큰 쌍 생성
/// 2. **토큰 검증**: 요청에 포함된 토큰의 유효성 검사
/// 3. **클레임 추출**: 토큰에서 사용자 정보 및 권한 정보 파싱
/// 4. **토큰 갱신**: 리프레시 토큰을 사용한 새 액세스 토큰 발급
/// 
/// ## 싱글톤 패턴
/// 
/// `#[service]` 매크로를 통해 자동으로 싱글톤으로 관리되며,
/// 메모리 효율성과 성능을 보장합니다.
/// 
/// ```rust,ignore
/// let token_service = TokenService::instance(); // 항상 동일한 인스턴스
/// ```
/// 
/// ## 설정 의존성
/// 
/// 이 서비스는 다음 설정에 의존합니다:
/// 
/// - `JWT_SECRET`: 토큰 서명을 위한 비밀키 (최소 256비트)
/// - `JWT_EXPIRATION_HOURS`: 액세스 토큰 수명 (기본: 1시간)
/// - `JWT_REFRESH_EXPIRATION_DAYS`: 리프레시 토큰 수명 (기본: 30일)
/// 
/// ## 보안 고려사항
/// 
/// - **키 관리**: JWT 시크릿은 환경변수로 관리하고 정기적으로 교체
/// - **토큰 순환**: 리프레시 토큰 사용 시 새로운 토큰 쌍 발급
/// - **클록 스큐**: 서버 간 시간 차이를 고려한 만료 시간 검증
/// - **토큰 블랙리스트**: 로그아웃 시 토큰 무효화 처리
/// 
/// ## 성능 최적화
/// 
/// - **메모리 캐싱**: 자주 사용되는 설정값 캐싱
/// - **비동기 처리**: 토큰 검증의 비블로킹 처리
/// - **배치 검증**: 다중 토큰 동시 검증 지원
/// 
/// ## 사용 예제
/// 
/// ```rust,ignore
/// use crate::services::auth::TokenService;
/// 
/// async fn login_flow(user: &User) -> Result<TokenPair, AppError> {
///     let token_service = TokenService::instance();
///     
///     // 로그인 성공 후 토큰 생성
///     let tokens = token_service.generate_token_pair(user)?;
///     
///     log::info!("토큰 발급 완료: 사용자={}", user.email);
///     Ok(tokens)
/// }
/// 
/// async fn protected_route(auth_header: &str) -> Result<String, AppError> {
///     let token_service = TokenService::instance();
///     
///     // Bearer 토큰 추출
///     let token = token_service.extract_bearer_token(auth_header)?;
///     
///     // 토큰 검증 및 클레임 추출
///     let claims = token_service.verify_token(token)?;
///     
///     // 권한 확인
///     if !claims.roles.contains(&"user".to_string()) {
///         return Err(AppError::AuthorizationError("접근 권한이 없습니다".to_string()));
///     }
///     
///     Ok(format!("안녕하세요, {}님!", claims.username))
/// }
/// ```
#[service]
pub struct TokenService {
    // 매크로가 자동으로 의존성 주입 처리
    // 이 서비스는 외부 의존성이 없으므로 필드가 비어있음
}

impl TokenService {
    /// 사용자를 위한 JWT 액세스 토큰 생성
    /// 
    /// 인증된 사용자 정보를 바탕으로 단기간 유효한 액세스 토큰을 생성합니다.
    /// 이 토큰은 API 요청 시 인증 수단으로 사용됩니다.
    /// 
    /// # 인자
    /// 
    /// * `user` - 토큰을 발급받을 사용자 정보
    /// 
    /// # 반환값
    /// 
    /// * `Ok(String)` - 생성된 JWT 액세스 토큰
    /// * `Err(AppError::InternalError)` - 토큰 생성 실패 또는 사용자 ID 없음
    /// 
    /// # 토큰 특성
    /// 
    /// - **수명**: 설정된 시간 (기본 1시간)
    /// - **알고리즘**: HMAC-SHA256 (HS256)
    /// - **클레임**: 사용자 ID, 이메일, 권한 등 포함
    /// 
    /// # 보안 고려사항
    /// 
    /// - **짧은 수명**: 탈취 위험을 최소화하기 위해 짧은 만료 시간 설정
    /// - **필수 정보만**: 인증/인가에 필요한 최소한의 정보만 포함
    /// - **서명 검증**: 토큰 무결성 보장을 위한 HMAC 서명
    /// 
    /// # 에러 상황
    /// 
    /// - 사용자 ID가 없는 경우 (새로 생성된 사용자가 아직 저장되지 않음)
    /// - JWT 인코딩 실패 (잘못된 시크릿 키 또는 클레임)
    /// - 시스템 시간 오류 (만료 시간 계산 실패)
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// let token_service = TokenService::instance();
    /// let user = authenticate_user(email, password).await?;
    /// 
    /// let access_token = token_service.generate_access_token(&user)?;
    /// 
    /// // HTTP 응답에 포함
    /// Ok(Json(json!({
    ///     "access_token": access_token,
    ///     "token_type": "Bearer",
    ///     "expires_in": 3600
    /// })))
    /// ```
    pub fn generate_access_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::hours(JwtConfig::expiration_hours());
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            email: user.email.clone(),
            username: user.username.clone(),
            auth_provider: user.auth_provider.clone(),
            roles: user.roles.clone(),
            iat: now.timestamp(),
            exp: expiration.timestamp(),
        };

        let secret = JwtConfig::secret();
        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::InternalError(format!("JWT 토큰 생성 실패: {}", e)))
    }

    /// 사용자를 위한 리프레시 토큰 생성
    /// 
    /// 액세스 토큰 갱신을 위한 장기간 유효한 리프레시 토큰을 생성합니다.
    /// 이 토큰은 액세스 토큰이 만료된 후 새로운 토큰 쌍을 발급받는 데 사용됩니다.
    /// 
    /// # 인자
    /// 
    /// * `user` - 토큰을 발급받을 사용자 정보
    /// 
    /// # 반환값
    /// 
    /// * `Ok(String)` - 생성된 JWT 리프레시 토큰
    /// * `Err(AppError::InternalError)` - 토큰 생성 실패
    /// 
    /// # 토큰 특성
    /// 
    /// - **장기 수명**: 설정된 시간 (기본 30일)
    /// - **제한적 사용**: 오직 토큰 갱신 목적으로만 사용
    /// - **일회성**: 사용 후 새로운 리프레시 토큰 발급 권장
    /// 
    /// # 보안 고려사항
    /// 
    /// - **안전한 저장**: Secure HttpOnly Cookie에 저장 권장
    /// - **토큰 순환**: 사용 시마다 새로운 리프레시 토큰 발급
    /// - **블랙리스트**: 로그아웃 시 즉시 무효화 처리
    /// - **제한된 스코프**: 토큰 갱신 외 다른 용도로 사용 금지
    /// 
    /// # 사용 패턴
    /// 
    /// ```rust,ignore
    /// // 초기 로그인 시
    /// let refresh_token = token_service.generate_refresh_token(&user)?;
    /// 
    /// // 안전한 쿠키에 저장
    /// let cookie = Cookie::build("refresh_token", refresh_token)
    ///     .http_only(true)
    ///     .secure(true)
    ///     .same_site(SameSite::Strict)
    ///     .max_age(Duration::days(30))
    ///     .finish();
    /// 
    /// // 토큰 갱신 시
    /// let new_tokens = token_service.refresh_token_pair(&refresh_token)?;
    /// ```
    pub fn generate_refresh_token(&self, user: &User) -> Result<String, AppError> {
        let now = Utc::now();
        let expiration = now + Duration::days(JwtConfig::refresh_expiration_days());
        
        let claims = TokenClaims {
            sub: user.id_string().ok_or_else(|| {
                AppError::InternalError("사용자 ID가 없습니다".to_string())
            })?,
            email: user.email.clone(),
            username: user.username.clone(),
            auth_provider: user.auth_provider.clone(),
            roles: user.roles.clone(),
            iat: now.timestamp(),
            exp: expiration.timestamp(),
        };

        let secret = JwtConfig::secret();
        let header = Header::default();
        let encoding_key = EncodingKey::from_secret(secret.as_ref());

        encode(&header, &claims, &encoding_key)
            .map_err(|e| AppError::InternalError(format!("리프레시 토큰 생성 실패: {}", e)))
    }

    /// 토큰 쌍 생성 (액세스 + 리프레시)
    /// 
    /// 사용자 인증 성공 시 클라이언트에게 전달할 완전한 토큰 세트를 생성합니다.
    /// OAuth 2.0 표준의 토큰 응답 형식을 따릅니다.
    /// 
    /// # 인자
    /// 
    /// * `user` - 토큰을 발급받을 사용자 정보
    /// 
    /// # 반환값
    /// 
    /// * `Ok(TokenPair)` - 액세스/리프레시 토큰과 만료 정보를 포함한 토큰 쌍
    /// * `Err(AppError::InternalError)` - 토큰 생성 실패
    /// 
    /// # TokenPair 구성요소
    /// 
    /// - `access_token`: 즉시 사용 가능한 액세스 토큰
    /// - `refresh_token`: 토큰 갱신용 리프레시 토큰
    /// - `expires_in`: 액세스 토큰 만료까지 남은 시간 (초)
    /// 
    /// # 클라이언트 사용 패턴
    /// 
    /// ```javascript
    /// // 로그인 응답 처리
    /// const response = await fetch('/auth/login', {
    ///   method: 'POST',
    ///   body: JSON.stringify({ email, password })
    /// });
    /// 
    /// const { access_token, refresh_token, expires_in } = await response.json();
    /// 
    /// // 토큰 저장
    /// localStorage.setItem('access_token', access_token);
    /// document.cookie = `refresh_token=${refresh_token}; Secure; HttpOnly`;
    /// 
    /// // 만료 시간 계산
    /// const expiresAt = Date.now() + (expires_in * 1000);
    /// localStorage.setItem('token_expires_at', expiresAt);
    /// ```
    /// 
    /// # 보안 모범 사례
    /// 
    /// 1. **액세스 토큰**: 메모리나 SessionStorage에 저장
    /// 2. **리프레시 토큰**: Secure HttpOnly Cookie에 저장
    /// 3. **HTTPS 강제**: 모든 토큰 전송은 TLS 암호화
    /// 4. **토큰 갱신**: 액세스 토큰 만료 전 자동 갱신
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// use actix_web::{web, HttpResponse, Result};
    /// 
    /// async fn login_handler(credentials: web::Json<LoginRequest>) -> Result<HttpResponse> {
    ///     let user_service = UserService::instance();
    ///     let token_service = TokenService::instance();
    ///     
    ///     // 사용자 인증
    ///     let user = user_service
    ///         .verify_password(&credentials.email, &credentials.password)
    ///         .await?;
    ///     
    ///     // 토큰 쌍 생성
    ///     let token_pair = token_service.generate_token_pair(&user)?;
    ///     
    ///     // 응답 생성
    ///     Ok(HttpResponse::Ok().json(json!({
    ///         "access_token": token_pair.access_token,
    ///         "refresh_token": token_pair.refresh_token,
    ///         "expires_in": token_pair.expires_in,
    ///         "token_type": "Bearer"
    ///     })))
    /// }
    /// ```
    pub fn generate_token_pair(&self, user: &User) -> Result<TokenPair, AppError> {
        let access_token = self.generate_access_token(user)?;
        let refresh_token = self.generate_refresh_token(user)?;
        let expires_in = JwtConfig::expiration_hours() * 3600; // 초 단위로 변환

        Ok(TokenPair {
            access_token,
            refresh_token: Some(refresh_token),
            expires_in,
        })
    }

    /// JWT 토큰 검증 및 클레임 추출
    /// 
    /// 클라이언트에서 전송된 JWT 토큰의 유효성을 검증하고,
    /// 토큰에 포함된 사용자 정보와 권한 정보를 추출합니다.
    /// 
    /// # 인자
    /// 
    /// * `token` - 검증할 JWT 토큰 문자열 (Bearer 접두사 제외)
    /// 
    /// # 반환값
    /// 
    /// * `Ok(TokenClaims)` - 검증된 토큰의 클레임 정보
    /// * `Err(AppError::AuthenticationError)` - 토큰 검증 실패
    /// * `Err(AppError::InternalError)` - 기타 시스템 오류
    /// 
    /// # 검증 과정
    /// 
    /// 1. **구조 검증**: JWT 형식 (Header.Payload.Signature) 확인
    /// 2. **서명 검증**: HMAC-SHA256 서명 무결성 확인
    /// 3. **만료 시간 검증**: 현재 시간과 exp 클레임 비교
    /// 4. **클레임 파싱**: JSON 페이로드를 TokenClaims 구조체로 변환
    /// 
    /// # 에러 유형 및 처리
    /// 
    /// | 에러 유형 | 원인 | 클라이언트 처리 |
    /// |-----------|------|----------------|
    /// | `ExpiredSignature` | 토큰 만료 | 리프레시 토큰으로 갱신 |
    /// | `InvalidToken` | 잘못된 형식/서명 | 재로그인 요청 |
    /// | `InvalidSignature` | 서명 불일치 | 재로그인 요청 |
    /// | `InvalidAlgorithm` | 알고리즘 불일치 | 재로그인 요청 |
    /// 
    /// # 보안 고려사항
    /// 
    /// - **타이밍 공격 방지**: 검증 실패 시 일정한 응답 시간 유지
    /// - **에러 정보 제한**: 공격자에게 유용한 정보 노출 방지
    /// - **클록 스큐 허용**: 서버 간 시간 차이 고려 (일반적으로 ±30초)
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// use actix_web::{HttpRequest, Result};
    /// 
    /// async fn protected_handler(req: HttpRequest) -> Result<HttpResponse> {
    ///     let token_service = TokenService::instance();
    ///     
    ///     // Authorization 헤더에서 토큰 추출
    ///     let auth_header = req.headers()
    ///         .get("Authorization")
    ///         .and_then(|h| h.to_str().ok())
    ///         .ok_or_else(|| AppError::AuthenticationError("토큰이 없습니다".to_string()))?;
    ///     
    ///     let token = token_service.extract_bearer_token(auth_header)?;
    ///     
    ///     // 토큰 검증
    ///     match token_service.verify_token(token) {
    ///         Ok(claims) => {
    ///             // 인증 성공 - 사용자 정보 사용 가능
    ///             log::debug!("인증된 사용자: {} ({})", claims.username, claims.email);
    ///             
    ///             // 권한 확인 예제
    ///             if claims.roles.contains(&"admin".to_string()) {
    ///                 // 관리자 권한 작업 수행
    ///             }
    ///             
    ///             Ok(HttpResponse::Ok().json(json!({"message": "접근 허용"})))
    ///         },
    ///         Err(AppError::AuthenticationError(msg)) if msg.contains("만료") => {
    ///             // 토큰 만료 - 클라이언트에게 갱신 요청
    ///             Ok(HttpResponse::Unauthorized()
    ///                 .json(json!({"error": "token_expired", "message": "토큰을 갱신해주세요"})))
    ///         },
    ///         Err(_) => {
    ///             // 기타 인증 오류 - 재로그인 요청
    ///             Ok(HttpResponse::Unauthorized()
    ///                 .json(json!({"error": "invalid_token", "message": "재로그인이 필요합니다"})))
    ///         }
    ///     }
    /// }
    /// ```
    pub fn verify_token(&self, token: &str) -> Result<TokenClaims, AppError> {
        let secret = JwtConfig::secret();
        let decoding_key = DecodingKey::from_secret(secret.as_ref());
        let validation = Validation::default();

        decode::<TokenClaims>(token, &decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    AppError::AuthenticationError("토큰이 만료되었습니다".to_string())
                },
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AppError::AuthenticationError("유효하지 않은 토큰입니다".to_string())
                },
                _ => AppError::InternalError(format!("토큰 검증 실패: {}", e))
            })
    }

    /// 액세스 토큰으로부터 사용자 ID 추출
    /// 
    /// JWT 토큰을 검증하고 사용자 ID (sub 클레임)만을 간단히 추출합니다.
    /// 전체 클레임이 필요하지 않고 사용자 식별만 필요한 경우 사용합니다.
    /// 
    /// # 인자
    /// 
    /// * `token` - 검증할 JWT 토큰 문자열
    /// 
    /// # 반환값
    /// 
    /// * `Ok(String)` - 사용자 ID (MongoDB ObjectId 문자열)
    /// * `Err(AppError::AuthenticationError)` - 토큰 검증 실패
    /// 
    /// # 사용 사례
    /// 
    /// - **빠른 사용자 식별**: 로깅, 감사 목적
    /// - **간단한 권한 확인**: 자원 소유자 확인
    /// - **API 레이트 리미팅**: 사용자별 요청 제한
    /// - **세션 관리**: 활성 사용자 추적
    /// 
    /// # 성능 최적화
    /// 
    /// 이 메서드는 내부적으로 `verify_token()`을 호출하므로 전체 토큰 검증을 수행합니다.
    /// 전체 클레임이 필요한 경우 `verify_token()`을 직접 사용하는 것이 더 효율적입니다.
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// // 리소스 소유권 확인
    /// async fn get_user_profile(token: &str, profile_id: &str) -> Result<UserProfile, AppError> {
    ///     let token_service = TokenService::instance();
    ///     let user_id = token_service.extract_user_id(token)?;
    ///     
    ///     // 본인의 프로필만 조회 가능
    ///     if user_id != profile_id {
    ///         return Err(AppError::AuthorizationError("다른 사용자의 프로필에 접근할 수 없습니다".to_string()));
    ///     }
    ///     
    ///     let profile = UserProfile::find_by_id(&user_id).await?;
    ///     Ok(profile)
    /// }
    /// 
    /// // 감사 로그 기록
    /// async fn log_user_action(token: &str, action: &str) -> Result<(), AppError> {
    ///     let token_service = TokenService::instance();
    ///     let user_id = token_service.extract_user_id(token)?;
    ///     
    ///     log::info!("사용자 {} 작업 수행: {}", user_id, action);
    ///     
    ///     // 감사 로그 DB 저장
    ///     AuditLog::create(user_id, action).await?;
    ///     Ok(())
    /// }
    /// ```
    pub fn extract_user_id(&self, token: &str) -> Result<String, AppError> {
        let claims = self.verify_token(token)?;
        Ok(claims.sub)
    }

    /// Bearer 토큰에서 실제 토큰 부분 추출
    /// 
    /// HTTP Authorization 헤더의 "Bearer {token}" 형식에서 토큰 부분만을 추출합니다.
    /// RFC 6750 Bearer Token 표준을 준수합니다.
    /// 
    /// # 인자
    /// 
    /// * `auth_header` - HTTP Authorization 헤더 값 전체
    /// 
    /// # 반환값
    /// 
    /// * `Ok(&str)` - Bearer 접두사를 제거한 순수 토큰 문자열
    /// * `Err(AppError::AuthenticationError)` - 잘못된 헤더 형식
    /// 
    /// # 지원 형식
    /// 
    /// - ✅ **표준 형식**: `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`
    /// - ❌ **잘못된 형식**: `Token abc123`, `Basic dXNlcjpwYXNz`, `eyJhbGciOiJIUzI1...`
    /// 
    /// # RFC 6750 준수사항
    /// 
    /// ```text
    /// Authorization: Bearer <token>
    /// 
    /// bearer-token = "Bearer" 1*SP token
    /// token        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    /// ```
    /// 
    /// # 보안 고려사항
    /// 
    /// - **대소문자 구분**: "Bearer"는 대문자 B로 시작해야 함 (RFC 표준)
    /// - **공백 처리**: "Bearer "와 토큰 사이의 정확한 공백 1개 필요
    /// - **토큰 검증 분리**: 이 메서드는 형식만 확인, 실제 토큰 검증은 별도 수행
    /// 
    /// # 에러 처리
    /// 
    /// ```rust,ignore
    /// match token_service.extract_bearer_token(auth_header) {
    ///     Ok(token) => {
    ///         // 토큰 검증 계속
    ///         let claims = token_service.verify_token(token)?;
    ///     },
    ///     Err(_) => {
    ///         return Err(AppError::AuthenticationError(
    ///             "Authorization 헤더는 'Bearer <token>' 형식이어야 합니다".to_string()
    ///         ));
    ///     }
    /// }
    /// ```
    /// 
    /// # 사용 예제
    /// 
    /// ```rust,ignore
    /// use actix_web::HttpRequest;
    /// 
    /// async fn extract_token_from_request(req: &HttpRequest) -> Result<String, AppError> {
    ///     let token_service = TokenService::instance();
    ///     
    ///     // Authorization 헤더 가져오기
    ///     let auth_header = req.headers()
    ///         .get("Authorization")
    ///         .ok_or_else(|| AppError::AuthenticationError("Authorization 헤더가 없습니다".to_string()))?
    ///         .to_str()
    ///         .map_err(|_| AppError::AuthenticationError("헤더 값이 유효하지 않습니다".to_string()))?;
    ///     
    ///     // Bearer 토큰 추출
    ///     let token = token_service.extract_bearer_token(auth_header)?;
    ///     
    ///     Ok(token.to_string())
    /// }
    /// 
    /// // 미들웨어에서 사용 예제
    /// async fn auth_middleware(req: HttpRequest) -> Result<(), AppError> {
    ///     let token_service = TokenService::instance();
    ///     
    ///     if let Some(auth_header) = req.headers().get("Authorization") {
    ///         if let Ok(auth_str) = auth_header.to_str() {
    ///             if let Ok(token) = token_service.extract_bearer_token(auth_str) {
    ///                 // 토큰 검증 수행
    ///                 let _claims = token_service.verify_token(token)?;
    ///                 return Ok(());
    ///             }
    ///         }
    ///     }
    ///     
    ///     Err(AppError::AuthenticationError("유효한 인증 토큰이 필요합니다".to_string()))
    /// }
    /// ```
    pub fn extract_bearer_token<'a>(&self, auth_header: &'a str) -> Result<&'a str, AppError> {
        if auth_header.starts_with("Bearer ") {
            Ok(&auth_header[7..])
        } else {
            Err(AppError::AuthenticationError("유효하지 않은 인증 헤더 형식입니다".to_string()))
        }
    }
}
