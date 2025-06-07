//! # User Data Transfer Objects Module
//!
//! 사용자 관련 API의 요청/응답 데이터 구조를 정의하는 모듈입니다.
//! Spring Framework의 User 관련 DTO와 동일한 역할을 수행하며,
//! 클라이언트와 서버 간의 사용자 데이터 교환을 위한 계약을 정의합니다.
//!
//! ## Spring Framework와의 비교
//!
//! ### Spring Security UserDetails vs 이 시스템
//!
//! | Spring Security | 이 시스템 | 역할 |
//! |-----------------|-----------|------|
//! | `UserDetails` | `UserResponse` | 인증된 사용자 정보 |
//! | `UserDetailsService` | User Repository | 사용자 정보 조회 |
//! | `@RequestBody CreateUserDto` | `CreateUserRequest` | 회원가입 요청 |
//! | `@ResponseBody UserDto` | `UserResponse` | 사용자 정보 응답 |
//! | `JwtAuthenticationToken` | `LoginResponse` | 인증 토큰 응답 |
//! | `OAuth2User` | `GoogleTokenResponse` | OAuth 사용자 정보 |
//!
//! ## 모듈 구조
//!
//! ```text
//! users/
//! ├── request/                    # 클라이언트 → 서버 요청 DTO
//! │   ├── create_user.rs         # 회원가입 요청
//! │   ├── login_request.rs       # 로그인 요청 (향후 추가)
//! │   ├── update_profile.rs      # 프로필 수정 요청 (향후 추가)
//! │   └── password_change.rs     # 비밀번호 변경 요청 (향후 추가)
//! └── response/                   # 서버 → 클라이언트 응답 DTO
//!     ├── user_response.rs       # 기본 사용자 응답
//!     ├── google_oauth_response.rs # OAuth 관련 응답
//!     ├── auth_response.rs       # 인증 관련 응답 (향후 추가)
//!     └── profile_response.rs    # 프로필 관련 응답 (향후 추가)
//! ```
//!
//! ## Spring Boot User Controller와의 비교
//!
//! ### Spring Boot 예제
//! ```java
//! @RestController
//! @RequestMapping("/api/v1/users")
//! @PreAuthorize("hasRole('USER')")
//! public class UserController {
//!     
//!     @PostMapping("/register")
//!     public ResponseEntity<CreateUserResponse> register(
//!         @Valid @RequestBody CreateUserRequest request
//!     ) {
//!         User user = userService.createUser(request);
//!         return ResponseEntity.ok(CreateUserResponse.from(user));
//!     }
//!     
//!     @PostMapping("/login")
//!     public ResponseEntity<LoginResponse> login(
//!         @Valid @RequestBody LoginRequest request
//!     ) {
//!         Authentication auth = authenticationManager.authenticate(
//!             new UsernamePasswordAuthenticationToken(
//!                 request.getEmail(), 
//!                 request.getPassword()
//!             )
//!         );
//!         
//!         String token = jwtTokenProvider.generateToken(auth);
//!         return ResponseEntity.ok(LoginResponse.builder()
//!             .accessToken(token)
//!             .user(UserResponse.from(auth.getPrincipal()))
//!             .build());
//!     }
//!     
//!     @GetMapping("/me")
//!     @PreAuthorize("isAuthenticated()")
//!     public ResponseEntity<UserResponse> getCurrentUser(
//!         Authentication authentication
//!     ) {
//!         User user = (User) authentication.getPrincipal();
//!         return ResponseEntity.ok(UserResponse.from(user));
//!     }
//! }
//! ```
//!
//! ### 이 시스템 예제
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, Result};
//! use crate::domain::dto::users::{CreateUserRequest, UserResponse, LoginResponse};
//! use crate::core::errors::AppError;
//! use crate::services::UserService;
//! 
//! /// 회원가입 핸들러 (Spring의 /register와 동일)
//! pub async fn register(
//!     request: web::Json<CreateUserRequest>  // @RequestBody와 동일
//! ) -> Result<HttpResponse, AppError> {
//!     // 1. 유효성 검증 (Spring의 @Valid와 동일)
//!     let validated_request = request.into_inner();
//!     
//!     // 2. 서비스 호출
//!     let user = UserService::instance()
//!         .create_user(validated_request).await?;
//!     
//!     // 3. 응답 생성
//!     let response = CreateUserResponse {
//!         user: UserResponse::from(user),
//!         message: "회원가입이 완료되었습니다".to_string(),
//!     };
//!     
//!     Ok(HttpResponse::Created().json(response))
//! }
//! 
//! /// 로그인 핸들러 (Spring의 /login과 동일)
//! pub async fn login(
//!     request: web::Json<LoginRequest>
//! ) -> Result<HttpResponse, AppError> {
//!     let auth_result = AuthService::instance()
//!         .authenticate(request.into_inner()).await?;
//!     
//!     let response = LoginResponse::with_refresh_token(
//!         auth_result.user,
//!         auth_result.access_token,
//!         auth_result.expires_in,
//!         auth_result.refresh_token,
//!     );
//!     
//!     Ok(HttpResponse::Ok().json(response))
//! }
//! 
//! /// 현재 사용자 정보 조회 (Spring의 /me와 동일)
//! pub async fn get_current_user(
//!     user_id: web::ReqData<String>  // JWT에서 추출된 사용자 ID
//! ) -> Result<HttpResponse, AppError> {
//!     let user = UserService::instance()
//!         .find_by_id(&user_id).await?;
//!     
//!     Ok(HttpResponse::Ok().json(UserResponse::from(user)))
//! }
//! ```
//!
//! ## 요청 DTO (Request DTOs)
//!
//! ### CreateUserRequest - 회원가입 요청
//!
//! Spring Security의 회원가입 폼과 동일한 역할을 수행합니다.
//!
//! #### 주요 특징:
//! - **강력한 유효성 검증**: 이메일, 사용자명, 비밀번호 강도 검사
//! - **비밀번호 확인**: 클라이언트에서 입력한 비밀번호 일치 검증
//! - **커스텀 검증**: 사용자명 형식, 비밀번호 복잡성 규칙
//! - **한국어 에러 메시지**: 사용자 친화적인 검증 실패 메시지
//!
//! #### 사용 예제:
//! ```rust,ignore
//! use crate::domain::dto::users::CreateUserRequest;
//! use validator::Validate;
//! 
//! let request = CreateUserRequest {
//!     email: "user@example.com".to_string(),
//!     username: "john_doe".to_string(),
//!     display_name: "John Doe".to_string(),
//!     password: "SecurePass123!".to_string(),
//!     password_confirm: "SecurePass123!".to_string(),
//! };
//! 
//! // Spring의 @Valid와 동일한 검증
//! if let Err(errors) = request.validate() {
//!     return Err(AppError::ValidationError(format!("{:?}", errors)));
//! }
//! ```
//!
//! #### 검증 규칙:
//! - **이메일**: RFC 5322 표준 형식 검증
//! - **사용자명**: 3-30자, 영문/숫자/언더스코어만 허용
//! - **표시이름**: 1-50자, 모든 문자 허용
//! - **비밀번호**: 최소 8자, 대소문자+숫자 포함 필수
//! - **비밀번호 확인**: 원본 비밀번호와 일치 검증
//!
//! ## 응답 DTO (Response DTOs)
//!
//! ### UserResponse - 기본 사용자 정보
//!
//! Spring Security의 UserDetails 인터페이스와 유사한 역할을 수행합니다.
//!
//! #### 주요 특징:
//! - **보안**: 비밀번호 해시, 내부 ID 등 민감한 정보 제외
//! - **OAuth 지원**: 로컬/소셜 로그인 구분 정보 포함
//! - **역할 기반 권한**: 사용자 권한 목록 제공
//! - **상태 정보**: 계정 활성화, 이메일 인증 상태
//!
//! #### JSON 응답 예제:
//! ```json
//! {
//!   "id": "507f1f77bcf86cd799439011",
//!   "email": "user@example.com",
//!   "username": "john_doe",
//!   "display_name": "John Doe",
//!   "auth_provider": "Local",
//!   "is_oauth_user": false,
//!   "is_active": true,
//!   "is_email_verified": true,
//!   "roles": ["USER"],
//!   "profile_image_url": null,
//!   "last_login_at": "2024-01-15T10:30:00Z",
//!   "created_at": "2024-01-01T00:00:00Z",
//!   "updated_at": "2024-01-15T10:30:00Z"
//! }
//! ```
//!
//! ### LoginResponse - 인증 성공 응답
//!
//! Spring Security의 JWT 인증 응답과 동일한 형태입니다.
//!
//! #### 주요 특징:
//! - **JWT 토큰**: Bearer 토큰과 만료 시간 정보
//! - **사용자 정보**: 인증된 사용자의 기본 정보
//! - **리프레시 토큰**: 토큰 갱신을 위한 별도 토큰 (선택적)
//! - **표준 형식**: OAuth 2.0 Bearer Token 스펙 준수
//!
//! #### JSON 응답 예제:
//! ```json
//! {
//!   "user": {
//!     "id": "507f1f77bcf86cd799439011",
//!     "email": "user@example.com",
//!     "username": "john_doe",
//!     "display_name": "John Doe",
//!     "auth_provider": "Local",
//!     "is_oauth_user": false,
//!     "is_active": true,
//!     "is_email_verified": true,
//!     "roles": ["USER"]
//!   },
//!   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "token_type": "Bearer",
//!   "expires_in": 3600,
//!   "refresh_token": "def50200e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
//! }
//! ```
//!
//! ### CreateUserResponse - 회원가입 성공 응답
//!
//! #### JSON 응답 예제:
//! ```json
//! {
//!   "user": {
//!     "id": "507f1f77bcf86cd799439011",
//!     "email": "user@example.com",
//!     "username": "john_doe",
//!     "display_name": "John Doe",
//!     "auth_provider": "Local",
//!     "is_oauth_user": false,
//!     "is_active": true,
//!     "is_email_verified": false,
//!     "roles": ["USER"]
//!   },
//!   "message": "회원가입이 완료되었습니다"
//! }
//! ```
//!
//! ## OAuth 관련 DTO
//!
//! ### GoogleTokenResponse - Google OAuth 토큰 교환
//!
//! Spring Security OAuth2의 OAuth2AccessToken과 유사한 역할입니다.
//!
//! #### 사용 시나리오:
//! 1. 클라이언트가 Google 로그인 페이지에서 인증
//! 2. Google이 인증 코드를 콜백 URL로 전송
//! 3. 서버가 인증 코드를 액세스 토큰으로 교환
//! 4. `GoogleTokenResponse`로 토큰 정보 수신
//!
//! #### JSON 응답 예제:
//! ```json
//! {
//!   "access_token": "ya29.a0AfH6SMC...",
//!   "token_type": "Bearer",
//!   "expires_in": 3599,
//!   "refresh_token": "1//04z8...",
//!   "scope": "openid email profile"
//! }
//! ```
//!
//! ### OAuthLoginUrlResponse - OAuth 로그인 URL 생성
//!
//! #### JSON 응답 예제:
//! ```json
//! {
//!   "login_url": "https://accounts.google.com/o/oauth2/auth?client_id=...",
//!   "state": "random-csrf-token-123"
//! }
//! ```
//!
//! ## 실제 API 플로우 예제
//!
//! ### 1. 로컬 회원가입 플로우
//!
//! ```rust,ignore
//! // 1. 클라이언트 요청
//! POST /api/v1/users/register
//! Content-Type: application/json
//! 
//! {
//!   "email": "user@example.com",
//!   "username": "john_doe",
//!   "display_name": "John Doe",
//!   "password": "SecurePass123!",
//!   "password_confirm": "SecurePass123!"
//! }
//! 
//! // 2. 서버 응답 (성공)
//! HTTP/1.1 201 Created
//! Content-Type: application/json
//! 
//! {
//!   "user": {
//!     "id": "507f1f77bcf86cd799439011",
//!     "email": "user@example.com",
//!     "username": "john_doe",
//!     "display_name": "John Doe",
//!     "auth_provider": "Local",
//!     "is_oauth_user": false,
//!     "is_active": true,
//!     "is_email_verified": false,
//!     "roles": ["USER"]
//!   },
//!   "message": "회원가입이 완료되었습니다"
//! }
//! ```
//!
//! ### 2. Google OAuth 로그인 플로우
//!
//! ```rust,ignore
//! // 1단계: 로그인 URL 요청
//! GET /api/v1/auth/google/login
//! 
//! // 응답: OAuthLoginUrlResponse
//! {
//!   "login_url": "https://accounts.google.com/o/oauth2/auth?...",
//!   "state": "csrf-token-123"
//! }
//! 
//! // 2단계: Google 콜백 처리 (내부적으로 GoogleTokenResponse 사용)
//! GET /api/v1/auth/google/callback?code=...&state=...
//! 
//! // 응답: LoginResponse
//! {
//!   "user": {
//!     "id": "507f1f77bcf86cd799439011",
//!     "email": "user@gmail.com",
//!     "username": "user_gmail_com",
//!     "display_name": "User Name",
//!     "auth_provider": "Google",
//!     "is_oauth_user": true,
//!     "is_active": true,
//!     "is_email_verified": true,
//!     "roles": ["USER"]
//!   },
//!   "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
//!   "token_type": "Bearer",
//!   "expires_in": 3600
//! }
//! ```
//!
//! ## 향후 확장 계획
//!
//! ### 추가 예정 Request DTO
//! ```text
//! request/
//! ├── create_user.rs           ✅ 구현 완료
//! ├── login_request.rs         📋 계획 중
//! ├── update_profile.rs        📋 계획 중
//! ├── change_password.rs       📋 계획 중
//! ├── reset_password.rs        📋 계획 중
//! ├── verify_email.rs          📋 계획 중
//! └── deactivate_account.rs    📋 계획 중
//! ```
//!
//! ### 추가 예정 Response DTO
//! ```text
//! response/
//! ├── user_response.rs         ✅ 구현 완료
//! ├── google_oauth_response.rs ✅ 구현 완료
//! ├── auth_response.rs         📋 계획 중 (토큰 갱신 등)
//! ├── profile_response.rs      📋 계획 중 (상세 프로필)
//! ├── user_list_response.rs    📋 계획 중 (사용자 목록 + 페이지네이션)
//! └── activity_response.rs     📋 계획 중 (사용자 활동 내역)
//! ```
//!
//! ## 베스트 프랙티스
//!
//! ### 1. 보안 고려사항
//! - **민감 정보 제외**: Response DTO에서 비밀번호, 해시 등 제외
//! - **역할 기반 필터링**: 사용자 권한에 따른 정보 노출 제어
//! - **입력 검증**: 모든 Request DTO에 적절한 유효성 검증 적용
//!
//! ### 2. 성능 최적화
//! - **필요한 필드만**: 불필요한 데이터 전송 방지
//! - **캐시 친화적**: 자주 변경되지 않는 데이터는 별도 응답으로 분리
//! - **페이지네이션**: 대량 데이터 조회 시 페이지네이션 적용
//!
//! ### 3. API 진화
//! - **하위 호환성**: 기존 API 호환성 유지하면서 새 기능 추가
//! - **버전 관리**: 필요 시 v2 네임스페이스로 새 버전 제공
//! - **문서화**: 모든 필드와 제약사항 명확히 문서화

pub mod request;
pub mod response;

// Re-exports for convenience
pub use request::*;
pub use response::*;
