//! # 인증 및 보안 서비스 모듈
//! 
//! 애플리케이션의 인증, 인가, 보안을 담당하는 서비스들을 제공합니다.
//! Spring Security의 아키텍처를 참고하여 설계되었으며,
//! JWT 기반 토큰 인증과 OAuth 2.0 소셜 로그인을 지원합니다.
//! 
//! ## 아키텍처 개요
//! 
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                    Authentication Layer                      │
//! ├─────────────────────┬──────────────────────┬─────────────────┤
//! │   JWT Token Auth    │    OAuth 2.0 Auth    │   Local Auth    │
//! │                     │                      │                 │
//! │ ┌─────────────────┐ │ ┌──────────────────┐ │ ┌─────────────┐ │
//! │ │  TokenService   │ │ │ GoogleAuthService│ │ │ UserService │ │
//! │ │                 │ │ │                  │ │ │             │ │
//! │ │ • Access Token  │ │ │ • Authorization  │ │ │ • Password  │ │
//! │ │ • Refresh Token │ │ │ • User Info      │ │ │ • Validation│ │
//! │ │ • Verification  │ │ │ • Account Link   │ │ │ • bcrypt    │ │
//! │ └─────────────────┘ │ └──────────────────┘ │ └─────────────┘ │
//! └─────────────────────┴──────────────────────┴─────────────────┘
//!                                 │
//!                                 ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Authorization                           │
//! │  • Role-based Access Control (RBAC)                         │
//! │  • Resource-level Permissions                               │
//! │  • Dynamic Authorization Rules                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//! 
//! ## 제공 서비스
//! 
//! ### JWT 토큰 관리 ([`TokenService`])
//! 
//! JSON Web Token 기반의 상태 없는(stateless) 인증을 제공합니다.
//! Spring Security JWT와 유사한 방식으로 동작합니다.
//! 
//! **주요 기능:**
//! - **액세스 토큰 생성**: 짧은 수명의 인증 토큰
//! - **리프레시 토큰 관리**: 장기간 유효한 갱신 토큰
//! - **토큰 검증**: 서명 검증 및 만료 시간 확인
//! - **클레임 추출**: 사용자 정보 및 권한 정보 파싱
//! 
//! **보안 특징:**
//! - HMAC-SHA256 서명 알고리즘
//! - 환경별 토큰 수명 설정
//! - 자동 만료 처리
//! - Bearer 토큰 표준 준수
//! 
//! ### Google OAuth 인증 ([`GoogleAuthService`])
//! 
//! Google OAuth 2.0 프로토콜을 통한 소셜 로그인을 제공합니다.
//! Spring Security OAuth2와 유사한 플로우를 구현합니다.
//! 
//! **OAuth 2.0 플로우:**
//! 1. **Authorization URL 생성**: 사용자를 Google 인증 페이지로 리다이렉트
//! 2. **Authorization Code 수신**: Google로부터 인증 코드 받기
//! 3. **Access Token 교환**: 인증 코드를 액세스 토큰으로 교환
//! 4. **사용자 정보 조회**: Google API를 통한 프로필 정보 획득
//! 5. **계정 연동 또는 생성**: 기존 계정 확인 후 로그인/회원가입 처리
//! 
//! **보안 강화:**
//! - CSRF 방지를 위한 State 매개변수
//! - PKCE (Proof Key for Code Exchange) 지원 가능
//! - Nonce 값을 통한 재생 공격 방지
//! - HTTPS 강제 및 Secure Cookie 사용
//! 
//! ## 인증 플로우 패턴
//! 
//! ### 1. 로컬 인증 (Email + Password)
//! 
//! ```text
//! Client                    Server                   Database
//!   │                        │                         │
//!   │ POST /auth/login       │                         │
//!   │ {email, password}      │                         │
//!   ├─────────────────────→  │                         │
//!   │                        │ 1. Validate email       │
//!   │                        ├───────────────────────→ │
//!   │                        │ 2. Verify password      │
//!   │                        │ 3. Check user status    │
//!   │                        │                         │
//!   │                        ├─ TokenService ──────────┤
//!   │                        │ 4. Generate JWT         │
//!   │                        │                         │
//!   │ 200 {access_token,     │                         │
//!   │      refresh_token}    │                         │
//!   │←────────────────────── │                         │
//! ```
//! 
//! ### 2. OAuth 2.0 인증 (Google)
//! 
//! ```text
//! Client              Server              Google OAuth
//!   │                   │                      │
//!   │ GET /auth/google  │                      │
//!   ├─────────────────→ │                      │
//!   │                   │ 1. Generate state    │
//!   │                   │ 2. Build auth URL    │
//!   │ 302 Redirect to   │                      │
//!   │ Google OAuth      │                      │
//!   │←───────────────── │                      │
//!   │                   │                      │
//!   │ User authorizes   │                      │
//!   ├─────────────────────────────────────────→│
//!   │                   │                      │
//!   │ GET /auth/google/callback                │
//!   │ ?code=xxx&state=yyy                      │
//!   ├─────────────────→ │                      │
//!   │                   │ 3. Verify state      │
//!   │                   │ 4. Exchange code     │
//!   │                   ├────────────────────→ │
//!   │                   │ 5. Get access token  │
//!   │                   │←──────────────────── │
//!   │                   │ 6. Fetch user info   │
//!   │                   ├────────────────────→ │
//!   │                   │←──────────────────── │
//!   │                   │ 7. Create/find user  │
//!   │                   │ 8. Generate JWT      │
//!   │ 200 {tokens}      │                      │
//!   │←───────────────── │                      │
//! ```
//! 
//! ## 보안 고려사항
//! 
//! ### 1. 토큰 보안
//! 
//! - **짧은 액세스 토큰 수명**: 기본 1시간, 탈취 위험 최소화
//! - **리프레시 토큰 순환**: 사용 시마다 새로운 토큰 쌍 발급
//! - **강력한 서명 키**: 256비트 이상의 안전한 비밀키 사용
//! - **클레임 최소화**: 필요한 정보만 토큰에 포함
//! 
//! ### 2. OAuth 보안
//! 
//! - **State 매개변수**: CSRF 공격 방지를 위한 임의값 생성
//! - **리다이렉트 URI 검증**: 등록된 URI만 허용
//! - **코드 교환 시간 제한**: Authorization Code 즉시 사용
//! - **HTTPS 강제**: 모든 OAuth 통신은 TLS 암호화
//! 
//! ### 3. 비밀번호 보안
//! 
//! - **bcrypt 해싱**: 적응형 해시 함수로 무차별 대입 공격 방지
//! - **솔트 자동 생성**: 레인보우 테이블 공격 방지
//! - **환경별 Cost 설정**: 개발/운영 환경에 맞는 보안 강도
//! - **타이밍 공격 방지**: 일정한 검증 시간 유지
//! 
//! ## 사용 예제
//! 
//! ### JWT 토큰 기반 인증
//! 
//! ```rust,ignore
//! use crate::services::auth::{TokenService, TokenClaims};
//! 
//! async fn authenticate_with_jwt() -> Result<(), AppError> {
//!     let token_service = TokenService::instance();
//!     
//!     // 1. 사용자 로그인 후 토큰 생성
//!     let user = get_authenticated_user().await?;
//!     let token_pair = token_service.generate_token_pair(&user)?;
//!     
//!     println!("액세스 토큰: {}", token_pair.access_token);
//!     println!("만료 시간: {}초", token_pair.expires_in);
//!     
//!     // 2. 요청 시 토큰 검증
//!     let auth_header = format!("Bearer {}", token_pair.access_token);
//!     let token = token_service.extract_bearer_token(&auth_header)?;
//!     let claims = token_service.verify_token(token)?;
//!     
//!     println!("인증된 사용자: {}", claims.email);
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### Google OAuth 인증
//! 
//! ```rust,ignore
//! use crate::services::auth::GoogleAuthService;
//! 
//! async fn google_oauth_flow() -> Result<(), AppError> {
//!     let google_auth = GoogleAuthService::instance();
//!     
//!     // 1. 인증 URL 생성
//!     let login_response = google_auth.get_login_url()?;
//!     println!("Google 로그인 URL: {}", login_response.login_url);
//!     
//!     // 2. 콜백 처리 (웹 프레임워크에서 받은 파라미터)
//!     let authorization_code = "4/0AX4XfWh..."; // Google에서 받은 코드
//!     let state = login_response.state;
//!     
//!     // 3. 사용자 인증 및 계정 처리
//!     let user = google_auth.authenticate_with_code(authorization_code, &state).await?;
//!     
//!     // 4. JWT 토큰 생성
//!     let token_service = TokenService::instance();
//!     let tokens = token_service.generate_token_pair(&user)?;
//!     
//!     println!("Google 인증 성공: {}", user.email);
//!     println!("JWT 토큰: {}", tokens.access_token);
//!     
//!     Ok(())
//! }
//! ```
//! 
//! ### 미들웨어 인증 체크
//! 
//! ```rust,ignore
//! use actix_web::{web, HttpRequest, Result};
//! 
//! async fn protected_endpoint(req: HttpRequest) -> Result<impl Responder> {
//!     let token_service = TokenService::instance();
//!     
//!     // Authorization 헤더에서 토큰 추출
//!     let auth_header = req.headers()
//!         .get("Authorization")
//!         .and_then(|h| h.to_str().ok())
//!         .ok_or_else(|| AppError::AuthenticationError("인증 토큰이 없습니다".to_string()))?;
//!     
//!     // 토큰 검증
//!     let token = token_service.extract_bearer_token(auth_header)?;
//!     let claims = token_service.verify_token(token)?;
//!     
//!     // 권한 확인 (예: 관리자 권한)
//!     if !claims.roles.contains(&"admin".to_string()) {
//!         return Err(AppError::AuthorizationError("관리자 권한이 필요합니다".to_string()));
//!     }
//!     
//!     Ok(web::Json(json!({"message": "인증된 사용자 전용 리소스"})))
//! }
//! ```
//! 
//! ## 설정 요구사항
//! 
//! ### 환경 변수
//! 
//! ```bash
//! # JWT 설정
//! JWT_SECRET=your-super-secret-key-minimum-256-bits
//! JWT_EXPIRATION_HOURS=1
//! JWT_REFRESH_EXPIRATION_DAYS=30
//! 
//! # Google OAuth 설정
//! GOOGLE_CLIENT_ID=your-google-client-id.googleusercontent.com
//! GOOGLE_CLIENT_SECRET=your-google-client-secret
//! GOOGLE_REDIRECT_URI=https://yourapp.com/auth/google/callback
//! 
//! # 보안 설정
//! BCRYPT_COST=12
//! OAUTH_STATE_SECRET=your-oauth-state-secret
//! ```
//! 
//! ### 필수 의존성
//! 
//! ```toml
//! [dependencies]
//! jsonwebtoken = "8.3"
//! bcrypt = "0.14"
//! reqwest = { version = "0.11", features = ["json"] }
//! chrono = { version = "0.4", features = ["serde"] }
//! serde = { version = "1.0", features = ["derive"] }
//! urlencoding = "2.1"
//! ```
//! 
//! ## 확장 가능성
//! 
//! ### 추가 OAuth 프로바이더
//! 
//! 기존 Google OAuth 서비스를 참고하여 다른 프로바이더를 쉽게 추가할 수 있습니다:
//! 
//! ```rust,ignore
//! pub mod github_auth_service;    // GitHub OAuth
//! pub mod facebook_auth_service;  // Facebook OAuth
//! pub mod apple_auth_service;     // Apple Sign In
//! pub mod microsoft_auth_service; // Microsoft OAuth
//! ```
//! 
//! ### 추가 인증 방식
//! 
//! ```rust,ignore
//! pub mod mfa_service;           // 다중 인증 (2FA/MFA)
//! pub mod saml_service;          // SAML SSO
//! pub mod ldap_service;          // LDAP 통합
//! pub mod api_key_service;       // API 키 인증
//! ```
//! 
//! ### 권한 관리 확장
//! 
//! ```rust,ignore
//! pub mod rbac_service;          // 역할 기반 접근 제어
//! pub mod permission_service;    // 세밀한 권한 관리
//! pub mod policy_service;        // 동적 정책 엔진
//! ```
//! 
//! ## 성능 및 모니터링
//! 
//! ### 메트릭 수집
//! 
//! - **인증 요청 수**: 시간당 로그인 시도 횟수
//! - **토큰 검증 성능**: 평균 토큰 검증 시간
//! - **OAuth 플로우 완료율**: 성공적인 소셜 로그인 비율
//! - **실패 패턴 분석**: 인증 실패 원인별 통계
//! 
//! ### 캐싱 전략
//! 
//! - **토큰 블랙리스트**: 무효화된 토큰 Redis 캐싱
//! - **OAuth 사용자 정보**: 일정 시간 사용자 프로필 캐싱
//! - **권한 정보**: 역할 및 권한 정보 메모리 캐싱
//! 
//! 이 모듈은 현대적인 웹 애플리케이션의 보안 요구사항을 충족하면서도
//! 개발자 친화적인 API를 제공하여 안전하고 확장 가능한 인증 시스템을 구축할 수 있습니다.

pub mod token_service;
pub mod google_auth_service;

pub use token_service::*;
pub use google_auth_service::*;
