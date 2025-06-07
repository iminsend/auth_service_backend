//! # HTTP Request Handlers Module
//!
//! HTTP 요청을 처리하는 핸들러 함수들을 정의하는 모듈입니다.
//! Spring Framework의 Controller 레이어와 동일한 역할을 수행하며,
//! ActixWeb 프레임워크를 기반으로 구현되었습니다.
//!
//! ## 아키텍처 위치
//!
//! ```text
//! HTTP Layer Architecture
//! ┌─────────────────────────────────────────────┐
//!   Client (Browser, Mobile App, API Client)     
//! └─────────────────────┬───────────────────────┘
//!                       │ HTTP Request/Response
//! ┌─────────────────────▼───────────────────────┐
//!   Handlers (이 모듈) - HTTP 엔드포인트 처리         ← Web Layer
//! ├─────────────────────────────────────────────┤
//!   Services - 비즈니스 로직                        ← Service Layer  
//! ├─────────────────────────────────────────────┤
//!   Repositories - 데이터 접근                     ← Repository Layer
//! ├─────────────────────────────────────────────┤
//!   Entities/Models - 도메인 모델                  ← Domain Layer
//! └─────────────────────────────────────────────┘
//! ```
//!
//! ## Spring Framework와의 비교
//!
//! ### Spring MVC Controller
//! ```java
//! @RestController
//! @RequestMapping("/api/v1/users")
//! public class UserController {
//!     
//!     @Autowired
//!     private UserService userService;
//!     
//!     @PostMapping
//!     public ResponseEntity<UserResponse> createUser(@RequestBody CreateUserRequest request) {
//!         UserResponse response = userService.createUser(request);
//!         return ResponseEntity.status(HttpStatus.CREATED).body(response);
//!     }
//!     
//!     @GetMapping("/{id}")
//!     public ResponseEntity<UserResponse> getUser(@PathVariable String id) {
//!         UserResponse user = userService.getUserById(id);
//!         return ResponseEntity.ok(user);
//!     }
//! }
//! ```
//!
//! ### 이 모듈의 Rust 구현
//! ```rust,ignore
//! use actix_web::{web, HttpResponse, get, post};
//! use crate::services::users::UserService;
//!
//! #[post("")]
//! pub async fn create_user(
//!     payload: web::Json<CreateUserRequest>,
//! ) -> Result<HttpResponse, AppError> {
//!     let service = UserService::instance(); // 싱글톤 패턴
//!     let response = service.create_user(payload.into_inner()).await?;
//!     Ok(HttpResponse::Created().json(response))
//! }
//!
//! #[get("/{user_id}")]
//! pub async fn get_user(
//!     user_id: web::Path<String>,
//! ) -> Result<HttpResponse, AppError> {
//!     let service = UserService::instance();
//!     let user = service.get_user_by_id(&user_id).await?;
//!     Ok(HttpResponse::Ok().json(user))
//! }
//! ```
//!
//! ## 주요 특징
//!
//! ### 1. 비동기 처리
//! - **Future 기반**: 모든 핸들러가 `async/await` 사용
//! - **논블로킹 I/O**: 데이터베이스, 외부 API 호출 시 블로킹 없음
//! - **높은 처리량**: 적은 스레드로 많은 동시 요청 처리
//!
//! ```rust,ignore
//! // 논블로킹 데이터베이스 호출
//! let user = user_service.get_user_by_id(&user_id).await?;
//! 
//! // 여러 비동기 작업 동시 실행
//! let (user, profile, settings) = tokio::join!(
//!     user_service.get_user_by_id(&user_id),
//!     profile_service.get_profile(&user_id),
//!     settings_service.get_settings(&user_id)
//! );
//! ```
//!
//! ### 2. 타입 안전성
//! - **컴파일 타임 검증**: 요청/응답 타입 검증
//! - **자동 직렬화**: JSON ↔ Rust 구조체 자동 변환
//! - **검증 통합**: validator 크레이트로 입력 검증
//!
//! ```rust,ignore
//! #[derive(Deserialize, Validate)]
//! pub struct CreateUserRequest {
//!     #[validate(email)]
//!     pub email: String,
//!     
//!     #[validate(length(min = 8))]
//!     pub password: String,
//! }
//!
//! // 컴파일 타임에 타입 안전성 보장
//! #[post("/users")]
//! pub async fn create_user(
//!     payload: web::Json<CreateUserRequest>, // 자동 JSON 파싱
//! ) -> Result<HttpResponse, AppError> {
//!     payload.validate()?; // 검증 규칙 자동 적용
//!     // ...
//! }
//! ```
//!
//! ### 3. 에러 처리
//! - **Result 패턴**: Rust의 에러 처리 관용구 활용
//! - **자동 변환**: `?` 연산자로 에러 자동 전파
//! - **통합 에러 타입**: AppError로 모든 에러 통합 처리
//!
//! ## 모듈 구성
//!
//! ### 현재 구현된 핸들러
//! - **`auth`**: 인증 관련 엔드포인트
//!   - 로컬 로그인 (`POST /auth/login`)
//!   - OAuth 로그인 (`GET /auth/{provider}/login`)
//!   - OAuth 콜백 (`GET /auth/{provider}/callback`)
//!   - 토큰 검증 (`POST /auth/verify`)
//!
//! - **`users`**: 사용자 관리 엔드포인트
//!   - 사용자 생성 (`POST /users`)
//!   - 사용자 조회 (`GET /users/{id}`)
//!   - 사용자 삭제 (`DELETE /users/{id}`)
//!
//! ### 향후 확장 예정
//! ```text
//! handlers/
//! ├── mod.rs              ← 이 파일
//! ├── auth.rs             ← 인증/인가
//! ├── users.rs            ← 사용자 관리
//! ├── profiles.rs         ← 프로필 관리 (향후)
//! ├── notifications.rs    ← 알림 관리 (향후)
//! ├── admin.rs           ← 관리자 기능 (향후)
//! └── health.rs          ← 헬스체크 (향후)
//! ```
//!
//! ## 라우팅 설정
//!
//! ### main.rs에서의 설정 예제
//! ```rust,ignore
//! use actix_web::{web, App, HttpServer};
//! use crate::handlers::{auth, users};
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     HttpServer::new(|| {
//!         App::new()
//!             .service(
//!                 web::scope("/api/v1")
//!                     .service(
//!                         web::scope("/auth")
//!                             .service(auth::local_login)
//!                             .service(auth::google_login_url)
//!                             .service(auth::google_oauth_callback)
//!                             .service(auth::oauth_login_url)
//!                             .service(auth::oauth_callback)
//!                             .service(auth::verify_token)
//!                     )
//!                     .service(
//!                         web::scope("/users")
//!                             .service(users::create_user)
//!                             .service(users::get_user)
//!                             .service(users::delete_user)
//!                     )
//!             )
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ## 미들웨어 통합
//!
//! ### 인증 미들웨어
//! ```rust,ignore
//! use actix_web::dev::ServiceRequest;
//! use actix_web_httpauth::extractors::bearer::BearerAuth;
//! 
//! pub async fn jwt_validator(
//!     req: ServiceRequest,
//!     credentials: BearerAuth,
//! ) -> Result<ServiceRequest, actix_web::Error> {
//!     let token_service = TokenService::instance();
//!     
//!     match token_service.verify_token(credentials.token()) {
//!         Ok(claims) => {
//!             // 요청에 사용자 정보 추가
//!             req.extensions_mut().insert(claims);
//!             Ok(req)
//!         }
//!         Err(_) => Err(actix_web::error::ErrorUnauthorized("Invalid token")),
//!     }
//! }
//! ```
//!
//! ### CORS 설정
//! ```rust,ignore
//! use actix_cors::Cors;
//! use actix_web::http;
//!
//! let cors = Cors::default()
//!     .allowed_origin("http://localhost:3000") // 프론트엔드 도메인
//!     .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
//!     .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
//!     .allowed_header(http::header::CONTENT_TYPE)
//!     .max_age(3600);
//! ```
//!
//! ## 성능 최적화
//!
//! ### 요청 처리 최적화
//! ```rust,ignore
//! // 1. 데이터 스트리밍
//! #[get("/users/{id}/avatar")]
//! pub async fn get_user_avatar(
//!     user_id: web::Path<String>,
//! ) -> Result<HttpResponse, AppError> {
//!     let file_stream = file_service.stream_file(&avatar_path).await?;
//!     Ok(HttpResponse::Ok()
//!         .content_type("image/jpeg")
//!         .streaming(file_stream))
//! }
//!
//! // 2. 응답 압축
//! use actix_web::middleware::Compress;
//!
//! App::new()
//!     .wrap(Compress::default()) // 자동 gzip 압축
//!     .service(users_scope)
//! ```
//!
//! ### 캐싱 전략
//! ```rust,ignore
//! // HTTP 캐시 헤더 설정
//! #[get("/users/{id}")]
//! pub async fn get_user_profile(
//!     user_id: web::Path<String>,
//! ) -> Result<HttpResponse, AppError> {
//!     let user = user_service.get_user_by_id(&user_id).await?;
//!     
//!     Ok(HttpResponse::Ok()
//!         .insert_header(("Cache-Control", "public, max-age=300")) // 5분 캐시
//!         .insert_header(("ETag", format!("\"{}\"", user.updated_at.timestamp())))
//!         .json(user))
//! }
//! ```
//!
//! ## 보안 고려사항
//!
//! ### 입력 검증
//! - **자동 검증**: validator 크레이트 활용
//! - **SQL 인젝션 방지**: MongoDB의 타입 안전한 쿼리
//! - **XSS 방지**: 자동 JSON 이스케이프
//!
//! ### 인증/인가
//! - **JWT 토큰**: 상태 없는 인증
//! - **역할 기반 접근 제어**: 미들웨어를 통한 권한 검사
//! - **Rate Limiting**: 요청 빈도 제한
//!
//! ## 모니터링 및 로깅
//!
//! ### 구조화된 로깅
//! ```rust,ignore
//! use tracing::{info, warn, error, instrument};
//!
//! #[instrument(skip(payload))]
//! #[post("/users")]
//! pub async fn create_user(
//!     payload: web::Json<CreateUserRequest>,
//! ) -> Result<HttpResponse, AppError> {
//!     info!("사용자 생성 요청: {}", payload.email);
//!     
//!     let result = user_service.create_user(payload.into_inner()).await;
//!     
//!     match &result {
//!         Ok(_) => info!("사용자 생성 성공"),
//!         Err(e) => error!("사용자 생성 실패: {}", e),
//!     }
//!     
//!     result.map(|response| HttpResponse::Created().json(response))
//! }
//! ```
//!
//! ### 메트릭 수집
//! ```rust,ignore
//! use actix_web_prometheus::PrometheusMetrics;
//!
//! let prometheus = PrometheusMetrics::new("api", Some("/metrics"), None);
//! 
//! App::new()
//!     .wrap(prometheus.clone())
//!     .service(api_scope)
//! ```

pub mod users;
pub mod auth;