//! 인센드 인증 서비스 메인 애플리케이션
//!
//! Actix-web 기반의 HTTP 서버를 구동하고 모든 서비스를 초기화합니다.
//! MongoDB, Redis 연결을 설정하고 JWT 인증 기반의 REST API를 제공합니다.

use std::sync::Arc;
use actix_cors::Cors;
use actix_web::http::header;
use actix_web::{middleware, App, HttpServer};
use actix_governor::{Governor, GovernorConfigBuilder};
use dotenv::{dotenv};
use env_logger::Env;
use log::{error, info};
use auth_service_backend::caching::redis::RedisClient;
use auth_service_backend::core::registry::ServiceLocator;
use auth_service_backend::db::Database;
use auth_service_backend::routes::configure_all_routes;

/// Rate Limiting 설정 구조체
#[derive(Debug)]
struct RateLimitConfig {
    per_second: u64,
    burst_size: u32,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 환경 설정 및 로깅 초기화
    load_env_file();
    init_logging();

    info!("🚀 인센드 인증 서비스 시작중...");

    // 데이터 스토어 초기화
    let (database, redis_client) = initialize_data_stores().await;

    // ServiceLocator에 핵심 서비스 등록
    ServiceLocator::set(database);
    ServiceLocator::set(redis_client);

    // 모든 서비스 초기화
    ServiceLocator::initialize_all()
        .await
        .expect("서비스 초기화 실패");

    info!("✅ 모든 서비스가 성공적으로 초기화되었습니다!");

    // HTTP 서버 시작
    start_http_server().await
}

/// HTTP 서버를 구성하고 실행합니다
///
/// Actix-web 기반 HTTP 서버를 설정하고 실행합니다.
/// CORS, 로깅, 경로 정규화 미들웨어를 포함합니다.
///
/// # Returns
///
/// * `Ok(())` - 서버가 정상적으로 종료됨
///
/// # Errors
///
/// * `std::io::Error` - 포트 바인딩 실패 또는 서버 실행 오류
///
/// # Examples
///
/// ```rust,ignore
/// // 서버는 127.0.0.1:8080에서 실행됩니다
/// // Health check: http://127.0.0.1:8080/health
/// // API 엔드포인트: http://127.0.0.1:8080/api/v1/*
/// ```
async fn start_http_server() -> std::io::Result<()> {
    let bind_address = "127.0.0.1:8080";

    info!("🌐 서버가 http://{} 에서 실행중입니다", bind_address);
    info!("📍 Health check: http://{}/health", bind_address);
    info!("📍 API Docs: http://{}/api/v1", bind_address);

    // Rate Limiting 설정
    let rate_limit_config = load_rate_limit_config();
    let governor_conf = GovernorConfigBuilder::default()
        .requests_per_second(rate_limit_config.per_second)
        .burst_size(rate_limit_config.burst_size)
        .use_headers()
        .finish()
        .unwrap();

    info!(
        "🛡️ Rate Limiting 활성화: 초당 {}요청, 버스트 {}개", 
        rate_limit_config.per_second, 
        rate_limit_config.burst_size
    );

    HttpServer::new(move || {
        // CORS 설정
        let cors = configure_cors();

        App::new()
            // Rate Limiting 미들웨어 (가장 먼저 적용)
            .wrap(Governor::new(&governor_conf))
            
            // 기존 미들웨어들
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(middleware::NormalizePath::trim())

            // 라우트 설정
            .configure(configure_all_routes)
    })
        .bind(bind_address)?
        .workers(4) // 워커 스레드 수
        .run()
        .await
}

/// 환경별 설정 파일을 로드합니다
///
/// PROFILE 환경변수에 따라 적절한 .env 파일을 로드합니다.
/// 개발환경과 운영환경을 구분하여 설정을 관리합니다.
///
/// # Environment Variables
///
/// * `PROFILE=dev` - .env.dev 파일 로드 (기본값)
/// * `PROFILE=prod` - .env.prod 파일 로드
/// * 기타 - 기본 .env 파일 로드
///
/// # Examples
///
/// ```bash
/// # 개발 환경
/// PROFILE=dev cargo run
///
/// # 운영 환경  
/// PROFILE=prod cargo run
/// ```
fn load_env_file() {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "dev".to_string());

    info!("Current profile: {}", profile);

    match profile.as_str() {
        "prod" => match dotenv::from_filename(".env.prod") {
            Ok(_) => info!(".env.prod 파일 로드 됨"),
            Err(e) => error!(".env.prod 파일 로드 실패: {}", e),
        },
        "dev" => match dotenv::from_filename(".env.dev") {
            Ok(_) => info!(".env.dev 파일 로드 됨"),
            Err(e) => error!(".env.dev 파일 로드 실패: {}", e),
        },
        _ => {
            // 기본 .env 파일 로드
            dotenv().ok();
            info!("기본 .env 파일 로드");
        }
    }
}

/// 로깅 시스템을 초기화합니다
///
/// 환경변수 RUST_LOG를 기반으로 로깅 레벨을 설정합니다.
/// 기본값은 info 레벨이며, actix_web은 debug 레벨로 설정됩니다.
///
/// # Environment Variables
///
/// * `RUST_LOG` - 로깅 레벨 설정 (기본값: "info,actix_web=debug")
///
/// # Examples
///
/// ```bash
/// # 전체 debug 모드
/// RUST_LOG=debug cargo run
///
/// # 특정 모듈만 debug
/// RUST_LOG=auth_service_backend::services=debug cargo run
/// ```
fn init_logging() {
    env_logger::init_from_env(Env::default().default_filter_or("info,actix_web=debug"));
}

/// MongoDB와 Redis 연결을 초기화합니다
///
/// 데이터베이스 연결을 설정하고 Arc로 래핑된 핸들을 반환합니다.
/// 연결 실패 시 애플리케이션이 종료됩니다.
///
/// # Returns
///
/// * `(Arc<Database>, Arc<RedisClient>)` - 초기화된 데이터베이스 및 Redis 클라이언트
///
/// # Panics
///
/// * MongoDB 연결 실패 시
/// * Redis 연결 실패 시
///
/// # Examples
///
/// ```rust,ignore
/// let (db, redis) = initialize_data_stores().await;
/// ServiceLocator::set(db);
/// ServiceLocator::set(redis);
/// ```
async fn initialize_data_stores() -> (Arc<Database>, Arc<RedisClient>) {
    info!("📡 데이터베이스 연결 중...");

    // 데이터베이스 초기화
    let database = Arc::new(
        Database::new()
            .await
            .expect("데이터베이스 연결 실패")
    );

    info!("✅ MongoDB 연결 성공");

    // Redis 클라이언트 초기화
    let redis_client = Arc::new(
        RedisClient::new()
            .await
            .expect("Redis 연결 실패")
    );

    info!("✅ Redis 연결 성공");

    (database, redis_client)
}

/// CORS 설정을 구성합니다
///
/// 프론트엔드와의 통신을 위한 CORS(Cross-Origin Resource Sharing) 설정을 구성합니다.
/// 개발환경에서 로컬호스트 간 통신을 허용합니다.
///
/// # Returns
///
/// * `Cors` - 구성된 CORS 미들웨어
///
/// # Allowed Origins
///
/// * `http://localhost:3000` - React 개발 서버
/// * `http://localhost:8080` - 자체 서버
/// * `127.0.0.1` 동등한 주소들
///
/// # Examples
///
/// ```rust,ignore
/// let cors = configure_cors();
/// App::new().wrap(cors)
/// ```
fn configure_cors() -> Cors {
    Cors::default()
        // 허용할 Origin 설정
        .allowed_origin("http://localhost:3000")
        .allowed_origin("http://127.0.0.1:3000")
        .allowed_origin("http://localhost:8080")
        .allowed_origin("http://127.0.0.1:8080")

        // 허용할 HTTP 메서드
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])

        // 허용할 헤더
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::ACCEPT,
            header::CONTENT_TYPE,
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            header::ACCESS_CONTROL_REQUEST_METHOD,
        ])

        // 자격 증명(쿠키 등) 지원
        .supports_credentials()

        // Preflight 요청 캐시 시간 (초)
        .max_age(3600)
}

/// 환경변수에서 Rate Limiting 설정을 로드합니다
///
/// 환경변수에서 다음 설정을 읽어옵니다:
/// * `RATE_LIMIT_PER_SECOND` - 초당 허용 요청 수 (기본값: 100)
/// * `RATE_LIMIT_BURST_SIZE` - 버스트 허용량 (기본값: 200)
/// * `RATE_LIMIT_USE_HEADERS` - 응답 헤더 포함 여부 (기본값: true)
///
/// # Returns
///
/// * `RateLimitConfig` - 로드된 Rate Limiting 설정
///
/// # Examples
///
/// ```bash
/// # .env.dev (개발 환경)
/// RATE_LIMIT_PER_SECOND=20
/// RATE_LIMIT_BURST_SIZE=40
///
/// # .env.prod (운영 환경)  
/// RATE_LIMIT_PER_SECOND=500
/// RATE_LIMIT_BURST_SIZE=1000
/// ```
fn load_rate_limit_config() -> RateLimitConfig {
    let per_second = std::env::var("RATE_LIMIT_PER_SECOND")
        .unwrap_or_else(|_| "100".to_string())
        .parse::<u64>()
        .unwrap_or_else(|e| {
            error!("RATE_LIMIT_PER_SECOND 파싱 실패: {}. 기본값 100 사용", e);
            100
        });

    let burst_size = std::env::var("RATE_LIMIT_BURST_SIZE")
        .unwrap_or_else(|_| "200".to_string())
        .parse::<u32>()
        .unwrap_or_else(|e| {
            error!("RATE_LIMIT_BURST_SIZE 파싱 실패: {}. 기본값 200 사용", e);
            200
        });

    let config = RateLimitConfig {
        per_second,
        burst_size,
    };

    info!("Rate Limiting 설정 로드됨: {:?}", config);
    config
}
