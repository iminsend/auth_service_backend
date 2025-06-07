use std::sync::Arc;
use actix_cors::Cors;
use actix_web::http::header;
use actix_web::{middleware, App, HttpServer};
use dotenv::{dotenv};
use env_logger::Env;
use log::{error, info};
use auth_service_backend::caching::redis::RedisClient;
use auth_service_backend::core::registry::ServiceLocator;
use auth_service_backend::db::Database;
use auth_service_backend::routes::configure_all_routes;

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

/// # HTTP 서버 시작
///
/// 애플리케이션의 HTTP 서버를 구성하고 실행합니다.
async fn start_http_server() -> std::io::Result<()> {
    let bind_address = "127.0.0.1:8080";

    info!("🌐 서버가 http://{} 에서 실행중입니다", bind_address);
    info!("📍 Health check: http://{}/health", bind_address);
    info!("📍 API Docs: http://{}/api/v1", bind_address);

    HttpServer::new(|| {
        // CORS 설정
        let cors = configure_cors();

        App::new()
            // 미들웨어 등록
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

/// # 환경 설정 파일 로드
///
/// 개발/운영 환경에 따라 적절한 .env 파일을 로드합니다.
///
/// ## 환경 변수
/// - `PROFILE=dev`: .env.dev 파일 로드 (기본값)
/// - `PROFILE=prod`: .env.prod 파일 로드
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

/// 로깅 초기화
///
/// 환경 변수 기반으로 로깅 시스템을 초기화합니다.
fn init_logging() {
    env_logger::init_from_env(Env::default().default_filter_or("info,actix_web=debug"));
}

/// 데이터베이스 및 Redis 초기화
///
/// MongoDB와 Redis 연결을 설정하고 Arc로 감싼 핸들을 반환합니다.
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

/// CORS 설정 구성
///
/// HTTP 서버의 CORS(Cross-Origin Resource Sharing) 설정을 구성합니다.
/// 개발 환경에서 프론트엔드와의 통신을 위해 필요합니다.
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