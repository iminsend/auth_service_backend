use actix_web::{get, post, web, HttpResponse};
use serde::{Deserialize, Serialize};
use std::env;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use crate::errors::errors::AppError;
use crate::services::auth::{JwtRsaService, RsaService};

/// 공개키 데이터를 정리합니다 (NUL byte 및 잘못된 문자 제거)
///
/// # Arguments
///
/// * `public_key` - 원본 공개키 문자열
///
/// # Returns
///
/// 정리된 공개키 문자열
fn sanitize_public_key_data(public_key: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // 1. NUL byte 제거
    let cleaned = public_key.replace('\0', "");
    
    // 2. 다른 제어 문자 제거 (CR, LF 제외)
    let cleaned: String = cleaned
        .chars()
        .filter(|&c| c == '\r' || c == '\n' || c >= ' ')
        .collect();
    
    // 3. 공백 문자 정리 (앞뒤 공백 제거, 내부 줄바꿈 정리)
    let cleaned = cleaned.trim();
    
    // 4. PEM 형식 검증 및 정리
    if !cleaned.contains("-----BEGIN") || !cleaned.contains("-----END") {
        return Err("Invalid PEM format: Missing BEGIN/END markers".into());
    }
    
    // 5. 줄바꿈 정규화 (Windows CRLF -> Unix LF)
    let cleaned = cleaned.replace("\r\n", "\n");
    
    // 6. 빈 줄 제거 (PEM 헤더와 푸터 사이의 불필요한 공백)
    let lines: Vec<&str> = cleaned.lines().collect();
    let mut result_lines = Vec::new();
    
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        result_lines.push(trimmed);
    }
    
    // 7. 최종 PEM 형식으로 재조립
    let result = result_lines.join("\n");
    
    log::debug!("🔧 Sanitized public key in handler: {} chars -> {} chars", public_key.len(), result.len());
    
    Ok(result)
}

// 공개키 등록 요청 구조체
#[derive(Deserialize)]
pub struct RegisterPublicKeyRequest {
    pub service_name: String,
    pub public_key: String,
    pub service_info: Option<serde_json::Value>,
}

// 공개키 등록 응답 구조체
#[derive(Serialize)]
pub struct RegisterPublicKeyResponse {
    pub success: bool,
    pub message: String,
    pub service_name: String,
}

// 동적 공개키 등록 엔드포인트 (MongoDB 저장)
#[post("/register-public-key")]
pub async fn register_public_key(
    req: web::Json<RegisterPublicKeyRequest>,
) -> Result<HttpResponse, AppError> {
    log::info!("🔐 Public key registration request from service: {}", req.service_name);
    
    // 공개키 데이터 사전 처리
    let sanitized_public_key = match sanitize_public_key_data(&req.public_key) {
        Ok(key) => key,
        Err(e) => {
            log::error!("❌ Failed to sanitize public key for {}: {}", req.service_name, e);
            return Ok(HttpResponse::BadRequest().json(RegisterPublicKeyResponse {
                success: false,
                message: format!("Failed to process public key: {}", e),
                service_name: req.service_name.clone(),
            }));
        }
    };
    
    let rsa_service = RsaService::instance();
    
    match rsa_service.register_public_key(
        req.service_name.clone(),
        sanitized_public_key,
        req.service_info.clone(),
    ).await {
        Ok(_) => {
            log::info!("✅ Successfully processed public key for service: {}", req.service_name);
            
            Ok(HttpResponse::Ok().json(RegisterPublicKeyResponse {
                success: true,
                message: "Public key registered/updated successfully".to_string(),
                service_name: req.service_name.clone(),
            }))
        },
        Err(e) => {
            log::error!("❌ Failed to register public key for {}: {}", req.service_name, e);
            
            Ok(HttpResponse::BadRequest().json(RegisterPublicKeyResponse {
                success: false,
                message: format!("Failed to register public key: {}", e),
                service_name: req.service_name.clone(),
            }))
        }
    }
}

// 등록된 서비스 목록 조회 엔드포인트 (관리용)
#[get("/registered-services")]
pub async fn get_registered_services() -> Result<HttpResponse, AppError> {
    let rsa_service = RsaService::instance();
    
    match rsa_service.get_registered_services().await {
        Ok(services) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "registered_services": services,
                "count": services.len()
            })))
        },
        Err(e) => {
            log::error!("❌ Failed to get registered services: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve registered services",
                "message": e.to_string()
            })))
        }
    }
}

// 관리용 모든 키 상세 정보 조회 엔드포인트
#[get("/admin/all-keys")]
pub async fn get_all_keys_admin() -> Result<HttpResponse, AppError> {
    let rsa_service = RsaService::instance();
    
    match rsa_service.get_all_keys().await {
        Ok(keys) => {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "keys": keys,
                "count": keys.len()
            })))
        },
        Err(e) => {
            log::error!("❌ Failed to get all keys: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve all keys",
                "message": e.to_string()
            })))
        }
    }
}

// 키 관리 엔드포인트들
#[post("/admin/deactivate/{service_name}")]
pub async fn deactivate_key(
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service_name = path.into_inner();
    let rsa_service = RsaService::instance();
    
    match rsa_service.deactivate_key(&service_name).await {
        Ok(_) => {
            log::info!("🔒 Deactivated key for service: {}", service_name);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Key deactivated for service: {}", service_name)
            })))
        },
        Err(e) => {
            log::error!("❌ Failed to deactivate key for {}: {}", service_name, e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "message": format!("Failed to deactivate key: {}", e)
            })))
        }
    }
}

#[post("/admin/activate/{service_name}")]
pub async fn activate_key(
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let service_name = path.into_inner();
    let rsa_service = RsaService::instance();
    
    match rsa_service.activate_key(&service_name).await {
        Ok(_) => {
            log::info!("🔓 Activated key for service: {}", service_name);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Key activated for service: {}", service_name)
            })))
        },
        Err(e) => {
            log::error!("❌ Failed to activate key for {}: {}", service_name, e);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "success": false,
                "message": format!("Failed to activate key: {}", e)
            })))
        }
    }
}

#[post("/admin/cleanup-expired")]
pub async fn cleanup_expired_keys() -> Result<HttpResponse, AppError> {
    let rsa_service = RsaService::instance();
    
    match rsa_service.cleanup_expired_keys().await {
        Ok(deleted_count) => {
            log::info!("🧹 Cleaned up {} expired keys", deleted_count);
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Cleaned up {} expired keys", deleted_count),
                "deleted_count": deleted_count
            })))
        },
        Err(e) => {
            log::error!("❌ Failed to cleanup expired keys: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "message": format!("Failed to cleanup expired keys: {}", e)
            })))
        }
    }
}

// 기존 JWKS 핸들러 (유지)
#[get("/.well-known/jwks.json")]
pub async fn jwks_handler() -> Result<HttpResponse, AppError> {
    let jwt_service = JwtRsaService::instance();

    match jwt_service.get_jwks() {
        Ok(jwks) => {
            Ok(HttpResponse::Ok()
                .insert_header(("Cache-Control", "public, max-age=3600"))
                .json(jwks))
        },
        Err(e) => {
            log::error!("❌ Failed to generate JWKS: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate JWKS"
            })))
        }
    }
}

// RSA 인증 요청 구조체
#[derive(Deserialize)]
pub struct RsaAuthRequest {
    pub public_key: String,
    pub signature: String,
    pub timestamp: i64,
}

// JWT Secret 응답 구조체
#[derive(Serialize)]
pub struct JwtSecretResponse {
    pub jwt_secret: String,
    pub issued_at: i64,
    pub expires_at: i64,
}

// 에러 응답 구조체
#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

// JWT Secret 제공 엔드포인트 (실제 RSA 인증 필수)
#[post("/jwt-secret")]
pub async fn get_jwt_secret(
    req: web::Json<RsaAuthRequest>,
) -> Result<HttpResponse, AppError> {
    let current_time = chrono::Utc::now().timestamp();
    
    // 1. 타임스탬프 검증 (5분 이내)
    if (current_time - req.timestamp).abs() > 300 {
        return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "invalid_timestamp".to_string(),
            message: "Request timestamp is too old".to_string(),
        }));
    }
    
    let rsa_service = RsaService::instance();
    
    // 2. 실제 RSA 서명 검증 (필수!)
    if !verify_rsa_signature(&req.public_key, &req.signature, req.timestamp, &rsa_service).await {
        log::warn!("🚫 RSA signature verification failed for JWT secret request");
        return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "invalid_signature".to_string(),
            message: "RSA signature verification failed".to_string(),
        }));
    }
    
    // 3. 인증 성공 - JWT Secret 반환
    let jwt_secret = env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-secret-key".to_string());
    
    log::info!("🔑 JWT Secret provided to RSA-authenticated service");
    
    Ok(HttpResponse::Ok().json(JwtSecretResponse {
        jwt_secret,
        issued_at: current_time,
        expires_at: current_time + 3600, // 1시간 유효
    }))
}

// RSA 서명 검증 함수 (MongoDB에서 신뢰할 수 있는 키 조회)
async fn verify_rsa_signature(
    public_key: &str, 
    signature: &str, 
    timestamp: i64,
    rsa_service: &RsaService,
) -> bool {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use sha2::{Sha256, Digest};
    
    // 1. 기본적인 형식 검증
    if public_key.is_empty() || signature.is_empty() {
        log::warn!("❌ Empty public key or signature");
        return false;
    }
    
    // 2. Base64 디코딩 검증
    let public_key_bytes = match BASE64.decode(public_key) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("❌ Invalid base64 public key: {}", e);
            return false;
        }
    };
    
    let signature_bytes = match BASE64.decode(signature) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::error!("❌ Invalid base64 signature: {}", e);
            return false;
        }
    };
    
    // 3. 타임스탬프 검증 (5분 이내)
    let current_time = chrono::Utc::now().timestamp();
    if (current_time - timestamp).abs() > 300 {
        log::warn!("🚫 Timestamp verification failed: request too old");
        return false;
    }
    
    // 4. MongoDB에서 신뢰할 수 있는 resource_service 공개키 찾기
    let trusted_public_key = match get_trusted_resource_service_public_key(rsa_service).await {
        Some(key) => key,
        None => {
            log::error!("❌ No trusted public key found for resource service");
            return false;
        }
    };
    
    // 5. 공개키 정규화 및 비교
    if !compare_public_keys(&public_key_bytes, &trusted_public_key) {
        log::warn!("🚫 Received public key does not match any trusted resource_service key");
        log::debug!("📋 Received key length: {}, Trusted key length: {}", public_key_bytes.len(), trusted_public_key.len());
        return false;
    }
    
    // 5. PEM 형식으로 변환하여 RSA 공개키 파싱
    let public_key_pem = match std::str::from_utf8(&public_key_bytes) {
        Ok(pem) => pem,
        Err(e) => {
            log::error!("❌ Invalid UTF-8 in public key: {}", e);
            return false;
        }
    };
    
    let rsa_public_key = match rsa::RsaPublicKey::from_public_key_pem(public_key_pem) {
        Ok(key) => key,
        Err(e) => {
            log::error!("❌ Failed to parse RSA public key: {}", e);
            return false;
        }
    };
    
    // 6. 서명할 메시지 생성 (resource_service와 동일한 형식이어야 함)
    let message = format!("jwt_secret_request_{}", timestamp);
    
    // 7. SHA256 해시 생성
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    
    // 8. 실제 RSA 서명 검증
    match verify_rsa_pkcs1v15_signature(&rsa_public_key, &hash, &signature_bytes) {
        Ok(is_valid) => {
            if is_valid {
                log::info!("✅ RSA signature verification successful for resource_service");
                log::info!("📋 Verified message: {}", message);
                true
            } else {
                log::warn!("🚫 RSA signature verification failed: signature does not match");
                false
            }
        },
        Err(e) => {
            log::error!("❌ RSA signature verification error: {}", e);
            false
        }
    }
}

// PKCS#1 v1.5 RSA 서명 검증 함수
fn verify_rsa_pkcs1v15_signature(
    public_key: &rsa::RsaPublicKey, 
    hash: &[u8], 
    signature: &[u8]
) -> Result<bool, Box<dyn std::error::Error>> {
    use rsa::pkcs1v15::{VerifyingKey};
    use rsa::signature::Verifier;
    use sha2::Sha256;
    
    // new_unprefixed 사용 (API 이슈 해결)
    let verifying_key = VerifyingKey::<Sha256>::new_unprefixed(public_key.clone());
    
    // 서명을 Signature 타입으로 변환
    let signature = match rsa::pkcs1v15::Signature::try_from(signature) {
        Ok(sig) => sig,
        Err(e) => {
            log::error!("❌ Invalid signature format: {}", e);
            return Ok(false);
        }
    };
    
    // 서명 검증
    match verifying_key.verify(hash, &signature) {
        Ok(_) => {
            log::debug!("🔍 RSA signature verification: VALID");
            Ok(true)
        },
        Err(e) => {
            log::debug!("🔍 RSA signature verification: INVALID - {}", e);
            Ok(false)
        }
    }
}

// 공개키 정규화 및 비교 함수
fn compare_public_keys(received_key_bytes: &[u8], trusted_key_bytes: &[u8]) -> bool {
    // 방법 1: 직접 바이트 비교
    if received_key_bytes == trusted_key_bytes {
        log::debug!("🔍 Direct byte comparison: MATCH");
        return true;
    }
    
    // 방법 2: 두 키를 모두 PEM 문자열로 변환하여 정규화 후 비교
    let received_key_str = match std::str::from_utf8(received_key_bytes) {
        Ok(s) => normalize_pem_key(s),
        Err(_) => {
            log::debug!("🔍 Received key is not valid UTF-8, treating as raw bytes");
            return false;
        }
    };
    
    let trusted_key_str = match std::str::from_utf8(trusted_key_bytes) {
        Ok(s) => normalize_pem_key(s),
        Err(_) => {
            log::debug!("🔍 Trusted key is not valid UTF-8, treating as raw bytes");
            return false;
        }
    };
    
    if received_key_str == trusted_key_str {
        log::debug!("🔍 Normalized PEM comparison: MATCH");
        return true;
    }
    
    // 방법 3: RSA 공개키로 파싱해서 비교 (가장 확실한 방법)
    let received_rsa_key = match rsa::RsaPublicKey::from_public_key_pem(&received_key_str) {
        Ok(key) => key,
        Err(e) => {
            log::debug!("🔍 Failed to parse received key as RSA: {}", e);
            return false;
        }
    };
    
    let trusted_rsa_key = match rsa::RsaPublicKey::from_public_key_pem(&trusted_key_str) {
        Ok(key) => key,
        Err(e) => {
            log::debug!("🔍 Failed to parse trusted key as RSA: {}", e);
            return false;
        }
    };
    
    // RSA 키의 n(modulus)과 e(exponent) 비교
    let keys_match = received_rsa_key.n() == trusted_rsa_key.n() && 
                    received_rsa_key.e() == trusted_rsa_key.e();
    
    if keys_match {
        log::debug!("🔍 RSA key parameter comparison: MATCH");
        true
    } else {
        log::debug!("🔍 RSA key parameter comparison: NO MATCH");
        false
    }
}

// PEM 키 정규화 함수
fn normalize_pem_key(pem_str: &str) -> String {
    // 공백 제거, 줄바꿈 정규화
    let normalized = pem_str
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    
    normalized
}

// 신뢰할 수 있는 리소스 서비스 공개키를 가져오는 함수 (MongoDB 우선, 하위 호환성 유지)
async fn get_trusted_resource_service_public_key(rsa_service: &RsaService) -> Option<Vec<u8>> {
    // 방법 1: MongoDB에서 동적으로 등록된 키들 확인 (우선순위 1)
    // resource_service_backend 또는 일반적인 리소스 서비스 이름들 시도
    let service_names = vec![
        "resource_service_backend",
        "resource_service", 
        "resource-service",
        "api_service",
        "api-service"
    ];
    
    for service_name in service_names {
        if let Some(key_bytes) = rsa_service.get_trusted_public_key(service_name).await {
            log::info!("📋 Using MongoDB registered public key for service: {}", service_name);
            return Some(key_bytes);
        }
    }
    
    // 방법 2: 환경변수에서 공개키 경로 읽기 (기존 방식 - 하위 호환성)
    if let Ok(key_path) = env::var("RESOURCE_SERVICE_PUBLIC_KEY_PATH") {
        if let Ok(key_content) = std::fs::read(&key_path) {
            log::info!("📋 Loaded trusted public key from: {}", key_path);
            return Some(key_content);
        } else {
            log::warn!("⚠️ Failed to read public key from path: {}", key_path);
        }
    }
    
    // 방법 3: 환경변수에서 직접 공개키 읽기
    if let Ok(key_content) = env::var("RESOURCE_SERVICE_PUBLIC_KEY") {
        log::info!("📋 Loaded trusted public key from environment variable");
        return Some(key_content.into_bytes());
    }
    
    // 방법 4: 기본 키 파일 경로에서 읽기
    let default_path = "./secrets/resource_service_public_key.pem";
    if let Ok(key_content) = std::fs::read(default_path) {
        log::info!("📋 Loaded trusted public key from default path: {}", default_path);
        return Some(key_content);
    }
    
    // 방법 5: 하드코딩된 공개키 (개발/테스트용)
    if env::var("ALLOW_HARDCODED_KEY").unwrap_or_default() == "true" {
        log::warn!("⚠️ Using hardcoded public key for development/testing");
        let hardcoded_key = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsBC9FGVtoEDnrrXG+PoQ
cWXVvNLyMTliAsu8yPtxEd4FQor0D49lg4q2mFCJ9vcQaIWTYKtuNW6Y9EQPnbsj
tWPgBN/l4HornEUGkgqVWbNQ9gOqXfol3FBPS4rX1V5jFa7vB8VoUqOJgs/ZHxXe
8mXEJzFp7eUgFVkxtp0wLO/NR3hsZlz16z9QlYzJv8PETGCNYCRHe0FQjsrNZQ2V
anx9RLapzgqNUjK96NUhDihWPqUHty5JOKfDLMmiUYnNG73lQNzl1GbJVmnfSYs6
qNUjmB+Wc3sWBztORtgEc/jbAhAvzXYZ5pdGg0XDDCCnZLZxQVGwvP2b+KAAn8w1
hwIDAQAB
-----END PUBLIC KEY-----"#;
        return Some(hardcoded_key.as_bytes().to_vec());
    }
    
    log::error!("❌ No trusted public key found. No keys registered in MongoDB and no static configuration.");
    None
}
