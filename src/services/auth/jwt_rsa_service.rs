//! JWT RSA 기반 토큰 서비스
//!
//! RS256 알고리즘을 사용한 JWT 토큰 발급 및 검증 서비스입니다.
//! JWKS(JSON Web Key Set) 표준을 지원하여 마이크로서비스 간 토큰 검증을 가능하게 합니다.
//!
//! # 특징
//!
//! - RSA 공개키/개인키 기반 JWT 서명 및 검증
//! - JWKS 엔드포인트 지원으로 다른 서비스에서 토큰 검증 가능
//! - 싱글톤 패턴으로 키 로딩 최적화
//! - 표준 JWT 클레임 지원 (sub, exp, iat, iss, aud)
//!
//! # 설정 요구사항
//!
//! 다음 환경변수가 필요합니다:
//! - `JWT_PRIVATE_KEY_PATH`: RSA 개인키 파일 경로
//! - `JWT_PUBLIC_KEY_PATH`: RSA 공개키 파일 경로  
//! - `JWT_EXPIRATION_HOURS`: 토큰 만료 시간 (기본값: 1시간)
//!
//! # RSA 키 생성
//!
//! ```bash
//! # 개인키 생성
//! openssl genrsa -out jwt_private_key.pem 2048
//! # 공개키 추출
//! openssl rsa -in jwt_private_key.pem -pubout -out jwt_public_key.pem
//! ```
//!
//! # 사용 예제
//!
//! ```rust,no_run,ignore
//! # use std::env;
//! # env::set_var("JWT_PRIVATE_KEY_PATH", "jwt_private_key.pem");
//! # env::set_var("JWT_PUBLIC_KEY_PATH", "jwt_public_key.pem");
//! # env::set_var("JWT_EXPIRATION_HOURS", "1");
//!
//! use uuid::Uuid;
//! use crate::services::auth::jwt_rsa_service::JwtRsaService;
//!
//! // 토큰 발급
//! let jwt_service = JwtRsaService::instance();
//! let token = jwt_service.generate_token(
//!     Uuid::new_v4(),
//!     "Admin", 
//!     Uuid::new_v4()
//! )?;
//!
//! // 토큰 검증
//! let claims = jwt_service.validate_token(&token)?;
//!
//! // JWKS 정보 생성 (다른 서비스에서 토큰 검증용)
//! let jwks = jwt_service.get_jwks()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use jsonwebtoken::{encode, decode, Header, Algorithm, EncodingKey, DecodingKey, Validation};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::DecodeRsaPrivateKey, pkcs8::DecodePublicKey};
use std::fs;
use base64::{Engine as _, engine::general_purpose};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use uuid::Uuid;
use std::sync::Arc;
use once_cell::sync::OnceCell;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::EncodePublicKey;
use crate::config::AuthProvider;
use crate::domain::token::token::TokenClaims;

/// JWT 토큰 클레임 구조체
///
/// 표준 JWT 클레임과 애플리케이션별 커스텀 클레임을 포함합니다.
/*#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject: 사용자 ID (UUID 문자열)
    pub sub: String,
    /// 사용자 타입 (Admin, Supplier, Buyer)
    pub user_type: String,
    /// 소속 회사 ID (UUID 문자열)
    pub company_id: String,
    /// Expiration time: 만료 시간 (Unix timestamp)
    pub exp: usize,
    /// Issued at: 발급 시간 (Unix timestamp)
    pub iat: usize,
    /// Issuer: 토큰 발급자
    pub iss: String,
    /// Audience: 토큰 대상 서비스
    pub aud: String,
}*/

/// JWT RSA 서비스
///
/// RSA 공개키/개인키를 사용하여 JWT 토큰을 발급하고 검증하는 싱글톤 서비스입니다.
/// 마이크로서비스 아키텍처에서 인증 서버가 토큰을 발급하고,
/// 다른 리소스 서버들이 공개키로 토큰을 검증할 수 있도록 설계되었습니다.
pub struct JwtRsaService {
    /// RSA 개인키 (토큰 서명용)
    private_key: RsaPrivateKey,
    /// RSA 공개키 (토큰 검증용)
    public_key: RsaPublicKey,
    /// 키 식별자 (JWKS에서 사용)
    key_id: String,
}

/// 싱글톤 인스턴스 저장소
static JWT_RSA_SERVICE_INSTANCE: OnceCell<Arc<JwtRsaService>> = OnceCell::new();

impl JwtRsaService {
    /// 싱글톤 인스턴스를 가져옵니다.
    ///
    /// 첫 호출 시 RSA 키 파일을 로딩하여 인스턴스를 생성하고,
    /// 이후 호출에서는 캐시된 인스턴스를 반환합니다.
    ///
    /// # Panics
    ///
    /// RSA 키 파일 로딩에 실패하면 패닉이 발생합니다.
    /// 애플리케이션 시작 시 키 파일 존재 여부를 미리 확인하는 것을 권장합니다.
    pub fn instance() -> Arc<Self> {
        JWT_RSA_SERVICE_INSTANCE
            .get_or_init(|| {
                Arc::new(Self::new().expect("Failed to initialize JwtRsaService"))
            })
            .clone()
    }

    /// 새로운 JWT RSA 서비스 인스턴스를 생성합니다.
    ///
    /// 환경변수에서 키 파일 경로를 읽어 RSA 키를 로딩합니다.
    ///
    /// # Errors
    ///
    /// - 환경변수가 설정되지 않은 경우
    /// - 키 파일을 읽을 수 없는 경우
    /// - 키 파일 형식이 올바르지 않은 경우
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let private_key_path = std::env::var("JWT_PRIVATE_KEY_PATH")
            .unwrap_or_else(|_| "./secrets/jwt_private_key.pem".to_string());
        let public_key_path = std::env::var("JWT_PUBLIC_KEY_PATH")
            .unwrap_or_else(|_| "./secrets/jwt_public_key.pem".to_string());

        // 키 파일이 없으면 자동 생성
        if !std::path::Path::new(&private_key_path).exists() ||
            !std::path::Path::new(&public_key_path).exists() {

            log::info!("🔑 JWT keys not found. Generating new RSA key pair...");
            Self::generate_rsa_keys(&private_key_path, &public_key_path)?;
            log::info!("✅ JWT RSA keys generated successfully");
        } else {
            log::info!("🔑 Loading existing JWT RSA keys");
        }

        let private_key_pem = fs::read_to_string(&private_key_path)
            .map_err(|e| format!("Failed to read private key file '{}': {}", private_key_path, e))?;
        let public_key_pem = fs::read_to_string(&public_key_path)
            .map_err(|e| format!("Failed to read public key file '{}': {}", public_key_path, e))?;

        let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem)?;
        let public_key = RsaPublicKey::from_public_key_pem(&public_key_pem)?;

        Ok(Self {
            private_key,
            public_key,
            key_id: "auth-service-key-1".to_string(),
        })
    }

    /// RSA 키 쌍을 자동 생성합니다.
    fn generate_rsa_keys(private_key_path: &str, public_key_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        use rsa::RsaPrivateKey;

        // secrets 디렉토리 생성
        if let Some(parent) = std::path::Path::new(private_key_path).parent() {
            std::fs::create_dir_all(parent)?;
        }

        // RSA 키 생성 (2048비트) - rsa 크레이트의 기본 RNG 사용
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)?;
        let public_key = private_key.to_public_key();

        // 개인키 저장 (PKCS#1 형식)
        let private_key_pem = private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
        std::fs::write(private_key_path, private_key_pem.as_bytes())?;

        // 공개키 저장 (PKCS#8 형식)  
        let public_key_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
        std::fs::write(public_key_path, public_key_pem.as_bytes())?;

        // 파일 권한 설정 (Unix 계열 시스템에서만)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let private_perms = std::fs::Permissions::from_mode(0o600); // 소유자만 읽기/쓰기
            let public_perms = std::fs::Permissions::from_mode(0o644);  // 소유자 읽기/쓰기, 그룹/기타 읽기

            std::fs::set_permissions(private_key_path, private_perms)?;
            std::fs::set_permissions(public_key_path, public_perms)?;
        }

        log::info!("📁 Private key saved: {}", private_key_path);
        log::info!("📁 Public key saved: {}", public_key_path);

        Ok(())
    }

    /// JWT 토큰을 생성합니다.
    ///
    /// 사용자 정보를 기반으로 JWT 토큰을 생성하고 RSA 개인키로 서명합니다.
    ///
    /// # Arguments
    ///
    /// * `user_id` - 사용자 고유 식별자
    /// * `user_type` - 사용자 타입 ("Admin", "Supplier", "Buyer")
    /// * `company_id` - 소속 회사 고유 식별자
    ///
    /// # Returns
    ///
    /// 서명된 JWT 토큰 문자열
    ///
    /// # Errors
    ///
    /// - RSA 키 인코딩 실패
    /// - JWT 토큰 생성 실패
    /// - 환경변수 파싱 실패
    ///
    /// # Examples
    ///
    /// ```rust,no_run,ignore
    /// use uuid::Uuid;
    /// # use crate::services::auth::jwt_rsa_service::JwtRsaService;
    ///
    /// let service = JwtRsaService::instance();
    /// let token = service.generate_token(
    ///     Uuid::new_v4(),
    ///     "Admin",
    ///     Uuid::new_v4()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn generate_token(
        &self,
        user_id: Uuid,
        user_type: &str,
        email: Option<String>,
        auth_provider: AuthProvider  // 매개변수 추가
    ) -> Result<String, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let exp_hours: i64 = std::env::var("JWT_EXPIRATION_HOURS")
            .unwrap_or_else(|_| "1".to_string())
            .parse()?;

        let claims = TokenClaims {
            sub: user_id.to_string(),
            jti: Uuid::new_v4().to_string(),
            auth_provider, // 매개변수 사용
            roles: vec![user_type.to_string()],
            iat: now.timestamp(),
            exp: (now + Duration::hours(exp_hours)).timestamp(),
            user_id: user_id.to_string(),
            email,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());

        let private_key_pem = self.private_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)?;
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())?;

        encode(&header, &claims, &encoding_key)
            .map_err(|e| e.into())
    }

    /// JWT 토큰을 검증합니다.
    ///
    /// RSA 공개키를 사용하여 토큰의 서명을 검증하고 클레임을 추출합니다.
    ///
    /// # Arguments
    ///
    /// * `token` - 검증할 JWT 토큰 문자열
    ///
    /// # Returns
    ///
    /// 검증된 토큰의 클레임 정보
    ///
    /// # Errors
    ///
    /// - 토큰 서명이 유효하지 않은 경우
    /// - 토큰이 만료된 경우
    /// - 토큰 형식이 올바르지 않은 경우
    /// - audience 또는 issuer가 일치하지 않는 경우
    ///
    /// # Examples
    ///
    /// ```rust,no_run,ignore
    /// # use crate::services::auth::jwt_rsa_service::JwtRsaService;
    ///
    /// let service = JwtRsaService::instance();
    /// let claims = service.validate_token("eyJ0eXAiOiJKV1QiLCJhbGc...")?;
    /// println!("User ID: {}", claims.sub);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate_token(&self, token: &str) -> Result<TokenClaims, Box<dyn std::error::Error>> {
        let public_key_pem = self.public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["trading-platform"]);
        validation.set_issuer(&["auth-service"]);

        decode::<TokenClaims>(token, &decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| e.into())
    }

    /// JWKS(JSON Web Key Set) 형식의 공개키 정보를 생성합니다.
    ///
    /// 다른 마이크로서비스에서 토큰 검증 시 사용할 수 있도록
    /// 표준 JWKS 형식으로 RSA 공개키 정보를 제공합니다.
    ///
    /// # Returns
    ///
    /// JWKS 형식의 JSON 값
    ///
    /// # Errors
    ///
    /// RSA 공개키 인코딩에 실패한 경우
    ///
    /// # Examples
    ///
    /// ```rust,no_run,ignore
    /// # use crate::services::auth::jwt_rsa_service::JwtRsaService;
    ///
    /// let service = JwtRsaService::instance();
    /// let jwks = service.get_jwks()?;
    /// 
    /// // HTTP 엔드포인트에서 반환
    /// // GET /.well-known/jwks.json
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn get_jwks(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        use rsa::traits::PublicKeyParts;

        let n = general_purpose::URL_SAFE_NO_PAD.encode(self.public_key.n().to_bytes_be());
        let e = general_purpose::URL_SAFE_NO_PAD.encode(self.public_key.e().to_bytes_be());

        Ok(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "kid": self.key_id,
                "n": n,
                "e": e,
                "alg": "RS256"
            }]
        }))
    }
}

/// 서비스 레지스트리 생성자 함수
///
/// `inventory` 크레이트를 통한 자동 서비스 등록을 위한 생성자 함수입니다.
fn jwt_rsa_service_constructor() -> Box<dyn std::any::Any + Send + Sync> {
    Box::new(JwtRsaService::instance() as Arc<dyn std::any::Any + Send + Sync>)
}

/// 전역 서비스 레지스트리에 JWT RSA 서비스를 등록합니다.
inventory::submit! {
    crate::core::registry::ServiceRegistration {
        name: "jwt_rsa_service", 
        constructor: jwt_rsa_service_constructor,
    }
}
