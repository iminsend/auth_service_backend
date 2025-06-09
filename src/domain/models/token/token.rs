//! JWT 인증 토큰 구조체 및 페어링 된 세트
//! 
//! RFC 7591 JWT 표준 클레임과 2개의 용도별 토큰을 페어링 한 정보를 포시합니다.
use serde::{Deserialize, Serialize};
use crate::config::AuthProvider;

/// JWT 토큰의 클레임(Payload) 구조체
///
/// RFC 7519 JWT 표준의 클레임과 애플리케이션 특화 클레임을 포함합니다.
/// 개인정보 보호를 위해 최소한의 정보만 포함합니다.
///
/// ## 클레임 구성
///
/// - `sub`: 토큰의 주체 (사용자 ID)
/// - `iat`: 토큰 발급 시간 (Unix timestamp)  
/// - `exp`: 토큰 만료 시간 (Unix timestamp)
/// - `auth_provider`: 인증 방식 (Local, Google 등)
/// - `roles`: 사용자 권한 목록
/// - `user_id`: 사용자 ID (sub와 동일하지만 명시적 접근용)
/// - `email`: 사용자 이메일 (선택사항)
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    /// 토큰의 주체 (사용자 ID)
    pub sub: String,
    /// 인증 프로바이더
    pub auth_provider: AuthProvider,
    /// 사용자 역할 목록 (권한 기반 접근 제어용)
    pub roles: Vec<String>,
    /// 토큰 발급 시간 (Unix timestamp)
    pub iat: i64,
    /// 토큰 만료 시간 (Unix timestamp)
    pub exp: i64,
    /// 사용자 ID (sub와 동일)
    pub user_id: String,
    /// 사용자 이메일 (선택사항)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

/// JWT 토큰 쌍 구조체
///
/// 클라이언트에게 전달되는 토큰 집합을 나타냅니다.
/// OAuth 2.0 표준의 토큰 응답 형식을 따릅니다.
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPair {
    /// 액세스 토큰 (API 접근용 단기 토큰)
    pub access_token: String,
    /// 리프레시 토큰 (토큰 갱신용 장기 토큰, 선택사항)
    pub refresh_token: Option<String>,
    /// 액세스 토큰 만료 시간 (초)
    pub expires_in: i64,
}
