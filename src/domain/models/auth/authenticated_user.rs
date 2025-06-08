use std::future::{ready, Ready};
use actix_web::{Error, FromRequest, HttpMessage, HttpRequest};
use serde::{Deserialize, Serialize};
use crate::config::AuthProvider;

/// JWT 토큰에서 추출된 사용자 정보
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    /// 사용자 고유 ID
    pub user_id: String,

    /// 인증 프로바이더
    pub auth_provider: AuthProvider,

    /// 사용자 역할 목록
    pub roles: Vec<String>,
}

impl AuthenticatedUser {
    /// 특정 역할을 보유하고 있는지 확인
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }

    /// 여러 역할 중 하나라도 보유하고 있는지 확인
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|&role| self.has_role(role))
    }

    /// 관리자 권한을 보유하고 있는지 확인
    pub fn is_admin(&self) -> bool {
        self.has_role("admin")
    }
}


/// ActixWeb FromRequest trait 구현
impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<actix_web::Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        match req.extensions().get::<AuthenticatedUser>() {
            Some(user) => ready(Ok(user.clone())),
            None => ready(Err(actix_web::error::ErrorUnauthorized(
                "인증되지 않은 요청입니다"
            ))),
        }
    }
}

/// 선택적 인증 사용자 추출자
#[derive(Debug, Clone)]
pub struct OptionalUser(pub Option<AuthenticatedUser>);

impl FromRequest for OptionalUser {
    type Error = Error;
    type Future = Ready<actix_web::Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let user = req.extensions().get::<AuthenticatedUser>().cloned();
        ready(Ok(OptionalUser(user)))
    }
}