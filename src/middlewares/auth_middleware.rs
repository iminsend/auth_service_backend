//! JWT 인증 미들웨어
//!
//! ActixWeb 요청 파이프라인에서 JWT 토큰을 검증하고 사용자 정보를 추출합니다.

use std::future::{ready, Ready};
use std::rc::Rc;

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, Result,
    body::EitherBody,
};
use crate::domain::auth::authentication_request::{AuthMode, RequiredRole};
use crate::middlewares::auth_inner::AuthMiddlewareService;

/// JWT 인증 미들웨어
pub struct AuthMiddleware {
    /// 인증 모드 (Required/Optional)
    mode: AuthMode,
    /// 접근에 필요한 역할 (선택사항)
    required_role: Option<RequiredRole>,
}

impl AuthMiddleware {
    /// 새로운 인증 미들웨어 생성
    pub fn new(mode: AuthMode) -> Self {
        Self {
            mode,
            required_role: None,
        }
    }

    /// 역할 요구사항이 있는 인증 미들웨어 생성
    pub fn new_with_role(mode: AuthMode, required_role: RequiredRole) -> Self {
        Self {
            mode,
            required_role: Some(required_role),
        }
    }

    /// 필수 인증 미들웨어 생성
    pub fn required() -> Self {
        Self::new(AuthMode::Required)
    }

    /// 선택적 인증 미들웨어 생성
    pub fn optional() -> Self {
        Self::new(AuthMode::Optional)
    }

    /// 특정 역할 요구 인증 미들웨어 생성
    pub fn required_with_role(role: &str) -> Self {
        Self::new_with_role(
            AuthMode::Required,
            RequiredRole::Single(role.to_string())
        )
    }

    /// 복수 역할 중 하나 요구 인증 미들웨어 생성
    pub fn required_with_roles(roles: Vec<&str>) -> Self {
        let role_strings: Vec<String> = roles.into_iter().map(|s| s.to_string()).collect();
        Self::new_with_role(
            AuthMode::Required,
            RequiredRole::Any(role_strings)
        )
    }
}

/// ActixWeb Transform trait 구현
impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
            mode: self.mode.clone(),
            required_role: self.required_role.clone(),
        }))
    }
}


#[cfg(test)]
mod tests {
    use crate::config::AuthProvider;
    use crate::domain::auth::authenticated_user::AuthenticatedUser;
    use super::*;

    #[test]
    fn test_required_role_single() {
        let required = RequiredRole::Single("admin".to_string());
        let admin_roles = vec!["admin".to_string(), "user".to_string()];
        let user_roles = vec!["user".to_string()];

        assert!(required.is_satisfied(&admin_roles));
        assert!(!required.is_satisfied(&user_roles));
    }

    #[test]
    fn test_required_role_any() {
        let required = RequiredRole::Any(vec!["admin".to_string(), "moderator".to_string()]);
        let admin_roles = vec!["admin".to_string(), "user".to_string()];
        let moderator_roles = vec!["moderator".to_string(), "user".to_string()];
        let user_roles = vec!["user".to_string()];

        assert!(required.is_satisfied(&admin_roles));
        assert!(required.is_satisfied(&moderator_roles));
        assert!(!required.is_satisfied(&user_roles));
    }

    #[test]
    fn test_authenticated_user_has_role() {
        let user = AuthenticatedUser {
            user_id: "test_id".to_string(),
            auth_provider: AuthProvider::Local,
            roles: vec!["user".to_string(), "admin".to_string()],
        };

        assert!(user.has_role("admin"));
        assert!(user.has_role("user"));
        assert!(!user.has_role("moderator"));
        assert!(user.is_admin());
    }

    #[test]
    fn test_authenticated_user_has_any_role() {
        let user = AuthenticatedUser {
            user_id: "test_id".to_string(),
            auth_provider: AuthProvider::Local,
            roles: vec!["user".to_string(), "moderator".to_string()],
        };

        assert!(user.has_any_role(&["admin", "moderator"]));
        assert!(!user.has_any_role(&["admin", "premium"]));
        assert!(!user.is_admin());
    }
}
