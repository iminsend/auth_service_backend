//! AuthMiddleware 인증 로직의 핵심적인 기능
use std::rc::Rc;
use actix_web::body::EitherBody;
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse};
use actix_web::{Error, HttpMessage, HttpResponse};
use futures_util::future::LocalBoxFuture;
use crate::core::AppError;
use crate::domain::auth::authenticated_user::AuthenticatedUser;
use crate::domain::auth::authentication_request::{AuthMode, RequiredRole};
use crate::services::auth::TokenService;

/// 실제 인증 로직을 수행하는 서비스
pub struct AuthMiddlewareService<S> {
    pub service: Rc<S>,
    pub mode: AuthMode,
    pub required_role: Option<RequiredRole>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, actix_web::Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let mode = self.mode.clone();
        let required_role = self.required_role.clone();

        Box::pin(async move {
            // TokenService 인스턴스 가져오기
            let token_service = TokenService::instance();

            // Authorization 헤더에서 토큰 추출 시도
            let auth_result = extract_token_from_request(&req, &token_service).await;

            match (&mode, auth_result) {
                // Required 모드에서 인증 실패
                (AuthMode::Required, Err(err)) => {
                    log::warn!("인증 실패: {}", err);
                    let response = HttpResponse::Unauthorized()
                        .json(serde_json::json!({
                            "error": "authentication_required",
                            "message": "유효한 인증 토큰이 필요합니다"
                        }));
                    let (req, _) = req.into_parts();
                    let res = ServiceResponse::new(req, response)
                        .map_into_right_body();
                    return Ok(res);
                },
                // Required 모드에서 인증 성공
                (AuthMode::Required, Ok(user)) => {
                    // 역할 검증
                    if let Some(ref required) = required_role {
                        if !required.is_satisfied(&user.roles) {
                            log::warn!("권한 부족: 사용자 ID {} ({:?}), 필요 권한: {:?}", 
                                user.user_id, user.roles, required);
                            let response = HttpResponse::Forbidden()
                                .json(serde_json::json!({
                                    "error": "insufficient_permissions",
                                    "message": "접근 권한이 부족합니다"
                                }));
                            let (req, _) = req.into_parts();
                            let res = ServiceResponse::new(req, response)
                                .map_into_right_body();
                            return Ok(res);
                        }
                    }

                    // 사용자 정보를 Request Extensions에 저장
                    req.extensions_mut().insert(user.clone());
                    log::debug!("인증 성공: 사용자 ID {}", user.user_id);
                },
                // Optional 모드에서 인증 성공
                (AuthMode::Optional, Ok(user)) => {
                    // 역할 검증 (Optional 모드에서는 실패해도 진행)
                    if let Some(ref required) = required_role {
                        if required.is_satisfied(&user.roles) {
                            req.extensions_mut().insert(user.clone());
                            log::debug!("선택적 인증 성공: 사용자 ID {}", user.user_id);
                        } else {
                            log::debug!("선택적 인증: 권한 부족하지만 진행 허용");
                        }
                    } else {
                        req.extensions_mut().insert(user.clone());
                        log::debug!("선택적 인증 성공: 사용자 ID {}", user.user_id);
                    }
                },
                // Optional 모드에서 인증 실패 (진행 허용)
                (AuthMode::Optional, Err(_)) => {
                    log::debug!("선택적 인증: 토큰 없음, 요청 진행");
                },
            }

            // 다음 서비스로 요청 전달
            let res = service.call(req).await?;
            Ok(res.map_into_left_body())
        })
    }
}

/// 요청에서 JWT 토큰을 추출하고 검증
async fn extract_token_from_request(
    req: &ServiceRequest,
    token_service: &TokenService,
) -> actix_web::Result<AuthenticatedUser, AppError> {
    // Authorization 헤더 추출
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::AuthenticationError("Authorization 헤더가 없습니다".to_string()))?;

    // Bearer 토큰 추출
    let token = token_service.extract_bearer_token(auth_header)?;

    // 토큰 검증 및 클레임 추출
    let claims = token_service.verify_token(token)?;

    // AuthenticatedUser 구조체 생성
    Ok(AuthenticatedUser {
        user_id: claims.sub,
        auth_provider: claims.auth_provider,
        roles: claims.roles,
    })
}