use actix_web::{get, HttpResponse};
use crate::core::AppError;
use crate::services::auth::JwtRsaService;

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
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate JWKS"
            })))
        }
    }
}