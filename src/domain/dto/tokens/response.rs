use serde::Serialize;

/// API 응답 래퍼
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
        }
    }

    pub fn error(message: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: Some(message),
        }
    }
}