use serde::Deserialize;

/// 토큰 갱신 요청 DTO
#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// 로그아웃 요청 DTO (Header의 Authorization 정보에서 access_token 추출)
#[derive(Deserialize)]
pub struct LogoutRequest {
    // 필요시 추가 정보
}