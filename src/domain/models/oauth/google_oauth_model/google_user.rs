//! # Google OAuth 사용자 정보 모델
//!
//! 이 모듈은 Google OAuth 2.0 인증 플로우에서 반환되는 사용자 정보를 
//! 처리하기 위한 데이터 모델을 정의합니다.
//!
//! Google의 People API v1과 호환되며, Spring Security OAuth2와 
//! 유사한 방식으로 사용자 정보를 매핑합니다.

use serde::Deserialize;

/// Google OAuth 2.0 사용자 정보 응답 구조체
///
/// Google의 People API 또는 OAuth2 UserInfo 엔드포인트에서 반환되는
/// 사용자 정보를 역직렬화하기 위한 구조체입니다.
///
/// ## API 엔드포인트
///
/// 이 구조체는 다음 Google API 엔드포인트들과 호환됩니다:
///
/// - **UserInfo API**: `https://www.googleapis.com/oauth2/v2/userinfo`
/// - **People API**: `https://people.googleapis.com/v1/people/me`
///
/// ## OAuth 2.0 스코프 요구사항
///
/// 필드별로 필요한 OAuth 스코프:
///
/// | 필드 | 필수 스코프 | 설명 |
/// |------|-------------|------|
/// | `id`, `email` | `openid` | 기본 식별 정보 |
/// | `name`, `given_name`, `family_name` | `profile` | 프로필 정보 |
/// | `picture` | `profile` | 프로필 사진 |
/// | `verified_email` | `email` | 이메일 검증 상태 |
///
/// ## Spring Security OAuth2와의 비교
///
/// ```java
/// // Spring Security OAuth2 (Java)
/// @Component
/// public class GoogleOAuth2UserService extends DefaultOAuth2UserService {
///     @Override
///     public OAuth2User loadUser(OAuth2UserRequest userRequest) {
///         OAuth2User oauth2User = super.loadUser(userRequest);
///         // oauth2User.getAttribute("id")
///         // oauth2User.getAttribute("email")
///         // oauth2User.getAttribute("name")
///     }
/// }
/// ```
///
/// ```rust,ignore
/// // 이 구조체 (Rust)
/// let user_info: GoogleUserInfo = serde_json::from_str(&response_body)?;
/// println!("User ID: {}", user_info.id);
/// println!("Email: {}", user_info.email);
/// ```
///
/// ## 사용 예제
///
/// ```rust,ignore
/// use reqwest::Client;
/// use crate::domain::models::oauth::google_oauth_model::google_user::GoogleUserInfo;
///
/// async fn fetch_google_user_info(access_token: &str) -> Result<GoogleUserInfo, reqwest::Error> {
///     let client = Client::new();
///     let response = client
///         .get("https://www.googleapis.com/oauth2/v2/userinfo")
///         .bearer_auth(access_token)
///         .send()
///         .await?;
///
///     let user_info: GoogleUserInfo = response.json().await?;
///     Ok(user_info)
/// }
///
/// // 사용자 정보 처리
/// let user_info = fetch_google_user_info(&token).await?;
/// 
/// // 이메일 검증 확인
/// if user_info.verified_email {
///     println!("검증된 이메일: {}", user_info.email);
/// } else {
///     return Err("이메일이 검증되지 않았습니다".into());
/// }
///
/// // 사용자 등록 또는 로그인 처리
/// let user = User {
///     google_id: user_info.id,
///     email: user_info.email,
///     full_name: user_info.name,
///     first_name: user_info.given_name,
///     last_name: user_info.family_name,
///     avatar_url: user_info.picture,
///     email_verified: user_info.verified_email,
///     // ...
/// };
/// ```
///
/// ## 데이터 검증 고려사항
///
/// ### 필수 검증 항목
///
/// 1. **이메일 검증 상태**: `verified_email` 필드 확인 필수
/// 2. **ID 고유성**: Google ID는 변경되지 않는 고유 식별자
/// 3. **이메일 중복**: 다른 계정과 이메일 중복 가능성 고려
///
/// ### 보안 고려사항
///
/// ```rust,ignore
/// impl GoogleUserInfo {
///     /// 사용자 정보 검증
///     pub fn validate(&self) -> Result<(), ValidationError> {
///         // 1. 이메일 검증 상태 확인
///         if !self.verified_email {
///             return Err(ValidationError::EmailNotVerified);
///         }
///
///         // 2. 필수 필드 존재 확인
///         if self.id.is_empty() || self.email.is_empty() {
///             return Err(ValidationError::MissingRequiredFields);
///         }
///
///         // 3. 이메일 형식 검증
///         if !self.email.contains('@') {
///             return Err(ValidationError::InvalidEmailFormat);
///         }
///
///         Ok(())
///     }
/// }
/// ```
///
/// ## 프라이버시 정책 준수
///
/// Google의 사용자 데이터 정책에 따라:
///
/// - **최소 권한 원칙**: 필요한 스코프만 요청
/// - **데이터 보존**: 사용자가 연결 해제 시 데이터 삭제
/// - **투명성**: 수집하는 데이터와 용도를 명확히 공지
///
/// ## 에러 처리 패턴
///
/// ```rust,ignore
/// match serde_json::from_str::<GoogleUserInfo>(&response_body) {
///     Ok(user_info) => {
///         // 사용자 정보 검증
///         user_info.validate()?;
///         process_user_info(user_info).await
///     }
///     Err(e) => {
///         log::error!("Google 사용자 정보 파싱 실패: {}", e);
///         Err(AuthError::InvalidUserInfoResponse)
///     }
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct GoogleUserInfo {
    /// Google 사용자 고유 식별자
    ///
    /// Google 서비스에서 제공하는 변경되지 않는 고유 사용자 ID 입니다.
    /// 이 값은 사용자 계정의 Primary Key로 사용하기에 적합합니다.
    ///
    /// ## 특징
    ///
    /// - **불변성**: 한 번 할당되면 절대 변경되지 않음
    /// - **고유성**: Google 전체에서 고유함
    /// - **형식**: 숫자로 구성된 문자열 (예: "123456789012345678901")
    /// - **길이**: 일반적으로 21자리 숫자
    ///
    /// ## 사용 예제
    ///
    /// ```rust,ignore
    /// // 데이터베이스에서 기존 사용자 검색
    /// let existing_user = user_repository
    ///     .find_by_google_id(&user_info.id)
    ///     .await?;
    ///
    /// if existing_user.is_none() {
    ///     // 신규 사용자 등록
    ///     create_new_user_from_google(&user_info).await?;
    /// }
    /// ```
    pub id: String,

    /// 사용자 이메일 주소
    ///
    /// Google 계정의 기본 이메일 주소입니다.
    /// `email` 스코프가 있어야 접근 가능합니다.
    ///
    /// ## 검증 상태
    ///
    /// 이메일의 검증 상태는 `verified_email` 필드를 통해 확인해야 합니다.
    /// 검증되지 않은 이메일은 보안상 주의가 필요합니다.
    ///
    /// ## 중복 가능성
    ///
    /// - 같은 이메일로 여러 OAuth 제공자 계정 존재 가능
    /// - 기존 사용자와 이메일 중복 시 병합 또는 연결 정책 필요
    ///
    /// ## 사용 예제
    ///
    /// ```rust,ignore
    /// // 이메일 중복 검사
    /// let existing_user = user_repository
    ///     .find_by_email(&user_info.email)
    ///     .await?;
    ///
    /// match existing_user {
    ///     Some(user) => {
    ///         // 기존 계정에 Google 계정 연결
    ///         link_google_account(&user, &user_info).await?;
    ///     }
    ///     None => {
    ///         // 새 계정 생성
    ///         create_account_from_google(&user_info).await?;
    ///     }
    /// }
    /// ```
    pub email: String,

    /// 사용자 전체 이름
    ///
    /// 사용자의 표시 이름(Display Name)입니다.
    /// 일반적으로 "이름 성" 형태로 구성됩니다.
    ///
    /// ## 지역화 고려사항
    ///
    /// - **서양식**: "John Smith" (이름 + 성)
    /// - **동양식**: "김철수" (성 + 이름)
    /// - **단일명**: "Madonna" (하나의 이름만 사용)
    ///
    /// ## 사용 시나리오
    ///
    /// ```rust,ignore
    /// // UI 에서 사용자 인사
    /// println!("안녕하세요, {}님!", user_info.name);
    ///
    /// // 검색 인덱스용 정규화
    /// let normalized_name = user_info.name
    ///     .to_lowercase()
    ///     .trim()
    ///     .to_string();
    /// ```
    pub name: String,

    /// 사용자 이름 (First Name)
    ///
    /// 사용자의 이름 부분입니다.
    /// 서양식 이름에서는 Given Name에 해당합니다.
    ///
    /// ## 문화적 차이
    ///
    /// - **서양**: John (Smith 에서 John 부분)
    /// - **한국**: 철수 (김철수에서 철수 부분)
    /// - **일본**: 太郎 (田中太郎에서 太郎 부분)
    ///
    /// ## 활용 예제
    ///
    /// ```rust,ignore
    /// // 개인화된 인사말
    /// let greeting = format!("{}님, 환영합니다!", user_info.given_name);
    ///
    /// // 폼 자동 완성
    /// let user_form = UserRegistrationForm {
    ///     first_name: user_info.given_name,
    ///     last_name: user_info.family_name,
    ///     // ...
    /// };
    /// ```
    pub given_name: String,

    /// 사용자 성 (Last Name)
    ///
    /// 사용자의 성씨 부분입니다.
    /// 서양식 이름에서는 Family Name에 해당합니다.
    ///
    /// ## 문화적 차이
    ///
    /// - **서양**: Smith (John Smith 에서 Smith 부분)
    /// - **한국**: 김 (김철수에서 김 부분)
    /// - **일본**: 田中 (田中太郎에서 田中 부분)
    ///
    /// ## 데이터 처리 주의사항
    ///
    /// ```rust,ignore
    /// // 성이 없는 경우 처리
    /// let last_name = if user_info.family_name.is_empty() {
    ///     None
    /// } else {
    ///     Some(user_info.family_name)
    /// };
    ///
    /// // 알파벳 정렬용
    /// let sort_key = format!("{}, {}", 
    ///     user_info.family_name, 
    ///     user_info.given_name);
    /// ```
    pub family_name: String,

    /// 사용자 프로필 사진 URL
    ///
    /// Google 계정의 프로필 사진 URL 입니다.
    /// 사진이 설정되지 않은 경우 `None`이 될 수 있습니다.
    ///
    /// ## URL 특성
    ///
    /// - **HTTPS**: 항상 보안 연결
    /// - **크기 옵션**: URL 파라미터로 크기 조정 가능
    /// - **캐싱**: Google CDN 서버를 통해 전 세계적으로 캐싱됨
    /// - **만료**: URL이 만료될 수 있으므로 주기적 갱신 필요
    ///
    /// ## 크기 조정 예제
    ///
    /// ```rust,ignore
    /// if let Some(picture_url) = &user_info.picture {
    ///     // 다양한 크기로 조정 가능
    ///     let thumbnail = format!("{}=s50", picture_url);    // 50x50
    ///     let profile = format!("{}=s200", picture_url);     // 200x200
    ///     let large = format!("{}=s500", picture_url);       // 500x500
    ///
    ///     // 원본 크기 (파라미터 제거)
    ///     let original = picture_url.split('=').next().unwrap_or(picture_url);
    /// }
    /// ```
    ///
    /// ## 저장 전략
    ///
    /// ```rust,ignore
    /// match &user_info.picture {
    ///     Some(url) => {
    ///         // 옵션 1: URL 직접 저장 (간단, 하지만 외부 의존성)
    ///         user.avatar_url = Some(url.clone());
    ///
    ///         // 옵션 2: 이미지 다운로드 후 로컬 저장 (안정적)
    ///         let local_path = download_and_store_image(url).await?;
    ///         user.avatar_url = Some(local_path);
    ///     }
    ///     None => {
    ///         // 기본 아바타 또는 초기값 사용
    ///         user.avatar_url = None;
    ///     }
    /// }
    /// ```
    pub picture: Option<String>,

    /// 이메일 검증 상태
    ///
    /// Google 서비스에서 해당 이메일 주소가 검증되었는지 여부를 나타냅니다.
    /// 보안상 중요한 필드로, 검증되지 않은 이메일은 신뢰하지 않아야 합니다.
    ///
    /// ## 보안 중요성
    ///
    /// - **true**: Google이 이메일 소유권을 검증함
    /// - **false**: 검증되지 않은 이메일, 보안 위험 존재
    ///
    /// ## 정책 적용 예제
    ///
    /// ```rust,ignore
    /// // 강력한 보안 정책
    /// if !user_info.verified_email {
    ///     return Err(AuthError::EmailNotVerified {
    ///         message: "검증되지 않은 이메일로는 로그인할 수 없습니다".to_string(),
    ///         action: "Google 계정에서 이메일을 검증해주세요".to_string(),
    ///     });
    /// }
    ///
    /// // 유연한 정책 (경고와 함께 진행)
    /// if !user_info.verified_email {
    ///     log::warn!("검증되지 않은 이메일로 로그인: {}", user_info.email);
    ///     // 사용자에게 이메일 검증 필요성 알림
    ///     send_email_verification_notice(&user_info.email).await?;
    /// }
    /// ```
    ///
    /// ## 데이터베이스 저장
    ///
    /// ```rust,ignore
    /// let user = User {
    ///     email: user_info.email,
    ///     email_verified: user_info.verified_email,
    ///     email_verified_at: if user_info.verified_email {
    ///         Some(Utc::now())
    ///     } else {
    ///         None
    ///     },
    ///     // ...
    /// };
    /// ```
    pub verified_email: bool,
}
