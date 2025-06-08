//! Domain Entities Module
//!
//! 비즈니스 도메인의 핵심 엔티티들을 정의합니다.
//! MongoDB 문서와 직접 매핑되는 데이터 구조체들을 포함합니다.
//!
//! # 주요 역할
//! - **도메인 모델링**: 비즈니스 도메인의 핵심 개념들을 Rust 구조체로 표현
//! - **데이터베이스 매핑**: MongoDB 컬렉션과 1:1 대응되는 문서 구조 정의
//! - **타입 안전성**: 컴파일 타임에 데이터 일관성 보장
//! - **직렬화/역직렬화**: JSON ↔ Rust 구조체 변환 지원
//!
//! # 사용 예제
//!
//! ```rust,ignore
//! use crate::domain::entities::users::User;
//!
//! #[repository(collection = "users")]
//! struct UserRepository {
//!     db: Arc<Database>,
//! }
//!
//! impl UserRepository {
//!     async fn find_by_email(&self, email: &str) -> Option<User> {
//!         self.collection::<User>()
//!             .find_one(doc! { "email": email }, None)
//!             .await
//!             .ok()
//!             .flatten()
//!     }
//! }
//! ```

pub mod users;
