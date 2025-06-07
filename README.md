# Auth Service Backend

Rust로 구현된 백엔드 인증 서비스입니다. Spring Framework의 설계 철학을 Rust 생태계에 맞게 구현하여 타입 안전성과 성능을 모두 만족하는 DI 컨테이너와 인증 시스템을 제공합니다.

## 🚀 주요 기능

- **의존성 주입 시스템**: Spring의 ApplicationContext와 유사한 싱글톤 DI 컨테이너
- **자동 서비스 등록**: `#[service]`, `#[repository]` 매크로를 통한 컴파일 타임 등록
- **다중 인증 지원**: 로컬 인증, Google OAuth, JWT 토큰
- **MongoDB 통합**: 네이티브 MongoDB 쿼리 및 집계 파이프라인 지원
- **Redis 캐싱**: 성능 최적화를 위한 분산 캐시
- **통합 에러 처리**: 계층화된 에러 타입과 자동 HTTP 응답 변환

## 🛠 기술 스택

- **런타임**: Rust 1.70+
- **웹 프레임워크**: Actix-Web
- **데이터베이스**: MongoDB
- **캐시**: Redis
- **인증**: JWT, OAuth 2.0 (Google)
- **시리얼라이제이션**: Serde
- **비동기**: Tokio

## 📋 사전 요구사항

- Rust 1.70 이상
- MongoDB (로컬 또는 MongoDB Atlas)
- Redis (로컬 또는 클라우드)
- Google Cloud Console 계정 (OAuth 사용 시)

## ⚡ 빠른 시작

### 1. 저장소 클론

```bash
git clone https://github.com/iminsend/auth_service_backend.git
cd auth_service_backend
```

### 2. 환경 설정

```bash
# .env 파일 생성
cp .env.example .env

# 환경 변수 설정 (에디터로 .env 파일 편집)
vim .env
```

### 3. 필수 환경 변수 설정

다음 값들을 실제 값으로 교체하세요:

```bash
# 데이터베이스
MONGODB_URI=mongodb://localhost:27017
DATABASE_NAME=auth_service_dev

# Google OAuth (필수)
GOOGLE_CLIENT_ID=your-actual-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-actual-client-secret
GOOGLE_PROJECT_ID=your-project-id

# JWT 보안
JWT_SECRET=your-strong-256-bit-secret
```

### 4. 서비스 실행

```bash
# 개발 모드로 실행
cargo run

# 또는 릴리스 모드로 실행
cargo run --release
```

서버가 `http://localhost:8080`에서 시작됩니다.

## 🔧 Google OAuth 설정

### 1. Google Cloud Console 설정

1. [Google Cloud Console](https://console.cloud.google.com/) 접속
2. 새 프로젝트 생성 또는 기존 프로젝트 선택
3. **APIs & Services > Credentials** 로 이동
4. **Create Credentials > OAuth 2.0 Client IDs** 선택
5. Application type: **Web application** 선택
6. **Authorized redirect URIs**에 추가:
   - 개발: `http://localhost:8080/api/v1/auth/google/callback`
   - 프로덕션: `https://yourdomain.com/api/v1/auth/google/callback`

### 2. 환경 변수 설정

생성된 Client ID와 Client Secret을 `.env` 파일에 설정:

```bash
GOOGLE_CLIENT_ID=123456789-abcdefg.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-client-secret
GOOGLE_PROJECT_ID=your-project-id
```

## 🗄️ 데이터베이스 설정

### MongoDB 로컬 설치

```bash
# macOS (Homebrew)
brew install mongodb-community
brew services start mongodb-community

# Ubuntu
sudo apt install mongodb
sudo systemctl start mongodb

# Docker
docker run -d -p 27017:27017 --name mongodb mongo:latest
```

### MongoDB Atlas (클라우드)

1. [MongoDB Atlas](https://cloud.mongodb.com/) 계정 생성
2. 클러스터 생성
3. 연결 문자열 복사
4. `.env` 파일의 `MONGODB_URI` 업데이트:

```bash
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
```

## 🚦 Redis 설정

### Redis 로컬 설치

```bash
# macOS (Homebrew)
brew install redis
brew services start redis

# Ubuntu
sudo apt install redis-server
sudo systemctl start redis

# Docker
docker run -d -p 6379:6379 --name redis redis:alpine
```

## 📁 프로젝트 구조

```
src/
├── core/           # 핵심 프레임워크 (DI, 에러 처리)
├── config/         # 설정 관리 (환경, 인증, 데이터)
├── db/             # 데이터베이스 연결 관리
├── caching/        # Redis 캐시 관리
├── domain/         # 도메인 모델 (entities, DTOs)
├── repositories/   # 데이터 액세스 계층
├── services/       # 비즈니스 로직 계층
├── handlers/       # HTTP 핸들러 (컨트롤러)
├── routes/         # 라우팅 설정
├── utils/          # 유틸리티 함수
└── lib.rs          # 라이브러리 루트
```

## 🔑 API 엔드포인트

### 인증 API

```bash
# Google OAuth 로그인 시작
GET /api/v1/auth/google

# Google OAuth 콜백
GET /api/v1/auth/google/callback

# 로컬 로그인
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "password"
}

# 회원가입
POST /api/v1/auth/register
{
  "email": "user@example.com",
  "password": "password",
  "name": "User Name"
}

# 토큰 갱신
POST /api/v1/auth/refresh
{
  "refresh_token": "your-refresh-token"
}
```

### 사용자 API

```bash
# 현재 사용자 정보
GET /api/v1/users/me
Authorization: Bearer your-jwt-token

# 사용자 목록 (관리자)
GET /api/v1/users
Authorization: Bearer admin-jwt-token
```

## 🧪 테스트 실행

```bash
# 단위 테스트
cargo test

# 통합 테스트
cargo test --test integration

# 특정 테스트 실행
cargo test test_user_service
```

## 🚀 배포

### Docker 배포

```bash
# Docker 이미지 빌드
docker build -t auth-service .

# 컨테이너 실행
docker run -d \
  -p 8080:8080 \
  --env-file .env.prod \
  --name auth-service \
  auth-service
```

### 환경 변수 배포

프로덕션 환경에서는 다음 환경 변수들을 안전하게 설정하세요:

```bash
# 보안 (강력한 랜덤 값 사용)
JWT_SECRET=your-production-256-bit-secret
OAUTH_STATE_SECRET=your-production-oauth-secret

# 데이터베이스 (실제 클러스터)
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/...
DATABASE_NAME=auth_service_prod

# OAuth (프로덕션 Google 프로젝트)
GOOGLE_CLIENT_ID=prod-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-prod-client-secret

# 서버 설정
ENVIRONMENT=production
HOST=0.0.0.0
PORT=8080
BCRYPT_COST=12
```

## 🐛 트러블슈팅

### 일반적인 문제들

#### MongoDB 연결 실패
```bash
Error: Failed to connect to MongoDB
```
**해결**: MongoDB 서버 상태 확인, URI 검증

#### Google OAuth 오류
```bash
Error: Invalid client credentials
```
**해결**: Google Cloud Console에서 Client ID/Secret 재확인

#### Redis 연결 실패
```bash
Error: Redis connection refused
```
**해결**: Redis 서버 실행 상태 확인

#### 포트 충돌
```bash
Error: Address already in use
```
**해결**: `.env`에서 다른 포트 번호 설정

## 📖 개발 가이드

### 새 서비스 추가

```rust
use std::sync::Arc;
use crate::repositories::UserRepository;

#[service]
pub struct EmailService {
    user_repo: Arc<UserRepository>,  // 자동 주입
}

impl EmailService {
    pub async fn send_verification(&self, email: &str) -> Result<(), AppError> {
        // 이메일 발송 로직
        Ok(())
    }
}
```

### 새 리포지토리 추가

```rust
use std::sync::Arc;
use crate::db::Database;

#[repository(collection = "posts")]
pub struct PostRepository {
    db: Arc<Database>,  // 자동 주입
}

impl PostRepository {
    pub async fn create(&self, post: Post) -> Result<Post, AppError> {
        self.collection().insert_one(&post, None).await?;
        Ok(post)
    }
}
```

## 🤝 기여하기

1. 이 저장소를 포크합니다
2. 기능 브랜치를 생성합니다 (`git checkout -b feature/amazing-feature`)
3. 변경사항을 커밋합니다 (`git commit -m 'Add amazing feature'`)
4. 브랜치에 푸시합니다 (`git push origin feature/amazing-feature`)
5. Pull Request를 생성합니다

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.

## 📞 지원

문제가 발생하거나 질문이 있으시면:

- GitHub Issues에 문제 보고
- 이메일: support@yourdomain.com
- 문서: [프로젝트 위키](https://github.com/iminsend/auth_service_backend/wiki)

---

**⚠️ 보안 주의사항**: 
- 실제 환경에서는 강력한 비밀키를 사용하세요
- 환경 파일(.env)을 Git에 커밋하지 마세요
- 프로덕션에서는 HTTPS를 필수로 사용하세요
- 정기적으로 의존성을 업데이트하세요
