# DawnAuth - OAuth2 인증 서버 (JWT 기반)

DawnAuth는 **Express**와 **PostgreSQL**을 사용하여 구현한 JWT 기반 인증 서버입니다. 이 서버는 사용자 인증 및 권한 부여를 위해 **JWT** 토큰을 발급하며, 사용자 데이터는 **PostgreSQL**에 저장됩니다.

## 설치 및 실행

### 1. 패키지 설치
```bash
npm install
```

### 2. 환경 변수 설정
프로젝트 루트에 `.env` 파일을 생성한 후, 다음 내용을 추가합니다:

```plaintext
DB_USER=your_pg_user
DB_PASS=your_pg_password
DB_NAME=your_pg_db
DB_HOST=localhost
DB_PORT=5432

JWT_SECRET=your_jwt_secret
REFRESH_TOKEN_SECRET=your_refresh_token_secret
```

### 3. 서버 실행
```bash
npx nodemon app.js
```

서버는 기본적으로 `http://localhost:3000`에서 실행됩니다.

---

## API 엔드포인트

### 1. 회원가입 (User Registration)
사용자를 등록하여 데이터베이스에 저장합니다.

- **URL**: `/register`
- **메서드**: `POST`
- **요청 헤더**:
  ```http
  Content-Type: application/json
  ```
- **요청 본문**:
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```
- **응답 본문**:
  ```json
  {
    "message": "User created successfully",
    "user": {
      "id": 1,
      "username": "your_username"
    }
  }
  ```

### 2. 로그인 (User Login)
로그인 후 JWT 토큰과 리프레시 토큰을 발급합니다.

- **URL**: `/login`
- **메서드**: `POST`
- **요청 헤더**:
  ```http
  Content-Type: application/json
  ```
- **요청 본문**:
  ```json
  {
    "username": "your_username",
    "password": "your_password"
  }
  ```
- **응답 본문**:
  ```json
  {
    "message": "Login successful",
    "accessToken": "your_access_token",
    "refreshToken": "your_refresh_token"
  }
  ```

### 3. 리프레시 토큰 (Refresh Token)
리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급받습니다.

- **URL**: `/token`
- **메서드**: `POST`
- **요청 헤더**:
  ```http
  Content-Type: application/json
  ```
- **요청 본문**:
  ```json
  {
    "refreshToken": "your_refresh_token"
  }
  ```
- **응답 본문**:
  ```json
  {
    "accessToken": "new_access_token"
  }
  ```

### 4. 로그아웃 (User Logout)
로그아웃하여 리프레시 토큰을 무효화합니다.

- **URL**: `/logout`
- **메서드**: `POST`
- **요청 헤더**:
  ```http
  Content-Type: application/json
  ```
- **요청 본문**:
  ```json
  {
    "refreshToken": "your_refresh_token"
  }
  ```
- **응답 본문**:
  ```
  204 No Content
  ```

### 5. 프로필 조회 (Protected Route)
JWT 토큰을 사용하여 사용자 정보를 보호된 라우트에서 조회합니다.

- **URL**: `/profile`
- **메서드**: `GET`
- **요청 헤더**:
  ```http
  Authorization: Bearer your_access_token
  ```
- **응답 본문**:
  ```json
  {
    "message": "Welcome to your profile!",
    "user": {
      "id": 1,
      "username": "your_username"
    }
  }
  ```

---

## 데이터베이스 설정

DawnAuth는 사용자 정보를 PostgreSQL에 저장합니다. 아래 SQL 명령어를 사용하여 `users` 테이블을 생성할 수 있습니다.

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    refresh_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 사용된 기술 스택

- **Node.js**: 서버 환경
- **Express**: 웹 프레임워크
- **PostgreSQL**: 데이터베이스
- **JWT (jsonwebtoken)**: 인증 및 권한 부여
- **Passport**: 인증 미들웨어
- **bcryptjs**: 비밀번호 해시화

---
