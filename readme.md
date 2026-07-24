# Tiny Second-hand Shopping Platform

간단한 중고거래 플랫폼
Flask + Flask-SocketIO + SQLAlchemy(SQLite) 기반이며,
회원가입/로그인, 상품 등록·조회·수정·삭제, 검색, 실시간 전체/1:1 채팅, 신고 및 자동 차단·휴면 처리,
유저 간 송금, 관리자 페이지를 제공함


## 기능 목록

- 회원 관리: 회원가입, 로그인(실패 잠금 포함), 로그아웃, 마이페이지(소개글/비밀번호 수정), 다른 사용자 프로필 조회
- 상품 관리: 등록, 전체 조회, 상세 조회, 검색, 소유자 본인만 수정/삭제 가능, 내 상품 관리
- 실시간 채팅: 전체 채팅방 + 1:1 채팅 (로그인한 사용자만 접속 가능)
- 신고/차단: 상품·사용자 신고, 중복 신고 방지, 신고 누적 시 상품 자동 차단 / 사용자 자동 휴면
- 송금: 사용자 간 잔액 송금, 거래 내역 조회
- 관리자: 사용자 휴면 처리/해제, 상품 차단/해제/삭제, 신고 내역 조회

## 환경 설정

### 1. 저장소 클론

```bash
git clone <이 저장소 URL>
cd tiny-marketplace
```

### 2. Python 가상환경 준비 (둘 중 하나)

**venv + pip**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**conda**
```bash
conda env create -f enviroments.yaml
conda activate secure_coding
```

### 3. 환경변수 설정

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # 출력값을 복사해서
# .env 파일의 SECRET_KEY= 뒤에 붙여넣기
```

`SECRET_KEY`는 세션 서명에 사용되므로 반드시 설정해야 하며, 값이 없으면 서버가 시작되지 않을 수 있음

## 실행 방법

```bash
python app.py
```

기본적으로 `http://localhost:5000` 에서 접속할 수 있음 (최초 실행 시 `market.db` SQLite 파일이 자동 생성)

외부에서 접속 테스트가 필요하면 ngrok으로 포워딩 가능.

```bash
# optional
sudo snap install ngrok
ngrok http 5000
```

## 관리자 계정 만들기

1. 일반 회원가입으로 계정을 하나 생성함
2. 아래 명령어로 해당 계정을 관리자로 승격함

```bash
flask --app app create-admin <사용자명>
```

3. 다시 로그인하면 네비게이션에 "관리자" 메뉴가 표시됨 (`/admin`)

## 참고

- 데이터베이스: SQLite (`market.db`, 파일은 git에 포함되지 않음)
- 비밀번호는 평문 저장되지 않고 `werkzeug.security`의 salted hash(PBKDF2-SHA256)로 저장됨.
- 로컬 개발(HTTP)에서는 `.env`의 `SESSION_COOKIE_SECURE=false`를 유지 -> HTTPS(ngrok 등) 환경에서 테스트할 때는 `true`로 바꾸는 것을 권장
