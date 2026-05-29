# HSPACE LiveFire CLI 배포 가이드

기준 서버: `knights.hspace.io`  
Coordinator API: `http://knights.hspace.io:42000`  
CLI 공지 txt: `http://knights.hspace.io:42000/deploy/DISCORD_NOTICE.txt`  
배포 번들: `http://knights.hspace.io:42000/deploy-bundle.tar.gz`

이 문서는 참가자가 CLI로 서비스 템플릿을 받아 개발, 검증, 제출하는 절차만 다룹니다. Proxmox, 포트포워딩, VM 생성, 서버 SSH 접속, 그래픽 화면은 운영 대상이 아닙니다.

## 1. 서버 주소와 포트

| 용도 | 주소 |
|---|---|
| Coordinator API | `http://knights.hspace.io:42000` |
| Team 1 서비스 | `http://knights.hspace.io:42001` |
| Team 2 서비스 | `http://knights.hspace.io:42002` |
| Team 3 서비스 | `http://knights.hspace.io:42003` |
| Team 4 서비스 | `http://knights.hspace.io:42004` |
| Team 5 서비스 | `http://knights.hspace.io:42005` |
| Team 6 서비스 | `http://knights.hspace.io:42006` |

사용자는 위 주소와 CLI helper만 사용합니다. 서버 내부 IP, VM 설정, 40000/49000 관리 콘솔은 운영자가 관리합니다.

## 2. 운영자에게 받을 정보

각 팀은 아래 세 가지를 받아야 합니다.

| 항목 | 예시 | 설명 |
|---|---|---|
| 팀 ID | `team1` | `team1`~`team6` 중 하나 |
| 팀 토큰 | `<TEAM_TOKEN>` | 자기 팀 repo 제출용 토큰 |
| Coordinator URL | `http://knights.hspace.io:42000` | 로그인, 검증, 제출 대상 |

`ADMIN_SECRET`, `RUNNER_SECRET`, 다른 팀 토큰, VM 계정은 사용자에게 전달하지 않습니다.

## 3. 로컬 준비

필수 도구:

- Python 3.10 이상
- Git
- Docker Desktop 또는 Docker Engine
- 인터넷 연결

확인 명령:

```bash
python3 --version
git --version
docker --version
docker ps
```

## 4. 배포 파일 받기

권장 방식은 팀별 private GitHub repo를 clone하는 것입니다.

| 팀 | GitHub repo |
|---|---|
| team1 | `https://github.com/Knights-HS/team1` |
| team2 | `https://github.com/Knights-HS/team2` |
| team3 | `https://github.com/Knights-HS/team3` |
| team4 | `https://github.com/Knights-HS/team4` |
| team5 | `https://github.com/Knights-HS/team5` |
| team6 | `https://github.com/Knights-HS/team6` |

예시:

```bash
git clone https://github.com/Knights-HS/team1.git
cd team1
cp .env.example .env
# .env의 TEAM_TOKEN을 운영자에게 받은 토큰으로 교체
```

팀 repo에는 `TEAM_ID`와 `COORDINATOR_URL` 기본값이 이미 들어 있습니다. 토큰은 `.env`에만 저장하고 GitHub에 커밋하지 마세요.
이후 `make run`, `make check`, `make push` 명령은 팀별 GitHub repo 루트 기준입니다.

GitHub 접근이 어렵거나 전체 템플릿 번들이 필요할 때는 아래 파일을 받습니다.

```bash
curl -fLO http://knights.hspace.io:42000/deploy-bundle.tar.gz
tar -xzf hspace-livefire-user-deploy.tar.gz
cd user_deploy
```

공지 txt만 확인할 때:

```bash
curl -fsS http://knights.hspace.io:42000/deploy/DISCORD_NOTICE.txt
```

## 5. 폴더 구성

| 경로 | 용도 |
|---|---|
| `web_service/` | 서비스 예시 템플릿 |
| `web_service/vuln_spec.json` | checker와 공격 검증 명세 |
| `attack_agent/` | 공격 agent 템플릿 |
| `defense_agent/` | 방어 agent 템플릿 |
| `agent_sdk/` | coordinator 연동 SDK |
| `scripts/gitctf.py` | 로그인, 검증, 제출, agent 빌드 CLI |
| `scripts/validate_vulns.py` | 로컬 취약점 검증 엔진 |
| `RULEBOOK.md` | 대회 규칙 |
| `DISCORD_NOTICE.txt` | 참가자 공지 원문 |
| `USER_DEPLOY_GUIDE.md` | 이 CLI 가이드 |

## 6. 서비스 개발

예시 템플릿은 FastAPI 기반입니다. 팀은 API를 자유롭게 바꿀 수 있지만 `vuln_spec.json`에는 실제 요청 경로와 기대 응답을 정확히 적어야 합니다.

템플릿 실행:

```bash
make run
```

배포 번들을 받은 경우:

```bash
cd web_service
make run
```

다른 터미널에서 헬스체크:

```bash
curl -fsS http://127.0.0.1:8000/health
```

응답이 아래처럼 나오면 기본 서버는 떠 있습니다.

```json
{"status":"ok"}
```

## 7. 취약점 명세 작성

`web_service/vuln_spec.json`에는 정확히 4개 취약점이 있어야 합니다.

각 취약점은 최소한 아래 흐름을 검증할 수 있어야 합니다.

| 단계 | 의미 |
|---|---|
| `checker.inject` | 라운드별 flag를 서비스에 주입 |
| `checker.retrieve` | 주입된 flag가 저장됐는지 운영 checker가 확인 |
| `attack` | 공격 payload로 flag가 실제 응답에 노출되는지 확인 |
| `checker.basic_function` | 취약점 패치 뒤에도 기본 기능이 살아 있는지 확인 |

검증기는 `test_payload`로 공격 요청을 보내고, 응답에서 `HSPACE{...}` 형식의 flag를 찾습니다.

## 8. 로컬 검증

서비스가 `127.0.0.1:8000`에서 떠 있는 상태로 실행합니다.

```bash
make check
```

배포 번들을 받은 경우:

```bash
cd web_service
python ../scripts/gitctf.py check --repeat 3
```

통과 기준:

- health OK
- 4개 취약점 모두 inject 성공
- retrieve 성공
- attack 3/3 성공
- basic_function OK

실패하면 `vuln_spec.json`의 endpoint, method, body, response_path, expect_contains와 서비스 구현을 먼저 맞춥니다.

## 9. 대회 서버 로그인

운영자에게 받은 팀 ID와 팀 토큰을 저장합니다.

```bash
python scripts/gitctf.py login team1 --token "<TEAM_TOKEN>" --coordinator http://knights.hspace.io:42000
```

`team1`는 자기 팀 ID로 바꿉니다. 이 명령은 로컬 설정 파일에 토큰을 저장합니다.

## 10. 서비스 제출

로컬 검증을 통과한 뒤 제출합니다.

```bash
make push
```

배포 번들을 받은 경우:

```bash
python ../scripts/gitctf.py push --message "submit service"
```

제출 중 서버에서 자동으로 수행하는 일:

1. git push 인증
2. `Dockerfile` 빌드 검증
3. `vuln_spec.json` JSON 검증
4. 서비스 이미지 빌드
5. 팀별 내부 IP에 컨테이너 배포
6. 팀별 외부 포트로 gateway 연결

제출 후 자기 팀 포트를 확인합니다.

```bash
curl -fsS http://knights.hspace.io:42001/health
```

Team 1는 `42001`, Team 2는 `42002`, ..., Team 6는 `42006`입니다.

## 11. 점수 / 라운드 상태 조회

상태는 JSON API를 CLI로 조회합니다.

```bash
curl -fsS http://knights.hspace.io:42000/status | python3 -m json.tool
curl -fsS http://knights.hspace.io:42000/scoreboard | python3 -m json.tool
```

운영자는 로컬 또는 서버에서 단일 CLI로 더 간단히 확인할 수 있습니다.

```bash
python scripts/gitctf.py admin status --coordinator http://knights.hspace.io:42000
```

## 12. agent 빌드

공격 agent 이미지:

```bash
cd user_deploy
python scripts/gitctf.py agent build team1 --mode attack
```

방어 agent 이미지:

```bash
python scripts/gitctf.py agent build team1 --mode defense
```

entrypoint 확인:

```bash
python scripts/gitctf.py agent doctor --mode attack
python scripts/gitctf.py agent doctor --mode defense
```

공식 라운드의 agent 실행은 운영 서버가 담당합니다. 일반 참가자가 로컬에서 만든 agent run은 점수 산출 기준이 아닙니다.

## 13. 대회 중 패치 제출

대회 시작 전에는 자기 팀이 자기 repo에 직접 push할 수 있습니다. 사전검증 완료 뒤에는 운영 정책에 따라 추가 push가 제한될 수 있습니다.

대회 중 방어 agent가 지정된 대상 repo를 패치할 때는 서버가 `Agent-Run-ID` provenance를 검증합니다. 일반 사용자가 임의로 다른 팀 repo를 push하면 거부됩니다.

## 14. 자주 나는 오류

| 증상 | 원인 | 해결 |
|---|---|---|
| `coordinator 연결 실패` | URL 오타 또는 네트워크 문제 | `curl -fsS http://knights.hspace.io:42000/health` 확인 |
| `Git 인증 실패` | 팀 ID/토큰 불일치 | 운영자에게 자기 팀 토큰 재확인 |
| `Dockerfile 없음` | 서비스 폴더 루트가 아님 | `Dockerfile`이 있는 폴더에서 push |
| `vuln_spec.json 없음` | 명세 파일 누락 | 서비스 루트에 `vuln_spec.json` 추가 |
| `health 실패` | 서비스 미실행 또는 포트 불일치 | 로컬 `make run`, `curl -fsS :8000/health` 확인 |
| `inject 실패` | checker endpoint/header/body 불일치 | `checker.inject`와 서비스 `/admin/inject` 구현 확인 |
| `flag 미탈취` | attack payload/response_path 불일치 | `attack` 명세와 실제 응답 확인 |
| `basic_function 실패` | 정상 기능이 깨짐 | 패치 후 기본 기능 응답 복구 |

## 15. 제출 전 체크리스트

- `Dockerfile`이 서비스 루트에 있다.
- `vuln_spec.json`이 서비스 루트에 있다.
- 취약점은 정확히 4개다.
- `python ../scripts/gitctf.py check --repeat 3`가 통과한다.
- 팀 ID와 토큰이 자기 팀 것인지 확인했다.
- `python ../scripts/gitctf.py push`가 성공했다.
- 자기 팀 외부 포트 `/health`가 200을 반환한다.

## 16. 운영자에게 문의할 때 같이 보낼 정보

아래 정보를 같이 보내면 빠르게 확인할 수 있습니다.

- 팀 ID
- 실행한 명령
- 터미널 오류 전문
- `vuln_spec.json`
- 서비스 `/health` 응답
- 로컬 `git status --short` 결과

토큰은 전체 채팅방에 올리지 말고 운영자에게만 직접 전달합니다.
