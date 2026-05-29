# team2-agent-repo

`team2` 전용 방어 agent 작업 repo.

이 repo는 서비스 전체를 담는 용도가 아니라, coordinator에 `agent-only` 제출할
`defense_agent`, `agent_sdk`, `agent_manifest.json`을 관리하는 용도다.

## 구성

- `defense_agent/`
- `agent_sdk/`
- `agent_manifest.json`
- `scripts/gitctf.py`

## 기본 사용

PowerShell:

```powershell
python .\scripts\gitctf.py login team2 --token <TEAM_TOKEN> --coordinator http://knights.hspace.io:42000
make doctor-defense
make push
```

기본 방어 대상은 `team1`로 잡아 두었다. 다른 팀을 방어할 때는:

```powershell
make push TARGET_TEAM=team3
```

## 참고

- 이 repo의 `make push`는 `--repo-team $(TARGET_TEAM)`와 `--no-commit`를 기본으로 사용한다.
- 실제 라운드 실행은 coordinator가 담당한다.
