.PHONY: login doctor-defense build-defense push

TARGET_TEAM ?= team1
PUSH_ARGS ?= --no-commit
GITCTF = python scripts/run_gitctf_latest.py

login:
	$(GITCTF) login team2

doctor-defense:
	$(GITCTF) agent doctor --mode defense

build-defense:
	$(GITCTF) agent build team2 --mode defense

push:
	$(GITCTF) push --team team2 --repo-team $(TARGET_TEAM) --message submit-agent $(PUSH_ARGS)
