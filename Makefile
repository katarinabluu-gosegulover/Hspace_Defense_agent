.PHONY: login doctor-attack doctor-defense build-attack build-defense push

TARGET_TEAM ?= team1
PUSH_ARGS ?=
GITCTF = python scripts/run_gitctf_latest.py

login:
	$(GITCTF) login team2

doctor-attack:
	$(GITCTF) agent doctor --mode attack

doctor-defense:
	$(GITCTF) agent doctor --mode defense

build-attack:
	$(GITCTF) agent build team2 --mode attack

build-defense:
	$(GITCTF) agent build team2 --mode defense

push:
	$(GITCTF) push --team team2 --repo-team $(TARGET_TEAM) --message submit-agent $(PUSH_ARGS)
