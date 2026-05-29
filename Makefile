.PHONY: login doctor-attack doctor-defense build-defense push push-attack push-defense

TARGET_TEAM ?= team2
PUSH_ARGS ?= --no-commit
GITCTF = python scripts/run_gitctf_latest.py

login:
	$(GITCTF) login team2

doctor-attack:
	$(GITCTF) agent doctor --mode attack

doctor-defense:
	@echo defense targets are disabled in this attack-only repo
	@exit 1

build-defense:
	@echo defense targets are disabled in this attack-only repo
	@exit 1

push:
	$(MAKE) push-attack

push-attack:
	python scripts/guard_attack_push.py
	$(GITCTF) push --team team2 --repo-team team2 --message submit-attack-agent $(PUSH_ARGS)

push-defense:
	@echo defense targets are disabled in this attack-only repo
	@exit 1
