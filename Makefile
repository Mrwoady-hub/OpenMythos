PYTHON ?= python3

.PHONY: gate01-unit gate01-inputs gate01-config gate01-kernel gate01-payload
.PHONY: gate01-qcow2 gate01-boot gate01-repro gate01

gate01-unit:
	$(PYTHON) -m unittest discover -s tests/gate01 -p 'test_*.py' -v

gate01-inputs:
	scripts/gate01/fetch-inputs.sh

.PHONY: gate01-toolchain
gate01-toolchain:
	scripts/gate01/build-toolchain.sh

gate01-config:
	scripts/gate01/generate-config.sh --check

gate01-kernel:
	scripts/gate01/build-kernel.sh canonical

gate01-payload:
	scripts/gate01/build-payload.sh canonical

gate01-qcow2:
	scripts/gate01/build-qcow2.sh canonical

gate01-boot:
	scripts/gate01/boot-qemu.sh canonical

gate01-repro:
	scripts/gate01/repro-check.sh

gate01:
	scripts/gate01/release-gate.sh
