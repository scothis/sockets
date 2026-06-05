SHELL := /bin/bash

export RUST_BACKTRACE ?= 1
export WASMTIME_BACKTRACE_DETAILS ?= 1

GITHUB_REPOSITORY ?= componentized/sockets

COMPONENTS = $(sort $(notdir $(patsubst %/,%,$(dir $(wildcard  components/*/Cargo.toml)))))

.PHONY: all
all: components

.PHONY: clean
clean:
	cargo clean
	rm -rf lib/*.wasm
	rm -rf lib/*.wasm.md
	rm -rf lib/tests/*.wasm
	rm -rf lib/tests/*.wasm.md

.PHONY: test
test:
	@echo "TODO add tests"

.PHONY: components
components: $(foreach component,$(COMPONENTS),lib/$(component).wasm) $(foreach component,$(COMPONENTS),lib/$(component).debug.wasm) lib/gate.wasm lib/gate.debug.wasm

define BUILD_COMPONENT

lib/$1.wasm: Cargo.toml Cargo.lock wit/deps $(shell find components/$1 -type f) $(shell find crates -type f)
	cargo component build -p $1 --target wasm32-unknown-unknown --release
	cp target/wasm32-unknown-unknown/release/$(subst -,_,$1).wasm lib/$1.wasm
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: Cargo.toml Cargo.lock wit/deps $(shell find components/$1 -type f) $(shell find crates -type f)
	cargo component build -p $1 --target wasm32-wasip2
	cp target/wasm32-wasip2/debug/$(subst -,_,$1).wasm lib/$1.debug.wasm
	cp components/$1/README.md lib/$1.debug.wasm.md

endef

$(foreach component,$(COMPONENTS),$(eval $(call BUILD_COMPONENT,$(component))))

lib/gate.wasm: components/gate/gate.wac lib/gate-ip-name-lookup.wasm lib/gate-tcp.wasm lib/gate-udp.wasm components/gate/README.md
	wac compose components/gate/gate.wac \
		-d componentized:gate-ip-name-lookup=lib/gate-ip-name-lookup.wasm \
		-d componentized:gate-tcp=lib/gate-tcp.wasm \
		-d componentized:gate-udp=lib/gate-udp.wasm \
		-o lib/gate.wasm
	cp components/gate/README.md lib/gate.wasm.md

lib/gate.debug.wasm: components/gate/gate.wac lib/gate-ip-name-lookup.debug.wasm lib/gate-tcp.debug.wasm lib/gate-udp.debug.wasm components/gate/README.md
	wac compose components/gate/gate.wac \
		-d componentized:gate-ip-name-lookup=lib/gate-ip-name-lookup.debug.wasm \
		-d componentized:gate-tcp=lib/gate-tcp.debug.wasm \
		-d componentized:gate-udp=lib/gate-udp.debug.wasm \
		-o lib/gate.debug.wasm
	cp components/gate/README.md lib/gate.debug.wasm.md

.PHONY: wit
wit: wit/deps

wit/deps: wkg.toml $(shell find wit -type f -name "*.wit" -not -path "deps")
	wkg wit fetch

.PHONY: publish
publish: $(shell find lib -type f -name "*.wasm" | sed -e 's:^lib/:publish-:g')

.PHONY: publish-%
publish-%:
ifndef VERSION
	$(error VERSION is undefined)
endif
ifndef REPOSITORY
	$(error REPOSITORY is undefined)
endif
	@$(eval FILE := $(@:publish-%=%))
	@$(eval COMPONENT := $(FILE:%.wasm=%))
	@$(eval DESCRIPTION := $(shell head -n 3 "lib/${FILE}.md" | tail -n 1))
	@$(eval REVISION := $(shell git rev-parse HEAD)$(shell git diff --quiet HEAD && echo "+dirty"))
	@$(eval TAG := $(shell echo "${VERSION}" | sed 's/[^a-zA-Z0-9_.\-]/--/g'))

	$(eval DIGEST=$(shell 
		wkg oci push \
			--annotation "org.opencontainers.image.title=${COMPONENT}" \
			--annotation "org.opencontainers.image.description=${DESCRIPTION}" \
			--annotation "org.opencontainers.image.version=${VERSION}" \
			--annotation "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}.git" \
			--annotation "org.opencontainers.image.revision=${REVISION}" \
			--annotation "org.opencontainers.image.licenses=Apache-2.0" \
			"${REPOSITORY}/${COMPONENT}:${TAG}" \
			"lib/${FILE}" \
			2>&1 \
			| tee /dev/stderr \
			| grep -oE "sha256:[a-f0-9]{64}" \
			| head -n1 \
	))

	cosign sign --yes \
		"${REPOSITORY}/${COMPONENT}:${TAG}@${DIGEST}"
