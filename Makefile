SHELL := /bin/bash

export RUST_BACKTRACE ?= 1
export WASMTIME_BACKTRACE_DETAILS ?= 1

# cli tools, pinned in tools/Cargo.toml and installed into target/tools, see `make tools`
TOOLS_DIR := $(abspath target/tools)
export PATH := $(TOOLS_DIR)/bin:$(PATH)

# cargo binstall downloads prebuilt binaries, without it the tools are built with cargo install
CARGO_INSTALL := $(if $(shell command -v cargo-binstall 2> /dev/null),cargo binstall --no-confirm --disable-telemetry,cargo install)

COMPONENTS = $(sort $(notdir $(patsubst %/,%,$(dir $(wildcard $(addprefix components/*/,*.properties *.wac *.wkg Cargo.toml))))))
TOOLS := static-config wac-cli wasm-tools wkg

.PHONY: all
all: components

.PHONY: clean
clean:
	cargo clean
	rm -rf lib/*.wasm
	rm -rf lib/*.wasm.md

.PHONY: test
test: components
	cargo test --workspace


tool_version = $(shell sed -n 's/^$(1) = "=\(.*\)"$$/\1/p' tools/Cargo.toml)
# a stamp naming the version of a tool installed in target/tools/bin, e.g. `wkg@0.16.1`, the binary
# does not say which version it is. Bumping the pinned version names a stamp that does not exist yet,
# so the tool is installed again.
tool = $(TOOLS_DIR)/.installed/$(1)@$(call tool_version,$(1))

.PHONY: tools ## Install the cli tools pinned in tools/Cargo.toml
tools: $(foreach name,$(TOOLS),$(call tool,$(name)))

define INSTALL_TOOL

$(call tool,$1):
	$(CARGO_INSTALL) --locked --root $(TOOLS_DIR) --version $(call tool_version,$1) $1
	@mkdir -p $$(@D)
	@# only the installed version has a stamp, so going back to a previous version installs it again
	@rm -f $$(@D)/$1@*
	@touch $$@

endef

$(foreach name,$(TOOLS),$(eval $(call INSTALL_TOOL,$(name))))

.PHONY: components
components: lib/interface.wasm $(foreach component,$(COMPONENTS),lib/$(component).wasm lib/$(component).debug.wasm)

define BUILD_COMPONENT

.PHONY: components/$1
components/$1: lib/$1.wasm lib/$1.debug.wasm

ifneq ($(wildcard components/$1/$1.properties),)

lib/$1.wasm: components/$1/$1.properties components/$1/README.md | $(call tool,static-config)
	static-config -f components/$1/$1.properties -o lib/$1.wasm
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: components/$1/$1.properties components/$1/README.md | $(call tool,static-config)
	static-config -f components/$1/$1.properties -o lib/$1.debug.wasm
	cp components/$1/README.md lib/$1.debug.wasm.md

else ifneq ($(wildcard components/$1/$1.wac),)

# the local packages the composition instantiates, e.g. `new local:latch-n2 { ... }`
WAC_DEPS_$1 := $$(shell grep -v '^\s*//' components/$1/$1.wac | grep -oE 'local:[a-z0-9-]+' | sed 's/^local://' | sort -u)

lib/$1.wasm: components/$1/$1.wac components/$1/README.md $$(foreach component,$$(WAC_DEPS_$1),lib/$$(component).wasm) | $(call tool,wac-cli)
	wac compose $$(foreach component,$$(WAC_DEPS_$1),-d local:$$(component)=lib/$$(component).wasm) -o lib/$1.wasm components/$1/$1.wac
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: components/$1/$1.wac components/$1/README.md $$(foreach component,$$(WAC_DEPS_$1),lib/$$(component).debug.wasm) | $(call tool,wac-cli)
	wac compose $$(foreach component,$$(WAC_DEPS_$1),-d local:$$(component)=lib/$$(component).debug.wasm) -o lib/$1.debug.wasm components/$1/$1.wac
	cp components/$1/README.md lib/$1.debug.wasm.md

else ifneq ($(wildcard components/$1/$1.wkg),)

lib/$1.wasm: components/$1/$1.wkg components/$1/README.md | $(call tool,wkg)
	wkg oci pull $(shell cat components/$1/$1.wkg 2> /dev/null | head -1) -o lib/$1.wasm
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: components/$1/$1.wkg components/$1/README.md | $(call tool,wkg)
	wkg oci pull $(shell cat components/$1/$1.wkg  2> /dev/null | tail -1 2> /dev/null) -o lib/$1.debug.wasm
	cp components/$1/README.md lib/$1.debug.wasm.md

# cargo is checked last, other strategies may have a Cargo.toml for tests of non-rust sources
else ifneq ($(wildcard components/$1/Cargo.toml),)

lib/$1.wasm: Cargo.toml Cargo.lock components/wit/deps $(shell find components/$1 -type f) $(shell find crates -type f) | $(call tool,wasm-tools)
	cargo build -p $1 --target wasm32-unknown-unknown --release
	wasm-tools component new target/wasm32-unknown-unknown/release/$(subst -,_,$1).wasm -o lib/$1.wasm
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: Cargo.toml Cargo.lock components/wit/deps $(shell find components/$1 -type f) $(shell find crates -type f) | $(call tool,wasm-tools)
	cargo build --target wasm32-unknown-unknown -p $1
	wasm-tools component new target/wasm32-unknown-unknown/debug/$(subst -,_,$1).wasm -o lib/$1.debug.wasm
	cp components/$1/README.md lib/$1.debug.wasm.md

endif

endef

$(foreach component,$(COMPONENTS),$(eval $(call BUILD_COMPONENT,$(component))))

lib/interface.wasm: wit/deps README.md | $(call tool,wkg)
	wkg build -o lib/interface.wasm
	cp README.md lib/interface.wasm.md

.PHONY: wit
wit: wit/deps components/wit/deps

.PHONY: bump-interface-version ## Bump the interface package version, e.g. INTERFACE_VERSION=0.1.0
bump-interface-version:
ifndef INTERFACE_VERSION
	$(error INTERFACE_VERSION is undefined)
endif
	scripts/bump-interface-version.sh $(INTERFACE_VERSION)

wit/deps: wkg.toml $(shell find wit -type f -name "*.wit" -not -path "deps") | $(call tool,wkg)
	wkg fetch

components/wit/deps: wit/deps components/wkg.toml $(shell find components/wit -type f -name "*.wit" -not -path "deps") | $(call tool,wkg)
	( cd components && wkg fetch )

.PHONY: publish ## Publish each component in the lib directory
publish: $(shell find lib -maxdepth 1 -type f -name "*.wasm" -not -name "dep-*" -not -name "test-*" | sed -e 's:^lib/:publish-:g')

.PHONY: publish-%
publish-%: | $(call tool,wkg)
ifndef VERSION
	$(error VERSION is undefined)
endif
ifndef REPOSITORY
	$(error REPOSITORY is undefined)
endif
	@$(eval FILE := $(@:publish-%=%))
	@$(eval COMPONENT := $(if $(filter %.debug.wasm,$(FILE)),$(FILE:%.debug.wasm=%),$(FILE:%.wasm=%)))
	@$(eval TITLE := $(if $(filter %.debug.wasm,$(FILE)),$(COMPONENT) (debug),$(COMPONENT)))
	@$(eval DESCRIPTION := $(shell head -n 3 "lib/${FILE}.md" | tail -n 1))
	@$(eval REVISION := $(shell git rev-parse HEAD)$(shell git diff --quiet HEAD && echo "+dirty"))
	@$(eval COMPONENT_VERSION := $(if $(filter %.debug.wasm,$(FILE)),${VERSION}+debug,${VERSION}))
	@$(eval TAG := $(patsubst v%,%,$(subst +,_,$(COMPONENT_VERSION))))
	@$(eval IMAGE := $(if $(filter interface.wasm,$(FILE)),${REPOSITORY}:${TAG},${REPOSITORY}/${COMPONENT}:${TAG}))

	@echo "::group::${FILE} -> ${IMAGE}"
	@DIGEST=$$( \
		wkg oci push \
			--annotation "org.opencontainers.image.title=${TITLE}" \
			--annotation "org.opencontainers.image.description=${DESCRIPTION}" \
			--annotation "org.opencontainers.image.version=${COMPONENT_VERSION}" \
			--annotation "org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}.git" \
			--annotation "org.opencontainers.image.revision=${REVISION}" \
			--annotation "org.opencontainers.image.licenses=Apache-2.0" \
			"${IMAGE}" \
			"lib/${FILE}" \
			2>&1 \
			| tee /dev/stderr \
			| grep -o 'sha256:[a-f0-9]\{64\}' \
	) ; \
	cosign sign --yes "${IMAGE}@$${DIGEST}"
	@echo "::endgroup::"
