SHELL := /bin/bash

export RUST_BACKTRACE ?= 1
export WASMTIME_BACKTRACE_DETAILS ?= 1

# cargo components that build for wasm32-wasip3, all others build for wasm32-unknown-unknown
WASIP3_COMPONENTS = gate-types
CARGO_COMPONENTS = $(sort $(notdir $(patsubst %/,%,$(dir $(wildcard  components/*/Cargo.toml)))))
CONFIG_COMPONENTS = $(sort $(notdir $(patsubst %/,%,$(dir $(wildcard  components/*/*.properties)))))
WAC_COMPONENTS = $(sort $(notdir $(patsubst %/,%,$(dir $(wildcard  components/*/*.wac)))))
WKG_COMPONENTS = $(sort $(notdir $(patsubst %/,%,$(dir $(wildcard  components/*/*.wkg)))))
COMPONENTS = $(sort $(CARGO_COMPONENTS) $(CONFIG_COMPONENTS) $(WAC_COMPONENTS) $(WKG_COMPONENTS))

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

# cargo target for a component
cargo_target = $(if $(filter $1,$(WASIP3_COMPONENTS)),wasm32-wasip3,wasm32-unknown-unknown)
# order-only prerequisites for a component's cargo target
cargo_target_deps = $(if $(filter $1,$(WASIP3_COMPONENTS)),| $(WASI_SYSROOT))
# wasm32-wasip3 emits a component directly, wasm32-unknown-unknown emits a core module
cargo_component = $(if $(filter $1,$(WASIP3_COMPONENTS)),cp $2 $3,wasm-tools component new $2 -o $3)

# wasm32-wasip3 components link against wasi-libc with experimental cooperative threads support
WASI_SDK_VERSION = 34
WASI_SYSROOT = target/wasi-sysroot-$(WASI_SDK_VERSION).0
WASI_COOP_THREADS_LIB = $(CURDIR)/$(WASI_SYSROOT)/experimental-coop-threads/lib/wasm32-wasip3
export CARGO_TARGET_WASM32_WASIP3_RUSTFLAGS ?= -C link-self-contained=no -L native=$(WASI_COOP_THREADS_LIB) -C link-arg=$(WASI_COOP_THREADS_LIB)/crt1-reactor.o

$(WASI_SYSROOT):
	mkdir -p $(dir $(WASI_SYSROOT))
	curl -sSfL https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-$(WASI_SDK_VERSION)/wasi-sysroot-$(WASI_SDK_VERSION).0.tar.gz | tar -xz -C $(dir $(WASI_SYSROOT))

.PHONY: components
components: lib/interface.wasm $(foreach component,$(COMPONENTS),lib/$(component).wasm) $(foreach component,$(COMPONENTS),lib/$(component).debug.wasm)

define BUILD_COMPONENT

.PHONY: components/$1
components/$1: lib/$1.wasm lib/$1.debug.wasm

ifneq ($(filter $1,$(CARGO_COMPONENTS)),)

lib/$1.wasm: Cargo.toml Cargo.lock components/wit/deps $(shell find components/$1 -type f) $(call cargo_target_deps,$1)
	cargo build -p $1 --target $(call cargo_target,$1) --release
	$(call cargo_component,$1,target/$(call cargo_target,$1)/release/$(subst -,_,$1).wasm,lib/$1.wasm)
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: Cargo.toml Cargo.lock components/wit/deps $(shell find components/$1 -type f) $(call cargo_target_deps,$1)
	cargo build --target $(call cargo_target,$1) -p $1
	$(call cargo_component,$1,target/$(call cargo_target,$1)/debug/$(subst -,_,$1).wasm,lib/$1.debug.wasm)
	cp components/$1/README.md lib/$1.debug.wasm.md

else ifneq ($(filter $1,$(CONFIG_COMPONENTS)),)

lib/$1.wasm: components/$1/$1.properties components/$1/README.md
	static-config -f components/$1/$1.properties -o lib/$1.wasm
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: components/$1/$1.properties components/$1/README.md
	static-config -f components/$1/$1.properties -o lib/$1.debug.wasm
	cp components/$1/README.md lib/$1.debug.wasm.md

else ifneq ($(filter $1,$(WAC_COMPONENTS)),)

WAC_DEPS_$1 := $(shell wac parse components/$1/$1.wac 2> /dev/null | jq -r '[.. | .package?.name? | strings | select(startswith("local:")) | sub("^local:"; "")] | unique[]')

lib/$1.wasm: components/$1/$1.wac components/$1/README.md $$(foreach component,$$(WAC_DEPS_$1),lib/$$(component).wasm)
	wac compose $$(foreach component,$$(WAC_DEPS_$1),-d local:$$(component)=lib/$$(component).wasm) -o lib/$1.wasm components/$1/$1.wac
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: components/$1/$1.wac components/$1/README.md $$(foreach component,$$(WAC_DEPS_$1),lib/$$(component).debug.wasm)
	wac compose $$(foreach component,$$(WAC_DEPS_$1),-d local:$$(component)=lib/$$(component).debug.wasm) -o lib/$1.debug.wasm components/$1/$1.wac
	cp components/$1/README.md lib/$1.debug.wasm.md

else ifneq ifneq ($(filter $1,$(WKG_COMPONENTS)),)

lib/$1.wasm: components/$1/$1.wkg components/$1/README.md
	wkg oci pull $(shell cat components/$1/$1.wkg 2> /dev/null | head -1) -o lib/$1.wasm
	cp components/$1/README.md lib/$1.wasm.md

lib/$1.debug.wasm: components/$1/$1.wkg components/$1/README.md
	wkg oci pull $(shell cat components/$1/$1.wkg  2> /dev/null | tail -1 2> /dev/null) -o lib/$1.debug.wasm
	cp components/$1/README.md lib/$1.debug.wasm.md

endif

endef

$(foreach component,$(COMPONENTS),$(eval $(call BUILD_COMPONENT,$(component))))

lib/interface.wasm: wit/deps README.md
	wkg build -o lib/interface.wasm
	cp README.md lib/interface.wasm.md

.PHONY: wit
wit: wit/deps components/wit/deps

wit/deps: wkg.toml $(shell find wit -type f -name "*.wit" -not -path "deps")
	wkg fetch

components/wit/deps: wit/deps components/wkg.toml $(shell find components/wit -type f -name "*.wit" -not -path "deps")
	( cd components && wkg fetch )

.PHONY: publish ## Publish each component in the lib directory
publish: $(shell find lib -maxdepth 1 -type f -name "*.wasm" | sed -e 's:^lib/:publish-:g')

.PHONY: publish-%
publish-%:
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
