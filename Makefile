# https://github.com/flashbots/rbuilder-operator/blob/f5ef2cbc9a9a603eb915aed26f9525b91403c223/Makefile
#
# Heavily inspired by Lighthouse: https://github.com/sigp/lighthouse/blob/stable/Makefile
# and Reth: https://github.com/paradigmxyz/reth/blob/main/Makefile
.DEFAULT_GOAL := help

GIT_VER ?= $(shell git describe --tags --always --dirty="-dev")
GIT_TAG ?= $(shell git describe --tags --abbrev=0)

##@ Help

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: v
v: ## Show the current version
	@echo "Version: ${GIT_VER}"

##@ Build

.PHONY: clean
clean: ## Clean up
	cargo clean

.PHONY: build
build: ## Build static binary for x86_64
	cargo build --release --target x86_64-unknown-linux-gnu

# Environment variables for reproducible builds
# Initialize RUSTFLAGS
RUST_BUILD_FLAGS =

# Remove build ID from the binary to ensure reproducibility across builds
RUST_BUILD_FLAGS += -C link-arg=-Wl,--build-id=none

# Remove metadata hash from symbol names to ensure reproducible builds
RUST_BUILD_FLAGS += -C metadata=''

# Set timestamp from last git commit for reproducible builds
SOURCE_DATE ?= $(shell git log -1 --pretty=%ct)

# Disable incremental compilation to avoid non-deterministic artifacts
CARGO_INCREMENTAL_VAL = 0

# Set C locale for consistent string handling and sorting
LOCALE_VAL = C

# Set UTC timezone for consistent time handling across builds
TZ_VAL = UTC

# Set the target for the build, default to x86_64
TARGET ?= x86_64-unknown-linux-gnu

.PHONY: build-reproducible
build-reproducible: ## Build reproducible static binary for x86_64
	# Set timestamp from last git commit for reproducible builds
	SOURCE_DATE_EPOCH=$(SOURCE_DATE) \
	RUSTFLAGS="${RUST_BUILD_FLAGS} --remap-path-prefix $$(pwd)=." \
	CARGO_INCREMENTAL=${CARGO_INCREMENTAL_VAL} \
	LC_ALL=${LOCALE_VAL} \
	TZ=${TZ_VAL} \
	cargo build --release --locked --target $(TARGET)

.PHONY: docker-image
docker-image: ## Build a rbuilder Docker image
	docker build --platform linux/amd64 . -t rbuilder

##@ Dev

.PHONY: lint
lint: ## Run the linters
	cargo fmt -- --check
	cargo clippy -- -D warnings

.PHONY: test
test: ## Run the tests
	cargo test --verbose

.PHONY: lt
lt: lint test ## Run "lint" and "test"

fmt: ## Format the code
	cargo fmt
	cargo fix --allow-staged
	cargo clippy --fix --allow-staged
