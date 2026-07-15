APP := miuturn
DIST_DIR := dist
IMAGE ?= miuturn:latest
PLATFORMS ?= linux/amd64,linux/arm64
DOCKER_OUTPUT ?= --push
UPX ?= upx
UPX_FLAGS ?= --best --lzma

AMD64_TARGET := x86_64-unknown-linux-gnu
ARM64_TARGET := aarch64-unknown-linux-gnu

AMD64_BINARY := $(DIST_DIR)/$(APP)-linux-amd64
ARM64_BINARY := $(DIST_DIR)/$(APP)-linux-arm64

.PHONY: all zig-build docker-build clean-dist check-zigbuild

all: zig-build

zig-build: $(AMD64_BINARY) $(ARM64_BINARY)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

check-zigbuild:
	@command -v zig >/dev/null 2>&1 || { echo "zig is required for cargo-zigbuild"; exit 1; }
	@command -v cargo-zigbuild >/dev/null 2>&1 || { echo "cargo-zigbuild is required: cargo install cargo-zigbuild"; exit 1; }
	@command -v $(UPX) >/dev/null 2>&1 || { echo "upx is required for binary compression"; exit 1; }

$(AMD64_BINARY): | $(DIST_DIR) check-zigbuild
	rm -rf target/$(AMD64_TARGET)/release/$(APP)
	rm -rf $(AMD64_BINARY)
	cargo zigbuild --release --target $(AMD64_TARGET)
	cp target/$(AMD64_TARGET)/release/$(APP) $@
	$(UPX) $(UPX_FLAGS) $@

$(ARM64_BINARY): | $(DIST_DIR) check-zigbuild
	rm -rf target/$(AMD64_TARGET)/release/$(APP)
	rm -rf $(ARM64_BINARY)
	cargo zigbuild --release --target $(ARM64_TARGET)
	cp target/$(ARM64_TARGET)/release/$(APP) $@
	$(UPX) $(UPX_FLAGS) $@

docker-build: zig-build
	docker buildx build --platform $(PLATFORMS) $(DOCKER_OUTPUT) -t $(IMAGE) .
	rm -rf $(DIST_DIR)

clean-dist:
	rm -rf $(DIST_DIR)
