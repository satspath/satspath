# ─────────────────────────────────────────────────────────────────────────────
# SatsPath — Makefile
# Convenience targets for Docker build, run, and development workflows.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help build build-cli build-wasm build-wasm-wallet wallet-dev test run shell up down logs clean scan init smoke

# ── Default ──────────────────────────────────────────────────────────────────
help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Build ─────────────────────────────────────────────────────────────────────
build: build-cli ## Build the SatsPath CLI Docker image

build-wasm: ## Build WASM module for sdk/satspath-p2p (requires wasm-bindgen-cli)
	if [ -f "$(HOME)/.cargo/env" ]; then . "$(HOME)/.cargo/env"; fi && \
	  cargo build -p satspath-wasm --target wasm32-unknown-unknown --release && \
	  wasm-bindgen target/wasm32-unknown-unknown/release/satspath_wasm.wasm \
	    --out-dir sdk/satspath-p2p/pkg --target nodejs && \
	  echo '{"type":"commonjs"}' > sdk/satspath-p2p/pkg/package.json
	@echo "WASM built → sdk/satspath-p2p/pkg/"

build-wasm-wallet: ## Build WASM module and copy into wallet/public/ (requires wasm-pack)
	if [ -f "$(HOME)/.cargo/env" ]; then . "$(HOME)/.cargo/env"; fi && \
	  wasm-pack build crates/satspath-wasm \
	    --target web \
	    --release \
	    --out-dir ../../wallet/public/satspath-wasm-pkg && \
	  cp wallet/public/satspath-wasm-pkg/satspath_wasm_bg.wasm wallet/public/satspath_wasm_bg.wasm
	@echo "WASM → wallet/public/satspath_wasm_bg.wasm"

wallet-dev: ## Start the Arkade Money wallet dev server
	cd wallet && npm run dev

test: ## Run all Rust workspace tests
	if [ -f "$(HOME)/.cargo/env" ]; then . "$(HOME)/.cargo/env"; fi && cargo test --workspace

build-cli: ## Build the SatsPath CLI image
	docker build \
	  --target runtime \
	  --tag satspath-cli:latest \
	  --tag satspath-cli:$(shell git rev-parse --short HEAD 2>/dev/null || echo dev) \
	  --build-arg BUILDKIT_INLINE_CACHE=1 \
	  .

# ── Run ───────────────────────────────────────────────────────────────────────
run: ## Run a satspath CLI command (pass CMD=<args>, e.g. make run CMD="--help")
	docker compose run --rm satspath-cli $(CMD)

shell: ## Open a shell in the CLI container for debugging (overrides ENTRYPOINT)
	docker compose run --rm --entrypoint /bin/bash satspath-cli

# ── Compose ──────────────────────────────────────────────────────────────────
up: ## Start the daemon service (background)
	docker compose up -d

down: ## Stop all services
	docker compose down

logs: ## Tail logs from all running services
	docker compose logs -f

# ── Security scan ────────────────────────────────────────────────────────────
scan: ## Run Trivy vulnerability scan on images (requires trivy installed)
	@echo "==> Scanning satspath-cli:latest"
	trivy image --severity HIGH,CRITICAL satspath-cli:latest
	@echo "==> Scanning satspathd:latest"
	trivy image --severity HIGH,CRITICAL satspathd:latest

# ── Dev helpers ───────────────────────────────────────────────────────────────
clean: ## Remove built images and dangling layers
	docker compose down --remove-orphans --rmi local || true
	docker images satspath-cli -q | xargs -r docker rmi 2>/dev/null || true
	docker images satspathd -q | xargs -r docker rmi 2>/dev/null || true
	docker image prune -f

init: ## Run satspath init inside the container (creates /data/.satspath)
	docker compose run --rm satspath-cli init

# ── Quick smoke-test ──────────────────────────────────────────────────────────
smoke: build-cli ## Build then verify CLI image produces --help output
	@echo "==> CLI smoke test"
	docker run --rm satspath-cli:latest --help
