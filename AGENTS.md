# Repository Guidelines

## Project Structure & Module Organization
`miuturn` is a Rust TURN/STUN server. Core library modules live in `src/`, with `src/lib.rs` re-exporting public types and `src/main.rs` wiring config, logging, listeners, and the admin service. Protocol and runtime concerns are split into focused files such as `server.rs`, `allocation.rs`, `message.rs`, `auth.rs`, `health.rs`, `metrics.rs`, and `tls.rs`. Integration and end-to-end tests live in `tests/`. Static admin console pages are in `static/`, the example configuration is `miuturn.toml.example`, and `turn_cli.py` is a Python utility for manual TURN/STUN checks.

## Build, Test, and Development Commands
- `cargo build` compiles the debug binary and library.
- `cargo build --release` builds the optimized server used in production examples.
- `CONFIG=miuturn.toml cargo run` runs the server with a local config file; copy from `miuturn.toml.example` first.
- `cargo test` runs unit and integration tests. Some tests bind local ports such as `127.0.0.1:3478`, so stop any running server first.
- `cargo test --test integration_tests` runs the explicitly configured integration test target.
- `cargo fmt --check` verifies Rust formatting.
- `cargo clippy --all-targets -- -D warnings` checks lints across the binary, library, and tests.
- `docker build -t miuturn .` builds the container image.

## Coding Style & Naming Conventions
Use standard Rust 2024 style and `rustfmt` defaults: four-space indentation, `snake_case` for functions/modules, `PascalCase` for types, and `SCREAMING_SNAKE_CASE` only for constants. Keep async runtime code on Tokio primitives and prefer existing shared types exported from `src/lib.rs` over duplicate models. For Python helper changes, keep the current straightforward standard-library style and `snake_case` names.

## Testing Guidelines
Add focused tests under `tests/` for protocol, auth, admin, and end-to-end behavior. Name files and test functions by behavior, for example `login_test.rs` or `test_e2e_turn_allocation`. Prefer deterministic localhost ports or ephemeral ports where possible, and document any fixed port assumptions in the test.

## Commit & Pull Request Guidelines
Recent history uses Conventional Commit-style subjects such as `feat: enhance address normalization for relay traffic and add unit tests`. Follow `feat:`, `fix:`, `test:`, `docs:`, or `refactor:` with a concise imperative summary. Pull requests should describe behavior changes, list validation commands run, link related issues, and include screenshots when `static/` admin UI pages change.

## Security & Configuration Tips
Do not commit real `miuturn.toml` secrets, TURN REST secrets, admin passwords, certificates, or production IPs. Keep safe defaults in `miuturn.toml.example`, and use the `CONFIG` environment variable for local or deployment-specific configuration.
