# Agent Notes

## Scope and boundaries

- This is a single Python 3.12 service; `server.py` is the FastMCP HTTP entrypoint, `google_directory.py` is the Google API boundary, and `models.py` builds the stable tool responses.
- Google access is strictly read-only Directory API `users.get` and `users.list`; phase one has exactly four tools: status, search, aliases, and summary.
- Keep the only OAuth scope as `https://www.googleapis.com/auth/admin.directory.user.readonly`. Do not add groups or other APIs without an explicit scope/security review.
- Never make delegated subject, customer ID, credential path, OAuth scope, raw resource name, or response fields caller-selectable; these stay in server configuration or code.
- Explicit emails and returned aliases must match `GOOGLE_ALLOWED_DOMAINS` case-insensitively. Cross-domain aliases are filtered, never followed.
- Directory names, aliases, organizational-unit paths, and echoed queries are untrusted text; preserve the MCP trust-boundary instructions and control/format-character sanitization when changing response schemas.

## Secrets and runtime

- Keep service-account credentials outside the repository and image; never log credentials, tokens, private keys, raw Google error bodies, or complete user records.
- For Compose, `GOOGLE_SERVICE_ACCOUNT_HOST_FILE` is the host path and is mounted read-only as `/run/secrets/google_service_account`; direct local startup instead needs `GOOGLE_SERVICE_ACCOUNT_FILE` as an absolute readable path.
- Compose requires `GOOGLE_SERVICE_ACCOUNT_GID` so non-root UID 10001 can read the non-world-readable host key through its supplementary group.
- The application binds to `0.0.0.0:8000` inside the container and Compose publishes no host port.
- Compose uses the existing external Docker network `proxy` used by NPM; proxy to `google-mcp:8000`. Shared-network reachability is a residual risk, so gateway authentication must remain enabled.
- Production requires the shared API key in `Authorization: Bearer <key>`; it authorizes the internal IT group but does not provide individual attribution. Keep external TLS or an equivalent trusted boundary in front of the bearer credential.

## Verification

- No lint, typecheck, codegen, or migration task is configured; the test suite is pytest and mocks Google, so it does not need credentials.
- Local tests: `python3 -m venv .venv && . .venv/bin/activate && python -m pip install -r requirements-dev.txt && pytest -q`.
- Focused tests: `pytest -q tests/test_google_directory.py` (API behavior), `pytest -q tests/test_config.py` (environment validation), or `pytest -q tests/test_auth.py` (gateway authentication).
- Container tests: `docker build --target test -t google-mcp:test .` then run `docker run --rm --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:size=16m -v "$PWD/tests:/app/tests:ro" google-mcp:test pytest -q -p no:cacheprovider`.
- Validate Compose before starting it with `docker compose config`; use `docker compose build`, `docker compose up -d`, and `docker compose logs --tail=100 google-mcp` for the configured deployment.
- Run `tests/smoke_mcp.py` only against a configured live deployment and only when `GOOGLE_TEST_USER` is explicitly set; it contacts Google and is not a unit test.
