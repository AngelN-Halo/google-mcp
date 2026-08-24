# Google Workspace Directory MCP

Production-oriented, read-only MCP service for narrowly scoped Google Workspace user lookups. It uses Python, FastMCP Streamable HTTP, the Google Admin SDK Directory API, a dedicated service-account JSON credential, Domain-Wide Delegation (DWD), and one fixed delegated-admin subject from server configuration.

The service performs only `users.get` and `users.list`. It cannot create, update, suspend, archive, rename, delete, or otherwise modify users.

## Architecture and threat boundary

```text
MCP client
  -> external TLS and human authentication at Nginx Proxy Manager
    -> existing Docker `proxy` network + gateway secret and verified identity headers
      -> FastMCP /mcp on 0.0.0.0:8000
        -> fixed-subject DWD credential provider
          -> Google Admin SDK Directory API (read-only users scope)
```

The external gateway authenticates the human and must inject a shared gateway secret plus a verified caller identity. The application verifies both, authorizes the identity, and includes it with a generated request ID in every tool audit event. The shared secret proves the request came through the trusted ingress path; it does not identify an individual and is not a replacement for network isolation or external TLS. NPM must remove client-supplied copies of both headers before injecting its own values.

The application binds to `0.0.0.0:8000` inside the container so NPM can reach it. Compose publishes no host port; the service is reachable as `google-mcp:8000` only from containers on the existing external `proxy` network. Because `proxy` is shared by other containers, gateway authentication remains mandatory and those containers could reach the service directly if they obtain valid gateway credentials.

The MCP process validates input and the allowed email domains, constructs bounded Google queries from plain search terms, limits search output, requests partial response fields, filters cross-domain aliases, removes control/format characters from directory text, and returns narrow stable schemas. Directory text is untrusted data and is explicitly marked as such in MCP server/tool instructions; clients must not treat names, aliases, paths, or queries as instructions. This is a trust-boundary control, not a substitute for the MCP client's system-level prompt-injection defenses.

DWD is powerful: Google authorizes the OAuth client and scopes, but does not enforce this application's fixed-subject choice. A holder of the service-account private key can write different code that chooses another subject permitted by DWD. This service fixes `GOOGLE_DELEGATED_ADMIN` in configuration and never accepts the subject as a tool argument, but that is an application control rather than a Google-enforced subject restriction.

## Phase-one tools

- `google_user_status(email)`
- `google_user_search(query, limit=10)`; `query` is a plain name/email fragment, hard maximum `20`
- `google_user_aliases(email)`
- `google_user_summary(email)`

Every explicit email argument must belong to one of `GOOGLE_ALLOWED_DOMAINS`, compared case-insensitively. Returned alias lists contain only those domains. Secondary Workspace domains must be listed explicitly. The service never follows an alias into another domain.

Planned, not implemented:

- `google_user_groups(email)` requires the additional scope `https://www.googleapis.com/auth/admin.directory.group.readonly`.

No group scope or group API operation is present in phase one.

## Google prerequisites

These are manual Google administration steps. This repository does not create cloud resources or credentials.

1. Create a dedicated Google Cloud project for this workload.
2. Enable **Admin SDK API** (`admin.googleapis.com`). No other Google API is required by phase one.
3. Create a dedicated service account and enable Domain-Wide Delegation for it.
4. Create or select a dedicated Workspace delegated-admin user. A narrowly scoped custom admin role should grant:
   - Admin API > Users > Read (`USERS_RETRIEVE`)
   - Admin API > Organizational Units > Read (`ORGANIZATION_UNITS_RETRIEVE`)
5. Assign that role across every OU the service is intended to query. Do not use a daily super-admin account.
6. In Admin console, open **Security > Access and data control > API controls > Manage Domain Wide Delegation**. Add the service account's **numeric OAuth client ID**, not its email address.
7. Authorize exactly this phase-one scope:

   ```text
   https://www.googleapis.com/auth/admin.directory.user.readonly
   ```

8. Create a JSON key only if a keyless deployment method is not currently available. Move it immediately to a root/deployment-owner controlled directory outside this repository, set host permissions such as `chmod 600`, restrict directory traversal, and document an owner and rotation schedule. Revoke the old key after a tested rotation.

The Compose `secrets` mechanism mounts the host file read-only but does **not** provide encryption at rest for that source file. Host storage protections, access control, backup handling, incident response, and rotation remain necessary. Never commit, email, paste into logs, or bake the key into an image.

## Configuration

| Variable | Required | Meaning |
|---|---:|---|
| `GOOGLE_SERVICE_ACCOUNT_FILE` | yes | Absolute in-container path to the mounted JSON credential |
| `GOOGLE_DELEGATED_ADMIN` | yes | Fixed delegated Workspace admin subject |
| `GOOGLE_CUSTOMER_ID` | yes in production | Explicit Directory customer; `my_customer` is allowed only in explicit test mode |
| `GOOGLE_ALLOWED_DOMAINS` | yes | Comma-separated Workspace domains accepted for users and aliases |
| `GOOGLE_MCP_TEST_MODE` | no | Must be explicitly `true` for unit/test configuration without gateway auth |
| `GOOGLE_MCP_GATEWAY_SECRET` | yes in production | Random shared secret from the trusted gateway; never a tool argument or log value |
| `GOOGLE_MCP_AUTHORIZED_USERS` | yes in production | Comma-separated authorized human identities |
| `GOOGLE_MCP_GATEWAY_SECRET_HEADER` | no | Header name; defaults to `X-MCP-Gateway-Secret` |
| `GOOGLE_MCP_IDENTITY_HEADER` | no | Header name; defaults to `X-Authenticated-User` |
| `GOOGLE_MCP_CALLER_DOMAINS` | no | Optional caller-domain allowlist; otherwise uses `GOOGLE_ALLOWED_DOMAINS` |
| `GOOGLE_MCP_HOST` | no | Listen address; defaults to `0.0.0.0` in code |
| `GOOGLE_MCP_PORT` | no | Listen port; defaults to `8000` |
| `GOOGLE_MCP_LOG_LEVEL` | no | `CRITICAL`, `ERROR`, `WARNING`, `INFO`, or `DEBUG` |
| `AUDIT_HASH_TARGETS` | no | HMAC-pseudonymize targets when true |
| `AUDIT_HMAC_KEY` | required for hashing | At least 32 characters; also pseudonymizes callers when set |
| `GOOGLE_EXPOSE_ADMIN_FLAGS` | no | Defaults to `false`; disabled fields are returned as `null` |
| `GOOGLE_EXPOSE_2SV_FLAGS` | no | Defaults to `true` |
| `GOOGLE_EXPOSE_LAST_LOGIN` | no | Defaults to `true` |
| `GOOGLE_EXPOSE_ORG_UNIT` | no | Defaults to `true` |

Normal startup validates configuration and the credential file path and then constructs delegated credentials. It fails fast with a sanitized error if configuration or credential initialization fails. Imports and unit tests do not require credentials.

## Deployment Runbook

Complete these steps in order for production. This repository does not modify NPM, create Google resources, or change Workspace/DWD settings automatically.

### 1. Prepare Google access

Complete the Google prerequisites above. Confirm the delegated admin has only Users Read and Organizational Units Read, DWD authorizes the exact phase-one scope, and `GOOGLE_CUSTOMER_ID` is an explicit customer ID.

### 2. Verify the existing proxy network

NPM and the Google MCP must share the existing external network named `proxy`:

```bash
docker network inspect proxy
```

If it does not exist, start the NPM project first. Do not create a second network for this service.

### 3. Confirm NPM network membership

The NPM project in `~/docker/npm` already attaches `app` to `proxy`. Verify it without changing the live configuration:

```bash
cd ~/docker/npm
docker compose config
docker network inspect proxy
```

The Google MCP Compose file also attaches only to this external `proxy` network and publishes no host port.

### 4. Create `.env`

From this repository:

```bash
cd ~/docker/google-mcp/google-mcp
cp .env.example .env
chmod 600 .env
```

Set the real external credential path, delegated admin, customer ID, comma-separated `GOOGLE_ALLOWED_DOMAINS`, gateway secret, and `GOOGLE_MCP_AUTHORIZED_USERS`. Set `GOOGLE_SERVICE_ACCOUNT_GID` to the credential file's host group ID, obtained with `stat -c '%g' /path/to/key`; keep the file non-world-readable. The gateway secret must be at least 32 characters and must match the secret configured in NPM. Set `GOOGLE_MCP_CALLER_DOMAINS` only when caller domains differ from Workspace data domains. Keep `GOOGLE_MCP_TEST_MODE=false`.

Generate random values without putting them in source control:

```bash
openssl rand -base64 48
openssl rand -base64 48
```

Use the first value for `GOOGLE_MCP_GATEWAY_SECRET` and the second for `AUDIT_HMAC_KEY` when audit pseudonymization is wanted. Keep the service-account JSON outside the repository; Compose mounts it read-only inside the container and grants only its host group as a supplementary group to the non-root process.

### 5. Configure the NPM Proxy Host

In **Proxy Hosts > Add Proxy Host**, use the external DNS name, scheme `http`, forward hostname `google-mcp`, port `8000`, and path `/mcp`. Preserve `/mcp` without rewriting. Issue/select the TLS certificate and enable **Force SSL**. Use SSO or another authentication mechanism that provides a verified `$remote_user`; NPM basic access lists that do not populate `$remote_user` are insufficient for caller attribution.

Add this NPM advanced configuration with placeholders replaced only in NPM:

```nginx
proxy_http_version 1.1;
proxy_buffering off;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;
proxy_set_header Connection "";
proxy_set_header X-MCP-Gateway-Secret "REPLACE_WITH_SECRET_FROM_NPM_SECRET_STORE";
proxy_set_header X-Authenticated-User $remote_user;
```

Both POST and GET must reach `/mcp`; do not restrict the route to GET. NPM must overwrite, not pass through, both authentication headers. The shared gateway secret proves the ingress path but does not identify an individual. Do not enable permissive CORS.

### 6. Validate, build, and start

Do not paste rendered Compose output into tickets or chat because it contains environment values and the external credential path:

```bash
cd ~/docker/google-mcp/google-mcp
docker compose config
docker compose build
docker compose up -d
docker compose ps
docker compose logs --tail=100 google-mcp
```

The application binds to `0.0.0.0:8000` inside the container. No host port is published; NPM reaches `http://google-mcp:8000/mcp` over `proxy`.

### 7. Run the authenticated smoke test

Use a known active user and an authorized caller. Set these only in the shell, never in a file or command history where possible:

```bash
export GOOGLE_TEST_USER='known-active-user@example.test'
export GOOGLE_TEST_MISSING_USER='known-missing-user@example.test' # optional
export GOOGLE_TEST_GATEWAY_SECRET='the-configured-gateway-secret'
export GOOGLE_TEST_CALLER='agent1@example.org'
python tests/smoke_mcp.py https://mcp.example.test/mcp
```

The smoke test verifies the four-tool set, caller-authenticated connection, `ACTIVE` status for the known user, and optional `NOT_FOUND` behavior. It contacts Google and is not a unit test.

## Tests

Unit tests mock the Directory API and never contact Google:

```bash
cd ~/docker/google-mcp/google-mcp
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
pytest -q
```

The containerized test path avoids host Python dependency assumptions:

```bash
docker build --target test -t google-mcp:test .
docker run --rm --user "$(id -u):$(id -g)" --read-only --tmpfs /tmp:size=16m \
  -v "$PWD/tests:/app/tests:ro" \
  google-mcp:test pytest -q -p no:cacheprovider
```

The live smoke script is documented in the deployment runbook above. It requires real test addresses and gateway headers, contacts Google, and prints only states—not complete user records.

## Stable response schemas

`google_user_status` returns exactly these state fields. A genuine Directory API 404 is the only `NOT_FOUND` condition. `ARCHIVED` takes precedence over `SUSPENDED`; all other existing users are `ACTIVE`. Google's epoch/sentinel last-login value becomes `null` plus `never_logged_in: true`. Optional fields remain present as `null` when disabled. Admin flags default to `null` unless explicitly exposed; 2SV, last-login, and OU fields default to exposed.

```json
{
  "email": "alex.rivera@example.test",
  "state": "ACTIVE",
  "suspended": false,
  "archived": false,
  "last_login_time": "2026-08-01T13:45:00.000Z",
  "never_logged_in": false,
  "org_unit_path": "/Staff/Campus-A",
  "is_admin": null,
  "is_delegated_admin": null,
  "is_enrolled_in_2sv": true,
  "is_enforced_in_2sv": true
}
```

For `NOT_FOUND`, exposed boolean fields are `false`, disabled fields are `null`, and `never_logged_in` is `false` when login exposure is enabled because no account exists from which to infer login history.

`google_user_aliases`:

```json
{
  "email": "alex.rivera@example.test",
  "state": "ACTIVE",
  "primary_email": "alex.rivera@example.test",
  "aliases": ["a.rivera@example.test"],
  "non_editable_aliases": ["alex@example.test"]
}
```

`google_user_summary` includes all status fields plus `requested_email`, `display_name`, `given_name`, `family_name`, `aliases`, and `non_editable_aliases`. It uses one `users.get` call.

`google_user_search` accepts a plain human-entered fragment, not Google Directory query syntax. It safely constructs an email-prefix/name-prefix query or an exact allowed-domain email query.

`google_user_search`:

```json
{
  "query": "Alex Rivera",
  "limit": 10,
  "count": 1,
  "truncated": false,
  "next_page_available": false,
  "users": [
    {
      "email": "alex.rivera@example.test",
      "display_name": "Alex Rivera",
      "state": "ACTIVE",
      "suspended": false,
      "archived": false,
      "last_login_time": "2026-08-01T13:45:00.000Z",
      "never_logged_in": false,
      "org_unit_path": "/Staff/Campus-A"
    }
  ]
}
```

The configured customer ID is always used. Results outside the allowed domains are omitted and make `truncated` true. The upstream page token is never exposed; callers should narrow the term when `truncated` or `next_page_available` is true. Terms must be 3..128 characters and contain no control/format characters or raw query syntax. Limits outside `1..20` are rejected, and only one upstream page is requested.

## Logging and failure behavior

Each tool call emits one structured JSON audit event containing UTC timestamp, generated request ID, verified caller identity (or HMAC pseudonym), tool, masked or HMAC-pseudonymized target, result state/count, latency, and sanitized error category. The service does not log gateway secrets, access tokens, credential contents or paths, private keys, complete Google records, raw prompts, aliases, names, phone/profile data, or raw Google error bodies.

Only HTTP 404 maps to `NOT_FOUND`. HTTP 401/403 become `AUTHORIZATION`; 429 and eligible 5xx (`500`, `502`, `503`, `504`) receive at most four total attempts with exponential backoff and jitter. Timeouts and transient transport failures are also bounded. Other malformed or upstream failures remain explicit sanitized errors.

## Troubleshooting

- `invalid_grant`: verify the delegated subject exists, has not been suspended, is in the same Workspace tenant, and the server clock is synchronized with NTP. Also verify the credential belongs to the DWD-enabled service account.
- `unauthorized_client`: use the service account's numeric OAuth client ID in DWD and authorize the exact scope shown above. DWD changes can take time to propagate.
- `403` / `AUTHORIZATION`: verify Users Read and Organizational Units Read privileges, OU assignment scope, API access controls, the delegated subject, and the Admin SDK API. A valid key alone is insufficient.
- Missing scope: compare the DWD entry character-for-character with `https://www.googleapis.com/auth/admin.directory.user.readonly`. Phase one intentionally requests no group, Drive, Gmail, Calendar, role-management, or security-management scopes.
- Wrong delegated subject: correct `GOOGLE_DELEGATED_ADMIN`; it must be the dedicated delegated admin whose role covers the queried OUs. The MCP caller cannot override it.
- Clock skew: synchronize the Docker host clock. Signed JWT assertions are time-sensitive.
- `NOT_FOUND` unexpectedly: confirm the requested email uses the configured allowed domain and is a current, non-deleted Directory user. Authorization and rate-limit failures never become `NOT_FOUND`.

## Emergency revocation

If the gateway, service account, or delegated identity is suspected to be compromised:

1. Disable or remove the NPM route.
2. Stop the MCP container.
3. Remove the DWD client entry if compromise is suspected.
4. Disable or delete the service-account key.
5. Disable the delegated admin if needed.
6. Preserve and review gateway, application, and Google audit logs.

## WIF migration note

The credential interface is isolated so another provider can be added later, but this release implements and tests only a mounted service-account JSON key. Workload Identity Federation is not claimed as supported. For DWD, WIF is not necessarily a drop-in replacement for a JSON key: generating the DWD JWT assertion can require IAM Credentials `signJwt` permissions and explicit signing/exchange logic. Design and test that path before removing the JSON-key provider.
# google-mcp
