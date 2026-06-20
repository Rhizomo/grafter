# Grafter

Grafter is an internal IAM portal that wraps Keycloak behind a controlled approval flow. Operators propose changes to user accounts — role assignments, team attributes, enabled state — and admins approve or reject them. Every action is audit-logged to object storage. Nothing touches Keycloak directly except the server.

---

## Architecture

```
                    ┌──────────────────────────────────────┐
    Browser ──────► │               Grafter                │
                    │  Axum 0.7 · Tera templates · OIDC    │
                    └──────┬───────────────────┬───────────┘
                           │                   │
                    ┌──────▼──────┐    ┌───────▼────────┐
                    │    Redis    │    │   MinIO / S3   │
                    │  sessions   │    │  change queue  │
                    │  dist. lock │    │  audit log     │
                    └─────────────┘    └────────────────┘
                           │
                    ┌──────▼──────────────────────────────┐
                    │            Keycloak                  │
                    │  OIDC login · Admin API (mutations)  │
                    └──────────────────────────────────────┘
```

Grafter holds two relationships with Keycloak: one OIDC client for browser login (authorization code flow), and one service-account client for Admin API calls (user/role/group mutations). These are separate credentials with separate scopes.

---

## Tech stack

| Layer | Technology | Why |
|---|---|---|
| Web framework | Axum 0.7 | Async, type-safe routing; extractors compose well with tower middleware |
| Templates | Tera | Server-side HTML; no JS build step, no hydration |
| Auth | OIDC authorization code flow | Delegates identity to Keycloak; no passwords stored |
| JWT verification | `jsonwebtoken` + manual JWKS cache | Fine-grained control over key rotation |
| Sessions | `tower-sessions` + Redis | Persistent across restarts; invalidatable server-side |
| Distributed lock | `fred` (Redis `SET NX EX 30`) | Prevents double-apply on concurrent approve/reject |
| Identity provider | `IdentityProvider` trait → `KeycloakProvider` | Keycloak is swappable without touching routes |
| Change storage | `ChangeStorage` trait → S3 via `object_store` | Append-only, no migrations, survives schema changes |
| Audit log | JSON objects in S3 (date-partitioned) | Immutable, cheap, no retention headaches |

---

## Running locally

### Prerequisites

- Docker and Docker Compose
- A Keycloak instance (dev or prod) with two clients configured — see [Auth flow](#auth-flow) below
- A MinIO instance with a `grafter` bucket

### Steps

```bash
git clone git@github.com:rhizomo/grafter.git
cd grafter
cp .env.example .env
# Edit .env — fill in all values
docker compose up --build
```

The app starts at `http://localhost:3000`. Redis is bundled in the compose file. Keycloak and MinIO are expected to be external.

### Keycloak setup (minimum)

1. **OIDC client** (`grafter`): Authorization Code flow, redirect URI `http://localhost:3000/auth/callback`, no service account.
2. **Admin client** (`grafter-admin`): Client Credentials flow, service account with realm `manage-users` and `manage-clients` roles.
3. Two realm roles: one for admins (`devops` by default), one for operators.

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `OIDC_ISSUER` | ✓ | Keycloak realm URL — e.g. `https://auth.example.com/realms/myrealm` |
| `OIDC_CLIENT_ID` | ✓ | OIDC browser client ID (e.g. `grafter`) |
| `OIDC_CLIENT_SECRET` | ✓ | OIDC browser client secret |
| `OIDC_REDIRECT_URI` | ✓ | Full callback URL — e.g. `https://grafter.example.com/auth/callback` |
| `KC_ADMIN_URL` | ✓ | Keycloak base URL — e.g. `https://auth.example.com` |
| `KC_ADMIN_REALM` | ✓ | Realm for admin token exchange |
| `KC_ADMIN_CLIENT_ID` | ✓ | Service account client ID |
| `KC_ADMIN_CLIENT_SECRET` | ✓ | Service account client secret |
| `IAM_ROLE_ADMIN` | ✓ | Keycloak realm role name that grants admin access |
| `IAM_ROLE_OPERATOR` | ✓ | Keycloak realm role name that grants operator access |
| `S3_ENDPOINT` | ✓ | MinIO/S3 endpoint URL |
| `S3_BUCKET` | ✓ | Bucket name (must exist) |
| `S3_ACCESS_KEY` | ✓ | S3 access key |
| `S3_SECRET_KEY` | ✓ | S3 secret key |
| `SESSION_SECRET` | ✓ | At least 32 bytes. Generate: `openssl rand -hex 32` |
| `REDIS_URL` | ✓ | Redis connection URL — e.g. `redis://127.0.0.1:6379` |
| `PORT` | — | Defaults to `3000` |

---

## Auth flow

Grafter uses OIDC authorization code flow. No passwords are handled by the app.

1. User visits any protected route → redirected to `/auth/login`
2. Server generates a random `state` and `nonce`, stores both in the session, redirects browser to Keycloak's `/auth` endpoint
3. User authenticates with Keycloak
4. Keycloak redirects to `/auth/callback?code=...&state=...`
5. Server verifies `state` matches the session value (CSRF protection)
6. Server exchanges `code` for tokens at Keycloak's `/token` endpoint
7. Server extracts `nonce` from the ID token, verifies it matches the session value (replay protection)
8. Server verifies the access token signature against JWKS (fetched from Keycloak, cached 1h, refreshed on key miss)
9. Server reads `realm_access.roles` from the JWT, maps to `Admin` or `Operator`
10. `SessionUser` is written to the Redis-backed session; user is redirected to `/`

Logout: session is flushed server-side, then browser is redirected to Keycloak's `/logout` endpoint with a `post_logout_redirect_uri` pointing back to `/auth/login`.

---

## Change queue

Grafter enforces a propose → approve → apply lifecycle for all Keycloak mutations made by operators.

1. **Propose**: Operator submits the edit form on a user's detail page. A `PendingChange` record is written to S3 (`grafter/changes/{uuid}.json`). Nothing touches Keycloak yet.
2. **Queue**: The change appears in the Changes tab with status `pending`. Admins see all pending changes; operators see only their own.
3. **Approve**: Admin clicks Approve. The server:
   - Acquires a Redis distributed lock (`SET grafter:change-lock:{id} 1 NX EX 30`) — if another request holds the lock, the admin gets a warning flash and the request is dropped
   - Re-reads the change from S3 and checks `status == Pending` (second guard against races)
   - Applies the change fields to Keycloak (update user, set enabled, set team attribute) in the minimum number of API calls
   - Updates the S3 record to `status: Approved`
   - Releases the lock only after the S3 write succeeds
   - If the S3 write fails after Keycloak was already mutated: lock is left to expire (blocks retries), and `RECONCILIATION REQUIRED` is logged for manual intervention
4. **Reject**: Same lock flow, no Keycloak calls. Reason is stored in the S3 record.
5. **Audit**: Every approve/reject appends an `AuditEntry` to S3 (`grafter/audit/YYYY-MM-DD/{uuid}.json`).

Admins can also apply changes directly (bypassing the queue) and create users outright.

---

## Audit logging

Every state-changing action — user edits, approvals, rejections, role assignments, bulk operations — writes an `AuditEntry` to S3.

**Key structure**: `grafter/audit/YYYY-MM-DD/{event-uuid}.json`

Each entry is a self-contained JSON object:

```json
{
  "id": "uuid",
  "timestamp": "2026-06-20T09:14:00Z",
  "actor": "fatemeh.j",
  "action": "approve_change",
  "target_realm": "smartech",
  "target_user": "sara.ahmadi",
  "detail": "change abc123 approved",
  "outcome": "success"
}
```

Date partitioning makes it trivial to query by day (list prefix `grafter/audit/2026-06-20/`). Each event is its own object — no read-modify-write, no locking, no concurrent write conflicts. Object storage is effectively append-only and cheap to retain indefinitely.

---

## Contributing

- Run `cargo clippy -- -D warnings` before committing. Zero warnings required.
- The `IdentityProvider` and `ChangeStorage` traits are the extension points. New providers implement the trait; routes don't change.
- Templates are in `templates/`. CSS lives in `base.html` using the Rhizomo design token set.
- All state-changing routes must append an audit entry.
