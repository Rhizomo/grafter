# Grafter — Architecture

Internal technical reference. Covers design decisions, system structure, and extension points.

---

## 1. Why this exists

### The problem

Keycloak's Admin UI gives unrestricted access to anyone with admin credentials. In a multi-team environment, that's too broad: a junior operator shouldn't be able to directly assign sensitive realm roles or disable accounts without review. We needed an approval layer — changes proposed by operators, applied by admins — with a full audit trail.

The alternative was restricting access to Keycloak entirely and routing all IAM operations through a service. That's what Grafter is.

### Why a wrapper, not a Keycloak plugin

Keycloak's extension system (SPIs) is tightly coupled to its internals, requires Java, and breaks across major versions. A standalone wrapper:

- Decouples the approval workflow from Keycloak's release cycle
- Can be replaced or extended without touching Keycloak
- Has its own audit store (not dependent on Keycloak's event log, which has limited retention and querying)
- The `IdentityProvider` trait makes Keycloak swappable if we ever move away from it

---

## 2. System architecture

### Request lifecycle

```
Browser HTTP request
  │
  ▼
Axum router (src/routes/mod.rs)
  │
  ├─ Session middleware (tower-sessions, Redis-backed)
  │    Extracts SessionUser from session cookie
  │
  ├─ require_session() / require_admin()
  │    Returns AppError::Unauthorized if session missing
  │    Returns AppError::Unauthorized if role insufficient
  │
  ├─ Route handler
  │    Reads from AppState (provider, storage, tera, config, jwks, redis)
  │    Calls IdentityProvider or ChangeStorage as needed
  │    Renders Tera template or returns Redirect
  │
  └─ AppError::into_response()
       Logs raw error server-side
       Returns safe static message to browser
       401 → redirect to /auth/login
       404 → 404 plain text
       403/500 → status + safe message
```

### AppState

```rust
pub struct AppState {
    pub provider: Arc<dyn IdentityProvider>,
    pub storage:  Arc<dyn ChangeStorage>,
    pub tera:     Arc<Tera>,
    pub config:   Arc<Config>,
    pub jwks:     Arc<JwksCache>,
    pub http:     reqwest::Client,
    pub redis:    RedisPool,
}
```

Everything is wrapped in `Arc` or cheaply clonable. Axum clones `AppState` per request; `Arc` makes this a reference count bump rather than a deep copy. `RedisPool` from `fred` is internally reference-counted and connection-pooled.

`redis` is stored directly (not through a trait) because it's used for a specific infrastructure concern — distributed locking — not a swappable abstraction.

### The IdentityProvider trait

Defined in `src/provider/mod.rs`. Abstracts everything Grafter does to an identity system:

```rust
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    async fn list_realms(&self) -> Result<Vec<Realm>, ProviderError>;
    async fn list_users(&self, realm: &str) -> Result<Vec<User>, ProviderError>;
    async fn get_user(&self, realm: &str, id: &str) -> Result<Option<User>, ProviderError>;
    async fn create_user(&self, realm: &str, user: NewUser) -> Result<String, ProviderError>;
    async fn update_user(&self, realm: &str, id: &str, update: UpdateUser) -> Result<(), ProviderError>;
    async fn set_user_enabled(&self, realm: &str, id: &str, enabled: bool) -> Result<(), ProviderError>;
    async fn set_user_attribute(&self, realm: &str, id: &str, key: &str, value: &str) -> Result<(), ProviderError>;
    async fn list_realm_roles(&self, realm: &str) -> Result<Vec<Role>, ProviderError>;
    async fn get_user_roles(&self, realm: &str, user_id: &str) -> Result<Vec<Role>, ProviderError>;
    async fn assign_realm_role(&self, realm: &str, user_id: &str, role: &Role) -> Result<(), ProviderError>;
    async fn remove_realm_role(&self, realm: &str, user_id: &str, role: &Role) -> Result<(), ProviderError>;
    async fn get_user_groups(&self, realm: &str, user_id: &str) -> Result<Vec<Group>, ProviderError>;
    async fn list_clients(&self, realm: &str) -> Result<Vec<Client>, ProviderError>;
    async fn get_client(&self, realm: &str, id: &str) -> Result<Option<Client>, ProviderError>;
}
```

To add a new provider (e.g. Auth0, Okta, LDAP): implement this trait, wire it in `main.rs`. Routes, storage, audit, and session handling don't change.

### The ChangeStorage trait

Defined in `src/storage/mod.rs`. Abstracts how pending changes and audit entries are persisted:

```rust
#[async_trait]
pub trait ChangeStorage: Send + Sync {
    async fn save_change(&self, change: &PendingChange) -> Result<()>;
    async fn get_change(&self, id: &str) -> Result<Option<PendingChange>>;
    async fn list_changes(&self) -> Result<Vec<PendingChange>>;
    async fn delete_change(&self, id: &str) -> Result<()>;
    async fn append_audit(&self, entry: &AuditEntry) -> Result<()>;
    async fn list_audit(&self, date: Option<&str>) -> Result<Vec<AuditEntry>>;
}
```

The current implementation is `S3Storage`. The trait could be backed by a database, but S3 was chosen deliberately — see section 5.

---

## 3. Auth & sessions

### OIDC authorization code flow

```
1.  User hits protected route
    → Server generates random state (32 bytes, base64url) and nonce (32 bytes, base64url)
    → Stores both in session
    → Redirects to:
      {OIDC_ISSUER}/protocol/openid-connect/auth
        ?response_type=code
        &client_id={OIDC_CLIENT_ID}
        &redirect_uri={OIDC_REDIRECT_URI}
        &scope=openid+profile+email
        &state={state}
        &nonce={nonce}

2.  User authenticates with Keycloak

3.  Keycloak redirects to /auth/callback?code=...&state=...

4.  Server verifies state == session["oauth_state"] (CSRF guard)

5.  Server POSTs to {OIDC_ISSUER}/protocol/openid-connect/token
      grant_type=authorization_code
      client_id, client_secret, redirect_uri, code

6.  Keycloak returns { access_token, id_token, refresh_token }

7.  Server extracts nonce from id_token payload (unsigned read — safe because
    nonce is only used for replay detection, not for identity)
    Verifies nonce == session["oauth_nonce"]

8.  Server verifies access_token signature via JWKS (see below)

9.  Server reads realm_access.roles from access_token claims
    Maps to Role::Admin or Role::Operator based on IAM_ROLE_ADMIN / IAM_ROLE_OPERATOR

10. Writes SessionUser { sub, username, email, role } to Redis session
    Clears oauth_state and oauth_nonce from session
    Redirects to /
```

### JWKS verification

Grafter fetches JWKS from `{OIDC_ISSUER}/protocol/openid-connect/certs` and caches it in-process for 1 hour behind an `Arc<RwLock<Option<JwksEntry>>>`.

On JWT verification:
1. Decode the header to extract `kid`
2. Find the matching JWK in cache; fall back to first key if `kid` is empty
3. Build a `DecodingKey` from RSA or EC components
4. Verify signature and issuer claim via `jsonwebtoken::decode`
5. If verification fails (key not found or signature error): clear cache, fetch fresh JWKS, retry once — handles Keycloak key rotation without a restart

`validate_aud = false` because Keycloak access tokens don't always include the client ID as audience. The issuer check is the binding constraint.

### Sessions

`tower-sessions` with `tower-sessions-redis-store`. Sessions are stored in Redis as signed, serialized blobs. The signing key is `SESSION_SECRET` (min 32 bytes, asserted at startup).

What's in a session:
- `SESSION_KEY` → `SessionUser { sub, username, email, role }` — set on login, checked on every protected request
- `"csrf"` → CSRF token string — regenerated on each page load that renders a form
- `"oauth_state"` / `"oauth_nonce"` → transient, cleared after callback
- `"flash"` → `Flash { text, kind }` — set before redirect, consumed on the next render

Sessions survive server restarts. To invalidate a user's session, delete their key from Redis.

### CSRF protection

Every form-rendering route generates a random 32-byte base64url token and stores it in the session. The token is embedded as a hidden field in the rendered HTML. On POST, the handler reads the token from the form body and compares it to the session value using constant-time XOR comparison (prevents timing oracle attacks). Mismatch → `AppError::CsrfMismatch` → 403.

---

## 4. The change queue

### Lifecycle

```
Operator submits edit form
  │
  ▼
PendingChange written to S3
  status: Pending
  grafter/changes/{uuid}.json
  │
  ▼
Admin reviews in Changes tab
  │
  ├─ Approve ──────────────────────────────────────────────────────┐
  │    Acquire Redis lock (SET NX EX 30)                           │
  │    Re-read change from S3                                      │
  │    Check status == Pending (idempotency guard)                 │
  │    Apply to Keycloak (update_user / set_enabled / set_attr)    │
  │    Update S3 record → status: Approved                         │
  │    Release lock (only on S3 success)                           │
  │    Append audit entry                                          │
  │                                                                │
  └─ Reject ───────────────────────────────────────────────────────┘
       Acquire Redis lock
       Re-read change from S3
       Check status == Pending
       Update S3 record → status: Rejected, reject_reason: ...
       Release lock
       Append audit entry
```

### S3 key structure

```
grafter/
  changes/
    {uuid}.json          ← one file per PendingChange, overwritten on status update
  audit/
    YYYY-MM-DD/
      {uuid}.json        ← one file per AuditEntry, never modified
```

`PendingChange` JSON includes: id, realm, user_id, username, proposed_by, proposed_at, status, resolved_by, resolved_at, reject_reason, diff (array of `{ field, before, after }`).

### Why S3/object storage (not Postgres)

- **No migrations**: the JSON schema can evolve without ALTER TABLE. Old records remain readable.
- **Append-only for audit**: each audit event is its own object. No UPDATE ever touches audit records.
- **Infrastructure reuse**: MinIO was already in the stack for blob storage. No new database to operate.
- **Retention**: object storage is cheap enough to keep indefinitely. A database would need a purge strategy.
- **Tradeoff**: no transactions, no relational queries. Listing changes means listing S3 objects and deserializing each one. At current scale (hundreds of changes) this is fine; at tens of thousands it would need pagination at the storage layer.

### Idempotency and the distributed lock

The Redis lock (`SET grafter:change-lock:{id} 1 NX EX 30`) solves the race where two admins approve the same change simultaneously:

- `NX`: only sets the key if it doesn't exist — atomic test-and-set
- `EX 30`: 30-second TTL — lock expires even if the holder crashes
- If `SET` returns `None`: lock is held → flash warning, return early
- If `SET` returns `Ok`: lock is acquired → proceed

The status guard (`status != Pending`) inside the lock is the second line of defense: if the lock races somehow, or if the lock expires and a retry comes in after the first request succeeded, the re-read catches it.

### The RECONCILIATION REQUIRED case

If Keycloak mutations succeed but the S3 `save_change` write fails:

- The lock is **not released** (left to expire after 30s)
- `tracing::error!` emits `RECONCILIATION REQUIRED: change applied to Keycloak but S3 record was not persisted`
- The route returns 500 to the browser

This is intentional: the lock expiring means no retry can happen automatically. A human must check whether the Keycloak state and the S3 record are consistent, then manually update the S3 record or re-run the change.

The alternative — releasing the lock and allowing a retry — risks double-applying the Keycloak mutation (e.g. adding a role twice). The conservative choice is to block until manual intervention.

---

## 5. Audit log

### What gets written

Every state-changing action appends an `AuditEntry`:

| Action string | When |
|---|---|
| `approve_change` | Admin approves a pending change |
| `reject_change` | Admin rejects a pending change |
| `create_user` | Admin creates a new user |
| `edit_user` | Admin applies a direct edit |
| `bulk_edit` | Admin runs a bulk enable/disable/team operation |
| `assign_role` | Admin assigns a realm role |
| `remove_role` | Admin removes a realm role |

Each entry: `{ id, timestamp, actor, action, target_realm, target_user, detail, outcome }`.

`outcome` is either `success` or `failure`. In practice, failures at the Keycloak layer return `AppError` before the audit write is reached, so all written entries are successes.

### S3 key structure

`grafter/audit/YYYY-MM-DD/{event-uuid}.json`

Date partitioning means querying a day's events is a single `list_objects` call with a date prefix. No secondary index needed. Each event is an independent object — `append_audit` is a pure PUT with no read.

### Why not a database

Same reasons as the change queue. Additionally:

- **Immutability**: you can't `UPDATE` an S3 object in-place — the operation is always PUT (full overwrite). Audit entries are never overwritten, making accidental or malicious tampering harder.
- **Compliance**: log immutability is often a compliance requirement. S3 object lock and versioning can enforce this at the infrastructure level.
- A database audit table would require either a separate database or careful schema management alongside the application tables.

---

## 6. Security model

### Role separation

| | Admin | Operator |
|---|---|---|
| View all users | ✓ | own realm only |
| Create users | ✓ | — |
| Direct edit (no queue) | ✓ | — |
| Propose changes | ✓ | ✓ |
| View change queue | all changes | own changes only |
| Approve / reject | ✓ | — |
| Assign / remove roles | ✓ | — |
| Bulk operations | ✓ | — |
| View clients | ✓ | — |

Operators cannot approve their own proposals — there is no self-approval path.

### Why bulk_edit and create_user require admin

Both operations bypass the change queue entirely. `create_user` writes directly to Keycloak and can provision accounts with credentials. `bulk_edit` can enable/disable multiple accounts or reassign team attributes in a single request. Both are admin-only to prevent operators from circumventing the approval flow.

In the previous version, `bulk_edit` used `require_session` (any authenticated user). This was a security bug — fixed by changing to `require_admin`.

### Service account scoping

`grafter-admin` (the Keycloak Admin API client) should have only the permissions it needs:

- `view-users`, `manage-users` for the target realm
- `view-clients` for client listing
- No `manage-realm` or cross-realm permissions

The service account token is obtained per-request via client credentials flow and cached with a short TTL. It is never stored in sessions or returned to the browser.

---

## 7. Adding a new identity provider

To add support for a different identity system (e.g. Auth0, Azure AD, LDAP):

1. Create `src/provider/myprovider.rs`
2. Implement `IdentityProvider` for your type — all methods, including the ones Grafter doesn't use yet (`delete_user`, group management)
3. Handle `ProviderError` variants: `Unauthorized`, `NotFound`, `UnexpectedResponse`, `Other`
4. In `main.rs`, replace `KeycloakProvider::new(...)` with your provider
5. Update `.env.example` with new provider-specific variables

**What doesn't change**: routes, templates, storage, audit, sessions, CSRF, the approval flow. The `IdentityProvider` trait is the entire surface area.

The `ChangeStorage` trait is similarly swappable. A Postgres-backed implementation would be straightforward — implement the trait, swap in `main.rs`.

---

## 8. Development decisions & tradeoffs

### Why Rust + Axum (not Go, not Node)

The binary compiles to ~10MB, runs in ~15MB RSS at idle, and handles concurrent requests without per-request allocations. For an internal tool with modest traffic, this is overkill — but the team already uses Rust and the type system catches entire classes of bugs (missing CSRF checks, unhandled error paths) at compile time rather than in production.

Go would have been equally reasonable. Node was ruled out: the template-plus-form pattern doesn't benefit from a JS runtime, and we didn't want a build pipeline.

### Why Tera (not a JS frontend)

Grafter is a form-heavy CRUD app. Every interaction is a POST → redirect → GET. Server-side rendering with Tera templates is exactly the right abstraction: no hydration, no client-server state sync, no JS bundle. The only client-side JS is for UX polish (bulk bar, sortable tables, reject modal). Total JS: ~200 lines of vanilla JS across all templates.

A React or Vue frontend would add complexity — separate build, API layer, client state management — for no user-visible benefit.

### Why MinIO/S3 for changes (not Postgres)

The change queue is append-mostly (writes) with occasional reads (list for approval). There are no joins, no transactions, no aggregate queries. S3 is available, cheap, and already used for other blob storage in the stack. Adding a Postgres instance for this workload would mean another service to operate, another migration system, another backup concern.

The tradeoff: listing all pending changes requires deserializing every object in `grafter/changes/`. At hundreds of changes this is fast (parallel GET). At tens of thousands it would need either pagination at the S3 layer or a secondary index. That's future work.

### Why tower-sessions + Redis (not JWT-only stateless auth)

Stateless JWT auth (storing everything in the token) would eliminate the Redis dependency, but at the cost of:

- **Unrevocable sessions**: you can't log out a user if their token is stolen — you'd need a blocklist, which requires state anyway
- **Role change lag**: if a user's role changes in Keycloak, their in-flight JWT still claims the old role until it expires
- **Flash messages**: the POST → redirect → GET flash pattern requires server-side state between requests

Redis-backed sessions solve all three. The dependency is lightweight and already needed for the distributed lock.

### What we'd do differently at 10x scale

- **Pagination at the storage layer**: `list_changes()` and `list_users()` currently load everything. S3 `list_objects` supports continuation tokens; Keycloak Admin API supports `?first=&max=`. Both need wiring.
- **WebSocket or SSE for the approval queue**: admins currently have to refresh to see new proposals. A live update channel would improve the workflow.
- **Separate read/write DB**: if the change queue grows large, an append-only write log + read replica with indexed queries would replace the S3 list-and-deserialize pattern.
- **Multi-region**: Redis sessions and the S3 store would need replication strategy.

---

## 9. Known limitations & future work

| Limitation | Impact | Notes |
|---|---|---|
| No server-side pagination | Keycloak realms with > ~500 users will be slow | API supports it; needs wiring |
| No email notifications | Operators don't know when their change is approved/rejected | Would need SMTP or webhook integration |
| No audit log UI | Audit entries exist in S3 but aren't browseable in the app | A date-picker + table view is straightforward to add |
| Mobile not supported | Layout is desktop-only | Not a use case for an internal admin tool |
| No bulk propose | Operators can only propose one change at a time | Bulk propose would complicate the diff structure |
| `delete_change` unrouted | The storage method exists but no route calls it | S3 changes accumulate indefinitely |
| Zero test coverage | No unit or integration tests | The approval flow and RECONCILIATION path are the highest-priority targets |
