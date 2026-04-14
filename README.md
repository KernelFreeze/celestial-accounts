# Celestial Accounts

A self-hosted identity and authorization provider built in Rust. Handles authentication, session management, multi-factor authentication, and (soon) full OAuth2 authorization. 

## Design principes

1. **No implicit trust.** Even first-party services authenticate through the same OAuth2 flows as third-party apps. Nothing gets unscoped access to identity data.
2. **Pluggable credentials.** Passwords, passkeys, and social logins are interchangeable credential records attached to an account. The account itself is identified by a username, never by an email.
3. **OWASP compliance by default.** The OWASP Top Ten and Cheat Sheet Series inform every subsystem, from password hashing parameters to response timing.

## Current status

The authentication core is functional. You can log in with a password, complete TOTP-based MFA, and revoke tokens. The database schema, credential architecture, and session management are in place. The OAuth2 authorization server, identity federation, and several other features exist as designed infrastructure (models, migrations, traits) but don't yet have wired endpoints.

## What's implemented

**Authentication.** Password verification uses Argon2id with an HMAC-SHA-256 pepper applied as a pre-hash. Every code path (valid account, invalid account, wrong password, locked account) takes the same wall-clock time. When the account doesn't exist, the handler runs a dummy Argon2id hash to equalize latency. All failure responses return a generic `{"error": "invalid_credentials"}` with a `401` status.

**Multi-factor authentication.** TOTP (RFC 6238) with 6-digit codes, 30-second steps, and ±1 window tolerance for clock skew. TOTP secrets are encrypted at rest with AES-256-GCM. After primary authentication succeeds on an MFA-required account, the server issues a partial session token (PASETO v4.local, 2-minute TTL) that grants access only to the MFA verification endpoint. Completing the challenge upgrades it to a full session.

**Session management.** Access tokens are PASETO v4.public (Ed25519-signed, 15-minute TTL). Refresh tokens are opaque 256-bit random values stored server-side as hashes, delivered in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. Refresh tokens have a 90-day absolute expiry.

**Token revocation.** A Redis-backed store tracks revoked token IDs (`jti`). Each entry has a TTL matching the token's remaining lifetime, so the store cleans itself up automatically.

**Account lockout.** After consecutive failed login attempts, progressive lockout kicks in: 1 minute, then 5, 15, and 60 minutes (exponential backoff).

**Token revocation endpoint.** `POST /oauth/revoke` accepts both refresh and access tokens, with optional type hints. Always returns `200 OK` regardless of whether the token was valid, per RFC 7009.

**Credential architecture.** The verifier system currently supports four credential kinds (`password`, `webauthn`, `oidc`, and `totp`) with constant-time verification across all types. It can be easily extended to new auth schemas. Custom Axum extractors handle authentication (`AuthenticatedUser`), scope enforcement (`Scoped<S>`), and client info resolution.

## Tech stack

| Component | Choice |
|---|---|
| Language | Rust (nightly, edition 2024) |
| Web framework | Axum 0.8 |
| Database | PostgreSQL via Diesel 2.3 (compile-time checked SQL) |
| Async runtime | Tokio |
| Token format | PASETO v4 (`rusty_paseto`) |
| Password hashing | Argon2id (`argon2` crate) + HMAC-SHA-256 pepper |
| Encryption at rest | AES-256-GCM (TOTP secrets) |
| Revocation store | Redis via `deadpool-redis` |
| Connection pooling | Deadpool |


## API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/login` | Authenticate with any credential kind |
| `POST` | `/auth/mfa/verify` | Complete an MFA challenge |
| `POST` | `/oauth/revoke` | Revoke an access or refresh token |

## Setup

### Prerequisites

- Rust nightly toolchain
- PostgreSQL
- Redis
- Diesel CLI (`cargo install diesel_cli --no-default-features --features postgres`)

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `PEPPER` | Yes | 32-byte hex-encoded secret for Argon2 pre-hash |
| `PASETO_PRIVATE_KEY` | Yes | Base64-encoded Ed25519 private key (64 bytes) |
| `PASETO_LOCAL_KEY` | Yes | Hex-encoded 256-bit symmetric key for v4.local tokens |
| `PASETO_KEY_ID` | Yes | Key identifier included in token footers |
| `TOTP_ENCRYPTION_KEY` | Yes | Hex-encoded 256-bit AES key for TOTP secret encryption |
| `ADDR` | No | Bind address (default: `0.0.0.0`) |
| `PORT` | No | Bind port (default: `8080`) |

### Running

```sh
# Run database migrations
diesel migration run

# Build and start the server
cargo run --release
```

## Database schema

The schema is managed through 9 Diesel migrations. Core tables:

| Table | Purpose |
|---|---|
| `accounts` | User identity (UUID primary key, case-insensitive username) |
| `credentials` | Pluggable auth methods linked to accounts |
| `emails` | Contact addresses (verified flag, primary flag) |
| `sessions` | Active sessions with IP and user-agent tracking |
| `refresh_tokens` | Hashed refresh tokens with rotation chain tracking |
| `organizations` | Multi-tenant organization records |
| `memberships` | Account-to-org relationships with roles (owner/admin/member) |
| `invitations` | Pending membership invites (7-day TTL) |
| `clients` | OAuth2 client registry (confidential and public) |
| `authorization_codes` | OAuth2 authorization codes (PKCE-bound, 60-second TTL) |
| `consent_grants` | Per-client user consent records |
| `audit_log` | Immutable append-only security event log |

### OAuth2 authorization server

Authorization code flow with PKCE (the only interactive grant; implicit and resource owner password grants are intentionally excluded per OAuth 2.1). Includes a consent screen for third-party clients, client credentials grant for machine-to-machine flows, audience-restricted access tokens, and refresh token rotation with stolen-token detection (reuse of a rotated token revokes the entire chain).

### Identity federation

OIDC integration with external providers (Google, GitHub, Apple). The server handles the authorization code exchange, validates the `id_token` against the provider's JWKS, and links the external `sub` claim to a local account. Auto-linking and auto-registration are configurable per provider.

### WebAuthn / FIDO2

Passkey registration and authentication, usable as either a primary credential or a second factor. The credential table and verifier trait already support the `webauthn` kind.

### Logout and session management

A user-facing session list showing IP, user-agent, and creation time, with the ability to revoke individual sessions. Password changes will revoke all sessions for the account. Organization admins will be able to revoke sessions for any member.

### Account registration

Registration endpoint with password policy enforcement (8–128 characters, all Unicode, no composition rules) and breach-corpus checking against the HaveIBeenPwned k-anonymity API. The response is always "check your email" regardless of whether the username exists.

### Password reset

Token-based reset flow with a 20-minute TTL. The reset URL is validated against a trusted-domain allowlist (never derived from the `Host` header). Completing a reset revokes all existing sessions.

### Organization management

Create organizations, invite members via 7-day token links, assign roles (owner > admin > member), enforce MFA at the organization level. At least one owner must exist at all times.

### Consent management

User-facing dashboard of authorized applications, showing which clients have access, which scopes were granted, and when. Revoking consent invalidates all tokens for that client-account pair.

### Rate limiting

Per-IP, per-account, and per-endpoint sliding-window counters backed by Redis, using the `governor` crate. CAPTCHA triggered after repeated failures as a defense-in-depth measure.

### Additional planned work

- CSRF protection (synchronizer token pattern + cookie-to-header for SPAs)
- User-visible audit log (recent login history, admin event streams)
- Ed25519 key rotation with overlap windows for zero-downtime rollover
- Public key endpoint at `GET /.well-known/paseto-keys` for resource server token verification

## License

MIT
