CREATE TABLE authorization_codes (
    code_hash               BYTEA       PRIMARY KEY,
    client_id               UUID        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    account_id              UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    scope                   TEXT        NOT NULL,
    code_challenge          TEXT        NOT NULL,
    code_challenge_method   TEXT        NOT NULL DEFAULT 'S256',
    redirect_uri            TEXT        NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL,
    used                    BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX idx_authorization_codes_client_id ON authorization_codes(client_id);
CREATE INDEX idx_authorization_codes_account_id ON authorization_codes(account_id);

CREATE TABLE consent_grants (
    account_id      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    client_id       UUID        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    granted_scopes  TEXT[]      NOT NULL DEFAULT '{}',
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    PRIMARY KEY (account_id, client_id)
);

CREATE TABLE refresh_tokens (
    token_hash      BYTEA       PRIMARY KEY,
    client_id       UUID        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    account_id      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    scope           TEXT        NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    rotated_from    BYTEA,
    revoked         BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens(client_id);
CREATE INDEX idx_refresh_tokens_account_id ON refresh_tokens(account_id);
