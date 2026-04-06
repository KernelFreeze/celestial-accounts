CREATE TABLE sessions (
    id              UUID        PRIMARY KEY,
    account_id      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    ip_address      TEXT        NOT NULL,
    user_agent      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_sessions_account_id ON sessions(account_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE password_reset_tokens (
    id              UUID        PRIMARY KEY,
    account_id      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash      BYTEA       NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used            BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_reset_tokens_account_id ON password_reset_tokens(account_id);
