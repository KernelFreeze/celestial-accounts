CREATE TABLE credentials (
    id              UUID        PRIMARY KEY,
    account_id      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind            TEXT        NOT NULL,
    provider        TEXT,
    credential_data BYTEA       NOT NULL,
    verified        BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_credentials_account_id ON credentials(account_id);
CREATE INDEX idx_credentials_account_kind ON credentials(account_id, kind);

CREATE TABLE emails (
    id              UUID        PRIMARY KEY,
    account_id      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    address         TEXT        NOT NULL UNIQUE,
    verified        BOOLEAN     NOT NULL DEFAULT false,
    is_primary      BOOLEAN     NOT NULL DEFAULT false,
    verified_at     TIMESTAMPTZ
);

CREATE INDEX idx_emails_account_id ON emails(account_id);
