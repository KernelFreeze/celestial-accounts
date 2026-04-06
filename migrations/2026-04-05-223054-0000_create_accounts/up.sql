CREATE TABLE accounts (
    id              UUID        PRIMARY KEY,
    username        TEXT        NOT NULL UNIQUE,
    display_name    TEXT        NOT NULL,
    mfa_enforced    BOOLEAN     NOT NULL DEFAULT false,
    locked_until    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

SELECT diesel_manage_updated_at('accounts');
