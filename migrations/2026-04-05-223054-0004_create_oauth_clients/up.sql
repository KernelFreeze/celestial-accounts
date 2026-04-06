CREATE TABLE clients (
    client_id           UUID        PRIMARY KEY,
    client_secret_hash  BYTEA,
    client_type         TEXT        NOT NULL,
    is_first_party      BOOLEAN     NOT NULL DEFAULT false,
    name                TEXT        NOT NULL,
    allowed_scopes      TEXT[]      NOT NULL DEFAULT '{}',
    redirect_uris       TEXT[]      NOT NULL DEFAULT '{}',
    consent_skip        BOOLEAN     NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
