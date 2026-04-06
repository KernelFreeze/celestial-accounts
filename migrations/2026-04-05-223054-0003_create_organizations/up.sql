CREATE TABLE organizations (
    id              UUID        PRIMARY KEY,
    slug            TEXT        NOT NULL UNIQUE,
    name            TEXT        NOT NULL,
    mfa_required    BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    account_id      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role            TEXT        NOT NULL,
    invited_by      UUID        REFERENCES accounts(id) ON DELETE SET NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, org_id)
);

CREATE INDEX idx_memberships_org_id ON memberships(org_id);

CREATE TABLE invitations (
    id              UUID        PRIMARY KEY,
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           TEXT        NOT NULL,
    role            TEXT        NOT NULL,
    token_hash      BYTEA       NOT NULL,
    invited_by      UUID        NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ NOT NULL,
    accepted_at     TIMESTAMPTZ
);

CREATE INDEX idx_invitations_org_id ON invitations(org_id);
CREATE INDEX idx_invitations_email ON invitations(email);
