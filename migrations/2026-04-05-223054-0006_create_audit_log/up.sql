CREATE TABLE audit_log (
    id              UUID        PRIMARY KEY,
    event_type      TEXT        NOT NULL,
    account_id      UUID        REFERENCES accounts(id) ON DELETE SET NULL,
    ip_address      TEXT        NOT NULL,
    user_agent      TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_account_id ON audit_log(account_id);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
