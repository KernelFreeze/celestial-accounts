ALTER TABLE credentials
    ALTER COLUMN kind TYPE TEXT;

ALTER TABLE memberships
    ALTER COLUMN role TYPE TEXT;

ALTER TABLE invitations
    ALTER COLUMN role TYPE TEXT;

ALTER TABLE clients
    ALTER COLUMN client_type TYPE TEXT;

DROP TYPE credential_kind;
DROP TYPE membership_role;
DROP TYPE client_type;
