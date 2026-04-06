CREATE TYPE credential_kind AS ENUM ('password', 'webauthn', 'oidc', 'totp');
CREATE TYPE membership_role AS ENUM ('owner', 'admin', 'member');
CREATE TYPE client_type AS ENUM ('confidential', 'public');

ALTER TABLE credentials
    ALTER COLUMN kind TYPE credential_kind USING kind::credential_kind;

ALTER TABLE memberships
    ALTER COLUMN role TYPE membership_role USING role::membership_role;

ALTER TABLE invitations
    ALTER COLUMN role TYPE membership_role USING role::membership_role;

ALTER TABLE clients
    ALTER COLUMN client_type TYPE client_type USING client_type::client_type;
