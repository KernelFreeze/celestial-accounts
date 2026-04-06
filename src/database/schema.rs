// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "client_type"))]
    pub struct ClientType;

    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "credential_kind"))]
    pub struct CredentialKind;

    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "membership_role"))]
    pub struct MembershipRole;
}

diesel::table! {
    accounts (id) {
        id -> Uuid,
        username -> Text,
        display_name -> Text,
        mfa_enforced -> Bool,
        locked_until -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    audit_log (id) {
        id -> Uuid,
        event_type -> Text,
        account_id -> Nullable<Uuid>,
        ip_address -> Text,
        user_agent -> Nullable<Text>,
        details -> Nullable<Jsonb>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    authorization_codes (code_hash) {
        code_hash -> Bytea,
        client_id -> Uuid,
        account_id -> Uuid,
        scope -> Text,
        code_challenge -> Text,
        code_challenge_method -> Text,
        redirect_uri -> Text,
        expires_at -> Timestamptz,
        used -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::ClientType;

    clients (client_id) {
        client_id -> Uuid,
        client_secret_hash -> Nullable<Bytea>,
        client_type -> ClientType,
        is_first_party -> Bool,
        name -> Text,
        allowed_scopes -> Array<Nullable<Text>>,
        redirect_uris -> Array<Nullable<Text>>,
        consent_skip -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    consent_grants (account_id, client_id) {
        account_id -> Uuid,
        client_id -> Uuid,
        granted_scopes -> Array<Nullable<Text>>,
        granted_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::CredentialKind;

    credentials (id) {
        id -> Uuid,
        account_id -> Uuid,
        kind -> CredentialKind,
        provider -> Nullable<Text>,
        credential_data -> Bytea,
        verified -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    emails (id) {
        id -> Uuid,
        account_id -> Uuid,
        address -> Text,
        verified -> Bool,
        is_primary -> Bool,
        verified_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::MembershipRole;

    invitations (id) {
        id -> Uuid,
        org_id -> Uuid,
        email -> Text,
        role -> MembershipRole,
        token_hash -> Bytea,
        invited_by -> Uuid,
        expires_at -> Timestamptz,
        accepted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::MembershipRole;

    memberships (account_id, org_id) {
        account_id -> Uuid,
        org_id -> Uuid,
        role -> MembershipRole,
        invited_by -> Nullable<Uuid>,
        joined_at -> Timestamptz,
    }
}

diesel::table! {
    organizations (id) {
        id -> Uuid,
        slug -> Text,
        name -> Text,
        mfa_required -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    password_reset_tokens (id) {
        id -> Uuid,
        account_id -> Uuid,
        token_hash -> Bytea,
        expires_at -> Timestamptz,
        used -> Bool,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    refresh_tokens (token_hash) {
        token_hash -> Bytea,
        client_id -> Uuid,
        account_id -> Uuid,
        scope -> Text,
        issued_at -> Timestamptz,
        expires_at -> Timestamptz,
        rotated_from -> Nullable<Bytea>,
        revoked -> Bool,
    }
}

diesel::table! {
    sessions (id) {
        id -> Uuid,
        account_id -> Uuid,
        ip_address -> Text,
        user_agent -> Text,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::joinable!(audit_log -> accounts (account_id));
diesel::joinable!(authorization_codes -> accounts (account_id));
diesel::joinable!(authorization_codes -> clients (client_id));
diesel::joinable!(consent_grants -> accounts (account_id));
diesel::joinable!(consent_grants -> clients (client_id));
diesel::joinable!(credentials -> accounts (account_id));
diesel::joinable!(emails -> accounts (account_id));
diesel::joinable!(invitations -> accounts (invited_by));
diesel::joinable!(invitations -> organizations (org_id));
diesel::joinable!(memberships -> organizations (org_id));
diesel::joinable!(password_reset_tokens -> accounts (account_id));
diesel::joinable!(refresh_tokens -> accounts (account_id));
diesel::joinable!(refresh_tokens -> clients (client_id));
diesel::joinable!(sessions -> accounts (account_id));

diesel::allow_tables_to_appear_in_same_query!(
    accounts,
    audit_log,
    authorization_codes,
    clients,
    consent_grants,
    credentials,
    emails,
    invitations,
    memberships,
    organizations,
    password_reset_tokens,
    refresh_tokens,
    sessions,
);
