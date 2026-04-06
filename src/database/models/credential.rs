use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use super::pg_enum;
use crate::database::schema::{credentials, sql_types};

pg_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CredentialKind (sql_types::CredentialKind) {
        Password => "password",
        Webauthn => "webauthn",
        Oidc => "oidc",
        Totp => "totp",
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub account_id: Uuid,
    pub kind: CredentialKind,
    pub provider: Option<String>,
    pub credential_data: Vec<u8>,
    pub verified: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub kind: &'a CredentialKind,
    pub provider: Option<&'a str>,
    pub credential_data: &'a [u8],
}
