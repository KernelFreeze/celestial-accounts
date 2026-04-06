use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::authorization_codes;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = authorization_codes)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuthorizationCode {
    pub code_hash: Vec<u8>,
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub redirect_uri: String,
    pub expires_at: OffsetDateTime,
    pub used: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = authorization_codes)]
pub struct NewAuthorizationCode<'a> {
    pub code_hash: &'a [u8],
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub scope: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub redirect_uri: &'a str,
    pub expires_at: OffsetDateTime,
}
