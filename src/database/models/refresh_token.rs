use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::refresh_tokens;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = refresh_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct RefreshToken {
    pub token_hash: Vec<u8>,
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub scope: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub rotated_from: Option<Vec<u8>>,
    pub revoked: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = refresh_tokens)]
pub struct NewRefreshToken<'a> {
    pub token_hash: &'a [u8],
    pub client_id: Uuid,
    pub account_id: Uuid,
    pub scope: &'a str,
    pub expires_at: OffsetDateTime,
    pub rotated_from: Option<&'a [u8]>,
}
