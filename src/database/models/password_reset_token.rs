use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::password_reset_tokens;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = password_reset_tokens)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct PasswordResetToken {
    pub id: Uuid,
    pub account_id: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: OffsetDateTime,
    pub used: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = password_reset_tokens)]
pub struct NewPasswordResetToken<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub token_hash: &'a [u8],
    pub expires_at: OffsetDateTime,
}
