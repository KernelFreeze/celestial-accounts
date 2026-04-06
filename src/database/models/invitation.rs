use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use super::MembershipRole;
use crate::database::schema::invitations;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = invitations)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Invitation {
    pub id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    pub role: MembershipRole,
    pub token_hash: Vec<u8>,
    pub invited_by: Uuid,
    pub expires_at: OffsetDateTime,
    pub accepted_at: Option<OffsetDateTime>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = invitations)]
pub struct NewInvitation<'a> {
    pub id: Uuid,
    pub org_id: Uuid,
    pub email: &'a str,
    pub role: &'a MembershipRole,
    pub token_hash: &'a [u8],
    pub invited_by: Uuid,
    pub expires_at: OffsetDateTime,
}
