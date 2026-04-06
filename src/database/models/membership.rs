use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use super::pg_enum;
use crate::database::schema::{memberships, sql_types};

pg_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MembershipRole (sql_types::MembershipRole) {
        Owner => "owner",
        Admin => "admin",
        Member => "member",
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = memberships)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Membership {
    pub account_id: Uuid,
    pub org_id: Uuid,
    pub role: MembershipRole,
    pub invited_by: Option<Uuid>,
    pub joined_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = memberships)]
pub struct NewMembership<'a> {
    pub account_id: Uuid,
    pub org_id: Uuid,
    pub role: &'a MembershipRole,
    pub invited_by: Option<Uuid>,
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = memberships)]
pub struct MembershipUpdate<'a> {
    pub role: Option<&'a MembershipRole>,
}
