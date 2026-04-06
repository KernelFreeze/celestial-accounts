use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::accounts;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Account {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub mfa_enforced: bool,
    pub locked_until: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = accounts)]
pub struct NewAccount<'a> {
    pub id: Uuid,
    pub username: &'a str,
    pub display_name: &'a str,
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = accounts)]
pub struct AccountUpdate<'a> {
    pub display_name: Option<&'a str>,
    pub mfa_enforced: Option<bool>,
    pub locked_until: Option<Option<OffsetDateTime>>,
}
