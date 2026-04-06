use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::emails;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = emails)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Email {
    pub id: Uuid,
    pub account_id: Uuid,
    pub address: String,
    pub verified: bool,
    pub is_primary: bool,
    pub verified_at: Option<OffsetDateTime>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = emails)]
pub struct NewEmail<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub address: &'a str,
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = emails)]
pub struct EmailUpdate {
    pub verified: Option<bool>,
    pub is_primary: Option<bool>,
    pub verified_at: Option<Option<OffsetDateTime>>,
}
