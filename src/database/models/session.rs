use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::sessions;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Session {
    pub id: Uuid,
    pub account_id: Uuid,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = sessions)]
pub struct NewSession<'a> {
    pub id: Uuid,
    pub account_id: Uuid,
    pub ip_address: &'a str,
    pub user_agent: &'a str,
    pub expires_at: OffsetDateTime,
}
