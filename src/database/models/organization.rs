use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::organizations;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = organizations)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Organization {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub mfa_required: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = organizations)]
pub struct NewOrganization<'a> {
    pub id: Uuid,
    pub slug: &'a str,
    pub name: &'a str,
}
