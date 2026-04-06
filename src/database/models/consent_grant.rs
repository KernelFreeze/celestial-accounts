use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::consent_grants;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = consent_grants)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ConsentGrant {
    pub account_id: Uuid,
    pub client_id: Uuid,
    pub granted_scopes: Vec<Option<String>>,
    pub granted_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = consent_grants)]
pub struct NewConsentGrant<'a> {
    pub account_id: Uuid,
    pub client_id: Uuid,
    pub granted_scopes: &'a [Option<String>],
}
