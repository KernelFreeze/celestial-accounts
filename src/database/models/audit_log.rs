use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::database::schema::audit_log;

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = audit_log)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub event_type: String,
    pub account_id: Option<Uuid>,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub details: Option<serde_json::Value>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = audit_log)]
pub struct NewAuditLogEntry<'a> {
    pub id: Uuid,
    pub event_type: &'a str,
    pub account_id: Option<Uuid>,
    pub ip_address: &'a str,
    pub user_agent: Option<&'a str>,
    pub details: Option<&'a serde_json::Value>,
}
