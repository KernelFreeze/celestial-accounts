use diesel::prelude::*;
use time::OffsetDateTime;
use uuid::Uuid;

use super::pg_enum;
use crate::database::schema::{clients, sql_types};

pg_enum! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ClientType (sql_types::ClientType) {
        Confidential => "confidential",
        Public => "public",
    }
}

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = clients)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Client {
    pub client_id: Uuid,
    pub client_secret_hash: Option<Vec<u8>>,
    pub client_type: ClientType,
    pub is_first_party: bool,
    pub name: String,
    pub allowed_scopes: Vec<Option<String>>,
    pub redirect_uris: Vec<Option<String>>,
    pub consent_skip: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = clients)]
pub struct NewClient<'a> {
    pub client_id: Uuid,
    pub client_secret_hash: Option<&'a [u8]>,
    pub client_type: &'a ClientType,
    pub is_first_party: bool,
    pub name: &'a str,
    pub allowed_scopes: &'a [Option<String>],
    pub redirect_uris: &'a [Option<String>],
    pub consent_skip: bool,
}
