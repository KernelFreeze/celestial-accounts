use diesel::prelude::*;
use diesel::result::Error;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use crate::database::models::{Credential, CredentialKind};
use crate::database::schema::credentials;

pub async fn find_by_account_and_kind(
    conn: &mut AsyncPgConnection, account_id: Uuid, kind: CredentialKind,
) -> Result<Credential, Error> {
    credentials::table
        .filter(credentials::account_id.eq(account_id))
        .filter(credentials::kind.eq(kind))
        .select(Credential::as_select())
        .first(conn)
        .await
}
