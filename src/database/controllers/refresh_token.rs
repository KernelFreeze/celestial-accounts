use diesel::OptionalExtension;
use diesel::prelude::*;
use diesel::result::Error;
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use uuid::Uuid;

use crate::database::models::{NewRefreshToken, RefreshToken};
use crate::database::schema::refresh_tokens;

pub async fn create(conn: &mut AsyncPgConnection, new_token: &NewRefreshToken<'_>) -> Result<(), Error> {
    diesel::insert_into(refresh_tokens::table)
        .values(new_token)
        .execute(conn)
        .await?;
    Ok(())
}

pub async fn find_by_hash(conn: &mut AsyncPgConnection, hash: &[u8]) -> Result<Option<RefreshToken>, Error> {
    refresh_tokens::table
        .filter(refresh_tokens::token_hash.eq(hash))
        .select(RefreshToken::as_select())
        .first(conn)
        .await
        .optional()
}

pub async fn revoke_by_hash(conn: &mut AsyncPgConnection, hash: &[u8]) -> Result<usize, Error> {
    diesel::update(refresh_tokens::table.filter(refresh_tokens::token_hash.eq(hash)))
        .set(refresh_tokens::revoked.eq(true))
        .execute(conn)
        .await
}

pub async fn revoke_all_for_account(conn: &mut AsyncPgConnection, account_id: Uuid) -> Result<usize, Error> {
    diesel::update(refresh_tokens::table.filter(refresh_tokens::account_id.eq(account_id)))
        .set(refresh_tokens::revoked.eq(true))
        .execute(conn)
        .await
}

pub async fn revoke_all_for_client_account(
    conn: &mut AsyncPgConnection, client_id: Uuid, account_id: Uuid,
) -> Result<usize, Error> {
    diesel::update(
        refresh_tokens::table
            .filter(refresh_tokens::client_id.eq(client_id))
            .filter(refresh_tokens::account_id.eq(account_id)),
    )
    .set(refresh_tokens::revoked.eq(true))
    .execute(conn)
    .await
}
