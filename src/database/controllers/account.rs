use diesel::prelude::*;
use diesel::result::Error;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::database::models::Account;
use crate::database::schema::accounts;

pub async fn find_by_username(conn: &mut AsyncPgConnection, username: &str) -> Result<Account, Error> {
    accounts::table
        .filter(accounts::username.eq(username.to_lowercase()))
        .select(Account::as_select())
        .first(conn)
        .await
}
