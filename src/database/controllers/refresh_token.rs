use diesel::result::Error;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::database::models::NewRefreshToken;
use crate::database::schema::refresh_tokens;

pub async fn create(conn: &mut AsyncPgConnection, new_token: &NewRefreshToken<'_>) -> Result<(), Error> {
    diesel::insert_into(refresh_tokens::table)
        .values(new_token)
        .execute(conn)
        .await?;
    Ok(())
}
