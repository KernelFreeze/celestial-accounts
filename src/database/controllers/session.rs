use diesel::result::Error;
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::database::models::NewSession;
use crate::database::schema::sessions;

pub async fn create(conn: &mut AsyncPgConnection, new_session: &NewSession<'_>) -> Result<(), Error> {
    diesel::insert_into(sessions::table)
        .values(new_session)
        .execute(conn)
        .await?;
    Ok(())
}
