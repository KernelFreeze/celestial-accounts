use derive_more::Deref;
use diesel::{ConnectionError, ConnectionResult};
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::{BuildError as DeadPoolBuildError, Pool};
use diesel_async::pooled_connection::{AsyncDieselConnectionManager, ManagerConfig};
use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use thiserror::Error;

pub mod controllers;
pub mod models;
pub mod schema;

pub type DatabasePoolType = Pool<AsyncPgConnection>;

#[derive(Clone, Deref)]
pub struct Database(DatabasePoolType);

#[derive(Debug, Error)]
pub enum DatabaseConnectionError {
    #[error(transparent)]
    DeadPoolBuildError(#[from] DeadPoolBuildError),
}

impl Database {
    pub async fn new_with_url(url: impl AsRef<str>) -> Result<Self, DatabaseConnectionError> {
        let mut config = ManagerConfig::default();
        config.custom_setup = Box::new(establish_connection);

        let mgr = AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_config(url.as_ref(), config);

        let pool = Pool::builder(mgr).build()?;
        Ok(Database(pool))
    }
}

fn establish_connection(config: &str) -> BoxFuture<'_, ConnectionResult<AsyncPgConnection>> {
    let fut = async {
        let rustls_config =
            ClientConfig::with_platform_verifier().map_err(|err| ConnectionError::BadConnection(err.to_string()))?;
        let tls = tokio_postgres_rustls::MakeRustlsConnect::new(rustls_config);
        let (client, conn) = tokio_postgres::connect(config, tls)
            .await
            .map_err(|e| ConnectionError::BadConnection(e.to_string()))?;

        AsyncPgConnection::try_from_client_and_connection(client, conn).await
    };
    fut.boxed()
}
