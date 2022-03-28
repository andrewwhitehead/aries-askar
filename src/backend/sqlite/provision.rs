use std::borrow::Cow;
use std::fs::remove_file;
use std::io::ErrorKind as IoErrorKind;
use std::str::FromStr;

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    ConnectOptions, Error as SqlxError, Row,
};

use super::SqliteStore;
use crate::{
    backend::{
        db_utils::{init_keys, random_profile_name},
        types::ManageBackend,
    },
    error::Error,
    future::{unblock, BoxFuture},
    protect::{KeyCache, PassKey, StoreKeyMethod, StoreKeyReference},
    storage::{IntoOptions, Options, Store},
};

/// Configuration options for Sqlite stores
#[derive(Debug)]
pub struct SqliteStoreOptions {
    pub(crate) in_memory: bool,
    pub(crate) path: String,
    pub(crate) max_connections: u32,
}

impl SqliteStoreOptions {
    /// Initialize `SqliteStoreOptions` from a generic set of options
    pub fn new<'a>(options: impl IntoOptions<'a>) -> Result<Self, Error> {
        let mut opts = options.into_options()?;
        let max_connections = if let Some(max_conn) = opts.query.remove("max_connections") {
            max_conn
                .parse()
                .map_err(err_map!(Input, "Error parsing 'max_connections' parameter"))?
        } else {
            num_cpus::get() as u32
        };
        let mut path = opts.host.to_string();
        path.push_str(&*opts.path);
        Ok(Self {
            in_memory: path == ":memory:",
            path,
            max_connections,
        })
    }

    async fn pool(&self, auto_create: bool) -> std::result::Result<SqlitePool, SqlxError> {
        #[allow(unused_mut)]
        let mut conn_opts = SqliteConnectOptions::from_str(self.path.as_ref())?
            .create_if_missing(auto_create)
            .shared_cache(true);
        #[cfg(feature = "log")]
        {
            conn_opts.log_statements(log::LevelFilter::Debug);
            conn_opts.log_slow_statements(log::LevelFilter::Debug, Default::default());
        }
        error!("connect options: {:?}", &conn_opts);
        SqlitePoolOptions::default()
            // maintains at least 1 connection.
            // for an in-memory database this is required to avoid dropping the database,
            // for a file database this signals other instances that the database is in use
            .min_connections(1)
            .max_connections(self.max_connections)
            .test_before_acquire(false)
            .connect_with(conn_opts)
            .await
    }

    /// Provision a new Sqlite store from these configuration options
    pub async fn provision(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        profile: Option<&'_ str>,
        recreate: bool,
    ) -> Result<Store<SqliteStore>, Error> {
        if recreate && !self.in_memory {
            try_remove_file(self.path.to_string()).await?;
        }
        let conn_pool = self.pool(true).await?;

        if !recreate {
            if sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config'",
            )
            .fetch_one(&conn_pool)
            .await?
                == 1
            {
                return open_db(
                    conn_pool,
                    Some(method),
                    pass_key,
                    profile,
                    self.path.to_string(),
                )
                .await;
            }
            // no 'config' table, assume empty database
        }

        let default_profile = profile
            .map(str::to_string)
            .unwrap_or_else(random_profile_name);
        let key_cache = init_db(&conn_pool, &default_profile, method, pass_key).await?;

        Ok(Store::new(SqliteStore::new(
            conn_pool,
            default_profile,
            key_cache,
            self.path.to_string(),
        )))
    }

    /// Open an existing Sqlite store from this set of configuration options
    pub async fn open(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<&'_ str>,
    ) -> Result<Store<SqliteStore>, Error> {
        let conn_pool = match self.pool(false).await {
            Ok(pool) => Ok(pool),
            Err(SqlxError::Database(db_err)) => {
                if db_err.code().expect("Expected SQLite error code") == "14" {
                    // SQLITE_CANTOPEN error
                    Err(err_msg!(
                        NotFound,
                        "The requested database path was not found"
                    ))
                } else {
                    Err(SqlxError::Database(db_err).into())
                }
            }
            Err(err) => Err(err.into()),
        }?;
        Ok(open_db(conn_pool, method, pass_key, profile, self.path.to_string()).await?)
    }

    /// Remove the Sqlite store defined by these configuration options
    pub async fn remove(self) -> Result<bool, Error> {
        if self.in_memory {
            Ok(true)
        } else {
            try_remove_file(self.path.to_string()).await
        }
    }

    /// Default options for an in-memory Sqlite store
    pub fn in_memory() -> Self {
        let mut opts = Options::default();
        opts.host = Cow::Borrowed(":memory:");
        Self::new(opts).unwrap()
    }

    /// Default options for a given Sqlite database path
    pub fn from_path(path: &str) -> Self {
        let mut opts = Options::default();
        opts.host = Cow::Borrowed(path);
        Self::new(opts).unwrap()
    }
}

impl<'a> ManageBackend<'a> for SqliteStoreOptions {
    type Store = Store<SqliteStore>;

    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Store<SqliteStore>, Error>> {
        Box::pin(self.open(method, pass_key, profile))
    }

    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Store<SqliteStore>, Error>> {
        Box::pin(self.provision(method, pass_key, profile, recreate))
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(self.remove())
    }
}

async fn init_db(
    conn_pool: &SqlitePool,
    profile_name: &str,
    method: StoreKeyMethod,
    pass_key: PassKey<'_>,
) -> Result<KeyCache, Error> {
    let (profile_key, enc_profile_key, store_key, store_key_ref) = unblock({
        let pass_key = pass_key.into_owned();
        move || init_keys(method, pass_key)
    })
    .await?;

    let mut conn = conn_pool.acquire().await?;

    sqlx::query(
        r#"
        BEGIN EXCLUSIVE TRANSACTION;

        CREATE TABLE config (
            name TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (name)
        );
        INSERT INTO config (name, value) VALUES
            ("default_profile", ?1),
            ("key", ?2),
            ("version", "1");

        CREATE TABLE profiles (
            id INTEGER NOT NULL,
            name TEXT NOT NULL,
            reference TEXT NULL,
            profile_key BLOB NULL,
            PRIMARY KEY(id)
        );
        CREATE UNIQUE INDEX ix_profile_name ON profiles (name);

        CREATE TABLE items (
            id INTEGER NOT NULL,
            profile_id INTEGER NOT NULL,
            kind INTEGER NOT NULL,
            category BLOB NOT NULL,
            name BLOB NOT NULL,
            value BLOB NOT NULL,
            expiry DATETIME NULL,
            PRIMARY KEY (id),
            FOREIGN KEY (profile_id) REFERENCES profiles (id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE UNIQUE INDEX ix_items_uniq ON items (profile_id, kind, category, name);

        CREATE TABLE items_tags (
            id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            name BLOB NOT NULL,
            value BLOB NOT NULL,
            plaintext BOOLEAN NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY (item_id) REFERENCES items (id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE INDEX ix_items_tags_item_id ON items_tags (item_id);
        CREATE INDEX ix_items_tags_name_enc ON items_tags (name, SUBSTR(value, 1, 12)) WHERE plaintext=0;
        CREATE INDEX ix_items_tags_name_plain ON items_tags (name, value) WHERE plaintext=1;

        INSERT INTO profiles (name, profile_key) VALUES (?1, ?3);

        COMMIT;
    "#,
    )
    .persistent(false)
    .bind(profile_name)
    .bind(store_key_ref)
    .bind(enc_profile_key)
    .execute(&mut conn)
    .await?;

    let mut key_cache = KeyCache::new(store_key);

    let row = sqlx::query("SELECT id FROM profiles WHERE name = ?1")
        .persistent(false)
        .bind(profile_name)
        .fetch_one(&mut conn)
        .await?;
    key_cache.add_profile_mut(profile_name.to_string(), row.try_get(0)?, profile_key);

    Ok(key_cache)
}

async fn open_db(
    conn_pool: SqlitePool,
    method: Option<StoreKeyMethod>,
    pass_key: PassKey<'_>,
    profile: Option<&str>,
    path: String,
) -> Result<Store<SqliteStore>, Error> {
    let mut conn = conn_pool.acquire().await?;
    let mut ver_ok = false;
    let mut default_profile: Option<String> = None;
    let mut store_key_ref: Option<String> = None;

    let config = sqlx::query(
        r#"SELECT name, value FROM config
        WHERE name IN ("default_profile", "key", "version")"#,
    )
    .fetch_all(&mut conn)
    .await?;
    for row in config {
        match row.try_get(0)? {
            "default_profile" => {
                default_profile.replace(row.try_get(1)?);
            }
            "key" => {
                store_key_ref.replace(row.try_get(1)?);
            }
            "version" => {
                if row.try_get::<&str, _>(1)? != "1" {
                    return Err(err_msg!(Unsupported, "Unsupported store version"));
                }
                ver_ok = true;
            }
            _ => (),
        }
    }
    if !ver_ok {
        return Err(err_msg!(Unsupported, "Store version not found"));
    }
    let profile = profile
        .map(str::to_string)
        .or(default_profile)
        .ok_or_else(|| err_msg!(Unsupported, "Default store profile not found"))?;
    let store_key = if let Some(store_key_ref) = store_key_ref {
        let wrap_ref = StoreKeyReference::parse_uri(&store_key_ref)?;
        if let Some(method) = method {
            if !wrap_ref.compare_method(&method) {
                return Err(err_msg!(Input, "Store key method mismatch"));
            }
        }
        unblock({
            let pass_key = pass_key.into_owned();
            move || wrap_ref.resolve(pass_key)
        })
        .await?
    } else {
        return Err(err_msg!(Unsupported, "Store key not found"));
    };
    let mut key_cache = KeyCache::new(store_key);

    let row = sqlx::query("SELECT id, profile_key FROM profiles WHERE name = ?1")
        .bind(&profile)
        .fetch_one(&mut conn)
        .await?;
    let profile_id = row.try_get(0)?;
    let profile_key = key_cache.load_key(row.try_get(1)?).await?;
    key_cache.add_profile_mut(profile.clone(), profile_id, profile_key);

    Ok(Store::new(SqliteStore::new(
        conn_pool, profile, key_cache, path,
    )))
}

async fn try_remove_file(path: String) -> Result<bool, Error> {
    unblock(|| match remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == IoErrorKind::NotFound => Ok(false),
        Err(err) => Err(err_msg!(Backend, "Error removing file").with_cause(err)),
    })
    .await
}
