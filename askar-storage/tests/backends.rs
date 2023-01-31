#![allow(clippy::bool_assert_comparison)]

mod utils;

const ERR_CLOSE: &str = "Error closing database";

macro_rules! backend_tests {
    ($run:expr) => {
        #[test]
        fn init() {
            $run(|db| async move {
                let _ = db;
            })
        }

        #[test]
        fn create_remove_profile() {
            $run(super::utils::db_create_remove_profile)
        }

        #[test]
        fn fetch_fail() {
            $run(super::utils::db_fetch_fail)
        }

        #[test]
        fn insert_fetch() {
            $run(super::utils::db_insert_fetch)
        }

        #[test]
        fn insert_duplicate() {
            $run(super::utils::db_insert_duplicate)
        }

        #[test]
        fn insert_remove() {
            $run(super::utils::db_insert_remove)
        }

        #[test]
        fn remove_missing() {
            $run(super::utils::db_remove_missing)
        }

        #[test]
        fn replace_fetch() {
            $run(super::utils::db_replace_fetch)
        }

        #[test]
        fn replace_missing() {
            $run(super::utils::db_replace_missing)
        }

        #[test]
        fn count() {
            $run(super::utils::db_count)
        }

        #[test]
        fn count_exist() {
            $run(super::utils::db_count_exist)
        }

        #[test]
        fn scan() {
            $run(super::utils::db_scan)
        }

        #[test]
        fn remove_all() {
            $run(super::utils::db_remove_all)
        }

        #[test]
        fn txn_rollback() {
            $run(super::utils::db_txn_rollback)
        }

        #[test]
        fn txn_drop() {
            $run(super::utils::db_txn_drop)
        }

        #[test]
        fn session_drop() {
            $run(super::utils::db_session_drop)
        }

        #[test]
        fn txn_commit() {
            $run(super::utils::db_txn_commit)
        }

        #[test]
        fn txn_fetch_for_update() {
            $run(super::utils::db_txn_fetch_for_update)
        }

        #[test]
        fn txn_contention() {
            $run(super::utils::db_txn_contention)
        }
    };
}

fn log_init() {
    // env_logger::builder().is_test(true).try_init().unwrap_or(());
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use askar_storage::backend::{
        any::{wrap_backend, AnyBackend},
        sqlite::SqliteStoreOptions,
    };
    use askar_storage::future::block_on;
    use askar_storage::{generate_raw_store_key, Backend, ManageBackend, StoreKeyMethod};
    use std::{future::Future, path::Path};

    use super::*;

    #[test]
    fn create_remove_db() {
        log_init();
        let fname = format!("sqlite-test-{}.db", uuid::Uuid::new_v4());
        assert_eq!(
            Path::new(&fname).exists(),
            false,
            "Oops, should be a unique filename"
        );

        let key = generate_raw_store_key(None).expect("Error creating raw key");
        block_on(async move {
            assert_eq!(
                SqliteStoreOptions::new(fname.as_str())
                    .expect("Error initializing sqlite store options")
                    .remove_backend()
                    .await
                    .expect("Error removing sqlite store"),
                false
            );

            let store = SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .provision_backend(StoreKeyMethod::RawKey, key.as_ref(), None, false)
                .await
                .expect("Error provisioning sqlite store");
            assert_eq!(Path::new(&fname).exists(), true);

            let store2 = SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .open_backend(Some(StoreKeyMethod::RawKey), key.as_ref(), None)
                .await
                .expect("Error opening sqlite store");
            store2.close().await.expect("Error closing sqlite store");

            store.close().await.expect("Error closing sqlite store");
            assert_eq!(Path::new(&fname).exists(), true);

            assert_eq!(
                SqliteStoreOptions::new(fname.as_str())
                    .expect("Error initializing sqlite store options")
                    .remove_backend()
                    .await
                    .expect("Error removing sqlite store"),
                true
            );
            assert_eq!(Path::new(&fname).exists(), false);
        })
    }

    #[test]
    fn rekey_db() {
        log_init();
        let fname = format!("sqlite-rekey-{}.db", uuid::Uuid::new_v4());
        let key1 = generate_raw_store_key(None).expect("Error creating raw key");
        let key2 = generate_raw_store_key(None).expect("Error creating raw key");
        assert_ne!(key1, key2);

        block_on(async move {
            let mut store = SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .provision_backend(StoreKeyMethod::RawKey, key1.as_ref(), None, false)
                .await
                .expect("Error provisioning sqlite store");

            store
                .rekey(StoreKeyMethod::RawKey, key2.as_ref())
                .await
                .expect("Error rekeying database");

            SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .open_backend(Some(StoreKeyMethod::RawKey), key2.as_ref(), None)
                .await
                .expect("Error opening rekeyed store")
                .close()
                .await
                .expect("Error closing store");

            store.close().await.expect("Error closing store");

            SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .remove_backend()
                .await
                .expect("Error removing sqlite store");
        })
    }

    #[test]
    fn txn_contention_file() {
        log_init();
        let fname = format!("sqlite-contention-{}.db", uuid::Uuid::new_v4());
        let key = generate_raw_store_key(None).expect("Error creating raw key");

        block_on(async move {
            let store = SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .provision_backend(StoreKeyMethod::RawKey, key.as_ref(), None, true)
                .await
                .expect("Error provisioning sqlite store");

            let db = wrap_backend(store);
            super::utils::db_txn_contention(db.clone()).await;
            db.close().await.expect("Error closing sqlite store");

            SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .remove_backend()
                .await
                .expect("Error removing sqlite store");
        });
    }

    #[cfg(feature = "stress_test")]
    #[test]
    fn stress_test() {
        log_init();
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
        use std::str::FromStr;
        let conn_opts = SqliteConnectOptions::from_str("sqlite:test.db")
            .unwrap()
            .create_if_missing(true);
        // .shared_cache(true);
        block_on(async move {
            let pool = SqlitePoolOptions::default()
                // maintains at least 1 connection.
                // for an in-memory database this is required to avoid dropping the database,
                // for a file database this signals other instances that the database is in use
                .min_connections(1)
                .max_connections(5)
                .test_before_acquire(false)
                .connect_with(conn_opts)
                .await
                .unwrap();

            let mut conn = pool.begin().await.unwrap();
            sqlx::query("CREATE TABLE test (name TEXT)")
                .execute(&mut conn)
                .await
                .unwrap();
            sqlx::query("INSERT INTO test (name) VALUES ('test')")
                .execute(&mut conn)
                .await
                .unwrap();
            conn.commit().await.unwrap();

            const TASKS: usize = 25;
            const COUNT: usize = 1000;

            async fn fetch(pool: SqlitePool) -> Result<(), &'static str> {
                // try to avoid panics in this section, as they will be raised on a tokio worker thread
                for _ in 0..COUNT {
                    let mut txn = pool.acquire().await.expect("Acquire error");
                    sqlx::query("BEGIN IMMEDIATE")
                        .execute(&mut txn)
                        .await
                        .expect("Transaction error");
                    let _ = sqlx::query("SELECT * FROM test")
                        .fetch_one(&mut txn)
                        .await
                        .expect("Error fetching row");
                    sqlx::query("COMMIT")
                        .execute(&mut txn)
                        .await
                        .expect("Commit error");
                }
                Ok(())
            }

            let mut tasks = vec![];
            for _ in 0..TASKS {
                tasks.push(tokio::spawn(fetch(pool.clone())));
            }

            for task in tasks {
                if let Err(s) = task.await.unwrap() {
                    panic!("Error in concurrent update task: {}", s);
                }
            }
        });
    }

    fn with_sqlite_in_memory<F, G>(f: F)
    where
        F: FnOnce(AnyBackend) -> G,
        G: Future<Output = ()>,
    {
        log_init();
        let key = generate_raw_store_key(None).expect("Error generating store key");
        block_on(async move {
            let db = wrap_backend(
                SqliteStoreOptions::in_memory()
                    .provision(StoreKeyMethod::RawKey, key, None, false)
                    .await
                    .expect("Error provisioning sqlite store"),
            );
            f(db.clone()).await;
            db.close().await.expect(ERR_CLOSE);
        })
    }

    backend_tests!(with_sqlite_in_memory);

    #[test]
    fn provision_from_str() {
        let key = generate_raw_store_key(None).expect("Error creating raw key");

        block_on(async {
            let db_url = "sqlite://:memory:";
            let _db = db_url
                .provision_backend(StoreKeyMethod::RawKey, key.as_ref(), None, false)
                .await
                .expect("Error provisioning store");
        });

        block_on(async {
            let db_url = "not-sqlite://test-db";
            let _db = db_url
                .provision_backend(StoreKeyMethod::RawKey, key.as_ref(), None, false)
                .await
                .expect_err("Expected provision failure");
        });
    }
}

#[cfg(feature = "pg_test")]
mod postgres {
    use askar_storage::{
        backend::{any::AnyBackend, postgres::test_db::TestDB},
        future::block_on,
    };
    use std::future::Future;

    use super::*;

    fn with_postgres<F, G>(f: F)
    where
        F: FnOnce(AnyBackend) -> G,
        G: Future<Output = ()>,
    {
        let db_url = match std::env::var("POSTGRES_URL") {
            Ok(p) if !p.is_empty() => p,
            _ => panic!("'POSTGRES_URL' must be defined"),
        };
        log_init();
        block_on(async move {
            let db = TestDB::provision(db_url.as_str())
                .await
                .expect("Error provisioning postgres test database");
            f(db.backend()).await;
            db.close().await.expect(ERR_CLOSE);
        })
    }

    backend_tests!(with_postgres);
}
