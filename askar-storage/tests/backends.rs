#![allow(clippy::bool_assert_comparison)]

mod utils;

const ERR_CLOSE: &str = "Error closing database";

macro_rules! backend_tests {
    ($init:expr) => {
        use askar_storage::future::block_on;
        use std::sync::Arc;
        use $crate::utils::TestStore;

        #[test]
        fn init() {
            block_on(async {
                let db = $init.await;
                db.close().await.expect(ERR_CLOSE);
            });
        }

        #[test]
        fn create_remove_profile() {
            block_on(async {
                let db = $init.await;
                super::utils::db_create_remove_profile(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn fetch_fail() {
            block_on(async {
                let db = $init.await;
                super::utils::db_fetch_fail(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn insert_fetch() {
            block_on(async {
                let db = $init.await;
                super::utils::db_insert_fetch(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn insert_duplicate() {
            block_on(async {
                let db = $init.await;
                super::utils::db_insert_duplicate(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn insert_remove() {
            block_on(async {
                let db = $init.await;
                super::utils::db_insert_remove(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn remove_missing() {
            block_on(async {
                let db = $init.await;
                super::utils::db_remove_missing(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn replace_fetch() {
            block_on(async {
                let db = $init.await;
                super::utils::db_replace_fetch(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn replace_missing() {
            block_on(async {
                let db = $init.await;
                super::utils::db_replace_missing(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn count() {
            block_on(async {
                let db = $init.await;
                super::utils::db_count(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn count_exist() {
            block_on(async {
                let db = $init.await;
                super::utils::db_count_exist(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn scan() {
            block_on(async {
                let db = $init.await;
                super::utils::db_scan(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn remove_all() {
            block_on(async {
                let db = $init.await;
                super::utils::db_remove_all(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn txn_rollback() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_rollback(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn txn_drop() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_drop(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn session_drop() {
            block_on(async {
                let db = $init.await;
                super::utils::db_session_drop(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn txn_commit() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_commit(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn txn_fetch_for_update() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_fetch_for_update(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }

        #[test]
        fn txn_contention() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_contention(db.clone()).await;
                db.close().await.expect(ERR_CLOSE);
            })
        }
    };
}

fn log_init() {
    // env_logger::builder().is_test(true).try_init().unwrap_or(());
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use askar_storage::backend::sqlite::{SqliteBackend, SqliteStoreOptions};
    use askar_storage::{generate_raw_store_key, Backend, ManageBackend, StoreKeyMethod};
    use std::path::Path;

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

            let db = std::sync::Arc::new(store);
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

    async fn init_db() -> Arc<SqliteBackend> {
        log_init();
        let key = generate_raw_store_key(None).expect("Error creating raw key");
        Arc::new(
            SqliteStoreOptions::in_memory()
                .provision(StoreKeyMethod::RawKey, key, None, false)
                .await
                .expect("Error provisioning sqlite store"),
        )
    }

    backend_tests!(init_db());

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
    use aries_askar::{backend::postgres::test_db::TestDB, postgres::PostgresStore, Store};
    use std::{future::Future, ops::Deref, pin::Pin};

    use super::*;

    #[derive(Clone, Debug)]
    struct Wrap(Arc<TestDB>);

    impl Deref for Wrap {
        type Target = Store<PostgresStore>;

        fn deref(&self) -> &Self::Target {
            &**self.0
        }
    }

    impl TestStore for Wrap {
        type DB = PostgresStore;

        fn close(self) -> Pin<Box<dyn Future<Output = Result<(), aries_askar::Error>>>> {
            let db = Arc::try_unwrap(self.0).unwrap();
            Box::pin(db.close())
        }
    }

    async fn init_db() -> Wrap {
        log_init();
        Wrap(Arc::new(
            TestDB::provision()
                .await
                .expect("Error provisioning postgres test database"),
        ))
    }

    backend_tests!(init_db());
}
