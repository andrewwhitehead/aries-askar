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
        fn list_profiles() {
            $run(super::utils::db_list_profiles)
        }

        #[test]
        fn get_set_default_profile() {
            $run(super::utils::db_get_set_default_profile)
        }

        #[test]
        fn fetch_fail() {
            $run(super::utils::db_fetch_fail)
        }

        #[test]
        fn insert_expired() {
            $run(super::utils::db_insert_expired)
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

        #[test]
        fn db_import() {
            $run(super::utils::db_import_scan)
        }
    };
}

fn log_init() {
    env_logger::builder().is_test(true).try_init().unwrap_or(());
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use askar_storage::any::{into_any_backend, AnyBackend};
    use askar_storage::backend::copy_store;
    use askar_storage::backend::sqlite::SqliteStoreOptions;
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
    fn copy_db() {
        log_init();
        let fname_source = format!("sqlite-copy-{}.db", uuid::Uuid::new_v4());
        let url_target = format!("sqlite://sqlite-copy-{}.db", uuid::Uuid::new_v4());
        let key_source = generate_raw_store_key(None).expect("Error creating raw key");
        let key_target = generate_raw_store_key(None).expect("Error creating raw key");

        block_on(async move {
            let source = SqliteStoreOptions::new(fname_source.as_str())
                .expect("Error initializing sqlite store options")
                .provision_backend(StoreKeyMethod::RawKey, key_source.as_ref(), None, false)
                .await
                .expect("Error provisioning sqlite store");
            let profile = source
                .get_default_profile()
                .await
                .expect("Error fetching default profile");

            let target = copy_store(
                &source,
                url_target.as_str(),
                StoreKeyMethod::RawKey,
                key_target.as_ref(),
                false,
            )
            .await
            .expect("Error copying store");
            target.close().await.expect("Error closing copied store");

            source.close().await.expect("Error closing store");
            SqliteStoreOptions::new(fname_source.as_str())
                .expect("Error initializing sqlite store options")
                .remove_backend()
                .await
                .expect("Error removing sqlite store");

            let copied = SqliteStoreOptions::new(url_target.as_str())
                .expect("Error initializing sqlite store options")
                .open_backend(Some(StoreKeyMethod::RawKey), key_target.as_ref(), None)
                .await
                .expect("Error opening copied store");
            assert_eq!(copied.get_active_profile(), profile);
            copied.close().await.expect("Error closing store");

            SqliteStoreOptions::new(url_target.as_str())
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

            let db = into_any_backend(store);
            super::utils::db_txn_contention(db.clone()).await;
            db.close().await.expect("Error closing sqlite store");

            SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .remove_backend()
                .await
                .expect("Error removing sqlite store");
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
            let db = into_any_backend(
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
    use askar_storage::any::AnyBackend;
    use askar_storage::backend::postgres::TestDB;
    use askar_storage::future::block_on;
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

    #[test]
    // The id sequences can be behind the highest id after rows have been copied or
    // restored. This must not be reported as a duplicate entry.
    fn insert_id_sequence_behind() {
        use askar_storage::{
            entry::{EntryKind, EntryOperation},
            Backend, BackendSession, Error, ErrorKind,
        };
        use sqlx::Connection;

        let db_url = std::env::var("POSTGRES_URL").expect("'POSTGRES_URL' must be defined");
        with_postgres(|db| async move {
            async fn insert(db: &AnyBackend, name: &str) -> Result<(), Error> {
                let mut conn = db.session(None, false).expect("Error starting session");
                conn.update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "category",
                    name,
                    Some(b"value"),
                    Some(&[]),
                    None,
                )
                .await
            }

            for name in ["a", "b", "c"] {
                insert(&db, name).await.expect("Error inserting test row");
            }

            // make the next sequence value unavailable
            let mut pg = sqlx::PgConnection::connect(&db_url)
                .await
                .expect("Error connecting to postgres");
            sqlx::query("SELECT setval('items_id_seq', (SELECT MIN(id) FROM items))")
                .execute(&mut pg)
                .await
                .expect("Error updating sequence");

            // an entry with a new name is not a duplicate, and the error explains the problem
            let err = insert(&db, "d").await.expect_err("Expected insert error");
            assert_eq!(err.kind(), ErrorKind::Backend);
            let msg = err.to_string();
            assert!(msg.contains("items_id_seq"), "Unexpected error: {msg}");

            // an actual duplicate is still reported as such
            let err = insert(&db, "a").await.expect_err("Expected insert error");
            assert_eq!(err.kind(), ErrorKind::Duplicate);

            // after updating the sequence, entries can be inserted
            sqlx::query("SELECT setval('items_id_seq', (SELECT MAX(id) FROM items))")
                .execute(&mut pg)
                .await
                .expect("Error updating sequence");
            insert(&db, "d").await.expect("Error inserting test row");
            let err = insert(&db, "d").await.expect_err("Expected insert error");
            assert_eq!(err.kind(), ErrorKind::Duplicate);
        });
    }

    #[test]
    // A failed update must not leave a transaction open on the connection while the
    // session is idle, as the transaction would hold locks and a snapshot, and could
    // be terminated by the server.
    fn failed_insert_ends_transaction() {
        use askar_storage::{
            entry::{EntryKind, EntryOperation},
            Backend, BackendSession, ErrorKind,
        };
        use sqlx::Connection;

        let db_url = std::env::var("POSTGRES_URL").expect("'POSTGRES_URL' must be defined");
        with_postgres(|db| async move {
            let mut pg = sqlx::PgConnection::connect(&db_url)
                .await
                .expect("Error connecting to postgres");
            // the test database holds a transaction with an advisory lock while it is open
            async fn open_transactions(pg: &mut sqlx::PgConnection) -> i64 {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database()
                    AND pid <> pg_backend_pid() AND state = 'idle in transaction'
                    AND query NOT LIKE '%pg_try_advisory_xact_lock%'",
                )
                .fetch_one(pg)
                .await
                .expect("Error querying activity")
            }

            // the session is kept open while the connection is checked
            let mut sess = db.session(None, false).expect("Error starting session");
            sess.update(
                EntryKind::Item,
                EntryOperation::Insert,
                "category",
                "name",
                Some(b"value"),
                None,
                None,
            )
            .await
            .expect("Error inserting test row");
            assert_eq!(open_transactions(&mut pg).await, 0);

            let err = sess
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "category",
                    "name",
                    Some(b"value"),
                    None,
                    None,
                )
                .await
                .expect_err("Expected duplicate error");
            assert_eq!(err.kind(), ErrorKind::Duplicate);
            assert_eq!(open_transactions(&mut pg).await, 0);

            let err = sess
                .update(
                    EntryKind::Item,
                    EntryOperation::Replace,
                    "category",
                    "missing",
                    Some(b"value"),
                    None,
                    None,
                )
                .await
                .expect_err("Expected not found error");
            assert_eq!(err.kind(), ErrorKind::NotFound);
            assert_eq!(open_transactions(&mut pg).await, 0);
        });
    }

    #[test]
    // Inserting a duplicate entry must not lock the existing entry, which would block
    // other sessions from updating it until the transaction completes.
    fn insert_duplicate_does_not_lock_entry() {
        use askar_storage::{
            entry::{EntryKind, EntryOperation},
            Backend, BackendSession, ErrorKind,
        };
        use sqlx::Connection;

        let db_url = std::env::var("POSTGRES_URL").expect("'POSTGRES_URL' must be defined");
        with_postgres(|db| async move {
            let mut sess = db.session(None, false).expect("Error starting session");
            sess.update(
                EntryKind::Item,
                EntryOperation::Insert,
                "category",
                "name",
                Some(b"value"),
                None,
                None,
            )
            .await
            .expect("Error inserting test row");
            drop(sess);

            // attempt a duplicate insert in a transaction, which remains open
            let mut txn = db.session(None, true).expect("Error starting transaction");
            let err = txn
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "category",
                    "name",
                    Some(b"value"),
                    None,
                    None,
                )
                .await
                .expect_err("Expected duplicate error");
            assert_eq!(err.kind(), ErrorKind::Duplicate);

            let mut pg = sqlx::PgConnection::connect(&db_url)
                .await
                .expect("Error connecting to postgres");
            sqlx::query("SELECT id FROM items FOR UPDATE NOWAIT")
                .fetch_all(&mut pg)
                .await
                .expect("Entry was locked by the duplicate insert");
            txn.close(false).await.expect("Error rolling back");
        });
    }
}
