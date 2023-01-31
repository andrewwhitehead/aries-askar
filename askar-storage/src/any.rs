//! Generic backend support

use std::{fmt::Debug, sync::Arc};

use super::{Backend, BackendSession, ManageBackend};
use crate::{
    entry::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::BoxFuture,
    options::IntoOptions,
    protect::{PassKey, StoreKeyMethod},
};

#[cfg(feature = "postgres")]
use super::postgres;

#[cfg(feature = "sqlite")]
use super::sqlite;

/// A dynamic store backend instance
pub type AnyBackend = Arc<dyn Backend<Session = AnyBackendSession>>;

/// Wrap a backend instance into an AnyBackend
pub fn into_any_backend(inst: impl Backend + 'static) -> AnyBackend {
    Arc::new(WrapBackend(inst))
}

#[derive(Debug)]
struct WrapBackend<B: Backend>(B);

impl<B: Backend> Backend for WrapBackend<B> {
    type Session = AnyBackendSession;

    #[inline]
    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        self.0.create_profile(name)
    }

    #[inline]
    fn get_profile_name(&self) -> &str {
        self.0.get_profile_name()
    }

    #[inline]
    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        self.0.remove_profile(name)
    }

    #[inline]
    fn scan(
        &self,
        profile: Option<String>,
        kind: Option<EntryKind>,
        category: Option<String>,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        self.0
            .scan(profile, kind, category, tag_filter, offset, limit)
    }

    #[inline]
    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        Ok(AnyBackendSession(Box::new(
            self.0.session(profile, transaction)?,
        )))
    }

    #[inline]
    fn rekey(
        &mut self,
        method: StoreKeyMethod,
        key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.0.rekey(method, key)
    }

    #[inline]
    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        self.0.close()
    }
}

/// A dynamic store session instance
#[derive(Debug)]
pub struct AnyBackendSession(Box<dyn BackendSession>);

impl BackendSession for AnyBackendSession {
    /// Count the number of matching records in the store
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        self.0.count(kind, category, tag_filter)
    }

    /// Fetch a single record from the store by category and name
    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>, Error>> {
        self.0.fetch(kind, category, name, for_update)
    }

    /// Fetch all matching records from the store
    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        self.0
            .fetch_all(kind, category, tag_filter, limit, for_update)
    }

    /// Remove all matching records from the store
    fn remove_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        self.0.remove_all(kind, category, tag_filter)
    }

    /// Insert or replace a record in the store
    #[allow(clippy::too_many_arguments)]
    fn update<'q>(
        &'q mut self,
        kind: EntryKind,
        operation: EntryOperation,
        category: &'q str,
        name: &'q str,
        value: Option<&'q [u8]>,
        tags: Option<&'q [EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> BoxFuture<'q, Result<(), Error>> {
        self.0
            .update(kind, operation, category, name, value, tags, expiry_ms)
    }

    /// Close the current store session
    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        self.0.close(commit)
    }
}

impl<'a> ManageBackend<'a> for &'a str {
    type Backend = AnyBackend;

    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Open store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = postgres::PostgresStoreOptions::new(opts)?;
                    let mgr = opts.open(method, pass_key, profile).await?;
                    Ok(into_any_backend(mgr))
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.open(method, pass_key, profile).await?;
                    Ok(into_any_backend(mgr))
                }

                _ => Err(err_msg!(
                    Unsupported,
                    "Unsupported backend: {}",
                    &opts.schema
                )),
            }
        })
    }

    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Provision store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = postgres::PostgresStoreOptions::new(opts)?;
                    let mgr = opts.provision(method, pass_key, profile, recreate).await?;
                    Ok(into_any_backend(mgr))
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.provision(method, pass_key, profile, recreate).await?;
                    Ok(into_any_backend(mgr))
                }

                _ => Err(err_msg!(
                    Unsupported,
                    "Unsupported backend: {}",
                    &opts.schema
                )),
            }
        })
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Remove store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = postgres::PostgresStoreOptions::new(opts)?;
                    Ok(opts.remove().await?)
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = sqlite::SqliteStoreOptions::new(opts)?;
                    Ok(opts.remove().await?)
                }

                _ => Err(err_msg!(
                    Unsupported,
                    "Unsupported backend: {}",
                    &opts.schema
                )),
            }
        })
    }
}
