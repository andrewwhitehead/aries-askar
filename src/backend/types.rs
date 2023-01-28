use crate::{
    error::Error,
    future::BoxFuture,
    protect::{PassKey, StoreKeyMethod},
    storage::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
};

/// Represents a generic backend implementation
pub trait Backend: Send + Sync {
    /// The type of session managed by this backend
    type Session: QueryBackend;

    /// Create a new profile
    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>>;

    /// Get the name of the active profile
    fn get_profile_name(&self) -> &str;

    /// Remove an existing profile
    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>>;

    /// Create a [`Scan`] against the store
    fn scan(
        &self,
        profile: Option<String>,
        kind: Option<EntryKind>,
        category: Option<String>,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>>;

    /// Create a new session against the store
    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error>;

    /// Replace the wrapping key of the store
    fn rekey_backend(
        &mut self,
        method: StoreKeyMethod,
        key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>>;

    /// Close the store instance
    fn close(&self) -> BoxFuture<'_, Result<(), Error>>;
}

/// Create, open, or remove a generic backend implementation
pub trait ManageBackend<'a> {
    /// The type of store being managed
    type Store;

    /// Open an existing store
    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Self::Store, Error>>;

    /// Provision a new store
    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Store, Error>>;

    /// Remove an existing store
    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>>;
}

/// Query from a generic backend implementation
pub trait QueryBackend: Send {
    /// Count the number of matching records in the store
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>>;

    /// Fetch a single record from the store by category and name
    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>, Error>>;

    /// Fetch all matching records from the store
    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>>;

    /// Remove all matching records from the store
    fn remove_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>>;

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
    ) -> BoxFuture<'q, Result<(), Error>>;

    /// Close the current store session
    fn close(self, commit: bool) -> BoxFuture<'static, Result<(), Error>>;
}
