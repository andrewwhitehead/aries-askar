use std::sync::Arc;

use super::entry::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter};
use crate::{
    backend::{Backend, QueryBackend},
    error::Error,
    kms::{KeyEntry, KeyParams, KmsCategory, LocalKey},
    protect::{PassKey, StoreKeyMethod},
};

#[derive(Debug)]
/// An instance of an opened store
pub struct Store<B: Backend>(B);

impl<B: Backend> Store<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self(inner)
    }

    #[cfg(test)]
    #[allow(unused)]
    pub(crate) fn inner(&self) -> &B {
        &self.0
    }

    pub(crate) fn into_inner(self) -> B {
        self.0
    }
}

impl<B: Backend> Store<B> {
    /// Get the default profile name used when starting a scan or a session
    pub fn get_profile_name(&self) -> &str {
        self.0.get_profile_name()
    }

    /// Replace the wrapping key on a store
    pub async fn rekey(
        &mut self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
    ) -> Result<(), Error> {
        self.0.rekey_backend(method, pass_key).await
    }

    /// Create a new profile with the given profile name
    pub async fn create_profile(&self, name: Option<String>) -> Result<String, Error> {
        self.0.create_profile(name).await
    }

    /// Remove an existing profile with the given profile name
    pub async fn remove_profile(&self, name: String) -> Result<bool, Error> {
        self.0.remove_profile(name).await
    }

    /// Create a new scan instance against the store
    ///
    /// The result will keep an open connection to the backend until it is consumed
    pub async fn scan(
        &self,
        profile: Option<String>,
        category: String,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Scan<'static, Entry>, Error> {
        self.0
            .scan(
                profile,
                EntryKind::Item,
                category,
                tag_filter,
                offset,
                limit,
            )
            .await
    }

    /// Create a new session against the store
    pub async fn session(&self, profile: Option<String>) -> Result<Session<B::Session>, Error> {
        // FIXME - add 'immediate' flag
        Ok(Session::new(self.0.session(profile, false)?))
    }

    /// Create a new transaction session against the store
    pub async fn transaction(&self, profile: Option<String>) -> Result<Session<B::Session>, Error> {
        Ok(Session::new(self.0.session(profile, true)?))
    }

    /// Close the store instance, waiting for any shutdown procedures to complete.
    pub async fn close(self) -> Result<(), Error> {
        self.0.close().await
    }

    pub(crate) async fn arc_close(self: Arc<Self>) -> Result<(), Error> {
        self.0.close().await
    }
}

/// An active connection to the store backend
#[derive(Debug)]
pub struct Session<Q: QueryBackend>(Q);

impl<Q: QueryBackend> Session<Q> {
    pub(crate) fn new(inner: Q) -> Self {
        Self(inner)
    }
}

impl<Q: QueryBackend> Session<Q> {
    /// Count the number of entries for a given record category
    pub async fn count(
        &mut self,
        category: &str,
        tag_filter: Option<TagFilter>,
    ) -> Result<i64, Error> {
        self.0.count(EntryKind::Item, category, tag_filter).await
    }

    /// Retrieve the current record at `(category, name)`.
    ///
    /// Specify `for_update` when in a transaction to create an update lock on the
    /// associated record, if supported by the store backend
    pub async fn fetch(
        &mut self,
        category: &str,
        name: &str,
        for_update: bool,
    ) -> Result<Option<Entry>, Error> {
        self.0
            .fetch(EntryKind::Item, category, name, for_update)
            .await
    }

    /// Retrieve all records matching the given `category` and `tag_filter`.
    ///
    /// Unlike `Store::scan`, this method may be used within a transaction. It should
    /// not be used for very large result sets due to correspondingly large memory
    /// requirements
    pub async fn fetch_all(
        &mut self,
        category: &str,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> Result<Vec<Entry>, Error> {
        self.0
            .fetch_all(EntryKind::Item, category, tag_filter, limit, for_update)
            .await
    }

    /// Insert a new record into the store
    pub async fn insert(
        &mut self,
        category: &str,
        name: &str,
        value: &[u8],
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<(), Error> {
        self.0
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                category,
                name,
                Some(value),
                tags,
                expiry_ms,
            )
            .await
    }

    /// Remove a record from the store
    pub async fn remove(&mut self, category: &str, name: &str) -> Result<(), Error> {
        self.0
            .update(
                EntryKind::Item,
                EntryOperation::Remove,
                category,
                name,
                None,
                None,
                None,
            )
            .await
    }

    /// Replace the value and tags of a record in the store
    pub async fn replace(
        &mut self,
        category: &str,
        name: &str,
        value: &[u8],
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<(), Error> {
        self.0
            .update(
                EntryKind::Item,
                EntryOperation::Replace,
                category,
                name,
                Some(value),
                tags,
                expiry_ms,
            )
            .await
    }

    /// Remove all records in the store matching a given `category` and `tag_filter`
    pub async fn remove_all(
        &mut self,
        category: &str,
        tag_filter: Option<TagFilter>,
    ) -> Result<i64, Error> {
        self.0
            .remove_all(EntryKind::Item, category, tag_filter)
            .await
    }

    /// Perform a record update
    ///
    /// This may correspond to an record insert, replace, or remove depending on
    /// the provided `operation`
    pub async fn update(
        &mut self,
        operation: EntryOperation,
        category: &str,
        name: &str,
        value: Option<&[u8]>,
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<(), Error> {
        self.0
            .update(
                EntryKind::Item,
                operation,
                category,
                name,
                value,
                tags,
                expiry_ms,
            )
            .await
    }

    /// Insert a local key instance into the store
    pub async fn insert_key(
        &mut self,
        name: &str,
        key: &LocalKey,
        metadata: Option<&str>,
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<(), Error> {
        let data = key.encode()?;
        let params = KeyParams {
            metadata: metadata.map(str::to_string),
            reference: None,
            data: Some(data),
        };
        let value = params.to_bytes()?;
        let mut ins_tags = Vec::with_capacity(10);
        let alg = key.algorithm().as_str();
        if !alg.is_empty() {
            ins_tags.push(EntryTag::Encrypted("alg".to_string(), alg.to_string()));
        }
        let thumbs = key.to_jwk_thumbprints()?;
        for thumb in thumbs {
            ins_tags.push(EntryTag::Encrypted("thumb".to_string(), thumb));
        }
        if let Some(tags) = tags {
            for t in tags {
                ins_tags.push(t.map_ref(|k, v| (format!("user:{}", k), v.to_string())));
            }
        }
        self.0
            .update(
                EntryKind::Kms,
                EntryOperation::Insert,
                KmsCategory::CryptoKey.as_str(),
                name,
                Some(value.as_ref()),
                Some(ins_tags.as_slice()),
                expiry_ms,
            )
            .await?;
        Ok(())
    }

    /// Fetch an existing key from the store
    ///
    /// Specify `for_update` when in a transaction to create an update lock on the
    /// associated record, if supported by the store backend
    pub async fn fetch_key(
        &mut self,
        name: &str,
        for_update: bool,
    ) -> Result<Option<KeyEntry>, Error> {
        Ok(
            if let Some(row) = self
                .0
                .fetch(
                    EntryKind::Kms,
                    KmsCategory::CryptoKey.as_str(),
                    name,
                    for_update,
                )
                .await?
            {
                Some(KeyEntry::from_entry(row)?)
            } else {
                None
            },
        )
    }

    /// Retrieve all keys matching the given filters.
    pub async fn fetch_all_keys(
        &mut self,
        algorithm: Option<&str>,
        thumbprint: Option<&str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> Result<Vec<KeyEntry>, Error> {
        let mut query_parts = Vec::with_capacity(3);
        if let Some(query) = tag_filter.map(|f| f.query) {
            query_parts.push(TagFilter::from(
                query
                    .map_names(|mut k| {
                        k.replace_range(0..0, "user:");
                        Result::<_, ()>::Ok(k)
                    })
                    .unwrap(),
            ));
        }
        if let Some(algorithm) = algorithm {
            query_parts.push(TagFilter::is_eq("alg", algorithm));
        }
        if let Some(thumbprint) = thumbprint {
            query_parts.push(TagFilter::is_eq("thumb", thumbprint));
        }
        let tag_filter = if query_parts.is_empty() {
            None
        } else {
            Some(TagFilter::all_of(query_parts))
        };
        let rows = self
            .0
            .fetch_all(
                EntryKind::Kms,
                KmsCategory::CryptoKey.as_str(),
                tag_filter,
                limit,
                for_update,
            )
            .await?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            entries.push(KeyEntry::from_entry(row)?)
        }
        Ok(entries)
    }

    /// Remove an existing key from the store
    pub async fn remove_key(&mut self, name: &str) -> Result<(), Error> {
        self.0
            .update(
                EntryKind::Kms,
                EntryOperation::Remove,
                KmsCategory::CryptoKey.as_str(),
                name,
                None,
                None,
                None,
            )
            .await
    }

    /// Replace the metadata and tags on an existing key in the store
    pub async fn update_key(
        &mut self,
        name: &str,
        metadata: Option<&str>,
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<(), Error> {
        let row = self
            .0
            .fetch(EntryKind::Kms, KmsCategory::CryptoKey.as_str(), name, true)
            .await?
            .ok_or_else(|| err_msg!(NotFound, "Key entry not found"))?;

        let mut params = KeyParams::from_slice(&row.value)?;
        params.metadata = metadata.map(str::to_string);
        let value = params.to_bytes()?;

        let mut upd_tags = Vec::with_capacity(10);
        if let Some(tags) = tags {
            for t in tags {
                upd_tags.push(t.map_ref(|k, v| (format!("user:{}", k), v.to_string())));
            }
        }
        for t in row.tags {
            if !t.name().starts_with("user:") {
                upd_tags.push(t);
            }
        }

        self.0
            .update(
                EntryKind::Kms,
                EntryOperation::Replace,
                KmsCategory::CryptoKey.as_str(),
                name,
                Some(value.as_ref()),
                Some(upd_tags.as_slice()),
                expiry_ms,
            )
            .await?;

        Ok(())
    }

    /// Commit the pending transaction
    pub async fn commit(self) -> Result<(), Error> {
        self.0.close(true).await
    }

    /// Roll back the pending transaction
    pub async fn rollback(self) -> Result<(), Error> {
        self.0.close(false).await
    }
}
