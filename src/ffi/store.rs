use std::{collections::BTreeMap, os::raw::c_char, ptr, str::FromStr, sync::Arc};

use async_mutex::{Mutex, MutexGuardArc};
use ffi_support::{rust_string_to_c, ByteBuffer, FfiStr};
use once_cell::sync::Lazy;

use super::{
    error::set_last_error,
    key::LocalKeyHandle,
    result_list::{EntryListHandle, FfiEntryList, FfiKeyEntryList, KeyEntryListHandle},
    CallbackId, EnsureCallback, ErrorCode,
};
use crate::{
    backend::{
        any::{AnySession, AnyStore},
        ManageBackend,
    },
    error::Error,
    future::spawn_ok,
    protect::{generate_raw_store_key, PassKey, StoreKeyMethod},
    storage::{Entry, EntryOperation, EntryTagSet, Scan, TagFilter},
};

new_sequence_handle!(StoreHandle, FFI_STORE_COUNTER);
new_sequence_handle!(SessionHandle, FFI_SESSION_COUNTER);
new_sequence_handle!(ScanHandle, FFI_SCAN_COUNTER);

static FFI_STORES: Lazy<Mutex<BTreeMap<StoreHandle, Arc<AnyStore>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static FFI_SESSIONS: Lazy<Mutex<BTreeMap<SessionHandle, Arc<Mutex<AnySession>>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static FFI_SCANS: Lazy<Mutex<BTreeMap<ScanHandle, Option<Scan<'static, Entry>>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

impl StoreHandle {
    pub async fn create(value: AnyStore) -> Self {
        let handle = Self::next();
        let mut repo = FFI_STORES.lock().await;
        repo.insert(handle, Arc::new(value));
        handle
    }

    pub async fn load(&self) -> Result<Arc<AnyStore>, Error> {
        FFI_STORES
            .lock()
            .await
            .get(self)
            .cloned()
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }

    pub async fn remove(&self) -> Result<Arc<AnyStore>, Error> {
        FFI_STORES
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid store handle"))
    }

    pub async fn replace(&self, store: Arc<AnyStore>) {
        FFI_STORES.lock().await.insert(*self, store);
    }
}

impl SessionHandle {
    pub async fn create(value: AnySession) -> Self {
        let handle = Self::next();
        let mut repo = FFI_SESSIONS.lock().await;
        repo.insert(handle, Arc::new(Mutex::new(value)));
        handle
    }

    pub async fn load(&self) -> Result<MutexGuardArc<AnySession>, Error> {
        Ok(Mutex::lock_arc(
            FFI_SESSIONS
                .lock()
                .await
                .get(self)
                .ok_or_else(|| err_msg!("Invalid session handle"))?,
        )
        .await)
    }

    pub async fn remove(&self) -> Result<Arc<Mutex<AnySession>>, Error> {
        FFI_SESSIONS
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid session handle"))
    }
}

impl ScanHandle {
    pub async fn create(value: Scan<'static, Entry>) -> Self {
        let handle = Self::next();
        let mut repo = FFI_SCANS.lock().await;
        repo.insert(handle, Some(value));
        handle
    }

    pub async fn borrow(&self) -> Result<Scan<'static, Entry>, Error> {
        FFI_SCANS
            .lock()
            .await
            .get_mut(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .take()
            .ok_or_else(|| err_msg!(Busy, "Scan handle in use"))
    }

    pub async fn release(&self, value: Scan<'static, Entry>) -> Result<(), Error> {
        FFI_SCANS
            .lock()
            .await
            .get_mut(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .replace(value);
        Ok(())
    }

    pub async fn remove(&self) -> Result<Scan<'static, Entry>, Error> {
        FFI_SCANS
            .lock()
            .await
            .remove(self)
            .ok_or_else(|| err_msg!("Invalid scan handle"))?
            .ok_or_else(|| err_msg!(Busy, "Scan handle in use"))
    }
}

#[no_mangle]
pub extern "C" fn askar_store_generate_raw_key(
    seed: ByteBuffer,
    out: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Create raw store key");
        let seed = match seed.as_slice() {
            s if s.is_empty() => None,
            s => Some(s)
        };
        let key = generate_raw_store_key(seed)?;
        unsafe { *out = rust_string_to_c(key.to_string()); }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_provision(
    spec_uri: FfiStr<'_>,
    key_method: FfiStr<'_>,
    pass_key: FfiStr<'_>,
    profile: FfiStr<'_>,
    recreate: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Provision store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No provision spec URI provided"))?;
        let key_method = match key_method.as_opt_str() {
            Some(method) => StoreKeyMethod::parse_uri(method)?,
            None => StoreKeyMethod::default()
        };
        let pass_key = PassKey::from(pass_key.as_opt_str()).into_owned();
        let profile = profile.into_opt_string();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(sid) => {
                    info!("Provisioned store {}", sid);
                    cb(cb_id, ErrorCode::Success, sid)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = spec_uri.provision_backend(
                    key_method,
                    pass_key,
                    profile.as_ref().map(String::as_str),
                    recreate != 0
                ).await?;
                Ok(StoreHandle::create(store).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_open(
    spec_uri: FfiStr<'_>,
    key_method: FfiStr<'_>,
    pass_key: FfiStr<'_>,
    profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: StoreHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Open store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No store URI provided"))?;
        let key_method = match key_method.as_opt_str() {
            Some(method) => Some(StoreKeyMethod::parse_uri(method)?),
            None => None
        };
        let pass_key = PassKey::from(pass_key.as_opt_str()).into_owned();
        let profile = profile.into_opt_string();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(sid) => {
                    info!("Opened store {}", sid);
                    cb(cb_id, ErrorCode::Success, sid)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), StoreHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = spec_uri.open_backend(
                    key_method,
                    pass_key,
                    profile.as_ref().map(String::as_str)
                ).await?;
                Ok(StoreHandle::create(store).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_remove(
    spec_uri: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, i8)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Remove store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let spec_uri = spec_uri.into_opt_string().ok_or_else(|| err_msg!("No store URI provided"))?;
        let cb = EnsureCallback::new(move |result: Result<bool,Error>|
            match result {
                Ok(removed) => cb(cb_id, ErrorCode::Success, removed as i8),
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = async {
                let removed = spec_uri.remove_backend().await?;
                Ok(removed)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_create_profile(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, result_p: *const c_char)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Create profile");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(name) => cb(cb_id, ErrorCode::Success, rust_string_to_c(name)),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let name = store.create_profile(profile).await?;
                Ok(name)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_get_profile_name(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, name: *const c_char)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Get profile name");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(name) => cb(cb_id, ErrorCode::Success, rust_string_to_c(name)),
                Err(err) => cb(cb_id, set_last_error(Some(err)), ptr::null_mut()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                Ok(store.get_profile_name().to_string())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_remove_profile(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, removed: i8)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Remove profile");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string().ok_or_else(|| err_msg!("Profile name not provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(removed) => cb(cb_id, ErrorCode::Success, removed as i8),
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                Ok(store.remove_profile(profile).await?)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_rekey(
    handle: StoreHandle,
    key_method: FfiStr<'_>,
    pass_key: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Re-key store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let key_method = match key_method.as_opt_str() {
            Some(method) => StoreKeyMethod::parse_uri(method)?,
            None => StoreKeyMethod::default()
        };
        let pass_key = PassKey::from(pass_key.as_opt_str()).into_owned();
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.remove().await?;
                match Arc::try_unwrap(store) {
                    Ok(mut store) => {
                        store.rekey(key_method, pass_key.as_ref()).await?;
                        handle.replace(Arc::new(store)).await;
                        Ok(())
                    }
                    Err(arc_store) => {
                        handle.replace(arc_store).await;
                        Err(err_msg!("Cannot re-key store with multiple references"))
                    }
                }
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_store_close(
    handle: StoreHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Close store");
        let cb = cb.map(|cb| {
            EnsureCallback::new(move |result|
                match result {
                    Ok(_) => cb(cb_id, ErrorCode::Success),
                    Err(err) => cb(cb_id, set_last_error(Some(err))),
                }
            )
        });
        spawn_ok(async move {
            let result = async {
                let store = handle.remove().await?;
                store.arc_close().await?;
                info!("Closed store {}", handle);
                Ok(())
            }.await;
            if let Some(cb) = cb {
                cb.resolve(result);
            }
            else if let Err(err) = result {
                error!("{}", err);
            }
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_start(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    offset: i64,
    limit: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: ScanHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store start");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let profile = profile.into_opt_string();
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let cb = EnsureCallback::new(move |result: Result<ScanHandle,Error>|
            match result {
                Ok(scan_handle) => {
                    info!("Started scan {} on store {}", scan_handle, handle);
                    cb(cb_id, ErrorCode::Success, scan_handle)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), ScanHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let scan = store.scan(profile, category, tag_filter, Some(offset), if limit < 0 { None }else {Some(limit)}).await?;
                Ok(ScanHandle::create(scan).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_next(
    handle: ScanHandle,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: EntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Scan store next");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: Result<Option<Vec<Entry>>,Error>|
            match result {
                Ok(Some(entries)) => {
                    let results = EntryListHandle::create(FfiEntryList::from(entries));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, EntryListHandle::invalid()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), EntryListHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut scan = handle.borrow().await?;
                let entries = scan.fetch_next().await?;
                handle.release(scan).await?;
                Ok(entries)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_scan_free(handle: ScanHandle) -> ErrorCode {
    catch_err! {
        trace!("Close scan");
        spawn_ok(async move {
            handle.remove().await.ok();
            info!("Closed scan {}", handle);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_start(
    handle: StoreHandle,
    profile: FfiStr<'_>,
    as_transaction: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, handle: SessionHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Session start");
        let profile = profile.into_opt_string();
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let cb = EnsureCallback::new(move |result: Result<SessionHandle,Error>|
            match result {
                Ok(sess_handle) => {
                    info!("Started session {} on store {} (txn: {})", sess_handle, handle, as_transaction != 0);
                    cb(cb_id, ErrorCode::Success, sess_handle)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), SessionHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let store = handle.load().await?;
                let session = if as_transaction == 0 {
                    store.session(profile).await?
                } else {
                    store.transaction(profile).await?
                };
                Ok(SessionHandle::create(session).await)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_count(
    handle: SessionHandle,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, count: i64)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let cb = EnsureCallback::new(move |result: Result<i64,Error>|
            match result {
                Ok(count) => cb(cb_id, ErrorCode::Success, count),
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.count(&category, tag_filter).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch(
    handle: SessionHandle,
    category: FfiStr<'_>,
    name: FfiStr<'_>,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: EntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Name not provided"))?;
        let cb = EnsureCallback::new(move |result: Result<Option<Entry>,Error>|
            match result {
                Ok(Some(entry)) => {
                    let results = EntryListHandle::create(FfiEntryList::from(entry));
                    cb(cb_id, ErrorCode::Success, results)
                },
                Ok(None) => cb(cb_id, ErrorCode::Success, EntryListHandle::invalid()),
                Err(err) => cb(cb_id, set_last_error(Some(err)), EntryListHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.fetch(&category, &name, for_update != 0).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch_all(
    handle: SessionHandle,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    limit: i64,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: EntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let limit = if limit < 0 { None } else {Some(limit)};
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(rows) => {
                    let results = EntryListHandle::create(FfiEntryList::from(rows));
                    cb(cb_id, ErrorCode::Success, results)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), EntryListHandle::invalid()),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.fetch_all(&category, tag_filter, limit, for_update != 0).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_remove_all(
    handle: SessionHandle,
    category: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, removed: i64)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Count from store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Category not provided"))?;
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(removed) => {
                    cb(cb_id, ErrorCode::Success, removed)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.remove_all(&category, tag_filter).await
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_update(
    handle: SessionHandle,
    operation: i8,
    category: FfiStr<'_>,
    name: FfiStr<'_>,
    value: ByteBuffer,
    tags: FfiStr<'_>,
    expiry_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Update store");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let operation = match operation {
            0 => EntryOperation::Insert,
            1 => EntryOperation::Replace,
            2 => EntryOperation::Remove,
            _ => return Err(err_msg!("Invalid update operation"))
        };
        let category = category.into_opt_string().ok_or_else(|| err_msg!("Entry category not provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("Entry name not provided"))?;
        let value = value.as_slice().to_vec();
        let tags = if let Some(tags) = tags.as_opt_str() {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        let expiry_ms = if expiry_ms < 0 {
            None
        } else {
            Some(expiry_ms)
        };
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => cb(cb_id, ErrorCode::Success),
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );
        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.update(operation, &category, &name, Some(value.as_slice()), tags.as_ref().map(Vec::as_slice), expiry_ms).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_insert_key(
    handle: SessionHandle,
    key_handle: LocalKeyHandle,
    name: FfiStr<'_>,
    metadata: FfiStr<'_>,
    tags: FfiStr<'_>,
    expiry_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Insert key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let key = key_handle.load()?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;
        let metadata = metadata.into_opt_string();
        let tags = if let Some(tags) = tags.as_opt_str() {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        let expiry_ms = if expiry_ms < 0 {
            None
        } else {
            Some(expiry_ms)
        };
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => {
                    cb(cb_id, ErrorCode::Success)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.insert_key(
                    name.as_str(),
                    &key,
                    metadata.as_ref().map(String::as_str),
                    tags.as_ref().map(Vec::as_slice),
                    expiry_ms,
                ).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch_key(
    handle: SessionHandle,
    name: FfiStr<'_>,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: KeyEntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;

        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(Some(entry)) => {
                    let results = KeyEntryListHandle::create(FfiKeyEntryList::from(entry));
                    cb(cb_id, ErrorCode::Success, results)
                }
                Ok(None) => {
                    cb(cb_id, ErrorCode::Success, KeyEntryListHandle::invalid())
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), KeyEntryListHandle::invalid()),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                let key_entry = session.fetch_key(
                    name.as_str(),
                    for_update != 0
                ).await?;
                Ok(key_entry)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_fetch_all_keys(
    handle: SessionHandle,
    alg: FfiStr<'_>,
    thumbprint: FfiStr<'_>,
    tag_filter: FfiStr<'_>,
    limit: i64,
    for_update: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, results: KeyEntryListHandle)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Fetch all keys");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let alg = alg.into_opt_string();
        let thumbprint = thumbprint.into_opt_string();
        let tag_filter = tag_filter.as_opt_str().map(TagFilter::from_str).transpose()?;
        let limit = if limit < 0 { None } else {Some(limit)};

        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(entries) => {
                    let results = KeyEntryListHandle::create(FfiKeyEntryList::from(entries));
                    cb(cb_id, ErrorCode::Success, results)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err)), KeyEntryListHandle::invalid()),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                let key_entry = session.fetch_all_keys(
                    alg.as_ref().map(String::as_str),
                    thumbprint.as_ref().map(String::as_str),
                    tag_filter,
                    limit,
                    for_update != 0
                ).await?;
                Ok(key_entry)
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_update_key(
    handle: SessionHandle,
    name: FfiStr<'_>,
    metadata: FfiStr<'_>,
    tags: FfiStr<'_>,
    expiry_ms: i64,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Update key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;
        let metadata = metadata.into_opt_string();
        let tags = if let Some(tags) = tags.as_opt_str() {
            Some(
                serde_json::from_str::<EntryTagSet<'static>>(tags)
                    .map_err(err_map!("Error decoding tags"))?
                    .into_vec(),
            )
        } else {
            None
        };
        let expiry_ms = if expiry_ms < 0 {
            None
        } else {
            Some(expiry_ms)
        };
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => {
                    cb(cb_id, ErrorCode::Success)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.update_key(
                    &name,
                    metadata.as_ref().map(String::as_str),
                    tags.as_ref().map(Vec::as_slice),
                    expiry_ms,

                ).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_remove_key(
    handle: SessionHandle,
    name: FfiStr<'_>,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Remove key");
        let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
        let name = name.into_opt_string().ok_or_else(|| err_msg!("No key name provided"))?;
        let cb = EnsureCallback::new(move |result|
            match result {
                Ok(_) => {
                    cb(cb_id, ErrorCode::Success)
                }
                Err(err) => cb(cb_id, set_last_error(Some(err))),
            }
        );

        spawn_ok(async move {
            let result = async {
                let mut session = handle.load().await?;
                session.remove_key(
                    &name,
                ).await?;
                Ok(())
            }.await;
            cb.resolve(result);
        });
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_session_close(
    handle: SessionHandle,
    commit: i8,
    cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode)>,
    cb_id: CallbackId,
) -> ErrorCode {
    catch_err! {
        trace!("Close session");
        let cb = cb.map(|cb| {
            EnsureCallback::new(move |result|
                match result {
                    Ok(_) => cb(cb_id, ErrorCode::Success),
                    Err(err) => {
                        cb(cb_id, set_last_error(Some(err)))
                    }
                }
            )
        });
        spawn_ok(async move {
            let result = async {
                let session = handle.remove().await?;
                if let Ok(session) = Arc::try_unwrap(session) {
                    if commit == 0 {
                        // not necessary - rollback is automatic for txn,
                        // and for regular session there is no action to perform
                        // session.into_inner().rollback().await?;
                    } else {
                        session.into_inner().commit().await?;
                    }
                    info!("Closed session {}", handle);
                    Ok(())
                } else {
                    Err(err_msg!("Error closing session: has outstanding references"))
                }
            }.await;
            if let Some(cb) = cb {
                cb.resolve(result);
            }
            else if let Err(err) = result {
                error!("{}", err);
            }
        });
        Ok(ErrorCode::Success)
    }
}
