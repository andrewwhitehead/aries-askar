use std::{ffi::CString, os::raw::c_char, ptr};

use super::{
    handle::ArcHandle, key::LocalKeyHandle, secret::SecretBuffer, tags::EntryTagSet, ErrorCode,
};
use crate::{error::Error, kms::KeyEntry, storage::entry::Entry};
pub enum FfiResultList<R> {
    Single(R),
    Rows(Vec<R>),
}

impl<R> FfiResultList<R> {
    pub fn get_row(&self, idx: i32) -> Result<&R, Error> {
        if idx >= 0 {
            match self {
                Self::Single(e) => {
                    if idx == 0 {
                        return Ok(e);
                    }
                }
                Self::Rows(r) => {
                    if let Some(e) = r.get(idx as usize) {
                        return Ok(e);
                    }
                }
            }
        }
        return Err(err_msg!(Input, "Invalid index for result set"));
    }

    pub fn len(&self) -> i32 {
        match self {
            Self::Single(..) => 0,
            Self::Rows(r) => r.len() as i32,
        }
    }
}

impl<R> From<R> for FfiResultList<R> {
    fn from(row: R) -> Self {
        Self::Single(row)
    }
}

impl<R> From<Vec<R>> for FfiResultList<R> {
    fn from(rows: Vec<R>) -> Self {
        Self::Rows(rows)
    }
}

pub type EntryListHandle = ArcHandle<FfiEntryList>;

pub type FfiEntryList = FfiResultList<Entry>;

#[no_mangle]
pub extern "C" fn askar_entry_list_count(handle: EntryListHandle, count: *mut i32) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(count);
        let results = handle.load()?;
        unsafe { *count = results.len() };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_entry_list_get_category(
    handle: EntryListHandle,
    index: i32,
    category: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(category);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        unsafe { *category = CString::new(entry.category.as_str()).unwrap().into_raw() };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_entry_list_get_name(
    handle: EntryListHandle,
    index: i32,
    name: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(name);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        unsafe { *name = CString::new(entry.name.as_str()).unwrap().into_raw() };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_entry_list_get_value(
    handle: EntryListHandle,
    index: i32,
    value: *mut SecretBuffer,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(value);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        unsafe { *value = SecretBuffer::from_secret(entry.value.as_ref()); }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_entry_list_get_tags(
    handle: EntryListHandle,
    index: i32,
    tags: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(tags);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        if entry.tags.is_empty() {
            unsafe { *tags = ptr::null() };
        } else {
            let tag_json = serde_json::to_vec(&EntryTagSet::from(entry.tags.as_slice())).unwrap();
            unsafe { *tags = CString::new(tag_json).unwrap().into_raw() };
        }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_entry_list_free(handle: EntryListHandle) {
    handle.remove();
}

pub type KeyEntryListHandle = ArcHandle<FfiKeyEntryList>;

pub type FfiKeyEntryList = FfiResultList<KeyEntry>;

#[no_mangle]
pub extern "C" fn askar_key_entry_list_count(
    handle: KeyEntryListHandle,
    count: *mut i32,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(count);
        let results = handle.load()?;
        unsafe { *count = results.len() };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_entry_list_free(handle: KeyEntryListHandle) {
    handle.remove();
}

#[no_mangle]
pub extern "C" fn askar_key_entry_list_get_algorithm(
    handle: KeyEntryListHandle,
    index: i32,
    alg: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(alg);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        if let Some(alg_name) = entry.algorithm() {
            unsafe { *alg = CString::new(alg_name).unwrap().into_raw() };
        } else {
            unsafe { *alg = ptr::null() };
        }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_entry_list_get_name(
    handle: KeyEntryListHandle,
    index: i32,
    name: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(name);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        unsafe { *name = CString::new(entry.name.as_str()).unwrap().into_raw() };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_entry_list_get_metadata(
    handle: KeyEntryListHandle,
    index: i32,
    metadata: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(metadata);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        if let Some(m) = entry.metadata() {
            unsafe { *metadata = CString::new(m).unwrap().into_raw(); }
        } else {
            unsafe { *metadata = ptr::null(); }
        }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_entry_list_get_tags(
    handle: KeyEntryListHandle,
    index: i32,
    tags: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        check_useful_c_ptr!(tags);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        if entry.tags.is_empty() {
            unsafe { *tags = ptr::null() };
        } else {
            let tag_json = serde_json::to_vec(&EntryTagSet::from(entry.tags.as_slice())).unwrap();
            unsafe { *tags = CString::new(tag_json).unwrap().into_raw() };
        }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_entry_list_load_local(
    handle: KeyEntryListHandle,
    index: i32,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        trace!("Load key");
        check_useful_c_ptr!(out);
        let results = handle.load()?;
        let entry = results.get_row(index)?;
        let key = entry.load_local_key()?;
        unsafe { *out = LocalKeyHandle::create(key) };
        Ok(ErrorCode::Success)
    }
}
