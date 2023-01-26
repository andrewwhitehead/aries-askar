use std::{
    borrow::Cow,
    fmt::{self, Debug, Formatter},
    pin::Pin,
    str::FromStr,
};

use futures_lite::stream::{Stream, StreamExt};
use serde::{
    de::{Error as SerdeError, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroize;

use super::wql;
use crate::{crypto::buffer::SecretBytes, error::Error};

pub(crate) fn sorted_tags(tags: &Vec<EntryTag>) -> Vec<&EntryTag> {
    if tags.is_empty() {
        Vec::new()
    } else {
        let mut tags = tags.iter().collect::<Vec<&EntryTag>>();
        tags.sort();
        tags
    }
}

/// A record in the store
#[derive(Clone, Debug, Eq)]
pub struct Entry {
    /// The category of the entry record
    pub category: String,

    /// The name of the entry record, unique within its category
    pub name: String,

    /// The value of the entry record
    pub value: SecretBytes,

    /// Tags associated with the entry record
    pub tags: Vec<EntryTag>,
}

impl Entry {
    /// Create a new `Entry`
    #[inline]
    pub fn new<C: Into<String>, N: Into<String>, V: Into<SecretBytes>>(
        category: C,
        name: N,
        value: V,
        tags: Vec<EntryTag>,
    ) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
            value: value.into(),
            tags,
        }
    }

    pub(crate) fn sorted_tags(&self) -> Vec<&EntryTag> {
        sorted_tags(&self.tags)
    }
}

impl PartialEq for Entry {
    fn eq(&self, rhs: &Self) -> bool {
        self.category == rhs.category
            && self.name == rhs.name
            && self.value == rhs.value
            && self.sorted_tags() == rhs.sorted_tags()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    Kms = 1,
    Item = 2,
}

/// Supported operations for entries in the store
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryOperation {
    /// Insert a new `Entry`
    Insert,
    /// Replace an existing `Entry`
    Replace,
    /// Remove an existing `Entry`
    Remove,
}

/// A tag on an entry record in the store
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub enum EntryTag {
    /// An entry tag to be stored encrypted
    Encrypted(String, String),
    /// An entry tag to be stored in plaintext (for ordered comparison)
    Plaintext(String, String),
}

impl EntryTag {
    /// Accessor for the tag name
    pub fn name(&self) -> &str {
        match self {
            Self::Encrypted(name, _) | Self::Plaintext(name, _) => name,
        }
    }

    pub(crate) fn map_ref(&self, f: impl FnOnce(&str, &str) -> (String, String)) -> Self {
        match self {
            Self::Encrypted(name, val) => {
                let (name, val) = f(name.as_str(), val.as_str());
                Self::Encrypted(name, val)
            }
            Self::Plaintext(name, val) => {
                let (name, val) = f(name.as_str(), val.as_str());
                Self::Plaintext(name, val)
            }
        }
    }

    /// Setter for the tag name
    pub(crate) fn update_name(&mut self, f: impl FnOnce(&mut String)) {
        match self {
            Self::Encrypted(name, _) | Self::Plaintext(name, _) => f(name),
        }
    }

    /// Accessor for the tag value
    pub fn value(&self) -> &str {
        match self {
            Self::Encrypted(_, val) | Self::Plaintext(_, val) => val,
        }
    }

    /// Unwrap the tag value
    pub(crate) fn into_value(self) -> String {
        match self {
            Self::Encrypted(_, value) | Self::Plaintext(_, value) => value,
        }
    }
}

impl Debug for EntryTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypted(name, value) => f
                .debug_tuple("Encrypted")
                .field(&name)
                .field(&value)
                .finish(),
            Self::Plaintext(name, value) => f
                .debug_tuple("Plaintext")
                .field(&name)
                .field(&value)
                .finish(),
        }
    }
}

/// A wrapper type used for managing (de)serialization of tags
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EntryTagSet<'e>(Cow<'e, [EntryTag]>);

impl EntryTagSet<'_> {
    #[inline]
    pub fn into_vec(self) -> Vec<EntryTag> {
        self.0.into_owned()
    }
}

impl<'e> From<&'e [EntryTag]> for EntryTagSet<'e> {
    fn from(tags: &'e [EntryTag]) -> Self {
        Self(Cow::Borrowed(tags))
    }
}

impl From<Vec<EntryTag>> for EntryTagSet<'static> {
    fn from(tags: Vec<EntryTag>) -> Self {
        Self(Cow::Owned(tags))
    }
}

impl<'de> Deserialize<'de> for EntryTagSet<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagSetVisitor;

        impl<'d> Visitor<'d> for TagSetVisitor {
            type Value = EntryTagSet<'static>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object containing zero or more entry tags")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'d>,
            {
                let mut v = Vec::with_capacity(access.size_hint().unwrap_or_default());

                while let Some((key, values)) = access.next_entry::<&str, EntryTagValues>()? {
                    let (tag, enc) = match key.chars().next() {
                        Some('~') => (key[1..].to_owned(), false),
                        None => return Err(M::Error::custom("invalid tag name: empty string")),
                        _ => (key.to_owned(), true),
                    };
                    match (values, enc) {
                        (EntryTagValues::Single(value), true) => {
                            v.push(EntryTag::Encrypted(tag, value))
                        }
                        (EntryTagValues::Single(value), false) => {
                            v.push(EntryTag::Plaintext(tag, value))
                        }
                        (EntryTagValues::Multiple(values), true) => {
                            for value in values {
                                v.push(EntryTag::Encrypted(tag.clone(), value))
                            }
                        }
                        (EntryTagValues::Multiple(values), false) => {
                            for value in values {
                                v.push(EntryTag::Plaintext(tag.clone(), value))
                            }
                        }
                    }
                }

                Ok(EntryTagSet(Cow::Owned(v)))
            }
        }

        deserializer.deserialize_map(TagSetVisitor)
    }
}

enum EntryTagValues {
    Single(String),
    Multiple(Vec<String>),
}

impl<'de> Deserialize<'de> for EntryTagValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagValuesVisitor;

        impl<'d> Visitor<'d> for TagValuesVisitor {
            type Value = EntryTagValues;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string or list of strings")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Ok(EntryTagValues::Single(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Ok(EntryTagValues::Single(value))
            }

            fn visit_seq<S>(self, mut access: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'d>,
            {
                let mut v = Vec::with_capacity(access.size_hint().unwrap_or_default());
                while let Some(value) = access.next_element()? {
                    v.push(value)
                }
                Ok(EntryTagValues::Multiple(v))
            }
        }

        deserializer.deserialize_any(TagValuesVisitor)
    }
}

impl Serialize for EntryTagSet<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use std::collections::BTreeMap;

        #[derive(PartialOrd, Ord)]
        struct TagName<'a>(&'a str, bool);

        impl<'a> PartialEq for TagName<'a> {
            fn eq(&self, other: &Self) -> bool {
                self.1 == other.1 && self.0 == other.0
            }
        }

        impl<'a> Eq for TagName<'a> {}

        impl Serialize for TagName<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if self.1 {
                    serializer.serialize_str(self.0)
                } else {
                    serializer.collect_str(&format_args!("~{}", self.0))
                }
            }
        }

        let mut tags = BTreeMap::new();
        for tag in self.0.iter() {
            let (name, value) = match tag {
                EntryTag::Encrypted(name, val) => (TagName(name.as_str(), true), val.as_str()),
                EntryTag::Plaintext(name, val) => (TagName(name.as_str(), false), val.as_str()),
            };
            tags.entry(name).or_insert_with(Vec::new).push(value);
        }

        let mut map = serializer.serialize_map(Some(tags.len()))?;
        for (tag_name, values) in tags.into_iter() {
            if values.len() > 1 {
                map.serialize_entry(&tag_name, &values)?;
            } else {
                map.serialize_entry(&tag_name, &values[0])?;
            }
        }
        map.end()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncEntryTag {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub plaintext: bool,
}

/// A WQL filter used to restrict record queries
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct TagFilter {
    pub(crate) query: wql::Query,
}

impl TagFilter {
    /// Combine multiple tag filters using the `AND` operator
    #[inline]
    pub fn all_of(each: Vec<TagFilter>) -> Self {
        Self {
            query: wql::Query::And(unsafe { std::mem::transmute(each) }),
        }
    }

    /// Combine multiple tag filters using the `OR` operator
    #[inline]
    pub fn any_of(each: Vec<TagFilter>) -> Self {
        Self {
            query: wql::Query::Or(unsafe { std::mem::transmute(each) }),
        }
    }

    /// Get the inverse of a tag filter
    #[inline]
    pub fn negate(filter: TagFilter) -> Self {
        Self {
            query: wql::Query::Not(Box::new(filter.query)),
        }
    }

    /// Create an equality comparison tag filter
    #[inline]
    pub fn is_eq(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Eq(name.into(), value.into()),
        }
    }

    /// Create an inequality comparison tag filter
    #[inline]
    pub fn is_not_eq(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Neq(name.into(), value.into()),
        }
    }

    /// Create an greater-than comparison tag filter
    #[inline]
    pub fn is_gt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Gt(name.into(), value.into()),
        }
    }

    /// Create an greater-than-or-equal comparison tag filter
    #[inline]
    pub fn is_gte(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Gte(name.into(), value.into()),
        }
    }

    /// Create an less-than comparison tag filter
    #[inline]
    pub fn is_lt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Lt(name.into(), value.into()),
        }
    }

    /// Create an less-than-or-equal comparison tag filter
    #[inline]
    pub fn is_lte(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Lte(name.into(), value.into()),
        }
    }

    /// Create a LIKE comparison tag filter
    #[inline]
    pub fn is_like(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Like(name.into(), value.into()),
        }
    }

    /// Create an IN comparison tag filter for a set of tag values
    #[inline]
    pub fn is_in(name: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            query: wql::Query::In(name.into(), values),
        }
    }

    /// Create an EXISTS tag filter for a set of tag names
    #[inline]
    pub fn exist(names: Vec<String>) -> Self {
        Self {
            query: wql::Query::Exist(names),
        }
    }

    /// Convert the tag filter to JSON format
    pub fn to_string(&self) -> Result<String, Error> {
        serde_json::to_string(&self.query).map_err(err_map!("Error encoding tag filter"))
    }
}

impl From<wql::Query> for TagFilter {
    fn from(query: wql::Query) -> Self {
        Self { query }
    }
}

impl FromStr for TagFilter {
    type Err = Error;

    fn from_str(query: &str) -> Result<Self, Error> {
        let query = serde_json::from_str(query).map_err(err_map!("Error parsing tag query"))?;
        Ok(Self { query })
    }
}

/// An active record scan of a store backend
pub struct Scan<'s, T> {
    #[allow(clippy::type_complexity)]
    stream: Option<Pin<Box<dyn Stream<Item = Result<Vec<T>, Error>> + Send + 's>>>,
    page_size: usize,
}

impl<'s, T> Scan<'s, T> {
    pub(crate) fn new<S>(stream: S, page_size: usize) -> Self
    where
        S: Stream<Item = Result<Vec<T>, Error>> + Send + 's,
    {
        Self {
            stream: Some(stream.boxed()),
            page_size,
        }
    }

    /// Fetch the next set of result rows
    pub async fn fetch_next(&mut self) -> Result<Option<Vec<T>>, Error> {
        if let Some(mut s) = self.stream.take() {
            match s.try_next().await? {
                Some(val) => {
                    if val.len() == self.page_size {
                        self.stream.replace(s);
                    }
                    Ok(Some(val))
                }
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
}

impl<S> Debug for Scan<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scan")
            .field("page_size", &self.page_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_tags() {
        let tags = EntryTagSet::from(vec![
            EntryTag::Encrypted("a".to_owned(), "aval".to_owned()),
            EntryTag::Plaintext("b".to_owned(), "bval".to_owned()),
            EntryTag::Plaintext("b".to_owned(), "bval-2".to_owned()),
        ]);
        let ser = serde_json::to_string(&tags).unwrap();
        assert_eq!(ser, r#"{"a":"aval","~b":["bval","bval-2"]}"#);
        let tags2 = serde_json::from_str(&ser).unwrap();
        assert_eq!(tags, tags2);
    }
}
