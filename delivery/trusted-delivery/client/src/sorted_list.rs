use serde::{Deserializer, Serializer};
use serde_with::{DeserializeAs, SerializeAs};
use std::ops::{Deref, DerefMut, Index, IndexMut};
use thiserror::Error;

/// Sorted vector
#[derive(Debug, Clone)]
pub struct SortedList<T>(Vec<T>);

impl<T: Ord> From<Vec<T>> for SortedList<T> {
    fn from(mut v: Vec<T>) -> Self {
        v.sort();
        Self(v)
    }
}

impl<T> Deref for SortedList<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T, U> SerializeAs<SortedList<T>> for Vec<U>
where
    U: SerializeAs<T>,
{
    fn serialize_as<S>(source: &SortedList<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <[U] as SerializeAs<[T]>>::serialize_as(&source, serializer)
    }
}

impl<'de, T: Ord, U> DeserializeAs<'de, SortedList<T>> for Vec<U>
where
    U: DeserializeAs<'de, T>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<SortedList<T>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let list = <Vec<U> as DeserializeAs<Vec<T>>>::deserialize_as(deserializer)?;
        Ok(SortedList::from(list))
    }
}

/// Guarantees that size of underlying list fits into `u16`
#[derive(Debug, Clone)]
pub struct SizeU16<V>(V);

#[derive(Debug, Error)]
#[error("list is too large")]
pub struct TooLarge<V>(pub V);

impl<V, T> SizeU16<V>
where
    V: Deref<Target = [T]>,
{
    pub fn from_list(list: V) -> Result<Self, TooLarge<V>> {
        match u16::try_from(list.len()) {
            Ok(_) => Ok(Self(list)),
            Err(_) => Err(TooLarge(list)),
        }
    }

    pub fn len(&self) -> u16 {
        self.0.len().try_into().expect("guaranteed to fit into u16")
    }
}

impl<T: Ord> SizeU16<SortedList<T>> {
    pub fn find_index(&self, value: &T) -> Option<u16> {
        self.0
            .binary_search(value)
            .ok()
            .map(|index| index.try_into().expect("guaranteed to fit into u16"))
    }

    pub fn get(&self, i: u16) -> Option<&T> {
        self.0.get(usize::from(i))
    }
}

impl<V, T> Deref for SizeU16<V>
where
    V: Deref<Target = [T]>,
{
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<V, T> Index<u16> for SizeU16<V>
where
    V: Deref<Target = [T]>,
{
    type Output = T;

    #[inline(always)]
    fn index(&self, index: u16) -> &Self::Output {
        self.0.index(usize::from(index))
    }
}

impl<V, T> IndexMut<u16> for SizeU16<V>
where
    V: DerefMut<Target = [T]>,
{
    #[inline(always)]
    fn index_mut(&mut self, index: u16) -> &mut Self::Output {
        self.0.index_mut(usize::from(index))
    }
}
