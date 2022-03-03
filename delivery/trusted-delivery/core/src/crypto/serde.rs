use std::fmt;

use generic_array::GenericArray;
use serde::{Deserializer, Serializer};

use super::Serializable;

pub fn serialize<T, S>(thing: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serializable,
{
    if serializer.is_human_readable() {
        serializer.serialize_str(&hex::encode(thing.to_bytes()))
    } else {
        serializer.serialize_bytes(&thing.to_bytes())
    }
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Serializable,
{
    use std::marker::PhantomData;

    use serde::de::{Error, Visitor};

    struct TheVisitor<S>(PhantomData<S>);
    impl<'de, S: Serializable> Visitor<'de> for TheVisitor<S> {
        type Value = S;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", S::NAME)
        }
        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            let mut bytes = GenericArray::<u8, S::Size>::default();
            hex::decode_to_slice(v, &mut bytes).map_err(|_| E::custom("invalid hex string"))?;
            S::from_bytes(&bytes).map_err(E::custom)
        }
        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            S::from_bytes(v).map_err(E::custom)
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_str(TheVisitor(PhantomData))
    } else {
        deserializer.deserialize_bytes(TheVisitor(PhantomData))
    }
}

pub struct SerdeAs;

impl<T: Serializable> serde_with::SerializeAs<T> for SerdeAs {
    fn serialize_as<S>(thing: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize(thing, serializer)
    }
}

impl<'de, T: Serializable> serde_with::DeserializeAs<'de, T> for SerdeAs {
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize(deserializer)
    }
}

// /// Wraps [`Serializable`] and implements [serde] traits: [`Serialize`] and [`Deserialize`]
// #[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
// pub struct Serde<S>(pub S);
//
// impl<S: Serializable> Serialize for Serde<S> {
//     fn serialize<M>(&self, serializer: M) -> Result<M::Ok, M::Error>
//     where
//         M: serde::ser::Serializer,
//     {
//         if serializer.is_human_readable() {
//             serializer.serialize_str(&hex::encode(self.0.to_bytes()))
//         } else {
//             serializer.serialize_bytes(&self.0.to_bytes())
//         }
//     }
// }
//
// impl<'de, S: Serializable> Deserialize<'de> for Serde<S> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::de::Deserializer<'de>,
//     {
//         use std::marker::PhantomData;
//
//         use serde::de::{Error, Visitor};
//
//         struct TheVisitor<S>(PhantomData<S>);
//         impl<'de, S: Serializable> Visitor<'de> for TheVisitor<S> {
//             type Value = S;
//             fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
//                 write!(f, "{}", S::NAME)
//             }
//             fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
//             where
//                 E: Error,
//             {
//                 let mut bytes = GenericArray::<u8, S::Size>::default();
//                 hex::decode_to_slice(v, &mut bytes).map_err(|_| E::custom("invalid hex string"))?;
//                 S::from_bytes(&bytes).map_err(E::custom)
//             }
//             fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
//             where
//                 E: Error,
//             {
//                 S::from_bytes(v).map_err(E::custom)
//             }
//         }
//
//         if deserializer.is_human_readable() {
//             deserializer
//                 .deserialize_str(TheVisitor(PhantomData))
//                 .map(Self)
//         } else {
//             deserializer
//                 .deserialize_bytes(TheVisitor(PhantomData))
//                 .map(Self)
//         }
//     }
// }
