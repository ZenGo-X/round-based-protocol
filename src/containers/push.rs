//! Abstraction over pushable collections
//!
//! [Push] trait allows writing functions which are generic over collection and can only append
//! elements to it, preventing from accident accessing/modifying existing data. Along with [PushExt]
//! trait, that provides extra utilities for `Push`able collections, they are convenient for
//! describing protocol in terms of rounds, where every round may send messages by appending
//! them to sending queue.

/// Collection which can only be appended by 1 element
pub trait Push<T> {
    fn push(&mut self, element: T);
}

impl<T> Push<T> for Vec<T> {
    fn push(&mut self, element: T) {
        Vec::push(self, element)
    }
}

impl<T, P> Push<T> for &mut P
where
    P: Push<T>,
{
    fn push(&mut self, element: T) {
        P::push(self, element)
    }
}

mod private {
    pub trait Sealed<T> {}
    impl<P, T> Sealed<T> for P where P: super::Push<T> {}
}

/// Utilities around [Push]able collections
pub trait PushExt<T>: Push<T> + private::Sealed<T> {
    /// Takes a closure and produces a `Push`able object which applies closure to each element
    fn gmap<B, F>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
        F: FnMut(B) -> T;
}

impl<P, T> PushExt<T> for P
where
    P: Push<T>,
{
    fn gmap<B, F>(self, f: F) -> Map<Self, F>
    where
        Self: Sized,
        F: FnMut(B) -> T,
    {
        Map { pushable: self, f }
    }
}

/// Wraps pushable collection and applies closure `f` to every pushed element
///
/// This wrapper is created by method [map](PushExt::gmap) on [PushExt]
pub struct Map<P, F> {
    pushable: P,
    f: F,
}

impl<A, B, P, F> Push<B> for Map<P, F>
where
    P: Push<A>,
    F: FnMut(B) -> A,
{
    fn push(&mut self, element: B) {
        self.pushable.push((self.f)(element))
    }
}
