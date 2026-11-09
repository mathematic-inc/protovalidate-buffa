//! Implementation details shared with generated validators.

use std::borrow::Borrow;

/// A zero-allocation, last-write-wins adapter over a protobuf map view.
///
/// Buffa's [`buffa::MapView`] retains duplicate wire entries. Validation must
/// instead observe protobuf map semantics, where only the last value for each
/// key exists. Buffa's unique iterator provides that behavior without copying
/// keys or values, at O(n²) worst-case cost.
#[derive(Debug)]
pub struct CanonicalMap<'view, 'buffer, K, V> {
    view: &'view buffa::MapView<'buffer, K, V>,
}

impl<'view, 'buffer, K, V> CanonicalMap<'view, 'buffer, K, V>
where
    K: PartialEq,
{
    /// Borrow a Buffa map view with canonical protobuf map semantics.
    #[must_use]
    pub const fn from_view(view: &'view buffa::MapView<'buffer, K, V>) -> Self {
        Self { view }
    }

    /// Return the number of distinct keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.view.len_unique()
    }

    /// Return whether the canonical map contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.view.is_empty()
    }

    /// Return the last value associated with `key`.
    #[must_use]
    pub fn get<Q>(&self, key: &Q) -> Option<&'view V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.view.get(key)
    }

    /// Return whether `key` is present.
    #[must_use]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.view.contains_key(key)
    }

    /// Iterate over distinct keys at their last wire position.
    pub fn keys(&self) -> impl Iterator<Item = &'view K> + use<'view, 'buffer, K, V> {
        self.view.iter_unique().map(|(key, _)| key)
    }

    /// Iterate over distinct key/value pairs at their last wire position.
    pub fn iter(&self) -> impl Iterator<Item = &'view (K, V)> + use<'view, 'buffer, K, V> {
        self.view.iter_unique()
    }
}

/// The default payload of a tuple variant, such as an unselected oneof
/// alternative's value.
#[must_use]
pub fn variant_default<T: Default, R>(_variant: fn(T) -> R) -> T {
    T::default()
}

/// Borrows a value through any references to it. Method lookup on `&&T`
/// stops at `T`, the first `Default` type, since references aren't.
pub trait Referent: Default {
    /// Borrow the value itself.
    fn referent(&self) -> &Self {
        self
    }
}

impl<T: Default> Referent for T {}
