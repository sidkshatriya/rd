use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
    ops::Deref,
    rc::Weak,
};

pub struct WeakWrap<T>(pub Weak<T>);

impl<T> Clone for WeakWrap<T> {
    fn clone(&self) -> Self {
        WeakWrap(self.0.clone())
    }
}

impl<T> PartialEq for WeakWrap<T> {
    fn eq(&self, other: &Self) -> bool {
        // We could upgrade the weak pointer and then check for ptr equality
        // However that will be slower and its uncertain if that
        // gives us more "correctness"
        self.0.ptr_eq(&other.0)
    }
}

impl<T> Eq for WeakWrap<T> {}

impl<T> Hash for WeakWrap<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We could upgrade the weak pointer and then take numeric address
        // However that will be slower and its uncertain if that gives
        // us more "correctness".
        let addr = self.0.as_ptr().cast::<u8>() as usize;
        // The hash is the hash of the address of the Refcell.
        addr.hash(state);
    }
}

impl<T> Deref for WeakWrap<T> {
    type Target = Weak<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Deref for WeakSet<T> {
    type Target = HashSet<WeakWrap<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct WeakSet<T>(HashSet<WeakWrap<T>>);

impl<T> Clone for WeakSet<T> {
    fn clone(&self) -> Self {
        WeakSet(self.0.clone())
    }
}

impl<T> WeakSet<T> {
    pub fn new() -> WeakSet<T> {
        WeakSet(HashSet::new())
    }

    pub fn inner_hashset(&self) -> &HashSet<WeakWrap<T>> {
        &self.0
    }

    pub fn insert(&mut self, t: Weak<T>) -> bool {
        self.0.insert(WeakWrap(t))
    }

    pub fn erase(&mut self, t: Weak<T>) -> bool {
        self.0.remove(&WeakWrap(t))
    }

    pub fn has(&self, t: Weak<T>) -> bool {
        self.0.contains(&WeakWrap(t))
    }
}

impl<T> Default for WeakSet<T> {
    fn default() -> Self {
        WeakSet(Default::default())
    }
}
