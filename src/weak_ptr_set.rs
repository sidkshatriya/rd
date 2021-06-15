use crate::{
    log::LogLevel::LogDebug,
    session::task::{Task, WeakTaskPtrSet},
    thread_group::{ThreadGroup, WeakThreadGroupPtrSet},
};
use std::{
    collections::{hash_set::Iter, HashSet},
    hash::{Hash, Hasher},
    ops::Deref,
    rc::{Rc, Weak},
};

pub struct WeakPtrWrap<T>(pub Weak<T>);

impl<T> Clone for WeakPtrWrap<T> {
    fn clone(&self) -> Self {
        WeakPtrWrap(self.0.clone())
    }
}

impl<T> PartialEq for WeakPtrWrap<T> {
    fn eq(&self, other: &Self) -> bool {
        // We could upgrade the weak pointer and then check for ptr equality
        // However that will be slower and its uncertain if that
        // gives us more "correctness"
        self.0.ptr_eq(&other.0)
    }
}

impl<T> Eq for WeakPtrWrap<T> {}

impl<T> Hash for WeakPtrWrap<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We could upgrade the weak pointer and then take numeric address
        // However that will be slower and its uncertain if that gives
        // us more "correctness".
        let addr = self.0.as_ptr().cast::<u8>() as usize;
        // The hash is the hash of the address of the Refcell.
        addr.hash(state);
    }
}

impl<T> Deref for WeakPtrWrap<T> {
    type Target = Weak<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> Deref for WeakPtrSet<T> {
    type Target = HashSet<WeakPtrWrap<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct WeakPtrSet<T>(HashSet<WeakPtrWrap<T>>);

impl<T> Clone for WeakPtrSet<T> {
    fn clone(&self) -> Self {
        WeakPtrSet(self.0.clone())
    }
}

impl WeakThreadGroupPtrSet {
    pub fn insert_tg(&mut self, tg: &ThreadGroup) -> bool {
        log!(
            LogDebug,
            "adding thread group {} (real tgid: {}) to set {:?}",
            tg.tgid,
            tg.real_tgid,
            self as *const _
        );
        self.0.insert(WeakPtrWrap(tg.weak_self_clone()))
    }

    pub fn erase_tg(&mut self, tg: &ThreadGroup) -> bool {
        log!(
            LogDebug,
            "removing thread group {} (real tgid: {}) from set {:?}",
            tg.tgid,
            tg.real_tgid,
            self as *const _
        );
        self.0.remove(&WeakPtrWrap(tg.weak_self_clone()))
    }
}

impl WeakTaskPtrSet {
    pub fn insert_task(&mut self, t: &dyn Task) -> bool {
        log!(
            LogDebug,
            "adding task {} (rec: {}) to set {:?}",
            t.tid(),
            t.rec_tid(),
            self as *const _
        );
        self.0.insert(WeakPtrWrap(t.weak_self_clone()))
    }

    pub fn erase_task(&mut self, t: &dyn Task) -> bool {
        log!(
            LogDebug,
            "removing task {} (rec: {}) from set {:?}",
            t.tid(),
            t.rec_tid(),
            self as *const _
        );
        self.0.remove(&WeakPtrWrap(t.weak_self_clone()))
    }
}

impl<T> WeakPtrSet<T> {
    pub fn new() -> WeakPtrSet<T> {
        WeakPtrSet(HashSet::new())
    }

    pub fn inner_hashset(&self) -> &HashSet<WeakPtrWrap<T>> {
        &self.0
    }

    pub fn iter(&self) -> SetIterator<T> {
        self.into_iter()
    }

    pub fn iter_except(&self, tw: Weak<T>) -> ExceptSetIterator<T> {
        ExceptSetIterator {
            hash_set_iterator: self.0.iter(),
            except: tw,
        }
    }

    pub fn insert(&mut self, t: Weak<T>) -> bool {
        log!(
            LogDebug,
            "adding item {:?} to set {:?}",
            t.as_ptr(),
            self as *const _
        );
        self.0.insert(WeakPtrWrap(t))
    }

    pub fn erase(&mut self, t: Weak<T>) -> bool {
        log!(
            LogDebug,
            "removing item {:?} from set {:?}",
            t.as_ptr(),
            self as *const _
        );
        self.0.remove(&WeakPtrWrap(t))
    }

    pub fn has(&self, t: Weak<T>) -> bool {
        self.0.contains(&WeakPtrWrap(t))
    }
}

impl<'a, T> IntoIterator for &'a WeakPtrSet<T> {
    type Item = Rc<T>;
    type IntoIter = SetIterator<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        SetIterator {
            hash_set_iterator: self.0.iter(),
        }
    }
}

pub struct SetIterator<'a, T> {
    hash_set_iterator: Iter<'a, WeakPtrWrap<T>>,
}

pub struct ExceptSetIterator<'a, T> {
    hash_set_iterator: Iter<'a, WeakPtrWrap<T>>,
    except: Weak<T>,
}

impl<T> Iterator for SetIterator<'_, T> {
    type Item = Rc<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.hash_set_iterator.next().map(|t| t.upgrade().unwrap())
    }
}

impl<T> Iterator for ExceptSetIterator<'_, T> {
    type Item = Rc<T>;

    fn next(&mut self) -> Option<Self::Item> {
        for WeakPtrWrap(it) in &mut self.hash_set_iterator {
            if it.ptr_eq(&self.except) {
                continue;
            } else {
                return Some(it.upgrade().unwrap());
            }
        }
        None
    }
}

impl<T> Default for WeakPtrSet<T> {
    fn default() -> Self {
        WeakPtrSet(Default::default())
    }
}
