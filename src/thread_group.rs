use std::cell::RefCell;
use std::rc::Rc;

pub struct ThreadGroup;

pub type ThreadGroupSharedPtr = Rc<RefCell<ThreadGroup>>;
