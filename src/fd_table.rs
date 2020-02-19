use std::cell::RefCell;
use std::rc::Rc;

pub struct FdTable;
pub type FdTableSharedPtr = Rc<RefCell<FdTable>>;
